// routes/auth.js
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const config = require('../config');
const casService = require('../services/cas');
const jwtService = require('../services/jwt');
const { logError, sanitizeValue } = require('../utils/error_handler');

const isProduction = config.env === 'production';
const JWT_COOKIE_NAME = 'authbridge.jwt';

function maskValue(value, left = 3, right = 2) {
  const raw = String(value || '');
  if (!raw) {
    return '';
  }
  if (!isProduction) {
    return raw;
  }
  if (raw.length <= left + right) {
    return '*'.repeat(raw.length);
  }
  return `${raw.slice(0, left)}***${raw.slice(-right)}`;
}

function sanitizeUrlForLog(rawUrl) {
  if (!rawUrl || !isProduction) {
    return rawUrl;
  }
  try {
    const urlObj = new URL(rawUrl);
    ["ticket", "token", "studentId", "state", "service"].forEach((key) => {
      if (urlObj.searchParams.has(key)) {
        const original = urlObj.searchParams.get(key);
        urlObj.searchParams.set(key, maskValue(original));
      }
    });
    return urlObj.toString();
  } catch (_error) {
    return String(rawUrl);
  }
}

function sanitizeValidationLog(validation) {
  if (!validation || !isProduction) {
    return validation;
  }

  const sanitized = { ...validation };
  if (sanitized.requestUrl) {
    sanitized.requestUrl = sanitizeUrlForLog(sanitized.requestUrl);
  }
  if (sanitized.responseBody && typeof sanitized.responseBody === 'string') {
    sanitized.responseBody = sanitized.responseBody.replace(/(ticket|token|studentId)=([^&\s]+)/gi, '$1=***');
  }
  return sanitized;
}

// 生成随机state
function generateState() {
  return crypto.randomBytes(16).toString('hex');
}

function getCasCallbackServiceUrl() {
  return config.buildAppUrl(config.casClient.paths.validate);
}

function getCasCallbackServiceUrlWithContext({ appid, returnMode, callback, state }) {
  const serviceUrl = new URL(getCasCallbackServiceUrl());

  if (appid) {
    serviceUrl.searchParams.set('appid', String(appid));
  }

  if (returnMode) {
    serviceUrl.searchParams.set('mode', String(returnMode));
  }

  if (callback) {
    serviceUrl.searchParams.set('callback', String(callback));
  }

  if (state) {
    serviceUrl.searchParams.set('state', String(state));
  }

  return serviceUrl.toString();
}

function getIncomingTarget(req) {
  const redirectKey = (config.cas && config.cas.redirectKey) || 'service';
  return req.query[redirectKey] || req.query.target || null;
}

function resolveLoginAppId(req) {
  const queryAppidRaw = req && req.query ? (req.query.appid || req.query.app) : null;
  const queryAppid = typeof queryAppidRaw === 'string' ? queryAppidRaw.trim() : '';
  if (queryAppid) {
    return queryAppid;
  }

  if (config.jwt && config.jwt.defaultAppId && config.applistMap && config.applistMap[config.jwt.defaultAppId]) {
    return config.jwt.defaultAppId;
  }

  const appIds = Object.keys(config.applistMap || {});
  if (appIds.length === 1) {
    return appIds[0];
  }

  return null;
}

function getDefaultReturnModeForApp(appid) {
  const appConfig = appid && config.applistMap ? config.applistMap[appid] : null;
  const configuredMode = appConfig
    ? (appConfig.return_mode || appConfig.returnMode || appConfig.mode)
    : null;
  const normalizedMode = normalizeReturnMode(configuredMode, null);
  if (normalizedMode) {
    return normalizedMode;
  }

  const hasWhitelistedCallback = getAppCallbackWhitelist(appid).length > 0;
  return hasWhitelistedCallback ? 'callback' : 'page';
}

function isValidRedirectUrl(input) {
  if (!input || typeof input !== 'string') {
    return false;
  }

  try {
    const target = new URL(input);
    return target.protocol === 'http:' || target.protocol === 'https:';
  } catch (_error) {
    return false;
  }
}

function normalizeHttpUrl(input) {
  if (!input || typeof input !== 'string') {
    return null;
  }

  try {
    const urlObj = new URL(input);
    if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
      return null;
    }
    urlObj.hash = '';
    return urlObj.toString();
  } catch (_error) {
    return null;
  }
}

function isWhitelistedUrl(targetUrl, whitelist) {
  const normalizedTarget = normalizeHttpUrl(targetUrl);
  if (!normalizedTarget) {
    return false;
  }

  const target = new URL(normalizedTarget);
  return (Array.isArray(whitelist) ? whitelist : []).some((rule) => {
    if (typeof rule !== 'string' || !rule.trim()) {
      return false;
    }

    const normalizedRule = normalizeHttpUrl(rule.trim());
    if (!normalizedRule) {
      return false;
    }

    const allowed = new URL(normalizedRule);
    if (allowed.origin !== target.origin || allowed.pathname !== target.pathname) {
      return false;
    }

    // 白名单未声明 query 时，允许动态 query（如 token/timestamp）
    if (!allowed.search) {
      return true;
    }

    return allowed.search === target.search;
  });
}

function getAppCallbackWhitelist(appid) {
  if (!appid || !config.applistMap || !config.applistMap[appid]) {
    return [];
  }

  const appConfig = config.applistMap[appid];
  const appListWhitelist = Array.isArray(appConfig.callback_whitelist) ? appConfig.callback_whitelist : [];
  const configWhitelist = config.callbackWhitelistMap && Array.isArray(config.callbackWhitelistMap[appid])
    ? config.callbackWhitelistMap[appid]
    : [];

  return Array.from(new Set([...appListWhitelist, ...configWhitelist]));
}

function isAllowedCallbackForApp(appid, callbackUrl) {
  const whitelist = getAppCallbackWhitelist(appid);
  return isWhitelistedUrl(callbackUrl, whitelist);
}

function isAllowedTargetUrl(appid, targetUrl) {
  if (!targetUrl || !isValidRedirectUrl(targetUrl)) {
    return false;
  }

  if (appid) {
    return isAllowedCallbackForApp(appid, targetUrl);
  }

  const allWhitelists = Object.keys(config.applistMap || {}).flatMap((appKey) => getAppCallbackWhitelist(appKey));
  return isWhitelistedUrl(targetUrl, allWhitelists);
}

function resolvePostLoginRedirect(req, appid) {
  const targetFromSession = req && req.session ? req.session.redirectTarget : null;
  if (!targetFromSession) {
    return null;
  }

  if (!isAllowedTargetUrl(appid, targetFromSession)) {
    return null;
  }

  return targetFromSession;
}

function getAllowedLogoutServiceWhitelist() {
  const allWhitelists = Object.keys(config.applistMap || {}).flatMap((appKey) => getAppCallbackWhitelist(appKey));
  return Array.from(new Set([config.appUrl, ...allWhitelists]));
}

function resolveSafeLogoutService(req) {
  const rawService = req && req.query ? req.query.service : null;
  const requestedService = typeof rawService === 'string' ? rawService.trim() : '';

  if (!requestedService) {
    return config.appUrl;
  }

  if (isWhitelistedUrl(requestedService, getAllowedLogoutServiceWhitelist())) {
    return requestedService;
  }

  return config.appUrl;
}

function normalizeReturnMode(rawMode, fallbackMode = null) {
  const mode = String(rawMode || "").trim().toLowerCase();
  if (mode === "callback") {
    return "callback";
  }
  if (mode === "page" || mode === "display") {
    return "page";
  }
  return fallbackMode;
}

function collectCookieDomains(req) {
  const domains = new Set();
  const hostHeader = req && typeof req.get === 'function' ? req.get('host') : '';
  const forwardedHostRaw = req && req.headers ? req.headers['x-forwarded-host'] : '';
  const forwardedHost = Array.isArray(forwardedHostRaw)
    ? forwardedHostRaw[0]
    : String(forwardedHostRaw || '').split(',')[0].trim();

  const host = String((req && req.hostname) || forwardedHost || hostHeader || '')
    .split(':')[0]
    .trim();

  if (!host) {
    return [undefined];
  }

  domains.add(undefined);
  domains.add(host);

  return Array.from(domains);
}

function clearTransientAuthState(req) {
  if (!req || !req.session) {
    return;
  }

  delete req.session.authState;
  delete req.session.targetApp;
  delete req.session.callbackUrl;
  delete req.session.redirectTarget;
  delete req.session.casFixedServiceUrl;
  delete req.session.returnMode;
  delete req.session.lastAuthFlow;
  delete req.session.jwtDisplay;
}

function clearClientAuthCookies(req, res) {
  const cookieName = config.session.name;
  const domains = collectCookieDomains(req);
  const appBasePath = config.appBasePath && config.appBasePath !== '/' ? config.appBasePath : '/';

  // 仅保留项目实际使用路径，避免产生过多 Set-Cookie 头
  const baseOptionsList = [
    { path: '/' },
    { path: appBasePath },
  ];

  const clearOptionsList = [];
  domains.forEach((domain) => {
    baseOptionsList.forEach((baseOptions) => {
      clearOptionsList.push(
        domain
          ? { ...baseOptions, domain }
          : baseOptions,
      );
    });
  });

  const candidateNames = Array.from(new Set([cookieName, JWT_COOKIE_NAME]));

  // 使用 clearCookie 即可，避免重复写回导致响应头膨胀
  candidateNames.forEach((name) => {
    clearOptionsList.forEach((options) => {
      res.clearCookie(name, options);
    });
  });

  // 现代浏览器可识别，强制清理当前源下 cookie
  res.setHeader('Clear-Site-Data', '"cookies"');
}

function renderAuthErrorAndClearSession(req, res, status, title, message) {
  clearTransientAuthState(req);
  casService.clearSession(req);

  const sendAuthErrorResponse = () => {
    clearClientAuthCookies(req, res);
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    return res.status(status).render('error', { title, message });
  };

  if (!req.session || typeof req.session.destroy !== 'function') {
    return sendAuthErrorResponse();
  }

  return req.session.destroy((err) => {
    if (err) {
      logError('认证失败时销毁session失败', err, {
        path: req.originalUrl,
      });
    }
    req.session = null;
    return sendAuthErrorResponse();
  });
}

function safeAsync(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch((error) => {
      logError('路由异步处理失败', error, {
        method: req.method,
        path: req.originalUrl,
        query: sanitizeValue(req.query),
      });
      next(error);
    });
  };
}

function regenerateSession(req) {
  if (!req.session || typeof req.session.regenerate !== 'function') {
    return Promise.resolve();
  }

  return new Promise((resolve, reject) => {
    req.session.regenerate((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

function saveSession(req) {
  if (!req.session || typeof req.session.save !== 'function') {
    return Promise.resolve();
  }

  return new Promise((resolve, reject) => {
    req.session.save((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

function getJwtExpiryMaxAge(token) {
  const fallback = config.session && Number(config.session.ttlMs) > 0
    ? Number(config.session.ttlMs)
    : 10 * 60 * 1000;

  try {
    const raw = String(token || '').trim();
    const parts = raw.split('.');
    if (parts.length < 2) {
      return fallback;
    }

    const payloadPart = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padded = payloadPart + '='.repeat((4 - (payloadPart.length % 4)) % 4);
    const decoded = Buffer.from(padded, 'base64').toString('utf8');
    const payload = JSON.parse(decoded);
    const exp = Number(payload && payload.exp);

    if (!Number.isFinite(exp)) {
      return fallback;
    }

    const maxAge = exp * 1000 - Date.now();
    if (!Number.isFinite(maxAge) || maxAge <= 0) {
      return 60 * 1000;
    }

    return Math.max(60 * 1000, maxAge);
  } catch (_error) {
    return fallback;
  }
}

function setJwtCookie(res, token) {
  if (!token) {
    return;
  }

  res.cookie(JWT_COOKIE_NAME, token, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    // 不设置 domain，保持 Host-Only Cookie，避免跨子域共享
    path: config.appBasePath,
    maxAge: getJwtExpiryMaxAge(token),
  });
}

function renderJwtCookieIssuedPage(res, studentId) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  return res.render('error', {
    title: '登录成功',
    message: `JWT 已通过 HttpOnly Cookie 安全下发（学号: ${maskValue(studentId, 2, 2)}），不再以明文展示或拼接到URL。`,
  });
}

function parseHeaderOrigin(input) {
  const raw = String(input || '').trim();
  if (!raw) {
    return null;
  }

  try {
    return new URL(raw).origin;
  } catch (_error) {
    return null;
  }
}

function isSameOriginRequest(req) {
  const expectedOrigin = parseHeaderOrigin(config.appUrl);
  if (!expectedOrigin) {
    return false;
  }

  const requestOrigin = parseHeaderOrigin(req.get('origin'));
  if (requestOrigin) {
    return requestOrigin === expectedOrigin;
  }

  const refererOrigin = parseHeaderOrigin(req.get('referer'));
  if (refererOrigin) {
    return refererOrigin === expectedOrigin;
  }

  return false;
}

function renderAutoPostTokenPage(res, callbackUrl, token, studentId) {
  let callbackOrigin = null;
  try {
    callbackOrigin = new URL(callbackUrl).origin;
  } catch (_error) {
    callbackOrigin = null;
  }

  const allowedFormAction = callbackOrigin ? `'self' ${callbackOrigin}` : "'self'";
  res.setHeader(
    'Content-Security-Policy',
    `default-src 'self'; base-uri 'self'; form-action ${allowedFormAction}; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'`,
  );
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  return res.render('auto-post-token', {
    callbackUrl,
    token,
    studentId,
    timestamp: Date.now(),
  });
}

function isLikelyGatewayIntercept403(validation) {
  if (!validation || Number(validation.status) !== 403) {
    return false;
  }

  const body = String(validation.responseBody || '').toLowerCase();
  return body.includes('<html') || body.includes('safeline') || body.includes('waf');
}

/**
 * CAS登录成功后业务扩展点
 * 在这里插入登录后自定义逻辑（如审计日志、用户画像加载等）
 */
async function onCasLoginSuccess(req, res, context) {
  // TODO: 在此插入 CAS 登录成功后的业务代码
  // context: { studentId, targetApp, callbackUrl }
  return context;
}

/**
 * 登录入口
 * GET /login?appid={appId}&mode={callback|page}&callback={url}
 */
router.get('/login', safeAsync(async (req, res) => {
  try {
    // 每次发起登录都刷新会话ID，降低会话固定攻击风险
    await regenerateSession(req);

    const appid = resolveLoginAppId(req);
    const callback = typeof req.query.callback === 'string' ? req.query.callback.trim() : '';
    const rawReturnMode = req.query.mode || req.query.return;
    const parsedReturnMode = normalizeReturnMode(rawReturnMode, null);
    const returnMode = parsedReturnMode || getDefaultReturnModeForApp(appid);
    const incomingTarget = getIncomingTarget(req);

    // 新一轮登录前，先清理上次可能残留的临时状态
    clearTransientAuthState(req);
    
    if (!appid) {
      return res.status(400).render('error', {
        title: '参数错误',
        message: '缺少 appid，请提供 appid 参数，或在配置中设置 DEFAULT_APP_ID'
      });
    }

    // 验证目标应用是否在 applist 中
    if (!config.applistMap[appid]) {
      return res.status(400).render('error', {
        title: '应用未授权',
        message: '请求的 appid 不在 applist 中'
      });
    }

    if (rawReturnMode && !parsedReturnMode) {
      return res.status(400).render('error', {
        title: '参数错误',
        message: 'mode 参数仅支持 callback 或 page'
      });
    }

    if (returnMode === 'page' && callback) {
      return res.status(400).render('error', {
        title: '参数错误',
        message: 'mode=page 不允许传 callback 参数'
      });
    }

    if (callback) {
      if (!isAllowedCallbackForApp(appid, callback)) {
        return res.status(400).render('error', {
          title: '回调地址未授权',
          message: 'callback 不在 applist 回调白名单中'
        });
      }
    }

    if (returnMode === 'callback') {
      const resolvedCallback = await casService.getCallbackUrl(appid, callback || null);
      if (!resolvedCallback) {
        return res.status(400).render('error', {
          title: '回调配置缺失',
          message: `应用 ${appid} 未配置有效回调地址；如需页面展示，请使用 mode=page 或在 applist 中配置 return_mode=page`
        });
      }
    }

    if (incomingTarget && !isAllowedTargetUrl(appid, incomingTarget)) {
      return res.status(400).render('error', {
        title: '重定向地址未授权',
        message: 'service/target 不在 applist 回调白名单中'
      });
    }

    // 生成state防止CSRF攻击
    const state = generateState();
    
    // 存储状态到session
    req.session.authState = state;
    req.session.targetApp = appid;
    req.session.callbackUrl = callback || null;
    req.session.redirectTarget = incomingTarget || null;
    req.session.returnMode = returnMode;
    
    console.log(`🔐 登录请求 - State: ${maskValue(state)}, appid: ${appid}, mode: ${returnMode}`);

    // service 必须和 connect-cas2 校验阶段的 service 完全一致，否则 CAS 会返回 403
    const serviceUrl = getCasCallbackServiceUrlWithContext({
      appid,
      returnMode,
      callback,
      state,
    });
    req.session.casFixedServiceUrl = serviceUrl;
    
    // 获取CAS登录URL
    const loginUrl = casService.getLoginUrl(serviceUrl);
    
    console.log(`重定向到CAS: ${sanitizeUrlForLog(loginUrl)}`);
    
    // 显式保存会话后再跳转，避免在外部存储下丢失 mode/appid/callback
    await saveSession(req);

    // 重定向到CAS登录
    return res.redirect(loginUrl);
    
  } catch (error) {
    logError('登录入口错误', error, {
      path: req.originalUrl,
      query: sanitizeValue(req.query),
    });
    res.status(500).render('error', {
      title: '登录失败',
      message: '系统错误，请稍后重试'
    });
  }
}));

/**
 * CAS验证回调
 * GET /cas/serviceValidate
 * 由connect-cas2处理CAS验证
 */
const casServiceValidateHandler = async (req, res) => {
  try {
    // ===== [CAS 回调处理开始] =====
    const { state, ticket } = req.query;
    
    console.log(`🔁 CAS验证回调 - State: ${state ? maskValue(state) : '无'}`);
    
    if (!ticket) {
      return renderAuthErrorAndClearSession(
        req,
        res,
        400,
        '参数错误',
        '缺少 ticket 参数，请重新登录'
      );
    }

    const expectedState = req.session && req.session.authState
      ? String(req.session.authState)
      : '';
    const targetApp = req.session && req.session.targetApp
      ? String(req.session.targetApp)
      : null;
    const callbackUrl = req.session ? req.session.callbackUrl || null : null;
    const requestedReturnMode = normalizeReturnMode(req.session && req.session.returnMode, null);
    const fixedServiceUrl = req.session && req.session.casFixedServiceUrl
      ? String(req.session.casFixedServiceUrl)
      : null;
    const redirectTarget = resolvePostLoginRedirect(req, targetApp);

    if (!expectedState || !targetApp || !requestedReturnMode || !fixedServiceUrl) {
      return renderAuthErrorAndClearSession(
        req,
        res,
        401,
        '会话过期',
        '登录上下文不完整，请重新发起登录'
      );
    }

    if (!config.applistMap[targetApp]) {
      return renderAuthErrorAndClearSession(
        req,
        res,
        400,
        '应用未授权',
        '请求的 appid 不在 applist 中'
      );
    }

    if (!state || state !== expectedState) {
      logError('State验证失败', new Error('State mismatch'), {
        queryState: maskValue(state),
        sessionState: maskValue(expectedState)
      });
      return renderAuthErrorAndClearSession(
        req,
        res,
        400,
        '会话过期',
        '登录会话已过期，请重新登录'
      );
    }

    if (req.session.cas && req.session.cas.st === ticket) {
      return renderAuthErrorAndClearSession(
        req,
        res,
        401,
        '认证失败',
        '检测到重复 ticket，请重新发起登录'
      );
    }

    const validation = await casService.validateTicket(ticket, fixedServiceUrl);
    if (!validation.ok) {
      logError('CAS票据校验失败', new Error('CAS ticket validation failed'), {
        validation: sanitizeValidationLog(validation),
        path: req.originalUrl,
      });
      const message = validation.status === 403
        ? (
          isLikelyGatewayIntercept403(validation)
            ? 'CAS校验请求被网关/WAF拦截（403），请检查CAS域名放行、反向代理与service白名单配置。'
            : '该票据已失效或已被使用，请重新发起登录。'
        )
        : validation.message;
      return renderAuthErrorAndClearSession(
        req,
        res,
        validation.status === 403 ? 401 : validation.status,
        '认证失败',
        message
      );
    }

    const casUser = {
      ...validation.userInfo,
      st: ticket
    };

    // 从CAS获取用户信息
    const studentId = casService.extractStudentId(casUser);
    if (!studentId) {
      return renderAuthErrorAndClearSession(
        req,
        res,
        401,
        '认证失败',
        'CAS认证失败，无法获取用户信息'
      );
    }

    // 清除state，防止重用
    delete req.session.authState;
    delete req.session.casFixedServiceUrl;

    // 认证成功后再次轮换会话ID，隔离认证前后会话
    await regenerateSession(req);

    req.session.cas = {
      ...(casUser || { user: studentId }),
      st: ticket,
    };
    casService.setSession(req, studentId);
    casService.registerTicketSession(ticket, req.sessionID);
    if (typeof req.session.touch === 'function') {
      req.session.touch();
    }

    await onCasLoginSuccess(req, res, {
      studentId,
      targetApp,
      callbackUrl,
    });
    
    // 清理临时数据
    delete req.session.targetApp;
    delete req.session.callbackUrl;
    delete req.session.returnMode;
    delete req.session.redirectTarget;
    
    console.log(`✅ 认证成功 - 学号: ${maskValue(studentId, 2, 2)}, Session: ${maskValue(req.sessionID, 4, 4)}`);

    // ===== [上层回调处理开始] =====
    // 情况0: 有service/target参数，优先按目标地址跳转
    if (redirectTarget) {
      console.log(`重定向到目标地址: ${sanitizeUrlForLog(redirectTarget)}`);
      await saveSession(req);
      return res.redirect(redirectTarget);
    }

    // 情况1: 选择回调，生成JWT并重定向上级应用
    if (requestedReturnMode === 'callback') {
      // ===== [JWT 调用] generateForApp =====
      const token = await jwtService.generateForApp(studentId, targetApp);
      const appCallbackUrl = await casService.getCallbackUrl(targetApp, callbackUrl);

      if (appCallbackUrl && !isAllowedCallbackForApp(targetApp, appCallbackUrl)) {
        return renderAuthErrorAndClearSession(
          req,
          res,
          400,
          '回调失败',
          `应用 ${targetApp} 回调地址不在白名单中`
        );
      }
      
      if (appCallbackUrl) {
        console.log(`通过POST表单跳转到应用: ${targetApp}`);
        await saveSession(req);
        return renderAutoPostTokenPage(res, appCallbackUrl, token, studentId);
      }

      return renderAuthErrorAndClearSession(
        req,
        res,
        400,
        '回调失败',
        `应用 ${targetApp} 未配置有效回调地址`
      );
    }

    // 情况2: mode=page 时，通过会话临时传递JWT并重定向展示页
    if (requestedReturnMode === 'page') {
      const token = await jwtService.generateForApp(studentId, targetApp);
      setJwtCookie(res, token);
      req.session.jwtDisplay = {
        token,
        studentId,
        createdAt: Date.now(),
      };
      await saveSession(req);
      return res.redirect(config.buildAppUrl('/jwt'));
    }

    return renderAuthErrorAndClearSession(
      req,
      res,
      400,
      '参数错误',
      '无效的登录返回模式'
    );
    // ===== [CAS 回调处理结束] =====
    
  } catch (error) {
    logError('CAS回调处理错误', error, {
      path: req.originalUrl,
      query: sanitizeValue(req.query),
    });
    return renderAuthErrorAndClearSession(
      req,
      res,
      500,
      '系统错误',
      '处理认证时发生错误'
    );
  }
};

router.get('/cas/serviceValidate', casServiceValidateHandler);
router.get('/serviceValidate', casServiceValidateHandler);

/**
 * CAS登录页面
 * GET /cas/login
 */
router.get('/cas/login', casService.getLoginMiddleware());

/**
 * 显示JWT令牌（仅从会话读取）
 * GET /jwt
 */
router.get('/jwt', (req, res) => {
  const display = req.session && req.session.jwtDisplay ? req.session.jwtDisplay : null;

  if (!display || !display.token || !display.studentId) {
    return res.status(400).render('error', {
      title: '参数错误',
      message: '令牌不存在或已过期，请重新登录'
    });
  }

  delete req.session.jwtDisplay;
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'",
  );
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  return res.render('cas-jwt', {
    title: 'JWT令牌',
    token: display.token,
    studentId: display.studentId,
  });
});

/**
 * CAS登出
 * POST /logout
 */
router.post('/logout', (req, res) => {
  if (!isSameOriginRequest(req)) {
    return res.status(403).render('error', {
      title: '请求被拒绝',
      message: '检测到跨站请求风险，请从本站页面重新发起登出',
    });
  }

  const serviceUrl = resolveSafeLogoutService(req);

  // 清除本地认证信息
  casService.clearSession(req);

  const finishLogout = () => {
    clearClientAuthCookies(req, res);
    const logoutUrl = casService.getLogoutUrl(serviceUrl);
    console.log(`登出，重定向到: ${sanitizeUrlForLog(logoutUrl)}`);
    return res.redirect(logoutUrl);
  };

  // 销毁本地session，确保单点登出后本地态彻底失效
  if (req.session) {
    return req.session.destroy((err) => {
      if (err) {
        logError('登出时销毁session失败', err, {
          path: req.originalUrl,
        });
      }
      return finishLogout();
    });
  }

  return finishLogout();
});

router.get('/logout', (req, res) => {
  return res.status(405).render('error', {
    title: '请求方式错误',
    message: '请使用 POST 方式发起登出',
  });
});

module.exports = router;