// routes/auth.js
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const config = require('../config');
const casService = require('../services/cas');
const jwtService = require('../services/jwt');
const { logError, sanitizeValue } = require('../utils/error_handler');

const isProduction = config.env === 'production';

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

function getCasCallbackServiceUrlWithContext({ appid, returnMode, callback }) {
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

  return serviceUrl.toString();
}

function deriveServiceUrlFromCallbackRequest(req) {
  if (!req) {
    return null;
  }

  try {
    const serviceUrl = new URL(config.buildAppUrl(req.path || config.casClient.paths.validate));
    const originalUrl = String(req.originalUrl || '');
    const queryPart = originalUrl.includes('?') ? originalUrl.slice(originalUrl.indexOf('?') + 1) : '';
    const params = new URLSearchParams(queryPart);

    params.delete('ticket');

    params.forEach((value, key) => {
      serviceUrl.searchParams.append(key, value);
    });

    return serviceUrl.toString();
  } catch (_error) {
    return null;
  }
}

function getIncomingTarget(req) {
  const redirectKey = (config.cas && config.cas.redirectKey) || 'service';
  return req.query[redirectKey] || req.query.target || null;
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

function resolvePostLoginRedirect(req) {
  const targetFromSession = req.session.redirectTarget;
  if (targetFromSession && isValidRedirectUrl(targetFromSession)) {
    return targetFromSession;
  }

  const targetFromQuery = getIncomingTarget(req);
  if (targetFromQuery && isValidRedirectUrl(targetFromQuery)) {
    return targetFromQuery;
  }

  return null;
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

  // 为常见跨子域部署场景增加父域清理
  if (host.includes('.') && host !== 'localhost' && !/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    const segments = host.split('.');
    if (segments.length >= 2) {
      domains.add(`.${segments.slice(-2).join('.')}`);
    }
  }

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
}

function clearClientAuthCookies(req, res) {
  const cookieName = config.session.name;
  const domains = collectCookieDomains(req);

  // 尽量覆盖不同部署下可能出现的 cookie 属性组合
  const baseOptionsList = [
    { path: '/' },
    { path: '/cas' },
    { path: '/', sameSite: 'lax' },
    { path: '/', sameSite: 'none', secure: true },
    { path: '/', secure: true },
    { path: '/', secure: false },
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

  const candidateNames = [cookieName, 'connect.sid'];

  // 同时使用 clearCookie 与显式过期写回，尽可能覆盖浏览器差异
  candidateNames.forEach((name) => {
    clearOptionsList.forEach((options) => {
      res.clearCookie(name, options);
      res.cookie(name, '', {
        ...options,
        expires: new Date(1),
        maxAge: 0,
      });
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

function isLikelyGatewayIntercept403(validation) {
  if (!validation || Number(validation.status) !== 403) {
    return false;
  }

  const body = String(validation.responseBody || '').toLowerCase();
  return body.includes('<html') || body.includes('safeline') || body.includes('waf');
}

async function handleSloNotification(req, res) {
  const logoutRequest = req.body && req.body.logoutRequest;
  if (!logoutRequest) {
    return res.status(204).end();
  }

  const result = await casService.handleBackChannelLogout(logoutRequest, req.sessionStore);
  if (!result.ok) {
    console.warn('CAS SLO处理失败:', sanitizeValue(result));
    return res.status(204).end();
  }

  if (result.destroyed) {
    console.log(`CAS SLO已销毁本地会话，SessionIndex: ${result.sessionIndex}`);
  } else {
    console.log(`CAS SLO命中但未找到本地会话，SessionIndex: ${result.sessionIndex}`);
  }

  return res.status(204).end();
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
router.get('/login', (req, res) => {
  try {
    const appid = req.query.appid || req.query.app || null;
    const { callback } = req.query;
    const returnMode = normalizeReturnMode(req.query.mode || req.query.return, null);
    const incomingTarget = getIncomingTarget(req);

    // 新一轮登录前，先清理上次可能残留的临时状态
    clearTransientAuthState(req);
    
    // 验证目标应用是否在 applist 中
    if (appid && !config.applistMap[appid]) {
      return res.status(400).render('error', {
        title: '应用未授权',
        message: '请求的 appid 不在 applist 中'
      });
    }

    if (returnMode === 'callback' && !appid) {
      return res.status(400).render('error', {
        title: '参数错误',
        message: 'mode=callback 时必须提供 appid'
      });
    }

    if (callback) {
      if (!appid) {
        return res.status(400).render('error', {
          title: '参数错误',
          message: 'callback 模式必须提供 appid'
        });
      }

      if (!isAllowedCallbackForApp(appid, callback)) {
        return res.status(400).render('error', {
          title: '回调地址未授权',
          message: 'callback 不在 applist 回调白名单中'
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
    
    console.log(`🔐 登录请求 - State: ${maskValue(state)}, appid: ${appid || '手动模式'}, mode: ${returnMode || 'auto'}`);

    // service 必须和 connect-cas2 校验阶段的 service 完全一致，否则 CAS 会返回 403
    const serviceUrl = getCasCallbackServiceUrlWithContext({
      appid,
      returnMode,
      callback,
    });
    req.session.casFixedServiceUrl = serviceUrl;
    
    // 获取CAS登录URL
    const loginUrl = casService.getLoginUrl(serviceUrl);
    
    console.log(`重定向到CAS: ${sanitizeUrlForLog(loginUrl)}`);
    
    // 显式保存会话后再跳转，避免在外部存储下丢失 mode/appid/callback
    req.session.save((saveError) => {
      if (saveError) {
        logError('保存登录会话失败', saveError, {
          path: req.originalUrl,
          query: sanitizeValue(req.query),
        });
        return res.status(500).render('error', {
          title: '登录失败',
          message: '会话保存失败，请稍后重试'
        });
      }

      // 重定向到CAS登录
      return res.redirect(loginUrl);
    });
    
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
});

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

    const isDuplicateTicketReplay = Boolean(req.session.cas && req.session.cas.st === ticket);

    // CAS 的 ST 是一次性的；若用户刷新带 ticket 的回调页，直接复用已登录会话
    if (isDuplicateTicketReplay) {
      console.log(`检测到重复ticket回调，跳过二次验签: ${maskValue(ticket, 4, 4)}`);
    } else {
      const serviceUrl = req.session.casFixedServiceUrl || deriveServiceUrlFromCallbackRequest(req) || getCasCallbackServiceUrl();
      const validation = await casService.validateTicket(ticket, serviceUrl);
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

      req.session.cas = {
        ...validation.userInfo,
        st: ticket
      };
      casService.registerTicketSession(ticket, req.sessionID);
    }

    // 仅在存在预期state时进行校验；手动模式允许无state回调
    const expectedState = req.session.authState;
    if (expectedState && state && state !== expectedState) {
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

    // 从CAS获取用户信息
    const studentId = casService.getStudentId(req);
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
    if (expectedState) {
      delete req.session.authState;
    }
    delete req.session.casFixedServiceUrl;
    
    // 设置用户会话
    casService.setSession(req, studentId);
    if (typeof req.session.touch === 'function') {
      req.session.touch();
    }
    
    // 获取目标应用
    let targetApp = req.session.targetApp || req.query.appid || req.query.app || null;
    let callbackUrl = req.session.callbackUrl || req.query.callback || null;
    let requestedReturnMode = normalizeReturnMode(
      req.session.returnMode || req.query.mode || req.query.return,
      null,
    );

    const replayContext = req.session.lastAuthFlow;
    if (
      isDuplicateTicketReplay
      && replayContext
      && replayContext.ticket === ticket
      && !targetApp
    ) {
      targetApp = replayContext.targetApp || targetApp;
      callbackUrl = replayContext.callbackUrl || callbackUrl;
      requestedReturnMode = normalizeReturnMode(replayContext.returnMode, requestedReturnMode);
      console.log(`复用上次回调上下文: appid=${targetApp || '无'}`);
    }

    const resolvedReturnMode = requestedReturnMode || (targetApp ? 'callback' : 'page');

    if (resolvedReturnMode === 'callback' && targetApp) {
      req.session.lastAuthFlow = {
        ticket,
        targetApp,
        callbackUrl: callbackUrl || null,
        returnMode: 'callback',
        updatedAt: Date.now(),
      };
    }

    await onCasLoginSuccess(req, res, {
      studentId,
      targetApp,
      callbackUrl,
    });
    
    // 清理临时数据
    const keepCallbackContext = resolvedReturnMode === 'callback' && targetApp;
    if (!keepCallbackContext) {
      delete req.session.targetApp;
      delete req.session.callbackUrl;
      delete req.session.returnMode;
    }
    const redirectTarget = resolvePostLoginRedirect(req);
    delete req.session.redirectTarget;
    
    console.log(`✅ 认证成功 - 学号: ${maskValue(studentId, 2, 2)}, Session: ${maskValue(req.sessionID, 4, 4)}`);

    // ===== [上层回调处理开始] =====
    // 情况0: 有service/target参数，优先按目标地址跳转
    if (redirectTarget) {
      console.log(`重定向到目标地址: ${sanitizeUrlForLog(redirectTarget)}`);
      return res.redirect(redirectTarget);
    }

    // 情况1: 选择回调，生成JWT并重定向上级应用
    if (resolvedReturnMode === 'callback' && targetApp) {
      // ===== [JWT 调用] generateForApp =====
      const token = jwtService.generateForApp(studentId, targetApp);
      const appCallbackUrl = await casService.getCallbackUrl(targetApp, token, callbackUrl);

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
        console.log(`重定向到应用: ${targetApp}`);
        return res.redirect(appCallbackUrl);
      }

      return renderAuthErrorAndClearSession(
        req,
        res,
        400,
        '回调失败',
        `应用 ${targetApp} 未配置有效回调地址`
      );
    }
    
    // // 情况2: 有自定义回调URL
    // if (callbackUrl) {
    //   // ===== [JWT 调用] generateToken =====
    //   const token = jwtService.generateToken(studentId);
    //   try {
    //     const url = new URL(callbackUrl);
    //     url.searchParams.set('token', token);
    //     url.searchParams.set('studentId', studentId);
    //     return res.redirect(url.toString());
    //   } catch (error) {
    //     console.error('回调URL格式错误:', error);
    //   }
    // }
    // ===== [上层回调处理结束] =====
    
    // 情况3: 无app和无自定义回调时，直接渲染JWT展示页
    // ===== [JWT 调用] generateToken =====
    const token = jwtService.generateToken(studentId);
    const jwtUrl = new URL(config.buildAppUrl('/jwt'));
    jwtUrl.searchParams.set('token', token);
    jwtUrl.searchParams.set('studentId', studentId);
    return res.redirect(jwtUrl.toString());
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
 * 忽略CAS服务端下发的SLO请求（不处理ST）
 * POST /cas/serviceValidate
 */
router.post('/cas/serviceValidate', safeAsync(handleSloNotification));

router.post('/serviceValidate', safeAsync(handleSloNotification));

router.post('/cas/slo', safeAsync(handleSloNotification));

/**
 * 显示JWT令牌
 * GET /jwt?token={token}&studentId={studentId}
 */
router.get('/jwt', (req, res) => {
  const { token, studentId } = req.query;
  
  if (!token || !studentId) {
    return res.status(400).render('error', {
      title: '参数错误',
      message: '缺少必要的参数'
    });
  }
  
  res.render('cas-jwt', {
    title: 'JWT令牌',
    token,
    studentId,
  });
});

/**
 * CAS登出
 * GET /logout
 */
router.get('/logout', (req, res) => {
  const serviceUrl = req.query.service || config.appUrl;

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

module.exports = router;