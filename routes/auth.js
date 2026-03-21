// routes/auth.js
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const config = require('../config');
const casService = require('../services/cas');
const jwtService = require('../services/jwt');

// 生成随机state
function generateState() {
  return crypto.randomBytes(16).toString('hex');
}

function getCasCallbackServiceUrl() {
  return new URL(config.casClient.paths.validate, config.cas.serviceUrl).toString();
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

function renderAuthErrorAndClearSession(req, res, status, title, message) {
  casService.clearSession(req);
  res.clearCookie(config.session.name);

  if (!req.session || typeof req.session.destroy !== 'function') {
    return res.status(status).render('error', { title, message });
  }

  return req.session.destroy((err) => {
    if (err) {
      console.error('认证失败时销毁session失败:', err);
    }
    return res.status(status).render('error', { title, message });
  });
}

async function handleSloNotification(req, res) {
  const logoutRequest = req.body && req.body.logoutRequest;
  if (!logoutRequest) {
    return res.status(204).end();
  }

  const result = await casService.handleBackChannelLogout(logoutRequest, req.sessionStore);
  if (!result.ok) {
    console.warn('CAS SLO处理失败:', result);
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
 * GET /login?app={appName}&callback={url}
 */
router.get('/login', (req, res) => {
  try {
    const { app, callback } = req.query;
    const incomingTarget = getIncomingTarget(req);
    
    // 验证目标应用是否在白名单中
    if (app && !config.whitelistedApps.includes(app)) {
      return res.status(400).render('error', {
        title: '应用未授权',
        message: '请求的应用不在白名单中'
      });
    }

    // 生成state防止CSRF攻击
    const state = generateState();
    
    // 存储状态到session
    req.session.authState = state;
    req.session.targetApp = app || null;
    req.session.callbackUrl = callback || null;
    req.session.redirectTarget = incomingTarget || null;
    
    console.log(`🔐 登录请求 - State: ${state}, 应用: ${app || '手动模式'}`);

    // service 必须和 connect-cas2 校验阶段的 service 完全一致，否则 CAS 会返回 403
    const serviceUrl = getCasCallbackServiceUrl();
    
    // 获取CAS登录URL
    const loginUrl = casService.getLoginUrl(serviceUrl);
    
    console.log(`重定向到CAS: ${loginUrl}`);
    
    // 重定向到CAS登录
    res.redirect(loginUrl);
    
  } catch (error) {
    console.error('登录入口错误:', error);
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
    
    console.log(`🔁 CAS验证回调 - State: ${state || '无'}`);
    
    if (!ticket) {
      return renderAuthErrorAndClearSession(
        req,
        res,
        400,
        '参数错误',
        '缺少 ticket 参数，请重新登录'
      );
    }

    // CAS 的 ST 是一次性的；若用户刷新带 ticket 的回调页，直接复用已登录会话
    if (req.session.cas && req.session.cas.st === ticket) {
      console.log(`检测到重复ticket回调，跳过二次验签: ${ticket}`);
    } else {
      const serviceUrl = getCasCallbackServiceUrl();
      const validation = await casService.validateTicket(ticket, serviceUrl);
      if (!validation.ok) {
        console.error('CAS票据校验失败:', validation);
        const message = validation.status === 403
          ? '该票据已失效或已被使用，请重新发起登录。'
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
      console.error('State验证失败', {
        queryState: state,
        sessionState: expectedState
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
    
    // 设置用户会话
    casService.setSession(req, studentId);
    if (typeof req.session.touch === 'function') {
      req.session.touch();
    }
    
    // 获取目标应用
    const targetApp = req.session.targetApp || req.query.app || null;
    const callbackUrl = req.session.callbackUrl || req.query.callback || null;

    await onCasLoginSuccess(req, res, {
      studentId,
      targetApp,
      callbackUrl,
    });
    
    // 清理临时数据
    delete req.session.targetApp;
    delete req.session.callbackUrl;
    const redirectTarget = resolvePostLoginRedirect(req);
    delete req.session.redirectTarget;
    
    console.log(`✅ 认证成功 - 学号: ${studentId}, Session: ${req.sessionID}`);

    // ===== [上层回调处理开始] =====
    // 情况0: 有service/target参数，优先按目标地址跳转
    if (redirectTarget) {
      console.log(`重定向到目标地址: ${redirectTarget}`);
      return res.redirect(redirectTarget);
    }

    // 情况1: 有目标应用，生成JWT并重定向
    if (targetApp) {
      // ===== [JWT 调用] generateForApp =====
      const token = jwtService.generateForApp(studentId, targetApp);
      const appCallbackUrl = await casService.getCallbackUrl(targetApp, token);
      
      if (appCallbackUrl) {
        console.log(`重定向到应用: ${targetApp}`);
        return res.redirect(appCallbackUrl);
      }
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
    const jwtUrl = new URL('/jwt', config.appUrl);
    jwtUrl.searchParams.set('token', token);
    jwtUrl.searchParams.set('studentId', studentId);
    return res.redirect(jwtUrl.toString());
    // ===== [CAS 回调处理结束] =====
    
  } catch (error) {
    console.error('CAS回调处理错误:', error);
    return renderAuthErrorAndClearSession(
      req,
      res,
      500,
      '系统错误',
      error.message || '处理认证时发生错误'
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
router.post('/cas/serviceValidate', (req, res) => {
  return handleSloNotification(req, res);
});

router.post('/serviceValidate', (req, res) => {
  return handleSloNotification(req, res);
});

router.post('/cas/slo', (req, res) => {
  return handleSloNotification(req, res);
});

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
    expiresIn: config.jwt.expiresIn
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
    res.clearCookie(config.session.name);
    const logoutUrl = casService.getLogoutUrl(serviceUrl);
    console.log(`登出，重定向到: ${logoutUrl}`);
    return res.redirect(logoutUrl);
  };

  // 销毁本地session，确保单点登出后本地态彻底失效
  if (req.session) {
    return req.session.destroy((err) => {
      if (err) {
        console.error('销毁session失败:', err);
      }
      return finishLogout();
    });
  }

  return finishLogout();
});

module.exports = router;