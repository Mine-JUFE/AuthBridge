// services/cas.js
const CAS = require('connect-cas2');
const axios = require('axios');
const { parseStringPromise, processors } = require('xml2js');
const config = require('../config');

const { stripPrefix } = processors;

// 初始化CAS客户端
const casClient = new CAS({
  servicePrefix: config.cas.serviceUrl,
  serverPath: config.cas.baseUrl,
  ignore: config.casClient.ignore || [],
  match: config.casClient.match || [],
  paths: config.casClient.paths,
  redirect: config.casClient.redirect,
  gateway: config.casClient.gateway,
  renew: config.casClient.renew,
  slo: config.casClient.slo,
  cache: config.casClient.cache,
  fromAjax: config.casClient.fromAjax,
  restletIntegration: null
});

// 扩展CAS客户端的功能
class CASConnectService {
  constructor() {
    this.client = casClient;
    this.ticketSessionMap = new Map();
    console.log('CAS客户端初始化完成:', {
      baseUrl: config.cas.baseUrl,
      serviceUrl: config.cas.serviceUrl,
      version: config.cas.version
    });
  }

  registerTicketSession(ticket, sessionId) {
    if (!ticket || !sessionId) {
      return;
    }
    this.ticketSessionMap.set(String(ticket), String(sessionId));
  }

  unregisterTicketSession(ticket) {
    if (!ticket) {
      return;
    }
    this.ticketSessionMap.delete(String(ticket));
  }

  consumeSessionIdByTicket(ticket) {
    if (!ticket) {
      return null;
    }

    const key = String(ticket);
    const sessionId = this.ticketSessionMap.get(key) || null;
    this.ticketSessionMap.delete(key);
    return sessionId;
  }

  async extractSessionIndexFromLogoutRequest(logoutRequestXml) {
    if (!logoutRequestXml || typeof logoutRequestXml !== 'string') {
      return null;
    }

    try {
      const parsed = await parseStringPromise(logoutRequestXml, {
        explicitArray: false,
        tagNameProcessors: [stripPrefix]
      });

      const root = parsed && (parsed.LogoutRequest || parsed.logoutRequest || parsed);
      if (!root) {
        return null;
      }

      const sessionIndex = root.SessionIndex;
      if (!sessionIndex) {
        return null;
      }

      if (typeof sessionIndex === 'string') {
        return sessionIndex;
      }

      if (sessionIndex && typeof sessionIndex._ === 'string') {
        return sessionIndex._;
      }

      return null;
    } catch (error) {
      console.warn('解析CAS logoutRequest失败:', error.message);
      return null;
    }
  }

  async handleBackChannelLogout(logoutRequestXml, sessionStore) {
    const sessionIndex = await this.extractSessionIndexFromLogoutRequest(logoutRequestXml);
    if (!sessionIndex) {
      return {
        ok: false,
        reason: 'missing-session-index'
      };
    }

    const sessionId = this.consumeSessionIdByTicket(sessionIndex);
    if (!sessionId) {
      return {
        ok: true,
        sessionIndex,
        destroyed: false,
        reason: 'session-not-found'
      };
    }

    if (!sessionStore || typeof sessionStore.destroy !== 'function') {
      return {
        ok: false,
        sessionIndex,
        destroyed: false,
        reason: 'invalid-session-store'
      };
    }

    return new Promise((resolve) => {
      sessionStore.destroy(sessionId, (error) => {
        if (error) {
          resolve({
            ok: false,
            sessionIndex,
            destroyed: false,
            reason: 'destroy-failed',
            error: error.message
          });
          return;
        }

        resolve({
          ok: true,
          sessionIndex,
          destroyed: true
        });
      });
    });
  }

  /**
   * 从对象中按点路径读取值，如 cas.user
   */
  getByPath(obj, dotPath) {
    if (!obj || !dotPath || typeof dotPath !== 'string') {
      return null;
    }

    return dotPath.split('.').reduce((acc, key) => {
      if (acc && Object.prototype.hasOwnProperty.call(acc, key)) {
        return acc[key];
      }
      return null;
    }, obj);
  }

  /**
   * 获取CAS登录中间件
   */
  getLoginMiddleware() {
    return (req, res) => {
      const loginUrl = this.getLoginUrl();
      return res.redirect(loginUrl);
    };
  }

  /**
   * 获取CAS验证中间件
   */
  getValidateMiddleware() {
    return this.client.core();
  }

  /**
   * 直接向CAS发起ticket校验，避免中间件在失败时直接写出响应
   */
  async validateTicket(ticket, service = null) {
    if (!ticket) {
      return {
        ok: false,
        status: 400,
        message: '缺少 ticket 参数'
      };
    }

    const serviceUrl = service || new URL(config.casClient.paths.validate, config.cas.serviceUrl).toString();
    const validateUrl = this.buildCasUrl(config.casClient.paths.serviceValidate || 'serviceValidate');
    validateUrl.searchParams.set('service', serviceUrl);
    validateUrl.searchParams.set('ticket', ticket);

    const requestOnce = (timeoutMs) => axios.get(validateUrl.toString(), {
      timeout: timeoutMs,
      validateStatus: () => true
    });

    let response;
    try {
      response = await requestOnce(config.cas.timeoutMs);
    } catch (error) {
      const isTimeout = error && (
        error.code === 'ECONNABORTED'
        || String(error.message || '').toLowerCase().includes('timeout')
      );

      if (!isTimeout) {
        return {
          ok: false,
          status: 500,
          message: '请求CAS校验接口失败',
          error: error.message,
          requestUrl: validateUrl.toString()
        };
      }

      const retryTimeout = Math.max(config.cas.timeoutMs * 2, 15000);
      console.warn(`CAS校验请求超时，准备重试: timeout=${config.cas.timeoutMs}ms -> ${retryTimeout}ms`);

      try {
        response = await requestOnce(retryTimeout);
      } catch (retryError) {
        return {
          ok: false,
          status: 500,
          message: '请求CAS校验接口失败',
          error: `首次: ${error.message}; 重试: ${retryError.message}`,
          requestUrl: validateUrl.toString()
        };
      }
    }

    if (response.status !== 200) {
      const responseBody = typeof response.data === 'string'
        ? response.data.slice(0, 500)
        : JSON.stringify(response.data || {}).slice(0, 500);
      return {
        ok: false,
        status: response.status,
        message: `CAS校验失败，状态码: ${response.status}`,
        requestUrl: validateUrl.toString(),
        responseBody
      };
    }

    try {
      const xmlText = typeof response.data === 'string'
        ? response.data
        : String(response.data || '');

      const parsed = await parseStringPromise(xmlText, {
        explicitArray: false,
        tagNameProcessors: [stripPrefix]
      });

      const serviceResponse = parsed && (parsed.serviceResponse || parsed);
      const success = serviceResponse && serviceResponse.authenticationSuccess;
      const failure = serviceResponse && serviceResponse.authenticationFailure;

      if (!success || !success.user) {
        return {
          ok: false,
          status: 401,
          message: 'CAS认证失败',
          failure,
          requestUrl: validateUrl.toString()
        };
      }

      return {
        ok: true,
        status: 200,
        userInfo: {
          user: String(success.user),
          attributes: success.attributes || {}
        },
        requestUrl: validateUrl.toString()
      };
    } catch (error) {
      return {
        ok: false,
        status: 500,
        message: '解析CAS校验响应失败',
        error: error.message,
        requestUrl: validateUrl.toString()
      };
    }
  }

  /**
   * 获取CAS登出中间件
   */
  getLogoutMiddleware() {
    return this.client.logout();
  }

  /**
   * 获取CAS登录URL
   */
  getLoginUrl(service = null) {
    const loginUrl = this.buildCasUrl('login');
    const defaultService = new URL(config.casClient.paths.validate, config.cas.serviceUrl).toString();
    loginUrl.searchParams.set('service', service || defaultService);
    return loginUrl.toString();
  }

  /**
   * 获取CAS登出URL
   */
  getLogoutUrl(service = null) {
    const logoutUrl = this.buildCasUrl('logout');
    if (service) {
      logoutUrl.searchParams.set('service', service);
    }
    return logoutUrl.toString();
  }

  /**
   * 构建CAS路径，保留baseUrl里的/cas前缀
   */
  buildCasUrl(endpoint) {
    const base = new URL(config.cas.baseUrl);
    const basePath = (base.pathname || '/').replace(/\/+$/, '');
    const cleanEndpoint = String(endpoint || '').replace(/^\/+/, '');
    base.pathname = `${basePath}/${cleanEndpoint}`;
    return base;
  }

  /**
   * 从会话中获取用户信息
   */
  getUserFromSession(req) {
    if (!req.session) {
      return null;
    }

    // 兼容项目自定义写法
    if (req.session.cas_user) {
      return req.session.cas_user;
    }

    // 兼容 connect-cas2 默认写法（validate.js 会写入 req.session.cas）
    if (req.session.cas) {
      return req.session.cas;
    }

    // 兼容通过 sessionName 指定的点路径（如 cas.user）
    const sessionName = config.casClient && config.casClient.sessionName;
    const namedUser = this.getByPath(req.session, sessionName);
    if (namedUser) {
      return namedUser;
    }

    return null;
  }

  /**
   * 获取用户的学号
   */
  getStudentId(req) {
    const user = this.getUserFromSession(req);
    if (user) {
      return this.extractStudentId(user);
    }
    return null;
  }

  /**
   * 从CAS用户信息中提取学号
   */
  extractStudentId(casUser) {
    if (!casUser) {
      return null;
    }

    // CAS返回的用户信息可能是字符串或对象
    let studentId = null;
    
    if (typeof casUser === 'string') {
      studentId = casUser;
    } else if (casUser.user) {
      studentId = casUser.user;
    } else if (casUser.attributes) {
      // 尝试从attributes中提取
      const attrs = casUser.attributes;
      studentId = attrs.studentId || attrs.studentid || attrs.user || attrs.uid;
    }

    if (studentId && this.isValidStudentId(studentId)) {
      return studentId;
    }
    
    return null;
  }

  /**
   * 验证学号格式
   */
  isValidStudentId(studentId) {
    if (!studentId || typeof studentId !== 'string') {
      return false;
    }
    return /^[A-Za-z0-9@._-]{2,64}$/.test(studentId);
  }

  /**
   * 验证用户是否已登录
   */
  isAuthenticated(req) {
    const user = this.getUserFromSession(req);
    if (!user) {
      return false;
    }

    // 检查session是否过期（10分钟）
    if (req.session.authenticatedAt) {
      const sessionAge = Date.now() - req.session.authenticatedAt;
      const maxAge = config.session.ttlMs;
      if (sessionAge > maxAge) {
        this.clearSession(req);
        return false;
      }
    }

    return !!this.getStudentId(req);
  }

  /**
   * 清除用户会话
   */
  clearSession(req) {
    if (req.session) {
      if (req.session.cas && req.session.cas.st) {
        this.unregisterTicketSession(req.session.cas.st);
      }
      delete req.session.cas;
      delete req.session.cas_user;
      delete req.session.authenticated;
      delete req.session.studentId;
      delete req.session.authenticatedAt;
    }
  }

  /**
   * 设置用户会话
   */
  setSession(req, studentId) {
    if (req.session && studentId) {
      req.session.authenticated = true;
      req.session.studentId = studentId;
      req.session.authenticatedAt = Date.now();
      req.session.cas_user = { user: studentId };
      return true;
    }
    return false;
  }

  /**
   * 获取目标应用的回调地址
   */
  async getCallbackUrl(targetApp, token, customCallbackUrl = null) {
    if (!targetApp) {
      return null;
    }

    const preferred = typeof customCallbackUrl === 'string' ? customCallbackUrl.trim() : '';
    const base = preferred || (config.callbackApps && config.callbackApps[targetApp]);
    if (!base) {
      console.warn(`未找到目标应用配置: ${targetApp}`);
      return null;
    }

    try {
      const callbackUrl = new URL(base);
      const callbackWhitelist = (config.callbackWhitelistMap && config.callbackWhitelistMap[targetApp]) || [];
      const isAllowed = callbackWhitelist.some((item) => {
        if (typeof item !== 'string' || !item.trim()) {
          return false;
        }

        try {
          const allowed = new URL(item);
          return allowed.origin === callbackUrl.origin && allowed.pathname === callbackUrl.pathname;
        } catch (_error) {
          return false;
        }
      });

      if (!isAllowed) {
        console.warn(`回调地址不在白名单中: ${targetApp} -> ${callbackUrl.toString()}`);
        return null;
      }

      callbackUrl.searchParams.set('token', token);
      callbackUrl.searchParams.set('timestamp', Date.now());
      return callbackUrl.toString();
    } catch (error) {
      console.error('构建回调URL失败:', error.message);
      return null;
    }
  }
}

module.exports = new CASConnectService();