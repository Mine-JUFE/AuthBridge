// services/cas-connect.js
const CAS = require("connect-cas2");
const config = require("../config");

// 初始化CAS客户端
const casClient = new CAS(config.casClient);

// 扩展CAS客户端的功能
class CASConnectService {
  constructor() {
    this.client = casClient;
    console.log("CAS客户端初始化完成:", {
      baseUrl: config.cas.baseUrl,
      serviceUrl: config.cas.serviceUrl,
      version: config.cas.version,
    });
  }

  /**
   * 获取CAS登录中间件
   */
  getLoginMiddleware() {
    return this.client.login();
  }

  /**
   * 获取CAS验证中间件
   */
  getValidateMiddleware() {
    return this.client.serviceValidate();
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
    const loginUrl = new URL("/login", config.cas.baseUrl);
    loginUrl.searchParams.set("service", service || config.cas.serviceUrl);
    return loginUrl.toString();
  }

  /**
   * 获取CAS登出URL
   */
  getLogoutUrl(service = null) {
    const logoutUrl = new URL("/logout", config.cas.baseUrl);
    if (service) {
      logoutUrl.searchParams.set("service", service);
    }
    return logoutUrl.toString();
  }

  /**
   * 从会话中获取用户信息
   */
  getUserFromSession(req) {
    if (!req.session) {
      return null;
    }
    return req.session[config.casClient.sessionName] || null;
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

    if (typeof casUser === "string") {
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
    if (!studentId || typeof studentId !== "string") {
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
      delete req.session[config.casClient.sessionName];
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
      return true;
    }
    return false;
  }

  /**
   * 获取目标应用的回调地址
   */
  async getCallbackUrl(targetApp, token) {
    if (!targetApp) {
      return null;
    }

    const base = config.callbackApps && config.callbackApps[targetApp];
    if (!base) {
      console.warn(`未找到目标应用配置: ${targetApp}`);
      return null;
    }

    try {
      const callbackUrl = new URL(base);
      callbackUrl.searchParams.set("token", token);
      callbackUrl.searchParams.set("timestamp", Date.now());
      return callbackUrl.toString();
    } catch (error) {
      console.error("构建回调URL失败:", error.message);
      return null;
    }
  }
}

module.exports = new CASConnectService();
