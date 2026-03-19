// config/index.js
require("dotenv").config();

module.exports = {
  // 环境配置
  env: process.env.NODE_ENV || "development",
  port: parseInt(process.env.PORT) || 3000,
  appName: process.env.APP_NAME || "AuthBridge",
  appUrl: process.env.APP_URL || "http://localhost:3000",
  appKey: process.env.APP_KEY || "authbridge-jufe",

  // CAS配置
  cas: {
    baseUrl: process.env.CAS_BASE_URL || "https://cas.jxufe.edu.cn/cas",
    serviceUrl: process.env.CAS_SERVICE_URL || "http://localhost:3000",
    version: process.env.CAS_VERSION || "3.0", // 支持 1.0, 2.0, 3.0
    service: process.env.CAS_SERVICE || "/cas/serviceValidate",
    loginPath: process.env.CAS_LOGIN_PATH || "/cas/login",
    logoutPath: process.env.CAS_LOGOUT_PATH || "/cas/logout",
    validatePath: process.env.CAS_VALIDATE_PATH || "/cas/serviceValidate",
    timeoutMs: parseInt(process.env.CAS_TIMEOUT_MS) || 10000,
  },

  // CAS客户端配置
  casClient: {
    ignore: [
      "/health",
      "/css/",
      "/js/",
      "/images/",
      "/favicon.ico",
      "/public/",
    ],
    match: [],
    servicePrefix: process.env.CAS_SERVICE_URL || "http://localhost:3000",
    serverPath: "/cas",
    paths: {
      validate: "/serviceValidate",
      serviceValidate: "/serviceValidate",
      proxy: "/proxy",
      login: "/login",
      logout: "/logout",
      proxyCallback: "/proxyCallback",
    },
    redirect: false,
    gateway: false,
    renew: false,
    slo: false, // 单点登出
    cache: {
      enable: false,
      ttl: 5 * 60 * 1000,
    },
    fromAjax: {
      header: "x-requested-with",
      status: 418,
    },
    sessionName: "cas.user",
    sessionInfo: false,
  },

  // JWT配置
  jwt: {
    secret:
      process.env.JWT_SECRET ||
      "your-super-secret-jwt-key-change-in-production",
    expiresIn: process.env.JWT_EXPIRES_IN || "1h",
  },

  // 会话配置
  session: {
    name: process.env.SESSION_NAME || "authbridge.sid",
    secret:
      process.env.SESSION_SECRET ||
      "your-session-secret-key-change-in-production",
    ttlMs: parseInt(process.env.SESSION_TTL_MS) || 10 * 60 * 1000, // 10分钟
  },

  // 回调应用配置
  callbackApps: {
    app1: process.env.CALLBACK_APP_1,
    app2: process.env.CALLBACK_APP_2,
  },

  // 应用白名单
  whitelistedApps: (process.env.WHITELISTED_APPS || "app1,app2")
    .split(",")
    .filter((app) => app.trim())
    .map((app) => app.trim()),
};
