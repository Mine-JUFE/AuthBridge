// config/index.js
require("dotenv").config();
const fs = require("fs");
const path = require("path");

function readJsonSafe(fileName, fallback) {
  try {
    const filePath = path.join(process.cwd(), fileName);
    if (!fs.existsSync(filePath)) {
      return fallback;
    }
    const raw = fs.readFileSync(filePath, "utf-8");
    return JSON.parse(raw);
  } catch (error) {
    console.warn(`读取 ${fileName} 失败，使用默认配置:`, error.message);
    return fallback;
  }
}

const whitelistConfig = readJsonSafe("whitelist.json", {
  apps: ["app1", "app2"],
});

const secretConfig = readJsonSafe("secret.json", {
  jwtSecret: process.env.JWT_SECRET || "your-super-secret-jwt-key-change-in-production",
  sessionSecret:
    process.env.SESSION_SECRET || "your-session-secret-key-change-in-production",
  appKey: process.env.APP_KEY || "authbridge-jufe",
});

const resolvedAppUrl = process.env.APP_URL || "http://localhost:3000";
const casBaseUrl = process.env.CAS_BASE_URL || "https://cas.jxufe.edu.cn/cas";

function normalizeOrigin(urlString) {
  try {
    return new URL(urlString).origin;
  } catch (_error) {
    return null;
  }
}

const configuredCasServiceUrl = process.env.CAS_SERVICE_URL || resolvedAppUrl;
const resolvedCasServiceUrl = normalizeOrigin(configuredCasServiceUrl) === normalizeOrigin(casBaseUrl)
  ? resolvedAppUrl
  : configuredCasServiceUrl;

module.exports = {
  // 环境配置
  env: process.env.NODE_ENV || "development",
  port: parseInt(process.env.PORT, 10) || 3000,
  appName: process.env.APP_NAME || "AuthBridge",
  appUrl: resolvedAppUrl,
  appKey: secretConfig.appKey,

  // CAS配置
  cas: {
    baseUrl: casBaseUrl,
    serviceUrl: resolvedCasServiceUrl,
    version: process.env.CAS_VERSION || "3.0", // 支持 1.0, 2.0, 3.0
    redirectKey: process.env.CAS_REDIRECT_KEY || "service",
    timeoutMs: parseInt(process.env.CAS_TIMEOUT_MS, 10) || 10000,
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
    serverPath: "/cas",
    paths: {
      validate: process.env.CAS_VALIDATE_PATH || "/cas/serviceValidate",
      serviceValidate: "/serviceValidate",
      // 空字符串表示关闭代理票据流程（不携带 pgtUrl）
      proxy: "",
      login: "/login",
      logout: "/logout",
      proxyCallback: "",
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
    secret: secretConfig.jwtSecret,
    expiresIn: process.env.JWT_EXPIRES_IN || "1h",
  },

  // 会话配置
  session: {
    name: process.env.SESSION_NAME || "authbridge.sid",
    secret: secretConfig.sessionSecret,
    ttlMs: parseInt(process.env.SESSION_TTL_MS, 10) || 10 * 60 * 1000, // 10分钟
  },

  // 回调应用配置
  callbackApps: {
    app1: process.env.CALLBACK_APP_1,
    app2: process.env.CALLBACK_APP_2,
  },

  // 应用白名单
  whitelistedApps: Array.isArray(whitelistConfig.apps)
    ? whitelistConfig.apps.filter((app) => typeof app === "string" && app.trim())
    : (process.env.WHITELISTED_APPS || "app1,app2")
        .split(",")
        .filter((app) => app.trim())
        .map((app) => app.trim()),
};
