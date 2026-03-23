// config/index.js
require("dotenv").config();
const fs = require("fs");
const path = require("path");

function resolveConfigPath(fileName, envVarName) {
  const configuredPath = envVarName ? process.env[envVarName] : null;
  if (!configuredPath) {
    return path.join(process.cwd(), fileName);
  }

  return path.isAbsolute(configuredPath)
    ? configuredPath
    : path.join(process.cwd(), configuredPath);
}

function readJsonSafe(fileName, fallback, envVarName) {
  try {
    const filePath = resolveConfigPath(fileName, envVarName);
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

const appListConfig = readJsonSafe("applist.json", {
  apps: [
    { appid: "app1", app_aud: "app1-client", encrypt_type: "aes" },
    { appid: "app2", app_aud: "app2-client", encrypt_type: "aes" },
  ],
}, "APPLIST_PATH");

const secretConfig = readJsonSafe("secret.json", {
  sessionSecret:
    process.env.SESSION_SECRET || "your-session-secret-key-change-in-production",
  appSecrets: {},
}, "SECRET_PATH");

const resolvedEnv = process.env.NODE_ENV || "production";

function isPlaceholderSecret(value) {
  const raw = String(value || "").trim().toLowerCase();
  if (!raw) {
    return true;
  }

  const placeholders = [
    "your-super-secret-jwt-key-change-in-production",
    "your-session-secret-key-change-in-production",
    "replace-with-strong-secret",
    "changeme",
    "change-me",
    "default",
    "123456",
  ];

  return placeholders.includes(raw) || raw.includes("placeholder") || raw.includes("example");
}

function isStrongSecret(value, minLength = 32) {
  const raw = String(value || "").trim();
  if (raw.length < minLength) {
    return false;
  }

  if (/^[0-9a-fA-F]+$/.test(raw)) {
    return raw.length >= minLength;
  }

  return true;
}

function assertSecureSecretConfig(configValue) {
  if (process.env.ALLOW_WEAK_SECRETS === "true") {
    return;
  }

  const issues = [];
  const sessionSecret = configValue && configValue.sessionSecret;

  if (isPlaceholderSecret(sessionSecret) || !isStrongSecret(sessionSecret, 32)) {
    issues.push("sessionSecret 不安全（占位符或长度不足）");
  }

  if (issues.length && resolvedEnv === "production") {
    throw new Error(
      `安全配置校验失败: ${issues.join("; ")}。请参考 secret.template.json 与 .env.example 生成生产密钥。`,
    );
  }
}

assertSecureSecretConfig(secretConfig);

function normalizeEncryptType(rawType) {
  const normalized = String(rawType || "aes").trim().toLowerCase();
  if (normalized === "ecc" || normalized === "hash") {
    return "ecc";
  }
  return "aes";
}

function normalizeHttpUrl(raw) {
  if (typeof raw !== "string" || !raw.trim()) {
    return null;
  }

  try {
    const urlObj = new URL(raw.trim());
    if (urlObj.protocol !== "http:" && urlObj.protocol !== "https:") {
      return null;
    }
    urlObj.hash = "";
    return urlObj.toString();
  } catch (_error) {
    return null;
  }
}

function normalizeCallbackWhitelist(rawList, callback) {
  const result = [];
  const list = Array.isArray(rawList) ? rawList : [];
  const callbackUrl = normalizeHttpUrl(callback);

  if (callbackUrl) {
    result.push(callbackUrl);
  }

  list.forEach((item) => {
    const normalized = normalizeHttpUrl(item);
    if (normalized) {
      result.push(normalized);
    }
  });

  return Array.from(new Set(result));
}

function normalizeAppList(rawConfig) {
  const fromConfig = Array.isArray(rawConfig && rawConfig.apps)
    ? rawConfig.apps
    : Array.isArray(rawConfig)
      ? rawConfig
      : [];

  const fallbackFromEnv = (process.env.WHITELISTED_APPS || "app1,app2")
    .split(",")
    .filter((item) => item && item.trim())
    .map((item) => item.trim());

  const sourceList = fromConfig.length
    ? fromConfig
    : fallbackFromEnv;

  return sourceList
    .map((item) => {
      if (typeof item === "string") {
        const appid = item.trim();
        if (!appid) {
          return null;
        }
        return {
          appid,
          app_aud: appid,
          encrypt_type: "aes",
        };
      }

      if (!item || typeof item !== "object") {
        return null;
      }

      const appid = typeof item.appid === "string" ? item.appid.trim() : "";
      if (!appid) {
        return null;
      }

      const appAud = typeof item.app_aud === "string" && item.app_aud.trim()
        ? item.app_aud.trim()
        : appid;

      return {
        ...item,
        appid,
        app_aud: appAud,
        callback: normalizeHttpUrl(item.callback),
        callback_whitelist: normalizeCallbackWhitelist(item.callback_whitelist, item.callback),
        encrypt_type: normalizeEncryptType(item.encrypt_type),
      };
    })
    .filter(Boolean);
}

const normalizedAppList = normalizeAppList(appListConfig);
const appListMap = normalizedAppList.reduce((acc, app) => {
  acc[app.appid] = app;
  return acc;
}, {});

const appSecretMap =
  (secretConfig && secretConfig.appSecrets && typeof secretConfig.appSecrets === "object")
    ? secretConfig.appSecrets
    : {};

function getAppJwtKey(appSecret) {
  if (!appSecret || typeof appSecret !== "object") {
    return null;
  }

  if (typeof appSecret.jwt_key === "string" && appSecret.jwt_key.trim()) {
    return appSecret.jwt_key.trim();
  }

  if (typeof appSecret.jwtSecret === "string" && appSecret.jwtSecret.trim()) {
    return appSecret.jwtSecret.trim();
  }

  return null;
}

function assertPerAppJwtSecrets(appList, secretMap) {
  if (process.env.ALLOW_WEAK_SECRETS === "true") {
    return;
  }

  const issues = [];

  appList.forEach((app) => {
    const appid = app && app.appid;
    const jwtKey = getAppJwtKey(secretMap && secretMap[appid]);
    if (!jwtKey) {
      issues.push(`appSecrets.${appid}.jwt_key 缺失`);
      return;
    }

    if (isPlaceholderSecret(jwtKey) || !isStrongSecret(jwtKey, 32)) {
      issues.push(`appSecrets.${appid}.jwt_key 不安全（占位符或长度不足）`);
    }
  });

  if (issues.length && resolvedEnv === "production") {
    throw new Error(
      `安全配置校验失败: ${issues.join("; ")}。请为每个应用配置独立 JWT 密钥。`,
    );
  }
}

assertPerAppJwtSecrets(normalizedAppList, appSecretMap);

const callbackAppsFromEnv = {
  app1: process.env.CALLBACK_APP_1,
  app2: process.env.CALLBACK_APP_2,
};

const callbackAppsFromList = normalizedAppList.reduce((acc, app) => {
  if (typeof app.callback === "string" && app.callback) {
    acc[app.appid] = app.callback;
  }
  return acc;
}, {});

const callbackWhitelistMap = normalizedAppList.reduce((acc, app) => {
  acc[app.appid] = Array.isArray(app.callback_whitelist) ? app.callback_whitelist : [];
  return acc;
}, {});

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
  env: resolvedEnv,
  port: parseInt(process.env.PORT, 10) || 3000,
  appName: process.env.APP_NAME || "AuthBridge",
  appUrl: resolvedAppUrl,

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
    expiresIn: process.env.JWT_EXPIRES_IN || "1h",
    issuer: process.env.JWT_ISSUER || process.env.APP_NAME || "AuthBridge",
    defaultAppId: process.env.DEFAULT_APP_ID || null,
  },

  // 会话配置
  session: {
    name: process.env.SESSION_NAME || "authbridge.sid",
    secret: secretConfig.sessionSecret,
    ttlMs: parseInt(process.env.SESSION_TTL_MS, 10) || 10 * 60 * 1000, // 10分钟
  },

  // 回调应用配置
  callbackApps: {
    ...callbackAppsFromList,
    ...callbackAppsFromEnv,
  },
  callbackWhitelistMap,

  // 应用列表（新版）
  applist: normalizedAppList,
  applistMap: appListMap,

  // 应用密钥映射（secret.json）
  appSecretMap,

  // 兼容旧逻辑
  whitelistedApps: normalizedAppList.map((item) => item.appid),

  // 安全开关
  security: {
    debugApiEnabled: process.env.ENABLE_DEBUG_API === "true" && resolvedEnv !== "production",
    verifyJwtApiEnabled: false,
  },
};
