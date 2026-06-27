require("dotenv").config();
const express = require("express");
const session = require("express-session");
const connectRedis = require("connect-redis");
const { createClient } = require("redis");
const path = require("path");
const cookieParser = require('cookie-parser');
const i18next = require('i18next');
const middleware = require('i18next-http-middleware');
const Backend = require('i18next-fs-backend');
// 导入模块
const config = require("./config");
const routes = require("./routes");
const { logError, createClientErrorPayload } = require("./utils/error_handler");
const createCsrfOriginGuard = require("./middleware/csrfOriginGuard");

const app = express();
const RedisStore = connectRedis.RedisStore || connectRedis.default || connectRedis;

function parseBooleanEnv(input, defaultValue = false) {
  if (input === undefined || input === null || String(input).trim() === "") {
    return defaultValue;
  }

  const normalized = String(input).trim().toLowerCase();
  return normalized === "1" || normalized === "true" || normalized === "yes" || normalized === "on";
}

function createSessionStore() {
  if (!config.session.useRedis || config.session.store !== "redis") {
    console.log("Session存储: memory（Redis已关闭）");
    return null;
  }

  const redisClient = createClient({
    url: config.session.redisUrl,
  });

  redisClient.on("error", (error) => {
    logError("Redis连接异常", error, {
      redisUrl: config.session.redisUrl,
    });
  });

  redisClient.connect().then(() => {
    console.log("Redis会话存储已连接");
  }).catch((error) => {
    logError("Redis连接失败", error, {
      redisUrl: config.session.redisUrl,
    });
  });

  return new RedisStore({
    client: redisClient,
    prefix: config.session.redisPrefix,
    ttl: Math.ceil(config.session.ttlMs / 1000),
  });
}

const sessionStore = createSessionStore();

if (config.env === "production") {
  // 允许在反向代理后正确识别 HTTPS，避免 secure session cookie 异常
  app.set("trust proxy", parseInt(process.env.TRUST_PROXY_HOPS || "1", 10));
}


app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser()); // 必须在 i18n 之前！

if (parseBooleanEnv(process.env.FORCE_X_FORWARDED_PROTO_HTTPS, false)) {
  app.use((req, res, next) => {
    req.headers["x-forwarded-proto"] = "https";
    if (!req.headers["x-forwarded-port"]) {
      req.headers["x-forwarded-port"] = "443";
    }
    next();
  });
}

if (process.env.DEBUG_PROXY_HEADERS === "true") {
  app.use((req, res, next) => {
    const forwardedProto = req.headers["x-forwarded-proto"];
    const forwardedHost = req.headers["x-forwarded-host"];
    const forwardedFor = req.headers["x-forwarded-for"];
    const cookieNames = Object.keys(req.cookies || {});

    console.log("[DEBUG_PROXY]", {
      method: req.method,
      url: req.originalUrl,
      secure: req.secure,
      protocol: req.protocol,
      host: req.get("host"),
      forwardedProto,
      forwardedHost,
      forwardedFor,
      cookieNames,
    });

    next();
  });
}

// 全局变量
app.locals.basePath = config.appBasePath;
app.locals.withBasePath = config.withBasePath;


i18next
    .use(Backend)
    .use(middleware.LanguageDetector)
    .init({
        fallbackLng: 'zh',
    supportedLngs: ['en', 'zh'],
        preload: ['en', 'zh'],
        ns: ['translation'],
        defaultNS: 'translation',
        detection: {
          order: ['cookie', 'header'],
            lookupCookie: 'lang',
            cookieMinutes: 60 * 24 * 30,
          cookieSecure: config.env === 'production',
            cookieHttpOnly: false,
        },
        backend: {
          loadPath: __dirname + '/locales/{{lng}}.json',
        },
    });


app.use(middleware.handle(i18next));

// 4. 强行把 t() 注入所有 EJS 模板
app.use((req, res, next) => {
    res.locals.t = req.t;
  const resolvedLanguage = req.resolvedLanguage || req.language || 'zh';
  res.locals.currentLanguage = resolvedLanguage;
  res.locals.htmlLang = resolvedLanguage === 'en' ? 'en' : 'zh-CN';
    next();
});

// 基础安全响应头
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'",
  );
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=()",
  );
  next();
});
// Redis客户端配置超时
const redisClient = new Redis({ commandTimeout: 2000 });
const store = new RedisStore({ client: redisClient });


// Session配置
const sessionCookieSecureMode = String(process.env.SESSION_COOKIE_SECURE || "").trim().toLowerCase();
const sessionCookieSecure = sessionCookieSecureMode === "true"
  ? true
  : sessionCookieSecureMode === "false"
    ? false
    : config.env === "production";

app.use(
  session({
    name: config.session.name,
    secret: config.session.secret,
    store: sessionStore || undefined,
    resave: false,
    saveUninitialized: false,
    unset: "destroy",
    rolling: true,
    cookie: {
      maxAge: config.session.ttlMs, // 10分钟
      secure: sessionCookieSecure,
      httpOnly: true,
      sameSite: "lax",
      path: config.appBasePath,
    },
  }),
);

// 引入路径查询中间件
const currentPathMiddleware = require("./middleware/currentPath");
app.use(currentPathMiddleware);

app.use((req, res, next) => {
  res.locals.basePath = config.appBasePath;
  res.locals.withBasePath = config.withBasePath;
  next();
});

app.use(createCsrfOriginGuard({
  appUrl: config.appUrl,
  appBasePath: config.appBasePath,
  cookieNames: [config.session.name, "authbridge.jwt"],
  exemptPaths: [
    "/cas/serviceValidate",
    "/serviceValidate",
    "/cas/slo",
  ],
}));

if (config.appBasePath !== "/") {
  app.get("/", (req, res) => {
    res.redirect(config.appBasePath);
  });
}

// 静态文件
app.use(config.appBasePath, express.static(path.join(__dirname, "public")));

// 路由
app.use(config.appBasePath, routes);

// 404处理
app.use("*", (req, res) => {
  res.status(404).render("404.ejs");
});
//全局捕获
app.use((err, req, res, next) => {
  // 判断Redis会话存储类异常
  if (err.message.includes('Redis') || err.message.includes('timeout')) {
    // 直接渲染静态错误页面，不再执行CAS跳转逻辑
    logError("Redis会话存储异常", err, {
      method: req.method,
      path: req.originalUrl,
      query: req.query,
      ip: req.ip,
    });
    return res.status(500).render(error, {
      title: "系统错误",
      message: "会话存储异常，请稍后再试。",
    });
  }
  next(err);
});
// 错误处理中间件
app.use((err, req, res, next) => {
  const status = Number(err && err.status) || 500;
  const payload = createClientErrorPayload(status);

  logError("全局异常", err, {
    method: req.method,
    path: req.originalUrl,
    query: req.query,
    ip: req.ip,
  });

  if (req.accepts("html")) {
    return res.status(status).render("error", {
      title: status >= 500 ? "系统错误" : "请求失败",
      message: payload.error,
    });
  }

  return res.status(status).json(payload);
});
module.exports = app;
