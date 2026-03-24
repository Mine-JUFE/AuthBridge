require("dotenv").config();
const express = require("express");
const session = require("express-session");
const connectRedis = require("connect-redis");
const { createClient } = require("redis");
const path = require("path");

// 导入模块
const config = require("./config");
const routes = require("./routes");
const { logError, createClientErrorPayload } = require("./utils/error_handler");

const app = express();
const RedisStore = connectRedis.RedisStore || connectRedis.default || connectRedis;

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

// 基本中间件
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.locals.basePath = config.appBasePath;
app.locals.withBasePath = config.withBasePath;

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

// Session配置
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
      secure: config.env === "production",
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

if (config.appBasePath !== "/") {
  app.get("/", (req, res) => {
    res.redirect(config.appBasePath);
  });
}

// 静态文件
app.use(config.appBasePath, express.static(path.join(__dirname, "public")));

// 路由
app.use(config.appBasePath, routes);

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

// 404处理
app.use("*", (req, res) => {
  res.status(404).render("404.ejs");
});

module.exports = app;
