require("dotenv").config();
const express = require("express");
const session = require("express-session");
const path = require("path");

// 导入模块
const config = require("./config");
const routes = require("./routes");

const app = express();

if (config.env === "production") {
  // 允许在反向代理后正确识别 HTTPS，避免 secure session cookie 异常
  app.set("trust proxy", parseInt(process.env.TRUST_PROXY_HOPS || "1", 10));
}

// 基本中间件
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));

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
    resave: false,
    saveUninitialized: false,
    unset: "destroy",
    rolling: true,
    cookie: {
      maxAge: config.session.ttlMs, // 10分钟
      secure: config.env === "production",
      httpOnly: true,
      sameSite: "lax",
    },
  }),
);

// 引入路径查询中间件
const currentPathMiddleware = require("./middleware/currentPath");
app.use(currentPathMiddleware);

// 静态文件
app.use(express.static(path.join(__dirname, "public")));

// 路由
app.use("/", routes);

// 错误处理中间件
app.use((err, req, res, next) => {
  console.error("Error:", err.message);
  res.status(err.status || 500).send({
    error: err.message || "Internal Server Error",
    path: req.originalUrl,
  });
});

// 404处理
app.use("*", (req, res) => {
  res.status(404).render("404.ejs");
});

module.exports = app;
