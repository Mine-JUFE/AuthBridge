const express = require("express");
const crypto = require("crypto");
const router = express.Router();

// 服务模块
const config = require("../config");
const casService = require("../services/cas");
const jwtService = require("../services/jwt");

// 首页
router.get("/", (req, res) => {
  res.render("index.ejs");
});
router.get("/about", (req, res) => {
  res.render("about.ejs");
});

// 跳转到 CAS 登录
router.get("/login", (req, res) => {
  const { app } = req.query;

  // 仅允许配置中存在的目标应用
  const targetApp =
    typeof app === "string" && config.callbackApps[app] ? app : null;
  const state = casService.generateState();

  req.session.casAuth = {
    state,
    targetApp,
    createdAt: Date.now(),
  };

  try {
    const casLoginUrl = casService.getLoginUrl(state);
    res.redirect(casLoginUrl);
  } catch (error) {
    console.error("Login redirect error:", error.message);
    res.status(500).send("❌ 登录初始化失败，请稍后重试");
  }
});

// CAS 回调处理
router.get("/callback", async (req, res) => {
  const { ticket, state } = req.query;

  if (!ticket || typeof ticket !== "string") {
    return res.status(400).send("❌ 缺少 ticket 参数");
  }

  if (!state || typeof state !== "string") {
    return res.status(400).send("❌ 缺少 state 参数");
  }

  const authSession = req.session.casAuth;
  if (!authSession || typeof authSession.state !== "string") {
    return res.status(401).send("❌ 会话已失效，请重新登录");
  }

  if (!safeEqual(authSession.state, state)) {
    return res.status(401).send("❌ 登录状态校验失败，请重新登录");
  }

  // Token 页面和回调页不应被缓存
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, private",
  );

  try {
    // 验证 CAS Ticket
    const studentId = await casService.validateTicket(ticket, state);

    if (!studentId) {
      return res.status(401).send(`
        <h2>❌ 认证失败</h2>
        <p>CAS 验证失败，请重试。</p>
        <a href="/">返回首页</a>
      `);
    }

    // 生成 JWT
    const token = jwtService.generate(studentId);
    const targetApp = authSession.targetApp;

    // 情况1: 回调到目标应用
    if (targetApp) {
      const callbackUrl = await casService.getCallbackUrl(targetApp, token);
      if (callbackUrl) {
        req.session.destroy(() => {});
        console.log(`↪️  跳转到应用 ${targetApp}`);
        return res.redirect(callbackUrl);
      }
    }

    req.session.destroy(() => {});

    // 情况2: 显示 JWT 给用户复制
    res.send(renderJWTPage(studentId, token));
  } catch (error) {
    console.error("Callback error:", error);
    res.status(500).send(`
      <h2>❌ 服务器错误</h2>
      <p>${error.message}</p>
      <a href="/">返回首页</a>
    `);
  }
});

function renderJWTPage(studentId, token) {
  const escapedStudentId = escapeHtml(studentId);
  const escapedToken = escapeHtml(token);
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>JWT 令牌 - CAS 网关</title>
      <style>
        ${getStyles()}
      </style>
    </head>
    <body>
      <div class="container">
        <header>
          <h1>🎉 认证成功！</h1>
          <p class="subtitle">您的 JWT 令牌已生成</p>
        </header>
        
        <div class="info-card">
          <div class="info-item">
            <span class="label">👤 用户学号</span>
            <span class="value">${escapedStudentId}</span>
          </div>
          <div class="info-item">
            <span class="label">⏰ 有效期</span>
            <span class="value">1小时</span>
          </div>
          <div class="info-item">
            <span class="label">🆔 令牌类型</span>
            <span class="value">JWT (JSON Web Token)</span>
          </div>
        </div>
        
        <div class="token-section">
          <h3>🔐 您的 JWT 令牌：</h3>
          <div class="token-box" id="token-box">${escapedToken}</div>
          
          <div class="actions">
            <button class="btn btn-primary" onclick="copyToken()">
              📋 复制令牌
            </button>
            <a href="/" class="btn btn-secondary">🏠 返回首页</a>
          </div>
          
          <div id="copy-status" class="status-message"></div>
        </div>
        
        <div class="instructions">
          <h3>📋 使用说明</h3>
          <ol>
            <li>点击"复制令牌"按钮复制 JWT</li>
            <li>在目标应用中粘贴此令牌</li>
            <li>令牌包含您的学号信息，无法被反向破解</li>
            <li>令牌将在 1 小时后过期</li>
          </ol>
        </div>
      </div>
      
      <script>
        function copyToken() {
          const tokenEl = document.getElementById('token-box');
          const text = tokenEl.innerText;
          
          navigator.clipboard.writeText(text).then(() => {
            const statusEl = document.getElementById('copy-status');
            statusEl.textContent = '✅ 令牌已复制到剪贴板！';
            statusEl.className = 'status-message success';
            
            setTimeout(() => {
              statusEl.textContent = '';
              statusEl.className = 'status-message';
            }, 3000);
          }).catch(err => {
            alert('复制失败，请手动选择复制');
          });
        }
      </script>
    </body>
    </html>
    `;
}

function escapeHtml(input) {
  return String(input)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function safeEqual(a, b) {
  const aBuffer = Buffer.from(a);
  const bBuffer = Buffer.from(b);

  if (aBuffer.length !== bBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(aBuffer, bBuffer);
}

// 样式函数
function getStyles() {
  return `
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      padding: 20px;
    }
    .container {
      max-width: 800px;
      margin: 0 auto;
      background: white;
      border-radius: 20px;
      padding: 40px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.3);
    }
    header { text-align: center; margin-bottom: 40px; }
    h1 { color: #333; margin-bottom: 10px; }
    .subtitle { color: #666; font-size: 1.2em; }
    .info-card {
      background: #f8f9fa;
      border-radius: 10px;
      padding: 20px;
      margin-bottom: 30px;
      border-left: 4px solid #667eea;
    }
    .info-item {
      display: flex;
      justify-content: space-between;
      padding: 10px 0;
      border-bottom: 1px solid #e9ecef;
    }
    .info-item:last-child { border-bottom: none; }
    .label { color: #666; font-weight: 500; }
    .value { color: #333; font-weight: 600; }
    .token-section { margin: 30px 0; }
    .token-box {
      background: #f8f9fa;
      border: 2px solid #dee2e6;
      border-radius: 8px;
      padding: 20px;
      margin: 20px 0;
      word-break: break-all;
      font-family: 'Courier New', monospace;
      font-size: 14px;
      line-height: 1.6;
      max-height: 200px;
      overflow-y: auto;
    }
    .actions { display: flex; gap: 15px; margin: 20px 0; }
    .btn {
      padding: 12px 24px;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      transition: all 0.3s;
    }
    .btn-primary {
      background: #667eea;
      color: white;
    }
    .btn-primary:hover { background: #5a6fd8; }
    .btn-secondary {
      background: #6c757d;
      color: white;
    }
    .btn-secondary:hover { background: #5a6268; }
    .status-message {
      margin: 20px 0;
      padding: 15px;
      border-radius: 8px;
      text-align: center;
      display: none;
    }
    .status-message.success {
      display: block;
      background: #d4edda;
      color: #155724;
      border: 1px solid #c3e6cb;
    }
    .instructions {
      background: #e7f3ff;
      border-radius: 10px;
      padding: 25px;
      margin-top: 30px;
    }
    .instructions h3 { margin-bottom: 15px; color: #0056b3; }
    .instructions ol { padding-left: 20px; }
    .instructions li { margin: 8px 0; }
    @media (max-width: 768px) {
      .container { padding: 20px; }
      .info-item { flex-direction: column; }
      .actions { flex-direction: column; }
    }
  `;
}

module.exports = router;
