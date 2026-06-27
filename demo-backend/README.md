# Demo Backend

这是一个最小示例，演示回调方如何接收来自 AuthBridge 的 POST 表单（`token`），在服务器端验证 JWT 并写入本域下的 HttpOnly cookie 以建立本地会话。

运行：

```bash
# 在 demo-backend 目录下
npm install
DEMO_APP_JWT_KEY=replace-with-demo-jwt-key node app.js
```

请在生产中替换 `DEMO_APP_JWT_KEY` 为真实的应用签名密钥，并在验签后执行更严格的业务检查与会话管理。