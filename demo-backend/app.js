const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

const PORT = process.env.PORT || 4000;
const JWT_KEY = process.env.DEMO_APP_JWT_KEY || 'replace-with-demo-jwt-key';

// 回调接收端示例
app.post('/api/auth/callback', (req, res) => {
  const { token } = req.body || {};
  if (!token) {
    return res.status(400).send('missing token');
  }

  try {
    const payload = jwt.verify(token, JWT_KEY, { algorithms: ['HS256'] });

    // TODO: 进行更多业务校验，例如 payload.enc、payload.sub 等

    // 验签通过：在当前域下写入 HttpOnly cookie（示例）
    res.cookie('demo.sid', 'local-session-id-' + Date.now(), {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000,
    });

    // 可选：返回页面或 JSON，指示登录成功
    return res.send(`login ok for ${payload.sub || 'unknown'}`);
  } catch (err) {
    console.error('verify failed', err && err.message);
    return res.status(401).send('invalid token');
  }
});

app.get('/', (req, res) => {
  res.send('Demo backend running');
});

app.listen(PORT, () => {
  console.log(`Demo backend listening on ${PORT}`);
});
