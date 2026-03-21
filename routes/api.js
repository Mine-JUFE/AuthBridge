// routes/api.js
const express = require('express');
const router = express.Router();
const config = require('../config');

/**
 * 健康检查
 * GET /api/health
 */
router.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: config.appName,
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    environment: config.env
  });
});

/**
 * 调试路由 - 显示当前session信息
 * GET /api/debug/session
 */
router.get('/debug/session', (req, res) => {
  if (config.env === 'production') {
    return res.status(403).json({ error: '禁止访问' });
  }
  
  res.json({
    sessionID: req.sessionID,
    authenticated: req.session.authenticated || false,
    studentId: req.session.studentId || null,
    authenticatedAt: req.session.authenticatedAt || null,
    authState: req.session.authState || null,
    targetApp: req.session.targetApp || null,
    sessionAge: req.session.authenticatedAt ? 
      Date.now() - req.session.authenticatedAt : 0
  });
});

/**
 * 验证JWT令牌
 * POST /api/verify-jwt
 */
router.post('/verify-jwt', (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    return res.status(400).json({ error: '缺少token参数' });
  }
  
  const result = require('../services/jwt').verifyToken(token);
  res.json(result);
});

module.exports = router;