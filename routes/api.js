// routes/api.js
const express = require('express');
const router = express.Router();
const config = require('../config');

const isProduction = config.env === 'production';
const isDebugApiEnabled = !!(config.security && config.security.debugApiEnabled);

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
  if (isProduction) {
    return res.status(404).json({ error: 'Not Found' });
  }

  if (!isDebugApiEnabled) {
    return res.status(403).json({ error: '调试接口已禁用' });
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
  return res.status(404).json({ error: 'Not Found' });
});

module.exports = router;