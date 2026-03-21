// routes/index.js
const express = require('express');
const router = express.Router();

// 导入分模块路由
const pagesRoutes = require('./pages');
const authRoutes = require('./auth');
const apiRoutes = require('./api');

// 注册路由模块
router.use('/', pagesRoutes);    // 页面路由
router.use('/', authRoutes);     // 认证路由
router.use('/api', apiRoutes);   // API路由



module.exports = router;