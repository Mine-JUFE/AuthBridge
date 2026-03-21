// routes/pages.js
const express = require('express');
const router = express.Router();

// 首页
router.get('/', (req, res) => {
  res.render('index');
});

// 关于页面
router.get('/about', (req, res) => {
  res.render('about');
});


module.exports = router;