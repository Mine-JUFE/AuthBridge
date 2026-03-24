// middleware/currentPath.js
const config = require("../config");
module.exports = function (req, res, next) {
  // 将当前路径注入到res.locals，所有视图都能访问
  res.locals.currentPath = config.normalizedApp;
  res.locals.isHomePage = req.path === "/";
  res.locals.isAboutPage = req.path.startsWith("/about");
  next();
};
