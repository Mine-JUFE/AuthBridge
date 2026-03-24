// middleware/currentPath.js
const config = require("../config");

function normalizePath(pathname) {
  const raw = String(pathname || "/").trim();
  if (!raw || raw === "/") {
    return "/";
  }

  const noQuery = raw.split("?")[0].split("#")[0];
  return noQuery.replace(/\/+$/, "") || "/";
}

module.exports = function (req, res, next) {
  const currentPath = normalizePath(req.path);
  const homePath = normalizePath(config.withBasePath("/"));
  const aboutPath = normalizePath(config.withBasePath("/about"));

  // 将当前路径注入到res.locals，所有视图都能访问
  res.locals.currentPath = currentPath;
  res.locals.isHomePage = currentPath === homePath;
  res.locals.isAboutPage = currentPath === aboutPath || currentPath.startsWith(`${aboutPath}/`);

  next();
};
