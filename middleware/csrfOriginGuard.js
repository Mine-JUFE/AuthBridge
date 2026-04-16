const { URL } = require("url");

function parseOrigin(input) {
  const raw = String(input || "").trim();
  if (!raw) {
    return null;
  }

  try {
    return new URL(raw).origin;
  } catch (_error) {
    return null;
  }
}

function isUnsafeMethod(method) {
  const normalized = String(method || "").toUpperCase();
  return normalized === "POST" || normalized === "PUT" || normalized === "PATCH" || normalized === "DELETE";
}

function stripBasePath(pathname, basePath) {
  const normalizedPath = String(pathname || "");
  const normalizedBase = String(basePath || "/");
  if (!normalizedBase || normalizedBase === "/") {
    return normalizedPath;
  }

  if (normalizedPath.startsWith(normalizedBase)) {
    const sliced = normalizedPath.slice(normalizedBase.length);
    return sliced.startsWith("/") ? sliced : `/${sliced}`;
  }

  return normalizedPath;
}

function hasSensitiveCookie(req, cookieNames) {
  if (!req || !req.cookies || !Array.isArray(cookieNames)) {
    return false;
  }

  return cookieNames.some((name) => !!req.cookies[name]);
}

function createCsrfOriginGuard(options = {}) {
  const appOrigin = parseOrigin(options.appUrl);
  const appBasePath = options.appBasePath || "/";
  const cookieNames = Array.isArray(options.cookieNames) ? options.cookieNames : [];
  const exemptPaths = new Set(Array.isArray(options.exemptPaths) ? options.exemptPaths : []);

  return (req, res, next) => {
    if (!isUnsafeMethod(req.method)) {
      return next();
    }

    const relativePath = stripBasePath(req.path, appBasePath);
    if (exemptPaths.has(relativePath)) {
      return next();
    }

    if (!hasSensitiveCookie(req, cookieNames)) {
      return next();
    }

    const origin = parseOrigin(req.get("origin"));
    const referer = parseOrigin(req.get("referer"));

    const isOriginAllowed = !!(appOrigin && origin && origin === appOrigin);
    const isRefererAllowed = !!(appOrigin && referer && referer === appOrigin);

    if (isOriginAllowed || isRefererAllowed) {
      return next();
    }

    if (req.accepts("html")) {
      return res.status(403).render("error", {
        title: "请求被拒绝",
        message: "检测到跨站请求风险，请从本站页面重新发起操作",
      });
    }

    return res.status(403).json({ error: "Forbidden: CSRF origin check failed" });
  };
}

module.exports = createCsrfOriginGuard;
