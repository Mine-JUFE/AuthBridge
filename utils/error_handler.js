const SENSITIVE_KEY_PATTERN = /(token|ticket|secret|password|authorization|cookie|session|studentid|key|signature|passwd|pwd)/i;

function maskValue(value, left = 3, right = 2) {
  const raw = String(value || "");
  if (!raw) {
    return "";
  }

  if (raw.length <= left + right) {
    return "*".repeat(raw.length);
  }

  return `${raw.slice(0, left)}***${raw.slice(-right)}`;
}

function sanitizeString(input) {
  const text = String(input || "");
  if (!text) {
    return "";
  }

  return text
    .replace(/(ticket|token|studentId|state|service|authorization)=([^&\s]+)/gi, "$1=***")
    .replace(/(bearer\s+)[A-Za-z0-9._~+/=-]+/gi, "$1***");
}

function sanitizeValue(value, keyHint = "", depth = 0) {
  if (depth > 5) {
    return "[Truncated]";
  }

  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value === "string") {
    if (SENSITIVE_KEY_PATTERN.test(String(keyHint || ""))) {
      return maskValue(value);
    }
    return sanitizeString(value);
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return value;
  }

  if (Buffer.isBuffer(value)) {
    return `[Buffer(${value.length})]`;
  }

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeValue(item, keyHint, depth + 1));
  }

  if (value instanceof Error) {
    return {
      name: value.name,
      message: sanitizeString(value.message),
      stack: typeof value.stack === "string" ? sanitizeString(value.stack).split("\n").slice(0, 6).join("\n") : undefined,
      code: value.code,
    };
  }

  if (typeof value === "object") {
    const output = {};
    Object.keys(value).forEach((key) => {
      output[key] = sanitizeValue(value[key], key, depth + 1);
    });
    return output;
  }

  return String(value);
}

function logError(scope, error, meta = null) {
  const payload = {
    scope,
    error: sanitizeValue(error),
  };

  if (meta) {
    payload.meta = sanitizeValue(meta);
  }

  console.error("[ERROR]", payload);
}

function createClientErrorPayload(status = 500) {
  if (status >= 500) {
    return { error: "系统繁忙，请稍后重试" };
  }

  return { error: "请求失败" };
}

module.exports = {
  maskValue,
  sanitizeString,
  sanitizeValue,
  logError,
  createClientErrorPayload,
};