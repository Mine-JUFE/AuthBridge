const jwt = require("jsonwebtoken");
const config = require("../config");
const {
  encryptStudentIdWithAes,
  decryptStudentIdWithAes,
} = require("../utils/jwt_aes_crypto");
const {
  encryptStudentIdWithEcc,
  decryptStudentIdWithEcc,
} = require("../utils/jwt_ecc_crypto");
const { logError } = require("../utils/error_handler");

const isProduction = config.env === "production";

class JWTService {
  maskValue(value, left = 2, right = 2) {
    const raw = String(value || "");
    if (!raw) {
      return "";
    }
    if (!isProduction) {
      return raw;
    }
    if (raw.length <= left + right) {
      return "*".repeat(raw.length);
    }
    return `${raw.slice(0, left)}***${raw.slice(-right)}`;
  }

  getSecretField(secretObj, fieldNames) {
    if (!secretObj || typeof secretObj !== "object") {
      return null;
    }

    for (const fieldName of fieldNames) {
      const value = secretObj[fieldName];
      if (typeof value === "string" && value.trim()) {
        return value.trim();
      }
    }

    return null;
  }

  normalizeJwtSecret(secret) {
    if (typeof secret !== "string") {
      return secret;
    }

    const trimmed = secret.trim();
    if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
      return Buffer.from(trimmed, "hex");
    }

    return trimmed;
  }

  resolveJwtSecretForApp(appid) {
    if (!appid || typeof appid !== "string") {
      throw new Error("JWT 缺少 appid，无法选择独立签名密钥");
    }

    const appSecret = this.getAppSecret(appid);
    if (appSecret && typeof appSecret === "object") {
      if (typeof appSecret.jwt_key === "string" && appSecret.jwt_key.trim()) {
        return this.normalizeJwtSecret(appSecret.jwt_key);
      }
      if (typeof appSecret.jwtSecret === "string" && appSecret.jwtSecret.trim()) {
        return this.normalizeJwtSecret(appSecret.jwtSecret);
      }
    }

    throw new Error(`应用 ${appid} 缺少独立 JWT 密钥配置（secret.json -> appSecrets.${appid}.jwt_key）`);
  }

  resolveDefaultAppId() {
    if (config.jwt && config.jwt.defaultAppId && config.applistMap[config.jwt.defaultAppId]) {
      return config.jwt.defaultAppId;
    }

    const appIds = Object.keys(config.applistMap || {});
    return appIds.length ? appIds[0] : null;
  }

  getAppConfig(appid) {
    if (!appid || typeof appid !== "string") {
      return null;
    }
    return (config.applistMap && config.applistMap[appid]) || null;
  }

  getAppSecret(appid) {
    const secret = config.appSecretMap && config.appSecretMap[appid];
    if (!secret || typeof secret !== "object") {
      return null;
    }
    return secret;
  }

  buildPayload(studentId, appid, appConfig, appSecret) {
    const encryptType = appConfig.encrypt_type || "aes";
    if (encryptType === "ecc") {
      const eccPublicKey = this.getSecretField(appSecret, ["ecc_public_key", "eccPublicKey"]);
      if (!eccPublicKey) {
        throw new Error(
          `应用 ${appid} 使用 ecc 模式，但缺少公钥配置（secret.json -> appSecrets.${appid}.ecc_public_key）`,
        );
      }

      const encrypted = encryptStudentIdWithEcc(studentId, eccPublicKey);
      return {
        sub: encrypted.encryptedText,
        iv: encrypted.iv,
        tag: encrypted.tag,
        epk: encrypted.epk,
        enc: "ecc",
        enc_alg: encrypted.alg,
        curve: encrypted.curve,
        appid,
        iat: Math.floor(Date.now() / 1000),
        iss: config.jwt.issuer,
        aud: appConfig.app_aud || appid,
        jti: this.generateJTI(),
      };
    }

    if (!appSecret || !appSecret.aes_key) {
      throw new Error(`应用 ${appid} 缺少 AES 密钥配置（secret.json -> appSecrets.${appid}.aes_key）`);
    }

    const encrypted = encryptStudentIdWithAes(studentId, appSecret.aes_key);

    return {
      sub: encrypted.encryptedText,
      iv: encrypted.iv,
      tag: encrypted.tag,
      enc: "aes",
      enc_alg: encrypted.alg,
      appid,
      iat: Math.floor(Date.now() / 1000),
      iss: config.jwt.issuer,
      aud: appConfig.app_aud || appid,
      jti: this.generateJTI(),
    };
  }

  signPayload(payload, appid) {
    const jwtSecret = this.resolveJwtSecretForApp(appid);
    return jwt.sign(payload, jwtSecret, {
      expiresIn: config.jwt.expiresIn,
    });
  }

  generateForApp(studentId, appid) {
    if (!studentId || typeof studentId !== "string") {
      throw new Error("无效的学号");
    }

    const appConfig = this.getAppConfig(appid);
    if (!appConfig) {
      throw new Error(`未知应用: ${appid}`);
    }

    const appSecret = this.getAppSecret(appid);
    const payload = this.buildPayload(studentId, appid, appConfig, appSecret);
    const token = this.signPayload(payload, appid);

    console.log(`🔐 为 ${this.maskValue(studentId)} 生成应用 JWT，appid: ${appid}, aud: ${payload.aud}`);
    return token;
  }

  generateToken(studentId) {
    const defaultAppId = this.resolveDefaultAppId();
    if (!defaultAppId) {
      throw new Error("未配置任何应用，无法生成JWT");
    }
    return this.generateForApp(studentId, defaultAppId);
  }

  verify(token, options = {}) {
    try {
      const unsafeDecoded = jwt.decode(token) || {};
      const tokenAppId = typeof unsafeDecoded.appid === "string" ? unsafeDecoded.appid : null;
      const jwtSecret = this.resolveJwtSecretForApp(tokenAppId);
      const payload = jwt.verify(token, jwtSecret, {
        issuer: config.jwt.issuer,
        ...options,
      });
      return payload;
    } catch (error) {
      logError("JWT 验证失败", error);
      return null;
    }
  }

  verifyToken(token) {
    const decoded = this.verify(token);
    if (!decoded) {
      return {
        valid: false,
        error: "JWT 验证失败",
      };
    }

    const result = {
      valid: true,
      payload: decoded,
      studentId: null,
    };

    if (decoded.enc === "aes" && decoded.appid) {
      try {
        const appSecret = this.getAppSecret(decoded.appid);
        if (!appSecret || !appSecret.aes_key) {
          throw new Error("缺少 app AES key");
        }

        result.studentId = decryptStudentIdWithAes(
          decoded.sub,
          decoded.iv,
          decoded.tag,
          appSecret.aes_key,
        );
      } catch (error) {
        logError("JWT AES 解密失败", error, {
          appid: decoded.appid,
        });
        return {
          valid: false,
          error: "JWT 解密失败",
          payload: decoded,
        };
      }
    }

    if (decoded.enc === "ecc" && decoded.appid) {
      try {
        const appSecret = this.getAppSecret(decoded.appid);
        const eccPrivateKey = this.getSecretField(appSecret, ["ecc_private_key", "eccPrivateKey"]);
        if (!eccPrivateKey) {
          return {
            valid: true,
            payload: decoded,
            studentId: null,
            note: "ECC 模式已验签；当前服务未配置 ecc_private_key，跳过明文解密",
          };
        }

        result.studentId = decryptStudentIdWithEcc(
          decoded.sub,
          decoded.iv,
          decoded.tag,
          decoded.epk,
          eccPrivateKey,
        );
      } catch (error) {
        logError("JWT ECC 解密失败", error, {
          appid: decoded.appid,
        });
        return {
          valid: false,
          error: "JWT 解密失败",
          payload: decoded,
        };
      }
    }

    return result;
  }

  decode(token) {
    try {
      return jwt.decode(token);
    } catch (error) {
      logError("JWT 解码失败", error);
      return null;
    }
  }

  generateJTI() {
    return "jti_" + Date.now() + "_" + Math.random().toString(36).slice(2, 11);
  }

  isExpiringSoon(token, thresholdSeconds = 300) {
    const decoded = this.decode(token);
    if (!decoded || !decoded.exp) return false;

    const now = Math.floor(Date.now() / 1000);
    return decoded.exp - now < thresholdSeconds;
  }
}

module.exports = new JWTService();
