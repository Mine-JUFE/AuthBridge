const jwt = require("jsonwebtoken");
const config = require("../config");

class JWTService {
  /**
   * 生成 JWT
   * @param {string} studentId - 学号
   * @returns {string} JWT Token
   */
  generate(studentId) {
    if (!studentId || typeof studentId !== "string") {
      throw new Error("无效的学号");
    }

    const payload = {
      sub: studentId, // 学号（主体）
      iat: Math.floor(Date.now() / 1000), // 签发时间
      iss: config.jwt.issuer, // 签发者
      aud: "Client-Applications", // 接收方
      jti: this.generateJTI(), // JWT ID
    };

    const token = jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.expiresIn,
    });

    console.log(`🔐 为 ${studentId} 生成 JWT，有效期: ${config.jwt.expiresIn}`);
    return token;
  }

  /**
   * 验证 JWT
   * @param {string} token - JWT Token
   * @returns {object|null} 解码后的 payload 或 null
   */
  verify(token) {
    try {
      return jwt.verify(token, config.jwt.secret, {
        issuer: config.jwt.issuer,
        audience: "Client-Applications",
      });
    } catch (error) {
      console.error("❌ JWT 验证失败:", error.message);
      return null;
    }
  }

  /**
   * 解码 JWT（不验证）
   * @param {string} token - JWT Token
   * @returns {object|null} 解码后的 payload
   */
  decode(token) {
    try {
      return jwt.decode(token);
    } catch (error) {
      console.error("❌ JWT 解码失败:", error.message);
      return null;
    }
  }

  /**
   * 生成 JWT ID
   */
  generateJTI() {
    return "jti_" + Date.now() + "_" + Math.random().toString(36).substr(2, 9);
  }

  /**
   * 检查 JWT 是否即将过期
   */
  isExpiringSoon(token, thresholdSeconds = 300) {
    const decoded = this.decode(token);
    if (!decoded || !decoded.exp) return false;

    const now = Math.floor(Date.now() / 1000);
    return decoded.exp - now < thresholdSeconds;
  }
}

module.exports = new JWTService();
