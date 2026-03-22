const crypto = require("crypto");

function encryptStudentIdWithAes(studentId, aesKeyHex) {
  if (typeof aesKeyHex !== "string") {
    throw new Error("AES key 缺失或格式错误");
  }

  const normalizedKeyHex = aesKeyHex.trim();
  if (!/^[0-9a-fA-F]+$/.test(normalizedKeyHex) || normalizedKeyHex.length % 2 !== 0) {
    throw new Error("AES key 必须是合法的十六进制字符串");
  }

  const key = Buffer.from(normalizedKeyHex, "hex");
  if (![16, 24, 32].includes(key.length)) {
    throw new Error("AES key 长度必须是16/24/32字节");
  }

  const iv = crypto.randomBytes(16);
  const algorithm = `aes-${key.length * 8}-cbc`;
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(studentId, "utf8", "base64");
  encrypted += cipher.final("base64");

  return {
    encryptedText: encrypted,
    iv: iv.toString("base64"),
    alg: algorithm,
  };
}

function decryptStudentIdWithAes(encryptedText, ivBase64, aesKeyHex) {
  const key = Buffer.from(String(aesKeyHex || "").trim(), "hex");
  if (![16, 24, 32].includes(key.length)) {
    throw new Error("AES key 长度不合法");
  }

  const iv = Buffer.from(ivBase64, "base64");
  const algorithm = `aes-${key.length * 8}-cbc`;
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  let decrypted = decipher.update(encryptedText, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

module.exports = {
  encryptStudentIdWithAes,
  decryptStudentIdWithAes,
};
