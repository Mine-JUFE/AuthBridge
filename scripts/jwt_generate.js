const crypto = require('crypto');

/**
 * 生成JWT对称密钥（HS256/HS512）
 * @param {number} byteLength 密钥字节长度（32=256位，64=512位）
 * @returns {object} 包含hex/base64格式的密钥
 */
function generateJWTSymmetricSecret(byteLength = 32) {
  // 生成加密安全的随机字节
  const secretBuffer = crypto.randomBytes(byteLength);
  
  // 转换为十六进制（便于存储/传输，和你之前Python代码的hex格式兼容）
  const secretHex = secretBuffer.toString('hex');
  
  // 转换为Base64（JWT库常用格式）
  const secretBase64 = secretBuffer.toString('base64');
  
  return {
    hex: secretHex,
    base64: secretBase64,
    byteLength: byteLength
  };
}

// 生成HS256推荐的32字节密钥
const hs256Secret = generateJWTSymmetricSecret(32);
console.log('=== HS256 对称密钥 ===');
console.log('十六进制格式（推荐存储）:', hs256Secret.hex);
console.log('Base64格式（部分JWT库使用）:', hs256Secret.base64);

// 生成HS512推荐的64字节密钥（更高安全级）
const hs512Secret = generateJWTSymmetricSecret(64);
console.log('\n=== HS512 对称密钥 ===');
console.log('十六进制格式:', hs512Secret.hex);
console.log('Base64格式:', hs512Secret.base64);