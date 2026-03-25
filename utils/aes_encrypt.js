// utils/aes-encrypt.js
import crypto from 'crypto'; 
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url'; 
const __dirname = path.dirname(fileURLToPath(import.meta.url));
/**
 * 读取AES密钥并加密文本（仅返回加密结果，不保存文件）
 * @param {string} plaintext - 要加密的明文字符串
 * @param {string} keyPath - AES密钥文件路径（默认：../keys/aes_key）
 * @returns {object} 加密结果（包含密文、IV、密钥长度等）
 */
export function encryptText(plaintext, keyPath = '../keys/aes_key') {
  try {
    // 1. 读取AES密钥文件
    const resolvedKeyPath = path.resolve(__dirname, keyPath);
    if (!fs.existsSync(resolvedKeyPath)) {
      throw new Error(`AES密钥文件不存在：${resolvedKeyPath}（请先执行aes-key-gen.js生成密钥）`);
    }
    const aesKeyHex = fs.readFileSync(resolvedKeyPath, 'utf8').trim();
    const aesKey = Buffer.from(aesKeyHex, 'hex'); // 转回Buffer

    // 2. 生成随机IV（GCM推荐12字节）
    const iv = crypto.randomBytes(12);

    // 3. AES-GCM加密文本
    const cipher = crypto.createCipheriv('aes-128-gcm', aesKey, iv);
    let encryptedText = cipher.update(plaintext, 'utf8', 'base64');
    encryptedText += cipher.final('base64');
    const tag = cipher.getAuthTag();

    // 4. 整理加密结果（仅返回，不保存）
    const encryptedResult = {
      encryptedText: encryptedText,       // Base64格式密文
      iv: iv.toString('base64'),          // Base64格式IV（解密必需）
      tag: tag.toString('base64'),        // Base64格式认证标签（GCM校验必需）
      encryptTime: new Date().toISOString(), // 加密时间（可选）
      keyLength: aesKey.length            // 密钥长度（可选，便于解密端校验）
    };

    console.log(`✅ 文本加密成功！`);
    console.log(`📝 原始明文（前20字符）：${plaintext.slice(0, 20)}...`);

    return encryptedResult; // 直接返回加密结果
  } catch (err) {
    console.error(`❌ 加密文本失败：${err.message}`);
    throw err; // 抛出错误，由调用方处理
  }
}
