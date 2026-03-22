const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * 生成AES密钥并写入指定路径
 * @param {number} keyLength AES密钥长度（仅支持16/24/32字节）
 * @param {string} outputPath 密钥文件输出路径
 * @returns {object} 密钥信息
 */
function generateAesKey(keyLength, outputPath) {
  // 1. 校验AES密钥长度合法性
  const validLengths = [16, 24, 32];
  if (!validLengths.includes(keyLength)) {
    throw new Error(`AES密钥长度仅支持：${validLengths.join('/')} 字节，当前传入：${keyLength}`);
  }

  // 2. 生成加密安全的随机密钥
  const aesKeyBuffer = crypto.randomBytes(keyLength);
  const aesKeyHex = aesKeyBuffer.toString('hex');

  // 3. 处理输出路径（转为绝对路径）
  const absoluteOutputPath = path.resolve(outputPath);
  const outputDir = path.dirname(absoluteOutputPath);

  // 4. 确保目录存在
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
    console.log(`✅ 已自动创建目录：${outputDir}`);
  }

  // 5. 写入密钥文件（权限600，仅当前用户可读）
  fs.writeFileSync(absoluteOutputPath, aesKeyHex, {
    encoding: 'utf8',
    mode: 0o600,
    flag: 'w'
  });

  // 返回密钥信息
  return {
    algorithm: `AES-${keyLength * 8}`,
    keyHex: aesKeyHex,
    outputPath: absoluteOutputPath
  };
}

// ==================== 处理命令行参数 ====================
// 从process.argv获取命令行参数（argv[0]=node路径，argv[1]=脚本路径，argv[2/3]是自定义参数）
const [, , inputLength, inputPath] = process.argv;

// 校验参数是否完整
if (!inputLength || !inputPath) {
  console.error('❌ 参数错误！使用方式：');
  console.error('   node 脚本名.js <密钥长度> <输出路径>');
  console.error('   示例：');
  console.error('   node generateAesKey.js 32 ../keys/aes_key  # 生成32字节AES密钥，写入../keys/aes_key');
  console.error('   node generateAesKey.js 16 D:/keys/my_aes.key # 生成16字节密钥，写入D盘指定路径');
  process.exit(1); // 退出进程，非0表示异常
}

// 转换长度为数字（命令行参数默认是字符串）
const keyLength = parseInt(inputLength, 10);
if (isNaN(keyLength)) {
  console.error(`❌ 密钥长度必须是数字！当前传入：${inputLength}`);
  process.exit(1);
}

// ==================== 执行生成逻辑 ====================
try {
  const keyInfo = generateAesKey(keyLength, inputPath);
  console.log('✅ AES密钥生成成功！');
  console.log(`🔐 算法：${keyInfo.algorithm}`);
  console.log(`📁 密钥文件路径：${keyInfo.outputPath}`);
  console.log(`🗝️  十六进制密钥（仅供验证）：${keyInfo.keyHex}`);
} catch (err) {
  console.error('❌ 生成失败：', err.message);
  process.exit(1);
}