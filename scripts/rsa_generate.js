const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * 生成RSA密钥对并写入指定路径
 * @param {number} modulusLength RSA密钥长度（推荐2048/4096，最小2048）
 * @param {string} privateKeyPath 私钥输出路径
 * @param {string} publicKeyPath 公钥输出路径
 * @returns {object} 密钥对信息
 */
function generateRSAKeyPair(modulusLength, privateKeyPath, publicKeyPath) {
  // 1. 校验RSA密钥长度合法性（2048及以上，推荐4096）
  if (!Number.isInteger(modulusLength) || modulusLength < 2048) {
    throw new Error(`RSA密钥长度必须是≥2048的整数（推荐4096），当前传入：${modulusLength}`);
  }

  // 2. 生成RSA密钥对
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: modulusLength, // 密钥长度
    publicKeyEncoding: {
      type: 'spki', // 公钥标准格式（兼容JWT/OpenSSL）
      format: 'pem' // PEM文本格式，便于存储/使用
    },
    privateKeyEncoding: {
      type: 'pkcs8', // 私钥标准格式（PKCS#8）
      format: 'pem'
      // 生产环境建议开启密码保护（取消注释并设置密码）
      // cipher: 'aes-256-cbc',
      // passphrase: '你的私钥保护密码'
    }
  });

  // 3. 处理路径（转为绝对路径，避免相对路径歧义）
  const absPrivatePath = path.resolve(privateKeyPath);
  const absPublicPath = path.resolve(publicKeyPath);
  const privateDir = path.dirname(absPrivatePath);
  const publicDir = path.dirname(absPublicPath);

  // 4. 确保输出目录存在
  if (!fs.existsSync(privateDir)) {
    fs.mkdirSync(privateDir, { recursive: true });
    console.log(`✅ 已创建私钥目录：${privateDir}`);
  }
  if (!fs.existsSync(publicDir)) {
    fs.mkdirSync(publicDir, { recursive: true });
    console.log(`✅ 已创建公钥目录：${publicDir}`);
  }

  // 5. 写入密钥文件（私钥权限600，公钥权限644）
  fs.writeFileSync(absPrivatePath, privateKey, {
    encoding: 'utf8',
    mode: 0o600, // 私钥仅当前用户可读可写，防止泄露
    flag: 'w'
  });
  fs.writeFileSync(absPublicPath, publicKey, {
    encoding: 'utf8',
    mode: 0o644, // 公钥可公开读取
    flag: 'w'
  });

  // 返回密钥对信息
  return {
    algorithm: `RSA-${modulusLength}`,
    privateKeyPath: absPrivatePath,
    publicKeyPath: absPublicPath
  };
}

// ==================== 处理命令行参数 ====================
// process.argv：[node路径, 脚本路径, 密钥长度, 私钥路径(可选), 公钥路径(可选)]
const [, , inputLength, inputPrivatePath, inputPublicKeyPath] = process.argv;

// 1. 定义默认路径（用户不传则使用默认）
const DEFAULT_PRIVATE_PATH = '../keys/rsa_private.pem';
const DEFAULT_PUBLIC_PATH = '../keys/rsa_public.pem';

// 2. 校验核心参数（长度）
if (!inputLength) {
  console.error('❌ 参数错误！使用方式：');
  console.error('   基础用法（使用默认路径）：node 脚本名.js <密钥长度>');
  console.error('   自定义路径：node 脚本名.js <密钥长度> <私钥路径> <公钥路径>');
  console.error('   示例：');
  console.error('   node generateRSAKey.js 4096                # 4096位密钥，写入默认路径');
  console.error('   node generateRSAKey.js 2048 ./rsa/priv.pem ./rsa/pub.pem # 自定义路径');
  process.exit(1);
}

// 3. 转换长度为数字并校验
const modulusLength = parseInt(inputLength, 10);
if (isNaN(modulusLength)) {
  console.error(`❌ 密钥长度必须是数字！当前传入：${inputLength}`);
  process.exit(1);
}

// 4. 确定最终路径（用户传了就用，没传用默认）
const privateKeyPath = inputPrivatePath || DEFAULT_PRIVATE_PATH;
const publicKeyPath = inputPublicKeyPath || DEFAULT_PUBLIC_PATH;

// ==================== 执行生成逻辑 ====================
try {
  const keyPairInfo = generateRSAKeyPair(modulusLength, privateKeyPath, publicKeyPath);
  console.log('✅ RSA密钥对生成成功！');
  console.log(`🔐 算法：${keyPairInfo.algorithm}`);
  console.log(`🔑 私钥路径：${keyPairInfo.privateKeyPath}`);
  console.log(`🔓 公钥路径：${keyPairInfo.publicKeyPath}`);
} catch (err) {
  console.error('❌ 生成失败：', err.message);
  process.exit(1);
}