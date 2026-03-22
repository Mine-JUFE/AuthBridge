const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

function ensureDir(filePath) {
  const dir = path.dirname(path.resolve(filePath));
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

function generateEccKeyPair(namedCurve = "prime256v1") {
  return crypto.generateKeyPairSync("ec", {
    namedCurve,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });
}

function writeKeys(publicKeyPath, privateKeyPath, publicKey, privateKey) {
  ensureDir(publicKeyPath);
  ensureDir(privateKeyPath);

  fs.writeFileSync(path.resolve(publicKeyPath), publicKey, {
    encoding: "utf8",
    mode: 0o644,
  });

  fs.writeFileSync(path.resolve(privateKeyPath), privateKey, {
    encoding: "utf8",
    mode: 0o600,
  });
}

const [, , curveArg, publicPathArg, privatePathArg] = process.argv;
const curve = curveArg || "prime256v1";
const publicPath = publicPathArg || "./keys/ecc_public.pem";
const privatePath = privatePathArg || "./keys/ecc_private.pem";

try {
  const { publicKey, privateKey } = generateEccKeyPair(curve);
  writeKeys(publicPath, privatePath, publicKey, privateKey);

  console.log("ECC 密钥生成成功");
  console.log(`curve: ${curve}`);
  console.log(`public: ${path.resolve(publicPath)}`);
  console.log(`private: ${path.resolve(privatePath)}`);
} catch (error) {
  console.error("ECC 密钥生成失败:", error.message);
  process.exit(1);
}
