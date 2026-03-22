const crypto = require("crypto");

function encryptStudentIdWithEcc(studentId, eccPublicKeyPem) {
  const receiverPublicKey = crypto.createPublicKey(eccPublicKeyPem);
  if (receiverPublicKey.asymmetricKeyType !== "ec") {
    throw new Error("ECC 公钥类型必须是 EC");
  }

  const curve =
    (receiverPublicKey.asymmetricKeyDetails
      && receiverPublicKey.asymmetricKeyDetails.namedCurve)
    || "prime256v1";

  const ephemeral = crypto.generateKeyPairSync("ec", { namedCurve: curve });
  const sharedSecret = crypto.diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: receiverPublicKey,
  });

  const key = crypto.createHash("sha256").update(sharedSecret).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  let encrypted = cipher.update(studentId, "utf8", "base64");
  encrypted += cipher.final("base64");
  const tag = cipher.getAuthTag();

  return {
    encryptedText: encrypted,
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    epk: ephemeral.publicKey.export({ type: "spki", format: "pem" }),
    alg: "ECDH-ES+A256GCM",
    curve,
  };
}

function decryptStudentIdWithEcc(encryptedText, ivBase64, tagBase64, epkPem, eccPrivateKeyPem) {
  const receiverPrivateKey = crypto.createPrivateKey(eccPrivateKeyPem);
  const ephemeralPublicKey = crypto.createPublicKey(epkPem);
  if (receiverPrivateKey.asymmetricKeyType !== "ec") {
    throw new Error("ECC 私钥类型必须是 EC");
  }

  const sharedSecret = crypto.diffieHellman({
    privateKey: receiverPrivateKey,
    publicKey: ephemeralPublicKey,
  });

  const key = crypto.createHash("sha256").update(sharedSecret).digest();
  const iv = Buffer.from(ivBase64, "base64");
  const tag = Buffer.from(tagBase64, "base64");

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encryptedText, "base64", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

module.exports = {
  encryptStudentIdWithEcc,
  decryptStudentIdWithEcc,
};
