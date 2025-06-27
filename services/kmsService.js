// services/kmsService.js
const { KMSClient, EncryptCommand, DecryptCommand } = require('@aws-sdk/client-kms');

const kmsClient = new KMSClient({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

async function encryptText(plainText) {
  const params = {
    KeyId: process.env.KMS_KEY_ID, // это ARN ключа или его ID
    Plaintext: Buffer.from(plainText),
  };

  const command = new EncryptCommand(params);
  const response = await kmsClient.send(command);
  return response.CiphertextBlob.toString("base64");
}

async function decryptText(encryptedText) {
  const params = {
    CiphertextBlob: Buffer.from(encryptedText, "base64"),
  };

  const command = new DecryptCommand(params);
  const response = await kmsClient.send(command);
  return response.Plaintext.toString("utf-8");
}

module.exports = {
  encryptText,
  decryptText,
};
