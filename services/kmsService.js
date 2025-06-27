const { KMSClient, EncryptCommand, DecryptCommand } = require('@aws-sdk/client-kms');

const kmsClient = new KMSClient({
  region: process.env.AWS_REGION, // ✅ Обязательно убедись, что переменная задана
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,       // ✅ Задано в .env
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY, // ✅ Задано в .env
  },
});

// 🔐 Шифрование
async function encryptText(plainText) {
  const params = {
    KeyId: process.env.KMS_KEY_ID, // 🔑 Пример: arn:aws:kms:region:account-id:key/key-id
    Plaintext: Buffer.from(plainText, "utf-8"),
  };

  const command = new EncryptCommand(params);
  const response = await kmsClient.send(command);
  return response.CiphertextBlob.toString("base64");
}

// 🔓 Расшифровка
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
