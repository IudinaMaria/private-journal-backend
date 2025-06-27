const mongoose = require("mongoose");
const { KMSClient, EncryptCommand, DecryptCommand } = require("@aws-sdk/client-kms");

// Инициализация клиента AWS KMS
const kmsClient = new KMSClient({ region: "us-east-1" });

// Функция для шифрования данных с использованием KMS
const encryptData = async (data) => {
  const params = {
    KeyId: "arn:aws:kms:eu-north-1:020510964266:key/0d35e7fa-3f26-4ca1-a312-69c8488b9b68",
    Plaintext: Buffer.from(data),
  };

  try {
    const result = await kmsClient.send(new EncryptCommand(params));
    return result.CiphertextBlob;
  } catch (err) {
    console.error("Ошибка при шифровании:", err);
  }
};

// Функция для расшифровки данных с использованием KMS
const decryptData = async (cipherText) => {
  const params = {
    CiphertextBlob: cipherText,
  };

  try {
    const result = await kmsClient.send(new DecryptCommand(params));
    return result.Plaintext.toString();
  } catch (err) {
    console.error("Ошибка при расшифровке:", err);
  }
};

const UserSchema = new mongoose.Schema({
  cognitoId: { type: String, required: true, unique: true }, // Уникальный идентификатор пользователя в Cognito
  email: { type: String, unique: true, required: true },
  profileData: {
    type: Map,
    of: String,
  }, // Дополнительные данные пользователя
  loginHistory: [
    {
      ip: Buffer, // Зашифрованный IP
      userAgent: Buffer, // Зашифрованный userAgent
      timestamp: { type: Date, default: Date.now },
    },
  ],
});

// Хук для шифрования данных перед сохранением
UserSchema.pre("save", async function (next) {
  if (this.isModified("loginHistory")) {
    // Шифруем каждую запись в истории входов перед сохранением
    for (let i = 0; i < this.loginHistory.length; i++) {
      const login = this.loginHistory[i];
      login.ip = await encryptData(login.ip);
      login.userAgent = await encryptData(login.userAgent);
    }
  }
  next();
});

// Метод для расшифровки истории входов
UserSchema.methods.decryptLoginHistory = async function () {
  const decryptedHistory = [];
  for (let i = 0; i < this.loginHistory.length; i++) {
    const login = this.loginHistory[i];
    const decryptedIp = await decryptData(login.ip);
    const decryptedUserAgent = await decryptData(login.userAgent);
    decryptedHistory.push({
      ip: decryptedIp,
      userAgent: decryptedUserAgent,
      timestamp: login.timestamp,
    });
  }
  return decryptedHistory;
};

module.exports = mongoose.model("User", UserSchema);
