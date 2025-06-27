const mongoose = require("mongoose");
const { KMSClient, EncryptCommand, DecryptCommand } = require("@aws-sdk/client-kms");

// Инициализация клиента AWS KMS
const kmsClient = new KMSClient({ region: "us-east-1" });

// Функция для шифрования данных с использованием KMS
const encryptData = async (data) => {
  const params = {
      KeyId: "arn:aws:kms:eu-north-1:102051096426:key/0d35e7fa-3f26-4ca1-a312-69c8488b9b68",
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

// Определение схемы записи
const entrySchema = new mongoose.Schema(
  {
    title: String,
    content: Buffer, // Храним контент как зашифрованные данные (Buffer)
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true }
);

// Хук для шифрования контента перед сохранением
entrySchema.pre("save", async function (next) {
  if (this.isModified("content")) {
    try {
      const encryptedContent = await encryptData(this.content); // Шифруем контент
      this.content = encryptedContent;
    } catch (err) {
      next(err); // Обработка ошибки шифрования
    }
  }
  next();
});

// Метод для расшифровки контента
entrySchema.methods.decryptContent = async function () {
  try {
    const decryptedContent = await decryptData(this.content); // Расшифровываем контент
    return decryptedContent;
  } catch (err) {
    throw new Error("Ошибка при расшифровке контента");
  }
};

module.exports = mongoose.model("Entry", entrySchema);
