const mongoose = require("mongoose");
const { KMSClient, EncryptCommand, DecryptCommand } = require("@aws-sdk/client-kms");

// 1. AWS KMS client и параметры
const kmsClient = new KMSClient({ region: "eu-north-1" }); // должен совпадать с регионом твоего KMS-ключа!
const KEY_ID = "arn:aws:kms:eu-north-1:020510964266:key/0d35e7fa-3f26-4ca1-a312-69c8488b9b68";

// 2. Вспомогательные функции
async function encryptData(plain) {
  const params = {
    KeyId: KEY_ID,
    Plaintext: Buffer.isBuffer(plain) ? plain : Buffer.from(plain, "utf8"),
  };
  const { CiphertextBlob } = await kmsClient.send(new EncryptCommand(params));
  return Buffer.from(CiphertextBlob); // обязательно делай Buffer!
}

async function decryptData(cipher) {
  const params = { CiphertextBlob: Buffer.isBuffer(cipher) ? cipher : Buffer.from(cipher) };
  const { Plaintext } = await kmsClient.send(new DecryptCommand(params));
  return Plaintext.toString("utf8");
}

// 3. Определение схемы
const entrySchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    content: { type: Buffer, required: true }, // encrypted
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  },
  { timestamps: true }
);

// 4. Хук: шифруем content перед сохранением
entrySchema.pre("save", async function (next) {
  if (this.isModified("content") && typeof this.content === "string") {
    try {
      this.content = await encryptData(this.content);
    } catch (err) {
      return next(err);
    }
  }
  next();
});

// 5. Метод для расшифровки
entrySchema.methods.decryptContent = async function () {
  return await decryptData(this.content);
};

module.exports = mongoose.model("Entry", entrySchema);
