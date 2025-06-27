const mongoose = require("mongoose");
const { encryptText, decryptText } = require("../services/kmsService");

const UserSchema = new mongoose.Schema({
  cognitoId: { type: String, required: true, unique: true },
  email: { type: String, unique: true, required: true },
  profileData: {
    type: Map,
    of: String,
  },
  loginHistory: [
    {
      ip: Buffer,
      userAgent: Buffer,
      timestamp: { type: Date, default: Date.now },
    },
  ],
});

// 🔐 Хук шифрования истории входов
UserSchema.pre("save", async function (next) {
  if (this.isModified("loginHistory")) {
    for (let login of this.loginHistory) {
      if (typeof login.ip === "string") login.ip = Buffer.from(await encryptText(login.ip));
      if (typeof login.userAgent === "string") login.userAgent = Buffer.from(await encryptText(login.userAgent));
    }
  }
  next();
});

// 🔓 Метод для расшифровки логов
UserSchema.methods.decryptLoginHistory = async function () {
  return await Promise.all(
    this.loginHistory.map(async (login) => ({
      ip: await decryptText(login.ip),
      userAgent: await decryptText(login.userAgent),
      timestamp: login.timestamp,
    }))
  );
};

module.exports = mongoose.model("User", UserSchema);
