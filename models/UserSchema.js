const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  cognitoId: { type: String, required: true, unique: true }, // Уникальный идентификатор пользователя в Cognito
  email: { type: String, unique: true, required: true },
  profileData: { 
    type: Map, 
    of: String 
  }, // дополнительные данные, связанные с пользователем (например, имя, настройки и т.д.)
  loginHistory: [
    {
      ip: String,
      userAgent: String,
      timestamp: { type: Date, default: Date.now },
    }
  ],
});

module.exports = mongoose.model("User", UserSchema);
