const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  passwordHash: String,
  loginHistory: [
  {
    ip: String,
    userAgent: String,
    timestamp: { type: Date, default: Date.now },
  }
],
});

module.exports = mongoose.model("User", UserSchema);
