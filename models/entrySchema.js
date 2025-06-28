const mongoose = require("mongoose");

const entrySchema = new mongoose.Schema(
  {
    userId: { type: String, required: true }, // Cognito user sub
    content: { type: String, required: true }, // base64 string from KMS
    title: { type: String, required: true },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Entry", entrySchema);