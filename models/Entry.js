const mongoose = require("mongoose");

const entrySchema = new mongoose.Schema(
  {
    title: String,
    content: String,
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Entry", entrySchema);
