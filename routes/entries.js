const express = require("express");
const router = express.Router();
const Entry = require("../models/entrySchema");
const authenticate = require("../middleware/authenticate"); // ✅ твой middleware
const { encryptText, decryptText } = require("../services/kmsService"); // если ты используешь KMS

// 📥 POST /api/entries — создать запись
router.post("/", authenticate, async (req, res) => {
  try {
    const { title, content } = req.body;
    const userId = req.user.sub; // ✅ взяли userId из токена Cognito

    if (!title || !content) {
      return res.status(400).json({ message: "Missing fields" });
    }

    // если ты шифруешь на сервере — зашифруй
    const encryptedContent = await encryptText(content);

    const newEntry = new Entry({
      userId,
      title,
      content: encryptedContent,
    });

    await newEntry.save();

    res.status(201).json({ message: "Запись сохранена" });
  } catch (err) {
    console.error("❌ Error saving entry:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

module.exports = router;
