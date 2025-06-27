const express = require("express");
const router = express.Router();
const Entry = require("../models/entrySchema");
const authenticate = require("../middleware/authenticate");
const { encryptText } = require("../services/kmsService");

router.post("/", authenticate, async (req, res) => {
  const { content, title } = req.body;
  if (!content || !title) return res.status(400).json({ error: "Пустое содержимое или заголовок" });

  try {
    console.log(" [POST /entries] Body:", req.body);
    console.log(" [POST /entries] User from token:", req.user);

    const encryptedContent = await encryptText(content);

    const entry = new Entry({
      userId: req.user.sub,
      title,
      content: encryptedContent,
      createdAt: new Date(),
    });

    await entry.save();
    res.status(201).json({ message: "Запись сохранена" });

  } catch (err) {
    console.error("❌ Ошибка при создании записи:", err.stack || err);
    res.status(500).json({ error: "Ошибка при создании записи" });
  }
});

module.exports = router;