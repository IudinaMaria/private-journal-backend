const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const Entry = require("../models/entrySchema");
const { encryptText, decryptText } = require("../services/kmsService");

// Cognito
const client = jwksClient({
  jwksUri: "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_vcXKxrYk5/.well-known/jwks.json",
});

const getKey = (header, callback) => {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.publicKey || key.rsaPublicKey);
  });
};

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Нет токена" });

  const token = authHeader.split(" ")[1];
  jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Неверный токен" });
    req.user = decoded;
    next();
  });
}

// 📥 Создать запись
router.post("/", authenticate, async (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: "Пустое содержимое" });

  try {
    const encryptedContent = await encryptText(content);
    const entry = new Entry({
      userId: req.user.sub,
      content: encryptedContent,
      createdAt: new Date(),
    });
    await entry.save();
    res.status(201).json({ message: "Запись сохранена" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка при создании записи" });
  }
});

// 📤 Получить записи (с фильтрацией по дате)
router.get("/", authenticate, async (req, res) => {
  try {
    const { from, to } = req.query;
    const filter = { userId: req.user.sub };

    if (from || to) {
      filter.createdAt = {};
      if (from) filter.createdAt.$gte = new Date(from);
      if (to) filter.createdAt.$lte = new Date(to);
    }

    const entries = await Entry.find(filter).sort({ createdAt: -1 });

    const decryptedEntries = await Promise.all(
      entries.map(async (entry) => ({
        _id: entry._id,
        content: await decryptText(entry.content),
        createdAt: entry.createdAt,
      }))
    );

    res.json(decryptedEntries);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка при получении записей" });
  }
});

// ✏️ Обновить запись
router.put("/:id", authenticate, async (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: "Пустое содержимое" });

  try {
    const entry = await Entry.findOne({ _id: req.params.id, userId: req.user.sub });
    if (!entry) return res.status(404).json({ error: "Запись не найдена" });

    entry.content = await encryptText(content);
    await entry.save();

    res.json({ message: "Запись обновлена" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка при обновлении записи" });
  }
});

// 🗑️ Удалить запись
router.delete("/:id", authenticate, async (req, res) => {
  try {
    const result = await Entry.findOneAndDelete({ _id: req.params.id, userId: req.user.sub });
    if (!result) return res.status(404).json({ error: "Запись не найдена" });

    res.json({ message: "Запись удалена" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка при удалении записи" });
  }
});

module.exports = router;
