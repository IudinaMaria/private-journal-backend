const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const Entry = require("../models/entrySchema");
const { encryptText, decryptText } = require("../services/kmsService");

// Cognito JWKS
const client = jwksClient({
  jwksUri: "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_vcXKxrYk5/.well-known/jwks.json",
});

const getKey = (header, callback) => {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    callback(null, key.publicKey || key.rsaPublicKey);
  });
};

// Middleware: JWT авторизация
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

// 📥 POST /api/entries — создать запись
router.post("/", authenticate, async (req, res) => {
  const { content, title } = req.body;
  if (!content || !title) return res.status(400).json({ error: "Пустое содержимое или заголовок" });

  try {
    // Двойное шифрование: клиент → trustCode (AES), сервер → KMS
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
    console.error("Ошибка при создании записи:", err);
    res.status(500).json({ error: "Ошибка при создании записи" });
  }
});

// 📤 GET /api/entries — получить записи
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
        title: entry.title,
        content: await decryptText(entry.content), // KMS → AES
        createdAt: entry.createdAt,
      }))
    );

    res.json(decryptedEntries);
  } catch (err) {
    console.error("Ошибка при получении записей:", err);
    res.status(500).json({ error: "Ошибка при получении записей" });
  }
});

// ✏️ PUT /api/entries/:id — обновить запись
router.put("/:id", authenticate, async (req, res) => {
  const { content, title } = req.body;
  if (!content || !title) return res.status(400).json({ error: "Пустое содержимое или заголовок" });

  try {
    const entry = await Entry.findOne({ _id: req.params.id, userId: req.user.sub });
    if (!entry) return res.status(404).json({ error: "Запись не найдена" });

    entry.content = await encryptText(content);
    entry.title = title;
    await entry.save();

    res.json({ message: "Запись обновлена" });
  } catch (err) {
    console.error("Ошибка при обновлении записи:", err);
    res.status(500).json({ error: "Ошибка при обновлении записи" });
  }
});

// 🗑️ DELETE /api/entries/:id — удалить запись
router.delete("/:id", authenticate, async (req, res) => {
  try {
    const result = await Entry.findOneAndDelete({ _id: req.params.id, userId: req.user.sub });
    if (!result) return res.status(404).json({ error: "Запись не найдена" });

    res.json({ message: "Запись удалена" });
  } catch (err) {
    console.error("Ошибка при удалении записи:", err);
    res.status(500).json({ error: "Ошибка при удалении записи" });
  }
});

module.exports = router;
