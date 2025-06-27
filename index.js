require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const { KMSClient, EncryptCommand, DecryptCommand } = require('@aws-sdk/client-kms');
const UserSchema = require("./models/UserSchema");  // Если нужно использовать модель пользователя
const Entry = require("./models/Entry"); // Модель записи для хранения в MongoDB

const app = express();

// Разрешённые источники (Origins)
const allowedOrigins = [
  'https://d1bdaso729tx0i.cloudfront.net',
  'http://localhost:3000',
  'http://d1bdaso729tx0i.cloudfront.net',
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json());

// Настройка подключения к MongoDB Atlas
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ Mongo error", err));

// Настройка клиента для получения JWKS от Cognito
const client = jwksClient({
  jwksUri: "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_vcXKxrYk5/.well-known/jwks.json",
});

// Функция для извлечения ключа
const getKey = (header, callback) => {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      return callback(err);
    }
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
};

// Middleware для защищённых маршрутов
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Нет токена или неверный формат" });
  }

  const token = authHeader.split(" ")[1];

  // Проверяем токен с использованием публичного ключа из Cognito
  jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Недействительный токен" });
    }
    req.userId = decoded.userId;  // Добавляем ID пользователя из токена в запрос
    next();
  });
};

// Инициализация клиента KMS
const kmsClient = new KMSClient({ region: "us-east-1" });

// Функция для шифрования данных
const encryptData = async (plaintext) => {
  const params = {
    KeyId: "arn:aws:kms:eu-north-1:020510964266:key/0d35e7fa-3f26-4ca1-a312-69c8488b9b68",  // ARN вашего ключа
    Plaintext: new TextEncoder().encode(plaintext),
  };

  try {
    const data = await kmsClient.send(new EncryptCommand(params));
    return data.CiphertextBlob;  // Возвращаем зашифрованные данные
  } catch (err) {
    console.error("Ошибка шифрования:", err);
  }
};

// Функция для расшифровки данных
const decryptData = async (cipherText) => {
  const params = {
    CiphertextBlob: cipherText,
  };

  try {
    const data = await kmsClient.send(new DecryptCommand(params));
    const plaintext = new TextDecoder().decode(data.Plaintext);
    return plaintext;
  } catch (err) {
    console.error("Ошибка расшифровки:", err);
  }
};

// Роуты для работы с записями

// Получить все записи
app.get("/api/entries", authMiddleware, async (req, res) => {
  const entries = await Entry.find({ userId: req.userId }).sort({ createdAt: -1 });
  res.json(entries);
});

// Получить конкретную запись
app.get("/api/entries/:id", authMiddleware, async (req, res) => {
  try {
    const entry = await Entry.findOne({ _id: req.params.id, userId: req.userId });

    if (!entry) {
      return res.status(404).json({ error: 'Запись не найдена' });
    }

    // Расшифровываем содержимое перед отправкой клиенту
    const decryptedContent = await decryptData(entry.content);

    res.json({ ...entry.toObject(), content: decryptedContent });
  } catch (err) {
    res.status(500).json({ error: 'Ошибка при загрузке записи' });
  }
});

// Создать запись
app.post("/api/entries", authMiddleware, async (req, res) => {
  const { title, content } = req.body;

  try {
    // Шифруем содержимое перед сохранением
    const encryptedContent = await encryptData(content);

    // Сохраняем запись с зашифрованным содержимым в базу данных
    const entry = new Entry({ title, content: encryptedContent, userId: req.userId });
    await entry.save();
    res.status(201).json(entry);
  } catch (err) {
    res.status(500).json({ error: 'Ошибка при создании записи' });
  }
});

// Обновить запись
app.put("/api/entries/:id", authMiddleware, async (req, res) => {
  const { title, content } = req.body;
  const entry = await Entry.findOne({ _id: req.params.id, userId: req.userId });
  if (!entry) return res.status(404).json({ error: "Не найдено" });

  try {
    // Шифруем новое содержимое перед обновлением
    const encryptedContent = await encryptData(content);

    entry.title = title;
    entry.content = encryptedContent;
    await entry.save();
    res.json({ message: "Обновлено" });
  } catch (err) {
    res.status(500).json({ error: 'Ошибка при обновлении записи' });
  }
});

// Удалить запись
app.delete("/api/entries/:id", authMiddleware, async (req, res) => {
  const entry = await Entry.findOneAndDelete({ _id: req.params.id, userId: req.userId });
  if (!entry) return res.status(404).json({ error: "Не найдено" });
  res.json({ message: "Удалено" });
});

// Запуск сервера
app.get("/", (req, res) => res.send("Backend is running!"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Listening on port ${PORT}`));

