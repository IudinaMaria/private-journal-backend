require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const { KMSClient, EncryptCommand, DecryptCommand } = require('@aws-sdk/client-kms');
const UserSchema = require("./models/UserSchema");
const Entry = require("./models/entrySchema"); // <-- Импорт модели

// 1. Импортируй middleware для логирования
const { requestLogger, errorLogger } = require('./middleware/loggerMiddleware');

const app = express();

// 2. Настройка CORS и body-parser
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

// 3. Логирование запросов
app.use(requestLogger);

// 4. Основные роуты
app.use('/api/security', require('./routes/security'));

// 5. Логирование ошибок (после роутов!)
app.use(errorLogger);

// Подключение к MongoDB
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ Mongo error", err));

// ...Остальной твой код (authMiddleware, KMS, encrypt/decrypt, роуты для /api/entries и т.д.)

// Запуск сервера
app.get("/", (req, res) => res.send("Backend is running!"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Listening on port ${PORT}`));
