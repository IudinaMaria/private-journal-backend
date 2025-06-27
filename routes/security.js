const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const User = require("../models/UserSchema"); // Модель, если необходимо хранить дополнительные данные

// Настройка клиента для получения JWKS от Cognito
const client = jwksClient({
  jwksUri: "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_vcXKxrYk5/.well-known/jwks.json", // Укажите свой jwksUri
});

// Функция для получения публичного ключа из JWKS
const getKey = (header, callback) => {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      return callback(err);
    }
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
};

// Получение истории входов авторизованного пользователя
router.get("/security/logins", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: "Нет токена" });
  }

  const token = authHeader.split(" ")[1];

  try {
    // Проверяем токен с использованием публичного ключа из Cognito
    jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
      if (err) {
        return res.status(401).json({ error: "Недействительный токен" });
      }

      // Получаем пользователя по уникальному идентификатору Cognito (cognitoId)
      const user = await User.findOne({ cognitoId: decoded.sub }); // Используем 'sub' из Cognito в качестве идентификатора пользователя
      if (!user) {
        return res.status(404).json({ error: "Пользователь не найден" });
      }

      // Возвращаем историю входов из MongoDB
      res.json(user.loginHistory || []);
    });
  } catch (err) {
    res.status(401).json({ error: "Ошибка при обработке токена" });
  }
});

module.exports = router;
