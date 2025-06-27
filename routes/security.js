const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const User = require("../models/UserSchema");

// ✅ Импортируем сервис для расшифровки (через KMS)
const { decryptText } = require("../services/kmsService");

// Cognito JWKS client
const client = jwksClient({
  jwksUri: "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_vcXKxrYk5/.well-known/jwks.json",
});

// Получение публичного ключа из Cognito
const getKey = (header, callback) => {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
};

// Получение истории входов
router.get("/logins", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Нет токена" });

  const token = authHeader.split(" ")[1];

  jwt.verify(token, getKey, { algorithms: ['RS256'] }, async (err, decoded) => {
    if (err) return res.status(401).json({ error: "Недействительный токен" });

    try {
      const user = await User.findOne({ cognitoId: decoded.sub });
      if (!user) return res.status(404).json({ error: "Пользователь не найден" });

      const decryptedLogins = await Promise.all(
        user.loginHistory.map(async (entry) => {
          const decryptedIp = await decryptText(entry.ip);
          const decryptedUserAgent = await decryptText(entry.userAgent);
          return {
            ip: decryptedIp,
            userAgent: decryptedUserAgent,
            timestamp: entry.timestamp,
          };
        })
      );

      res.json(decryptedLogins);
    } catch (e) {
      console.error("Ошибка при расшифровке логов:", e);
      res.status(500).json({ error: "Не удалось загрузить логи" });
    }
  });
});

module.exports = router;
