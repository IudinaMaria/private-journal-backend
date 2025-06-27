const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");
const { KMSClient, DecryptCommand } = require('@aws-sdk/client-kms');
const User = require("../models/UserSchema"); // Модель, если необходимо хранить дополнительные данные

// Настройка клиента для получения JWKS от Cognito
const client = jwksClient({
  jwksUri: "https://cognito-idp.eu-north-1.amazonaws.com/eu-north-1_vcXKxrYk5/.well-known/jwks.json", // Укажите свой jwksUri
});

// Инициализация клиента KMS
const kmsClient = new KMSClient({ region: "us-east-1" });

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

      // Расшифровываем историю входов, если она зашифрована
      const decryptedLogins = await Promise.all(
        user.loginHistory.map(async (loginEntry) => {
          const decryptedIp = await decryptData(loginEntry.ip);
          const decryptedUserAgent = await decryptData(loginEntry.userAgent);
          return {
            ip: decryptedIp,
            userAgent: decryptedUserAgent,
            timestamp: loginEntry.timestamp,
          };
        })
      );

      // Возвращаем расшифрованную историю входов
      res.json(decryptedLogins);
    });
  } catch (err) {
    res.status(401).json({ error: "Ошибка при обработке токена" });
  }
});

module.exports = router;
