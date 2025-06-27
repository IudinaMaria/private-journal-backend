const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const JWT_SECRET = process.env.JWT_SECRET;

// Получение истории входов авторизованного пользователя
router.get("/security/logins", async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: "Нет токена" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ error: "Пользователь не найден" });
    }

    res.json(user.loginHistory || []);
  } catch (err) {
    res.status(401).json({ error: "Недействительный токен" });
  }
});

module.exports = router;
