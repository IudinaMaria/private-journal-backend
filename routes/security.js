const express = require("express");
const router = express.Router();
const User = require("../models/User");

// Авторизованный пользователь получает историю входов
router.get("/security/logins", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Нет токена" });

  try {
    const jwt = require("jsonwebtoken");
    const decoded = jwt.verify(token, "super-secret-string");
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ error: "Пользователь не найден" });

    res.json(user.loginHistory);
  } catch (err) {
    res.status(401).json({ error: "Недействительный токен" });
  }
});

module.exports = router;
