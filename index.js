const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("./models/User");
const securityRoutes = require("./routes/security");

const app = express();

// ✅ CORS — важен порядок! Ставим в начало
app.use(cors({
  origin: "https://private-journal-frontend-98czwq4f3.vercel.app",
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

app.use(express.json()); // ✅ ЭТО вместо body-parser
app.use("/api", securityRoutes);

const JWT_SECRET = "super-secret-string";

// ✅ Подключение к MongoDB Atlas
mongoose.connect("mongodb+srv://gretarichterium:069649669w@gretarichter.ywr2un2.mongodb.net/private_journal?retryWrites=true&w=majority&appName=gretarichter")
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB error:", err));

// 📄 Схема записей
const EntrySchema = new mongoose.Schema({
  title: String,
  content: String,
  createdAt: { type: Date, default: Date.now },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
});

const Entry = mongoose.model("Entry", EntrySchema);

// 🔐 Регистрация
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;
  const passwordHash = await bcrypt.hash(password, 10);

  try {
    const user = new User({ email, passwordHash });
    await user.save();
    res.status(201).json({ message: "Пользователь зарегистрирован" });
  } catch {
    res.status(400).json({ error: "Email уже существует" });
  }
});

// 🔓 Вход
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(401).json({ error: "Неверные данные" });

  const isMatch = await bcrypt.compare(password, user.passwordHash);
  if (!isMatch) return res.status(401).json({ error: "Неверные данные" });

  const ip = req.ip || req.headers["x-forwarded-for"];
  const userAgent = req.headers["user-agent"];
  user.loginHistory.push({ ip, userAgent });
  await user.save();

  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "2h" });
  res.json({ token });
});

// ✅ Middleware
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Нет токена" });

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(401).json({ error: "Недействительный токен" });
  }
};

// 📥 Получить все записи
app.get("/api/entries", authMiddleware, async (req, res) => {
  const entries = await Entry.find({ userId: req.userId }).sort({ createdAt: -1 });
  res.json(entries);
});

// 📄 Получить одну запись
app.get("/api/entries/:id", authMiddleware, async (req, res) => {
  const entry = await Entry.findOne({ _id: req.params.id, userId: req.userId });
  if (!entry) return res.status(404).json({ error: "Запись не найдена" });
  res.json(entry);
});

// ➕ Создать запись
app.post("/api/entries", authMiddleware, async (req, res) => {
  const { title, content } = req.body;
  const entry = new Entry({ title, content, userId: req.userId });
  await entry.save();
  res.status(201).json(entry);
});

// ✏️ Обновить запись
app.put("/api/entries/:id", authMiddleware, async (req, res) => {
  const { title, content } = req.body;
  const entry = await Entry.findOne({ _id: req.params.id, userId: req.userId });
  if (!entry) return res.status(404).json({ error: "Запись не найдена" });

  entry.title = title;
  entry.content = content;
  await entry.save();
  res.json({ message: "Запись обновлена" });
});

// ❌ Удалить запись
app.delete("/api/entries/:id", authMiddleware, async (req, res) => {
  const entry = await Entry.findOneAndDelete({ _id: req.params.id, userId: req.userId });
  if (!entry) return res.status(404).json({ error: "Запись не найдена" });
  res.json({ message: "Запись удалена" });
});

// 🚀 Запуск сервера
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
