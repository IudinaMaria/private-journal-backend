require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("./models/User");
const securityRoutes = require("./routes/security");

const app = express();

// ✅ CORS: поддержка двух фронтендов
const allowedOrigins = [
  "https://private-journal-frontend-98czwq4f3.vercel.app",
  "https://private-journal-frontend-i243cl0pk.vercel.app"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
app.options("*", cors());

app.use(express.json());
app.use("/api", securityRoutes);

// ✅ MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ Mongo error", err));

// ✅ JWT секрет
const JWT_SECRET = "super-secret-string";

// ✅ Модель Entry
const EntrySchema = new mongoose.Schema({
  title: String,
  content: String,
  createdAt: { type: Date, default: Date.now },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
});
const Entry = mongoose.model("Entry", EntrySchema);

// ✅ Регистрация
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Поля обязательны" });

  const passwordHash = await bcrypt.hash(password, 10);
  try {
    const user = new User({ email, passwordHash });
    await user.save();
    res.status(201).json({ message: "Пользователь зарегистрирован" });
  } catch (err) {
    res.status(400).json({ error: "Email уже существует" });
  }
});

// ✅ Вход
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
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Нет токена" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    res.status(401).json({ error: "Недействительный токен" });
  }
};

// ✅ CRUD записи
app.get("/api/entries", authMiddleware, async (req, res) => {
  const entries = await Entry.find({ userId: req.userId }).sort({ createdAt: -1 });
  res.json(entries);
});

app.get("/api/entries/:id", authMiddleware, async (req, res) => {
  const entry = await Entry.findOne({ _id: req.params.id, userId: req.userId });
  if (!entry) return res.status(404).json({ error: "Не найдено" });
  res.json(entry);
});

app.post("/api/entries", authMiddleware, async (req, res) => {
  const { title, content } = req.body;
  const entry = new Entry({ title, content, userId: req.userId });
  await entry.save();
  res.status(201).json(entry);
});

app.put("/api/entries/:id", authMiddleware, async (req, res) => {
  const { title, content } = req.body;
  const entry = await Entry.findOne({ _id: req.params.id, userId: req.userId });
  if (!entry) return res.status(404).json({ error: "Не найдено" });

  entry.title = title;
  entry.content = content;
  await entry.save();
  res.json({ message: "Обновлено" });
});

app.delete("/api/entries/:id", authMiddleware, async (req, res) => {
  const entry = await Entry.findOneAndDelete({ _id: req.params.id, userId: req.userId });
  if (!entry) return res.status(404).json({ error: "Не найдено" });
  res.json({ message: "Удалено" });
});

const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`🚀 Listening on port ${PORT}`));
