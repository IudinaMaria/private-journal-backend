## 📂 Описание по папкам и файлам
## 🔹 index.js
- Главная точка входа в приложение:
Запускает Express-сервер.
Подключает MongoDB.
Регистрирует роуты (/api/security, /api/entries).
Применяет CORS, JSON, логгирование.

## 🔹 .env
- Файл конфигурации:
Хранит секреты и настройки, такие как:
MONGODB_URI=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=eu-north-1
KMS_KEY_ID=

## 🔹 logger.js
- Конфигурирует логгирование с помощью winston и winston-cloudwatch.
Все логи сохраняются в CloudWatch + консоль.
Используется для аудита, отладки и мониторинга.

## 📁 models/
## 🔸 entrySchema.js
- Содержит схему записей журнала (title, content, userId).
content — шифруется с помощью AWS KMS перед сохранением.
Хранит записи пользователя.

## 🔸 userSchema.js
- Содержит схему пользователя:
cognitoId, email, profileData, loginHistory.
loginHistory хранит зашифрованные IP и user-agent.
В схеме используется метод для расшифровки истории входов.

## 📁 routes/
## 🔸 entries.js
- API-маршруты:
POST /api/entries — создать запись
GET /api/entries — получить (с фильтрацией по дате)
PUT /api/entries/:id — редактировать
DELETE /api/entries/:id — удалить
Работают с KMS-шифрованием через kmsService.

## 🔸 security.js
- Обрабатывает:
Получение расшифрованной истории входов (GET /api/security/logins)
Проверяет токены через Cognito JWKS.

## 📁 services/
## 🔸 kmsService.js
- Централизует логику шифрования/расшифровки с помощью AWS KMS.
Используется во всех местах (записи, пользователи).
Работает с base64 строками и CiphertextBlob.

## 📁 middleware/
## 🔸 loggerMiddleware.js
- Логгирует:
Входящие HTTP-запросы (requestLogger)
Ошибки Express-приложения (errorLogger)
Использует logger.js, чтобы писать в CloudWatch.

## 📄 package.json
- Содержит список зависимостей проекта:
express, mongoose, winston, @aws-sdk/client-kms, winston-cloudwatch, и др.
Можно запускать команды: npm start, npm run dev, npm install.

## 🟩 Что реализовано в backend:
### 🔐 Безопасное хранение данных	
Все записи и история входов шифруются через AWS KMS
### 👤 Cognito авторизация	
JWT проверяется через JWKS (без передачи секретов)
### 🧠 Пользовательские записи	
CRUD API для личного журнала
### 🕵️‍♀️ Журналирование	
Входы и действия логируются в AWS CloudWatch
### 📦 Архитектура	
Чисто разделённые модели, сервисы, роуты, middleware