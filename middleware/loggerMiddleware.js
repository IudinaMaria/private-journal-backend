// middleware/loggerMiddleware.js
const logger = require('../logger');

const requestLogger = (req, res, next) => {
  logger.info('Request received', {
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.headers['user-agent'],
    time: new Date().toISOString()
  });
  next();
};

const errorLogger = (err, req, res, next) => {
  logger.error('Error caught in middleware', {
    error: err.message,
    stack: err.stack,
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    time: new Date().toISOString()
  });
  next(err);
};

module.exports = { requestLogger, errorLogger };
