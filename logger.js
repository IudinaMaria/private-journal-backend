const winston = require('winston');
require('winston-cloudwatch');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.Console(),
    new winston.transports.CloudWatch({
      logGroupName: '/aws/elasticbeanstalk/Private-journal-backend-env/environment-health.log',
      logStreamName: 'app-stream',
      awsRegion: process.env.AWS_REGION,
      awsAccessKeyId: process.env.AWS_ACCESS_KEY_ID,
      awsSecretKey: process.env.AWS_SECRET_ACCESS_KEY,
      jsonMessage: true
    })
  ],
});

logger.on('error', (err) => {
  console.error('Logger error:', err);
});

module.exports = logger;
