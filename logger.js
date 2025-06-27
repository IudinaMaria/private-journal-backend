const winston = require('winston');
require('winston-cloudwatch');

const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.CloudWatch({
      logGroupName: '/aws/elasticbeanstalk/Private-journal-backend-env/environment-health.log', // имя твоей группы
      logStreamName: 'app-stream', // любое имя, например, имя среды или инстанса
      awsRegion: 'eu-north-1',    // твой регион
      jsonMessage: true
    })
  ]
});

module.exports = logger;
