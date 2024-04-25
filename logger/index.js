const winston = require('winston');
require('winston-daily-rotate-file');

const getFileName = () => {
    const date = new Date();
    const hour = date.getHours();
    const minute = date.getMinutes();
    return `${hour}h-${minute}m`;
};

const logger = winston.createLogger({
    transports: [
        new winston.transports.DailyRotateFile({
            level: 'error',
            dirname: process.env.LOG_DIR,
            filename: `err-%DATE%-${getFileName()}.log`,
            maxSize: '5m',
            zippedArchive: true,
            format: winston.format.combine(
                winston.format.timestamp({ format: 'YYYY-MM-DD hh:mm:ss Z' }),
                winston.format.simple()
            ),
        }),
        new winston.transports.DailyRotateFile({
            dirname: process.env.LOG_DIR,
            filename: `inf-%DATE%-${getFileName()}.log`,
            maxSize: '5m',
            zippedArchive: true,
            format: winston.format.combine(
                winston.format.timestamp({ format: 'YYYY-MM-DD hh:mm:ss Z' }),
                winston.format.simple()
            ),
        }),
        new winston.transports.Console({
            handleExceptions: true,
            format: winston.format.combine(winston.format.colorize(), winston.format.simple()),
        }),
    ],
    exitOnError: false,
});

logger.stream = {
    write: function (message, encoding) {
        logger.info(message);
    },
};

global._logger = logger;
module.exports = logger;
