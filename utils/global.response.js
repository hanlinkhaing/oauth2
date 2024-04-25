global._response = ({
    status, message, data
}, res, next) => {
    if (status >= 400) _logger.error(`${status}-${message}`);
    else _logger.info(`${status}-${message}`);
    res.status(status).json({
        status, message, data
    });
    return next();
}