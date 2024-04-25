const { validationResult } = require('express-validator');

const catcher = (req) => {
    const errors = validationResult(req).formatWith((data) => data.msg);
    return errors ? errors.array().toString() : null;
};

module.exports = catcher;
