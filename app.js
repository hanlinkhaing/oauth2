require('dotenv').config();
require('./src/passport');
const express = require('express');
const app = express();
const path = require('path');
const logger = require('./src/logger');
const morgan = require('morgan');
require('./src/utils/global.response');

app.use(require('cors')());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(require('cookie-parser')());
app.use(
    morgan((token, req, res) => `${req.method}-${req.url}-${req.user ? req.user.id : 'noAuthUser'}`, {
        stream: logger.stream,
    })
);

app.use(express.static('public'));
app.use(require('express-ejs-layouts'));
app.set('layout', './layouts/default');
app.set('view engine', 'ejs');
// app.set('views', path.join(__dirname, 'views'));

app.use((err, req, res, next) => {
    err.statusCode = err.statusCode || 500;
    err.status = err.status || 'error';

    return res.status(err.statusCode).render('error', {
        error: { status: err.statusCode, message: err.message },
        layout: 'layouts/secondary',
    });
});

app.get('/', (req, res) => res.redirect(`${process.env.URL_PRE_FIX}/auth/login`));

app.use(`${process.env.URL_PRE_FIX}/auth`, require('./src/routes/auth.route'));
app.use(`${process.env.URL_PRE_FIX}/clients`, require('./src/routes/client.route'));
app.use(`${process.env.URL_PRE_FIX}`, require('./src/routes/oauth.route'));
app.use(`${process.env.URL_PRE_FIX}/users`, require('./src/routes/user.route'));
app.use(`${process.env.URL_PRE_FIX}/user-apis`, require('./src/apis/user.api'));

app.use((req, res) => {
    return res.status(404).render('error', {
        error: { status: 404, message: 'Unknown endpoint!' },
        layout: 'layouts/secondary',
    });
});

app.use((error, request, response, next) => {
    if (error.name === 'CastError') {
        return res.status(400).render('error', {
            error: { status: 400, message: 'malformatted id' },
            layout: 'layouts/secondary',
        });
    } else if (error.name === 'ValidationError') {
        return res.status(400).render('error', {
            error: { status: 400, message: error.message },
            layout: 'layouts/secondary',
        });
    }
    // else if (error.name === 'JsonWebTokenError') {
    //     return response.status(401).json({
    //         error: 'invalid token',
    //     });
    //     return res.status(400).render('error', {
    //         error: { status: 400, message: error.message },
    //         layout: 'layouts/secondary',
    //     });
    // }

    _logger.error(error.message);

    next(error);
});

app.listen(process.env.PORT || 5000, () => {
    console.log('Listening on: ', process.env.PORT || 5000);
});
