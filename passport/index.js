const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JWTStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const bcrypt = require('bcrypt');
const { PrismaClient } = require('@prisma/client');
const jwt = require('jsonwebtoken');
const { AuthCodeType } = require('../utils/enum');
const { verifyCode, sendAuthCode } = require('../services/auth.service');
const { getUserTokens } = require('../services/user.service');
const { sendAuthSms } = require('../services/sms.service');
const { AuthType } = require('../utils/enum');

const prisma = new PrismaClient();

passport.use(
    'login',
    new LocalStrategy({ usernameField: 'email', passwordField: 'password' }, async (username, password, done) => {
        try {
            const user = await prisma.user.findFirst({
                where: { email: { equals: username, mode: 'insensitive' } },
            });
            if (!user) return done({ status: 401, message: 'User not found!' }, false);
            if (!user.isEmailVerified) return done({ status: 401, message: 'Email verification needed!' }, false);
            const match = await bcrypt.compare(password, user.password);
            if (!match) return done({ status: 401, message: 'Incorrect password!' }, false);
            delete user.password;
            delete user.createdAt;
            delete user.updatedAt;
            // const authCode = await prisma.authCode.findFirst({ where: { userId: user.id, type: AuthCodeType.TWO_FA } });
            // authCode ||
            if (user.authType) user['isTwoFAOn'] = true;
            return done(null, user);
        } catch (err) {
            _logger.error('Method:loginLocalStrategy, Error:', err);
            return done({ status: 500, message: err.message }, false);
        }
    })
);

passport.use(
    'jwt',
    new JWTStrategy(
        {
            secretOrKey: process.env.JWT_TOKEN_KEY,
            jwtFromRequest: (req) => req.cookies.accessToken,
        },
        async (payload, done) => done(null, payload.user)
    )
);

passport.use(
    'jwtAPI',
    new JWTStrategy(
        {
            secretOrKey: process.env.JWT_TOKEN_KEY,
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        },
        async (payload, done) => done(null, payload.user)
    )
);

passport.use(
    'refresh',
    new JWTStrategy(
        {
            secretOrKey: process.env.JWT_REFRESH_TOKEN_KEY,
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        },
        async (token, done) => done(null, token.user)
    )
);

passport.use(
    'oauth',
    new JWTStrategy(
        {
            secretOrKeyProvider: async (req, rawJwtToken, done) => {
                try {
                    const authHeader = req.headers.authorization;
                    const token = authHeader.split(' ')[1];

                    const user = jwt.decode(token, { complete: true, json: true }).payload?.user;
                    if (!user) return done(new Error('Invalid Token!'), null);

                    const client = await prisma.oAuthClient.findUnique({ where: { clientId: user.clientId } });
                    if (!client) return done(new Error('Client not found!'), null);

                    done(null, client.publicKey);
                } catch (err) {
                    _logger.error('Method:secretOrKeyJWTStrategy, Error:', err);
                    return done({ status: 500, message: err.message }, false);
                }
            },
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        },
        async (token, done) => done(null, token.user)
    )
);

passport.use(
    'oauth_query',
    new JWTStrategy(
        {
            secretOrKeyProvider: async (req, rawJwtToken, done) => {
                try {
                    // const authHeader = req.query.token;
                    const token = req.query.token;
                    console.log('req.query:: ', req.query);
                    const user = jwt.decode(token, { complete: true, json: true }).payload?.user;
                    if (!user) return done(new Error('Invalid Token!'), null);

                    const client = await prisma.oAuthClient.findUnique({ where: { clientId: user.clientId } });
                    if (!client) return done(new Error('Client not found!'), null);

                    done(null, client.publicKey);
                } catch (err) {
                    _logger.error('Method:secretOrKeyJWTStrategy, Error:', err);
                    return done({ status: 500, message: err.message }, false);
                }
            },
            jwtFromRequest: ExtractJwt.fromUrlQueryParameter('token'),
        },
        async (token, done) => done(null, token.user)
    )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

global._login = (req, res, next) => {
    const users = [];
    passport.authenticate('login', async function (err, user, info) {
        try {
            if (err) {
                _logger.error(`${err.status}-${err.message}`);
                return res.render('login', {
                    error: { message: err.message },
                    layout: './layouts/secondary',
                    ...req.body,
                    requiredTFA: false,
                    users,
                });
            }
            if (info)
                return res.render('login', {
                    error: { message: info.message },
                    layout: './layouts/secondary',
                    ...req.body,
                    requiredTFA: false,
                    users,
                });
            if (user['isTwoFAOn']) {
                if (!req.body.code) {
                    const result = await sendAuthCode(user.email);
                    return res.render('login', {
                        requiredTFA: true,
                        error: { message: result instanceof Error ? result.message : result },
                        layout: './layouts/secondary',
                        ...req.body,
                        users,
                    });
                }

                const error = await verifyCode(req.body.code, user.email);
                if (error)
                    return res.render('login', {
                        requiredTFA: true,
                        error: { message: error },
                        layout: './layouts/secondary',
                        ...req.body,
                        users,
                    });
            }

            req['user'] = user;
            next();
        } catch (err) {
            _logger.error('Method:_login, Error:', err);
            return res.render('login', {
                error: { message: err.message },
                layout: './layouts/secondary',
                ...req.body,
                requiredTFA: false,
                users,
            });
        }
    })(req, res, next);
};

global._jwt = (req, res, next) => {
    passport.authenticate('jwt', async function (err, user, info) {
        try {
            if (err) {
                _logger.error(`${err.status}-${err.message}`);
                return res.redirect(`${process.env.URL_PRE_FIX}/auth/login?error=${err.message}`);
            }
            if (info) {
                if (info.message === 'jwt expired') {
                    const reqUser = jwt.decode(req.cookies.accessToken, { complete: true, json: true }).payload.user;
                    try {
                        const refreshResult = jwt.verify(req.cookies.refreshToken, process.env.JWT_REFRESH_TOKEN_KEY, {
                            complete: true,
                        });
                        _logger.info(refreshResult.message);
                    } catch (err) {
                        _logger.error(err);
                        if (err.message === 'jwt expired') {
                            res.clearCookie('accessToken');
                            res.clearCookie('refreshToken');

                            const tokens = req.cookies.tokens;
                            delete tokens[reqUser.email];
                            res.cookie('tokens', { ...tokens }, { maxAge: 1000 * 60 * 60 * 24 * 7 });

                            return res.redirect(
                                `${process.env.URL_PRE_FIX}/auth/login?error=${'Token expired. Please login again!'}`
                            );
                        }
                    }

                    user = await prisma.user.findFirst({
                        where: { email: { equals: reqUser.email, mode: 'insensitive' } },
                    });
                    const accessToken = jwt.sign(
                        {
                            user: {
                                id: user.id,
                                email: user.email,
                                phone: user.phone,
                                profileImageUrl: process.env.IMG_URL_PRE_FIX + user.profileImageUrl,
                                isEmailVerified: user.isEmailVerified,
                                isSmsVerified: user.isSmsVerified,
                            },
                        },
                        process.env.JWT_TOKEN_KEY,
                        { expiresIn: process.env.JWT_TOKEN_EXPIRATION }
                    );
                    let token = req.cookies.tokens[user.email];
                    res.cookie(
                        'tokens',
                        {
                            ...req.cookies.tokens,
                            [user.email]: { accessToken, refreshToken: token.refreshToken },
                        },
                        { maxAge: 1000 * 60 * 60 * 24 * 7 }
                    );
                    res.cookie('accessToken', accessToken, { maxAge: 1000 * 60 * 60 * 24 * 7 });
                    delete user.password;
                    delete user.createdAt;
                    delete user.updatedAt;
                } else return res.redirect(`${process.env.URL_PRE_FIX}/auth/login?error=${info.message}`);
            }
            if (req.originalUrl.includes('users') && user.id != req.params.id)
                return res.redirect(
                    `${process.env.URL_PRE_FIX}/auth/login?error=${'User id and token does not match!'}`
                );
            req['user'] = user;
            next();
        } catch (err) {
            _logger.error('Method:_jwt, Error:', err);
            return res.redirect(`${process.env.URL_PRE_FIX}/auth/login?error=${err.message}`);
        }
    })(req, res, next);
};

global._jwtAPI = (req, res, next) => {
    passport.authenticate('jwtAPI', async function (err, user, info) {
        if (err) {
            _logger.error(`${err.status}-${err.message}`);
            return res.status(401).json({ message: err.message });
        }
        if (info) {
            _logger.error(info.message);
            if (info.message === 'jwt expired') {
                return res.status(401).json({ message: 'Token expired!' });
            } else return res.status(401).json({ message: info.message });
        }
        req['user'] = user;
        next();
    })(req, res, next);
};

global._refreshAPI = (req, res, next) => {
    passport.authenticate('refresh', async function (err, user, info) {
        if (err) {
            _logger.error(`${err.status}-${err.message}`);
            return res.status(401).json({ message: err.message });
        }
        if (info) {
            _logger.error(info.message);
            if (info.message === 'jwt expired') {
                return res.status(401).json({ message: 'Token expired!' });
            } else return res.status(401).json({ message: info.message });
        }
        req['user'] = user;
        next();
    })(req, res, next);
};

global._oauth = (req, res, next) => {
    passport.authenticate('oauth', async function (err, user, info) {
        if (err) return res.status(401).json({ message: err.message });
        if (info) return res.status(401).json({ message: info.message });

        const tokenUser = jwt.decode(req.headers.authorization.split(' ')[1], { complete: true, json: true }).payload
            ?.user;

        const { email, client_id } = req.query;
        // if (tokenUser.email !== email) return res.status(401).json({ message: "Email and Token doesn't not match!" });
        if (tokenUser.clientId !== client_id)
            return res.status(401).json({ message: "Client ID and Token doesn't not match!" });

        req['user'] = user;
        next();
    })(req, res, next);
};

global._oauthReirect = (req, res, next) => {
    passport.authenticate('oauth_query', async function (err, user, info) {
        if (err)
            return res.render('error', {
                error: { status: 401, message: err.message },
                layout: 'layouts/secondary',
            });
        if (info)
            return res.render('error', {
                error: { status: 401, message: info.message },
                layout: 'layouts/secondary',
            });

        const tokenUser = jwt.decode(req.query.token, { complete: true, json: true }).payload?.user;

        const { email, client_id } = req.query;
        if (tokenUser.email !== email)
            return res.render('error', {
                error: { status: 401, message: "Email and Token doesn't not match!" },
                layout: 'layouts/secondary',
            });

        if (tokenUser.clientId !== client_id)
            return res.render('error', {
                error: { status: 401, message: "Client ID and Token doesn't not match!" },
                layout: 'layouts/secondary',
            });

        req['user'] = user;
        next();
    })(req, res, next);
};

global.passport = passport;
