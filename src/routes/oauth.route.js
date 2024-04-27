const express = require('express');
const passport = require('passport');
const router = express.Router();
const OAuth2Server = require('express-oauth-server');
const {
    getAuthorize,
    getAuthCode,
    verifyAuthCode,
    clientRequest,
    validateAccessTokenReq,
} = require('../controllers/oauth.controller');
const { query, param, check } = require('express-validator');
const { PrismaClient, Prisma } = require('@prisma/client');

const prisma = new PrismaClient();
const oauth = new OAuth2Server({
    model: require('../../model'),
    accessTokenLifetime: 2 * 60 * 60,
    useErrorHandler: true,
    allowEmptyState: true,
});

router.post(
    '/access_token',
    [
        check('grant_type')
            .notEmpty()
            .withMessage('Required grant type!')
            .isIn(['authorization_code', 'refresh_token'])
            .withMessage('Invalid grant type!'),
        check('client_id')
            .notEmpty()
            .withMessage('ClientId required!')
            .custom(async (value) => {
                const client = await prisma.oAuthClient.findUnique({
                    where: { clientId: value },
                });
                if (!client) throw new Error('Client ID not found!');
                else return value;
            }),
        check('client_secret')
            .notEmpty()
            .withMessage('Client Secret required!')
            .custom(async (value) => {
                const client = await prisma.oAuthClient.findUnique({
                    where: { clientSecret: value },
                });
                if (!client) throw new Error('Client Secret not found!');
                else return value;
            }),
        check('redirect_uri').notEmpty().withMessage('Redirect Uri required!'),
    ],
    validateAccessTokenReq,
    oauth.token({
        allowExtendedTokenAttributes: true,
    })
);

router.get(
    '/authorize',
    [
        query('client_id')
            .notEmpty()
            .withMessage('ClientId require!')
            .custom(async (value) => {
                const client = await prisma.oAuthClient.findUnique({
                    where: { clientId: value },
                });
                if (!client) throw new Error('Client not found!');
                else return value;
            }),
        query('scope')
            .notEmpty()
            .withMessage('Required scope!')
            .isIn(['open_id', 'open_id/contacts'])
            .withMessage('Invalid scope!'),
        query('response_type')
            .notEmpty()
            .withMessage('Required response type!')
            .isIn(['code'])
            .withMessage('Invalid response type!'),
        query('redirect_uri')
            .notEmpty()
            .withMessage('Required redirect uri!')
            .custom(async (value) => {
                const clientURI = await prisma.oAuthClient.findFirst({
                    where: { redirectUris: { contains: value, mode: 'insensitive' } },
                });
                if (!clientURI) throw new Error('Invalid redirect URI!');
                else return value;
            }),
    ],
    getAuthorize
);

router.post(
    '/authorize',
    oauth.authorize({
        authenticateHandler: {
            handle: async (req) => {
                return await prisma.user.findFirst({
                    where: { email: { equals: req.body.email, mode: 'insensitive' } },
                });
            },
        },
    })
);

router.get('/two-fa', _oauth, getAuthCode);

router.get(
    '/two-fa/:verifyCode',
    _oauth,
    param('verifyCode')
        .notEmpty()
        .withMessage('Required verify code!')
        .isLength({ min: 6, max: 6 })
        .withMessage('Verification code length must have 6!'),
    verifyAuthCode
);

router.get('/user', _oauth, async (req, res, next) => {
    try {
        const { email, clientId } = req.user;

        const user = await prisma.user.findFirst({ where: { email: { equals: email, mode: 'insensitive' } } });
        if (!user) return res.status(400).send('User not found!');

        const client = await prisma.oAuthClient.findUnique({
            where: { clientId: clientId },
        });
        if (!client) return res.status(400).send('Client not found!');

        const isScopeExist = await prisma.oAuthAccessToken.findFirst({
            where: { userId: user.id, clientId: client.id },
        });
        if (!isScopeExist) return res.status(400).send('Invalid token');

        const data = {
            name: user.username,
            email: user.email,
            profileImageUrl: process.env.IMG_URL_PRE_FIX + user.profileImageUrl,
        };
        if (client.scopes.includes('open_id/contacts')) {
            data['address1'] = user.address1;
            data['address2'] = user.address2;
            data['country'] = user.country;
            data['phone'] = user.phone;
            data['postalCode'] = user.postalCode;
            data['city'] = user.city;
            data['wallet'] = user.wallet;
            data['dob'] = user.dob;
            data['isSmsVerified'] = user.isSmsVerified;
            data['countryCode'] = user.countryCode;
            data['authType'] = user.authType;
            data['isoCode2'] = user.isoCode2;
        }
        return res.status(200).send(data);
    } catch (err) {
        _logger.error('Method:getOauthUser, Error:', err);
        return res.status(500).json({ message: err.message });
    }
});

router.get(
    '/request',
    [
        query('client_id')
            .notEmpty()
            .withMessage('ClientId require!')
            .custom(async (value) => {
                const client = await prisma.oAuthClient.findUnique({
                    where: { clientId: value },
                });
                if (!client) throw new Error('Client not found!');
                else return value;
            }),
        query('email').notEmpty().withMessage('Required email!').isEmail().withMessage('Invalid email!'),
        query('reqFunction').notEmpty().withMessage('Required function!'),
        query('callbackUrl').notEmpty().withMessage('Required callbackUrl!'),
        query('token').notEmpty().withMessage('Required token!'),
    ],
    _oauthReirect,
    clientRequest
);

module.exports = router;
