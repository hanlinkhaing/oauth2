const express = require('express');
const {
    registerGet,
    registerPost,
    getUserProfile,
    getTwoFactor,
    getTwoFactorAPP,
    getTwoFactorSMS,
    confirmPassword,
    checkRedirect,
    logout,
    getUpgrade,
    postUpgrade,
    getCities,
    getUserInfo,
} = require('../controllers/user.controller');
const { PrismaClient, Prisma } = require('@prisma/client');
const { check, param, query, body } = require('express-validator');
const multer = require('multer');
const { RedirectRequestFields } = require('../utils/enum');

const prisma = new PrismaClient();
const router = express.Router();

const upload = multer({
    storage: multer.diskStorage({
        destination: function (req, file, cb) {
            cb(null, process.env.UPLOAD_URL);
        },
        filename: function (req, file, cb) {
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
            const ext = file.originalname.split('.')[file.originalname.split('.').length - 1];
            cb(null, 'smiles-accounts-' + file.fieldname + '-' + uniqueSuffix + '.' + ext);
        },
    }),
    limits: { fileSize: (+process.env.FILE_SIZE_IN_MB || 5) * 1024 * 1024 },
});

router.post(
    '/register',
    upload.single('photo'),
    [
        check('username').notEmpty().withMessage('Required username!'),
        check('email')
            .notEmpty()
            .withMessage('Required email!')
            .isEmail()
            .withMessage('Invalid email!')
            .custom(async (value) => {
                const existed = await prisma.user.findFirst({
                    where: { email: { equals: value, mode: 'insensitive' } },
                });
                console.log('existed: ', existed);

                if (existed) throw new Error('Email already exist!');
                else return value;
            })
            .withMessage('Email already exist!'),
        check('password')
            .notEmpty()
            .withMessage('Required password!')
            .isLength({ min: 8 })
            .withMessage('Password length must be at least 8!')
            .custom(async (value) => {
                const regex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9])(?!.*\s).{8,}$/;
                const result = value.match(regex);
                if (!result) throw new Error('Need strong password!');
                else return value;
            })
            .withMessage('Password must have at least 1 upper case, 1 lower case, 1 number and 1 special!'),
        check('confirmPassword')
            .custom(async (value, meta) => {
                if (value !== meta.req.body.password) throw new Error('Password not same.');
                else return value;
            })
            .withMessage('Password and Confirm Password must be same!'),
    ],
    registerPost
);

router.get('/register', registerGet);

router.get('/cities/:code', getCities);

router.get(
    '/:id/profile',
    param('id')
        .notEmpty()
        .withMessage('Required user id!')
        .custom(async (value) => {
            const existed = await prisma.user.findUnique({
                where: { id: +value },
            });
            if (!existed) throw new Error('User id not found!');
            else return value;
        }),
    _jwt,
    getUserProfile
);

router.get(
    '/:id/two-fa',
    param('id')
        .notEmpty()
        .withMessage('Required user id!')
        .custom(async (value) => {
            const existed = await prisma.user.findUnique({
                where: { id: +value },
            });
            if (!existed) throw new Error('User id not found!');
            else return value;
        }),
    _jwt,
    getTwoFactor
);

router.get(
    '/:id/two-fa/app',
    param('id')
        .notEmpty()
        .withMessage('Required user id!')
        .custom(async (value) => {
            const existed = await prisma.user.findUnique({
                where: { id: +value },
            });
            if (!existed) throw new Error('User id not found!');
            else return value;
        }),
    _jwt,
    getTwoFactorAPP
);

router.get(
    '/:id/two-fa/sms',
    param('id')
        .notEmpty()
        .withMessage('Required user id!')
        .custom(async (value) => {
            const existed = await prisma.user.findUnique({
                where: { id: +value },
            });
            if (!existed) throw new Error('User id not found!');
            else return value;
        }),
    query('phone').notEmpty().withMessage('Required phone number!'),
    _jwt,
    getTwoFactorSMS
);

router.post(
    '/:id/confirm-pass',
    [
        param('id')
            .notEmpty()
            .withMessage('Required user id!')
            .custom(async (value) => {
                const existed = await prisma.user.findUnique({
                    where: { id: +value },
                });
                if (!existed) throw new Error('User id not found!');
                else return value;
            }),
    ],
    _jwt,
    confirmPassword
);

router.get(
    '/:id/redirect',
    param('id')
        .notEmpty()
        .withMessage('Required user id!')
        .custom(async (value) => {
            const existed = await prisma.user.findUnique({
                where: { id: +value },
            });
            if (!existed) throw new Error('User id not found!');
            else return value;
        }),
    query(RedirectRequestFields.Client_Oauth_Request).notEmpty().withMessage('Required client oauth request!'),
    _jwt,
    checkRedirect
);

router.get('/:id/logout', _jwt, logout);

router.get(
    '/:id/upgrade',
    param('id')
        .notEmpty()
        .withMessage('Required user id!')
        .custom(async (value) => {
            const existed = await prisma.user.findUnique({
                where: { id: +value },
            });
            if (!existed) throw new Error('User id not found!');
            else return value;
        }),
    _jwt,
    getUpgrade
);

router.post(
    '/:id/upgrade',
    upload.single('photo'),
    [
        check('phone')
            .notEmpty()
            .withMessage('Required phone!')
            .custom(async (value, { req, location, path }) => {
                const existed = await prisma.user.findFirst({
                    where: { phone: `${req.body.countryCode}${value}`, id: { not: +req.params.id } },
                });
                if (value && existed) throw new Error('Phone already exist!');
                else return value;
            }),
        check('dob').notEmpty().withMessage('Required date of birth!'),
        check('countryCode').notEmpty().withMessage('Required country code!'),
        check('city').notEmpty().withMessage('Required city!'),
        check('country').notEmpty().withMessage('Required country!'),
        check('address1').notEmpty().withMessage('Required at least one address!'),
        check('postalCode').notEmpty().withMessage('Required postal code!'),
        check('password')
            .if(check('hasPassword').equals('false'))
            .notEmpty()
            .withMessage('Required password!')
            .isLength({ min: 8 })
            .withMessage('Password length must be at least 8!')
            .custom(async (value, meta) => {
                const regex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9])(?!.*\s).{8,}$/;
                const result = value.match(regex);
                if (!result) throw new Error('Need strong password!');
                else return value;
            })
            .withMessage('Password must have at least 1 upper case, 1 lower case, 1 number and 1 special!'),
        check('confirmPassword')
            .if(check('hasPassword').equals('false'))
            .custom(async (value, meta) => {
                if (value !== meta.req.body.password) throw new Error('Password not same.');
                else return value;
            })
            .withMessage('Password and Confirm Password must be same!'),
    ],
    _jwt,
    postUpgrade
);

router.get('/:id', _jwt, getUserInfo);

module.exports = router;
