const express = require('express');
const router = express.Router();
const { query, param, check, body } = require('express-validator');
const {
    loginGet,
    loginPost,
    sendVerifyEmail,
    verifyEmail,
    verifyAuthCode,
    sendVerifySMS,
    verifySMS,
    bindVerifySMS,
    bindReqForPass,
    sendReqForPass,
    getResetPassword,
    resetPassword,
    getVerifyEmail,
    socialLoginPost,
} = require('../controllers/auth.controller');
const multer = require('multer');

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

router.get('/login', loginGet);
router.post('/login', _login, loginPost);

router.post(
    '/social-login',
    upload.single('photo'),
    [
        body('email').notEmpty().withMessage('Required email!').isEmail().withMessage('Invalid email!'),
        body('username').notEmpty().withMessage('Required user name!'),
    ],
    socialLoginPost
);

router.get(
    '/verify-email',
    query('email').notEmpty().withMessage('Required email!').isEmail().withMessage('Invalid email!'),
    sendVerifyEmail
);

router.get(
    '/get-verify-email',
    query('email').notEmpty().withMessage('Required email!').isEmail().withMessage('Invalid email!'),
    getVerifyEmail
);

router.get(
    '/verify-email/:verifyCode',
    param('verifyCode')
        .notEmpty()
        .withMessage('Required verify code!')
        .isLength({ min: 40, max: 40 })
        .withMessage('Verification code length must have 40!'),
    query('email').notEmpty().withMessage('Required email!').isEmail().withMessage('Invalid email!'),
    verifyEmail
);

router.get('/verify-sms', _jwt, bindVerifySMS);

router.post(
    '/verify-sms',
    query('email').notEmpty().withMessage('Required email!').isEmail().withMessage('Invalid email!'),
    [
        body('phone').notEmpty().withMessage('Required phone!'),
        body('countryCode').notEmpty().withMessage('Required country code!'),
    ],
    _jwt,
    sendVerifySMS
);

router.get(
    '/verify-sms/:verifyCode',
    param('verifyCode')
        .notEmpty()
        .withMessage('Required verify code!')
        .isLength({ min: 6, max: 6 })
        .withMessage('Verification code length must have 6!'),
    query('email').notEmpty().withMessage('Required email!').isEmail().withMessage('Invalid email!'),
    _jwt,
    verifySMS
);

router.get(
    '/verify-code/:verifyCode',
    param('verifyCode')
        .notEmpty()
        .withMessage('Required verify code!')
        .isLength({ min: 6, max: 6 })
        .withMessage('Verification code length must have 6!'),
    query('email').notEmpty().withMessage('Required email!').isEmail().withMessage('Invalid email!'),
    verifyAuthCode
);

router.get('/request-forgot-pass', bindReqForPass);

router.post(
    '/request-forgot-pass',
    body('email').notEmpty().withMessage('Required email!').isEmail().withMessage('Invalid email!'),
    sendReqForPass
);

router.get(
    '/request-forgot-pass/:forgotCode',
    param('forgotCode')
        .notEmpty()
        .withMessage('Required code!')
        .isLength({ min: 40, max: 40 })
        .withMessage('Code length must have 40!'),
    getResetPassword
);

router.post(
    '/request-forgot-pass/:forgotCode',
    param('forgotCode')
        .notEmpty()
        .withMessage('Required code!')
        .isLength({ min: 40, max: 40 })
        .withMessage('Code length must have 40!'),
    body('password')
        .notEmpty()
        .withMessage('Required password!')
        .isLength({ min: 8 })
        .withMessage('Password length must be at least 8!')
        .custom(async (value) => {
            const regex = '^(?=.*d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z])(?=.*[W]).{8,}$';
            const result = value.match(value);
            if (!result) throw new Error('Need strong password!');
            else return value;
        })
        .withMessage('Password must have at least 1 upper case, 1 lower case, 1 number and 1 special!'),
    resetPassword
);

module.exports = router;
