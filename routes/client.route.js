const express = require('express');
const { body } = require('express-validator');
const { PrismaClient, Prisma } = require('@prisma/client');
const bcrypt = require('bcrypt');
const uuidV4 = require('uuidv4');
const { generateKeyPairSync } = require('crypto');
const catcher = require('../utils/validation.catcher');
const { Grants } = require('../utils/enum');
const { generateClient, showClients } = require('../controllers/client.controller');
const multer = require('multer');

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
            cb(null, 'goya-accounts-' + file.fieldname + '-' + uniqueSuffix + '.' + ext);
        },
    }),
    limits: { fileSize: 1048576 },
});

router.post(
    '/generate',
    upload.single('logo'),
    [
        body('appName').notEmpty().withMessage('Required appName!'),
        body('appType').notEmpty().withMessage('Required appType!'),
        body('redirectUris').notEmpty().withMessage('Required redirect URIs!'),
        body('scopes').notEmpty().withMessage('Required scopes!'),
    ],
    _jwt,
    generateClient
);

router.get('/', _jwt, showClients);

module.exports = router;
