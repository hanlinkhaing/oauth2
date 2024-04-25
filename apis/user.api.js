const express = require('express');
const { check } = require('express-validator');
const { register, login, refresh, verifyToken, setUserData, getUserData } = require('../services/user.service');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const router = express.Router();

router.post(
    '/register',
    [
        check('username').notEmpty().withMessage('Required username!'),
        check('email')
            .notEmpty()
            .withMessage('Required email!')
            .isEmail()
            .withMessage('Invalid email!')
            .custom(async (value) => {
                try {
                    const existed = await prisma.user.findFirst({
                        where: { email: { equals: value, mode: 'insensitive' } },
                    });

                    if (existed) throw new Error('Email already exist!');
                    else return value;
                } catch (err) {
                    _logger.error(err.message);
                    throw new Error(`Internal server error while validating email (${err.message})!`);
                }
            }),
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
    ],
    register
);

router.post(
    '/login',
    [
        check('email').notEmpty().withMessage('Required email!'),
        check('password').notEmpty().withMessage('Required password!'),
    ],
    login
);

router.get('/refresh', _refreshAPI, refresh);

router.get('/verify-token', _jwtAPI, verifyToken);

router.post('/user-data', _jwtAPI, setUserData);

router.get('/user-data', _jwtAPI, getUserData);

module.exports = router;
