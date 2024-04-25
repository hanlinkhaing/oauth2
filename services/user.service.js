const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();
const jwt = require('jsonwebtoken');
const catcher = require('../utils/validation.catcher');
const bcrypt = require('bcrypt');

const getTimeStampInSecond = () => parseInt(new Date().getTime() / 1000);

const updateUser = async (id, data) => {
    return await prisma.user.update({
        where: { id },
        data: { ...data },
    });
};

const getUserTokens = (req) => {
    const users = [];
    if (req.cookies.tokens) {
        for (const [key, value] of Object.entries(req.cookies.tokens)) {
            const user = jwt.decode(value.accessToken, { complete: true, json: true }).payload.user;
            user['accessToken'] = value.accessToken;
            user['refreshToken'] = value.refreshToken;
            delete user.password;
            users.push(user);
        }
    }
    return users;
};

const register = async (req, res, next) => {
    const error = catcher(req);
    if (error) return res.status(400).json({ timestamp: getTimeStampInSecond(), message: error });

    const { username, email, password } = req.body;

    try {
        let user = await prisma.user.findFirst({ where: { email: { equals: email, mode: 'insensitive' } } });
        if (user) return res.status(400).json({ timestamp: getTimeStampInSecond(), message: 'Email already exist!' });

        const hashed = await bcrypt.hash(password, 10);
        user = await prisma.user.create({
            data: {
                username,
                email,
                password: hashed,
            },
            select: {
                username: true,
                email: true,
            },
        });

        return res
            .status(201)
            .json({ timestamp: getTimeStampInSecond(), message: 'Registration success!', data: user });
    } catch (err) {
        _logger.error('API:register, Error: ', err);
        return res.status(500).json({ timestamp: getTimeStampInSecond(), message: 'Internal Server Error!' });
    }
};

const getAccessToken = (username, email) => {
    return jwt.sign(
        {
            user: {
                username,
                email,
            },
        },
        process.env.JWT_TOKEN_KEY,
        { expiresIn: process.env.JWT_TOKEN_EXPIRATION }
    );
};

const getRefreshToken = (email) => {
    return jwt.sign(
        {
            user: {
                email,
            },
        },
        process.env.JWT_REFRESH_TOKEN_KEY,
        { expiresIn: process.env.JWT_REFRESH_TOKEN_EXPIRATION }
    );
};

const login = async (req, res, next) => {
    const error = catcher(req);
    if (error) return res.status(400).json({ timestamp: getTimeStampInSecond(), message: error });

    const { email, password } = req.body;

    try {
        const user = await prisma.user.findFirst({ where: { email: { equals: email, mode: 'insensitive' } } });
        if (!user) return res.status(401).json({ timestamp: getTimeStampInSecond(), message: 'User not found!' });

        const compared = await bcrypt.compare(password, user.password);
        if (!compared)
            return res.status(401).json({ timestamp: getTimeStampInSecond(), message: 'Incorrect password!' });

        return res.status(200).json({
            timestamp: getTimeStampInSecond(),
            message: 'Login success!',
            data: {
                username: user.username,
                email: user.email,
                accessToken: getAccessToken(user.username, user.email),
                refreshToken: getRefreshToken(user.email),
            },
        });
    } catch (err) {
        _logger.error('API:login, Error: ', err);
        return res.status(500).json({ timestamp: getTimeStampInSecond(), message: 'Internal Server Error!' });
    }
};

const refresh = async (req, res, next) => {
    try {
        const user = await prisma.user.findFirst({ where: { email: { equals: req.user.email, mode: 'insensitive' } } });
        if (!user) return res.status(401).json({ timestamp: getTimeStampInSecond(), message: 'User not found!' });

        return res.status(200).json({
            timestamp: getTimeStampInSecond(),
            message: 'Refresh success!',
            data: {
                username: user.username,
                email: user.email,
                accessToken: getAccessToken(user.username, user.email),
            },
        });
    } catch (err) {
        _logger.error('API:refresh, Error: ', err);
        return res.status(500).json({ timestamp: getTimeStampInSecond(), message: 'Internal Server Error!' });
    }
};

const verifyToken = async (req, res, next) => {
    return res.status(200).json({ timestamp: getTimeStampInSecond(), message: 'Verification success!' });
};

const transformUserData = async (user) => {
    for await (const d of user.UserData) {
        user[d.name] = d.value;
    }
    delete user.UserData;
    return user;
};

const setUserData = async (req, res, next) => {
    try {
        let user = await prisma.user.findFirst({ where: { email: { equals: req.user.email, mode: 'insensitive' } } });
        if (!user) return res.status(404).json({ timestamp: getTimeStampInSecond(), message: 'User not found!' });

        for await (const [key, value] of Object.entries(req.body)) {
            const data = {
                userId: user.id,
                name: key,
                value: value,
            };
            const existed = await prisma.userData.findFirst({ where: { name: { equals: key, mode: 'insensitive' } } });
            if (existed) await prisma.userData.update({ where: { id: existed.id }, data: { value } });
            else await prisma.userData.create({ data });
        }

        user = await prisma.user.findUnique({
            where: { id: user.id },
            select: {
                username: true,
                email: true,
                UserData: true,
            },
        });

        return res.status(200).json({
            timestamp: getTimeStampInSecond(),
            message: 'Update success!',
            data: await transformUserData(user),
        });
    } catch (err) {
        _logger.error('API:setUserData, Error: ', err);
        return res.status(500).json({ timestamp: getTimeStampInSecond(), message: 'Internal Server Error!' });
    }
};

const getUserData = async (req, res, next) => {
    try {
        const user = await prisma.user.findUnique({
            where: { email: req.user.email },
            select: {
                username: true,
                email: true,
                UserData: true,
            },
        });

        if (!user) return res.status(404).json({ timestamp: getTimeStampInSecond(), message: 'User not found!' });

        return res.status(200).json({
            timestamp: getTimeStampInSecond(),
            message: 'Retrieve success!',
            data: await transformUserData(user),
        });
    } catch (err) {
        _logger.error('API:getUserData, Error: ', err);
        return res.status(500).json({ timestamp: getTimeStampInSecond(), message: 'Internal Server Error!' });
    }
};

module.exports = { updateUser, getUserTokens, register, login, refresh, verifyToken, setUserData, getUserData };
