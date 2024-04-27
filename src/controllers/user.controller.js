const { validationResult } = require('express-validator');
const { PrismaClient, Prisma } = require('@prisma/client');
const bcrypt = require('bcrypt');
const { userSelectForResponse } = require('../utils/user.select');
const catcher = require('../utils/validation.catcher');
const countries = require('../utils/county.list');
const speakEasy = require('speakeasy');
const qr = require('qrcode');
const { AuthCodeType, RedirectRequestFields, ReqFunction } = require('../utils/enum');
const { updateUser } = require('../services/user.service');
const { sendAuthSms } = require('../services/sms.service');
const { generateRandomCode } = require('../utils/random.code');
const { decode } = require('js-base64');
const { City } = require('country-state-city');

const prisma = new PrismaClient();

const registerGet = async (req, res, next) => {
    return res.render('register', {
        user: {
            username: null,
            email: null,
            password: null,
            confirmPassword: null,
            country: null,
            countryCode: null,
            isoCode2: null,
            address1: null,
            address2: null,
            postalCode: null,
            dob: null,
        },
        countries,
        error: { message: null },
        layout: 'layouts/secondary',
    });
};

const getCities = async (req, res, next) => {
    return res.status(200).json({
        message: `Successfully retrieved!`,
        data: await Promise.all(City.getCitiesOfCountry(req.params.code).map((city) => city.name)),
    });
};

const registerPost = async (req, res, next) => {
    const error = catcher(req);
    if (error)
        return res.render('register', {
            user: req.body,
            countries,
            error: { message: error },
            layout: 'layouts/secondary',
        });
    if (!req.file)
        return res.render('register', {
            user: req.body,
            countries,
            error: { message: 'Required profile image!' },
            layout: 'layouts/secondary',
        });
    try {
        const hashed = await bcrypt.hash(req.body.password, 10);
        const file = req.file;
        const url = file.filename;
        const data = { ...req.body };
        delete data.confirmPassword;
        const user = await prisma.user.create({
            data: {
                ...data,
                // phone: req.body.countryCode + req.body.phone,
                password: hashed,
                // dob: new Date(req.body.dob),
                profileImageUrl: url,
                profileImage: {
                    create: {
                        name: file.filename,
                        mime: file.mimetype,
                        size: file.size,
                    },
                },
            },
            select: userSelectForResponse,
        });
        return res.redirect(
            `${process.env.URL_PRE_FIX}/auth/verify-email?email=${user.email}${
                req.query[RedirectRequestFields.Client_Oauth_Request]
                    ? `&${RedirectRequestFields.Client_Oauth_Request}=${
                          req.query[RedirectRequestFields.Client_Oauth_Request]
                      }`
                    : ''
            }`
        );
    } catch (err) {
        _logger.error('Method:registerPost, Error:', err);
        return res.render('register', {
            user: req.body,
            countries,
            error: { message: err.message },
            layout: 'layouts/secondary',
        });
    }
};

const getUserProfile = async (req, res, next) => {
    try {
        const user = await prisma.user.findFirst({
            where: { email: { equals: req.user.email, mode: 'insensitive' } },
        });
        return res.render('profile', { user, error: { message: null } });
    } catch (err) {
        _logger.error('Method:getUserProfile, Error:', err);
        return res.render('error', {
            error: { status: 500, message: err.message },
            layout: 'layouts/secondary',
        });
    }
};

const getTwoFactor = async (req, res, next) => {
    try {
        const user = await prisma.user.findFirst({
            where: { email: { equals: req.user.email, mode: 'insensitive' } },
        });
        if (!user.isSmsVerified) return res.redirect(`${process.env.URL_PRE_FIX}/users/${req.user.id}/profile`);
        return res.render('twoFactor', { user, error: { message: null } });
    } catch (err) {
        _logger.error('Method:getTwoFactor, Error:', err);
        return res.render('error', {
            error: { status: 500, message: err.message },
            layout: 'layouts/secondary',
        });
    }
};

const getTwoFactorAPP = async (req, res, next) => {
    try {
        const error = catcher(req);
        if (error) return res.status(400).json({ message: error });

        const user = await prisma.user.findFirst({
            where: { email: { equals: req.user.email, mode: 'insensitive' } },
        });
        const secretCode = speakEasy.generateSecret({
            name: `${process.env.BRAND_NAME.toString().replace(/\s/g, '')}-${user.email}`,
        });
        const authCode = await prisma.authCode.findFirst({ where: { userId: user.id, type: AuthCodeType.TWO_FA } });
        if (!authCode)
            await prisma.authCode.create({
                data: {
                    code: secretCode.base32,
                    userId: user.id,
                    type: AuthCodeType.TWO_FA,
                },
            });
        else
            await prisma.authCode.update({
                where: { id: authCode.id },
                data: {
                    code: secretCode.base32,
                    userId: user.id,
                    type: AuthCodeType.TWO_FA,
                },
            });
        await updateUser(user.id, { authType: null });
        return qr.toFileStream(res, secretCode.otpauth_url);
    } catch (err) {
        _logger.error('Method:getTwoFactorAPP, Error:', err);
        return res.status(500).json({ message: err.message });
    }
};

const getTwoFactorSMS = async (req, res, next) => {
    try {
        const error = catcher(req);
        if (error) return res.status(400).json({ message: error });
        let user = await prisma.user.findFirst({ where: { email: { equals: req.user.email, mode: 'insensitive' } } });
        let phone = `${user.countryCode}${req.query.phone.trim()}`;

        if (!user.isSmsVerified && phone !== user.phone) {
            const phoneExisted = await prisma.user.findFirst({
                where: { phone, email: { not: user.email, mode: 'insensitive' } },
            });
            if (phoneExisted)
                return res.status(400).json({ message: 'This phone number is already taken by other account!' });
            // return res.render('error', {
            //     error: { status: 400, message: 'This phone number is already taken by other account!' },
            // });
            user = await prisma.user.update({ where: { id: user.id }, data: { phone: phone } });
        } else phone = user.phone;

        const code = generateRandomCode(6, true);
        const authCode = await prisma.authCode.findFirst({ where: { userId: user.id, type: AuthCodeType.TWO_FA } });
        if (!authCode)
            await prisma.authCode.create({
                data: {
                    code: code,
                    userId: user.id,
                    type: AuthCodeType.TWO_FA,
                },
            });
        else
            await prisma.authCode.update({
                where: { id: authCode.id },
                data: {
                    code: code,
                    userId: user.id,
                    type: AuthCodeType.TWO_FA,
                },
            });
        await updateUser(user.id, { authType: null });
        sendAuthSms(user.phone, code);
        return res.status(200).json({ message: `Auth Code successfully send to your phone ${user.phone}` });
    } catch (err) {
        _logger.error('Method:getTwoFactorSMS, Error:', err);
        return res.status(500).json({ message: err.message });
    }
};

const confirmPassword = async (req, res, next) => {
    try {
        const error = catcher(req);
        if (error) return res.status(400).json({ message: error });

        const password = req.body.password;
        let user = await prisma.user.findFirst({ where: { email: { equals: req.user.email, mode: 'insensitive' } } });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(400).json({ message: 'Incorrect password!' });
        return res.status(200).json({ message: 'Success!' });
    } catch (err) {
        _logger.error('Method:confirmPassword, Error:', err);
        return res.status(500).json({ message: err.message });
    }
};

const checkRedirect = async (req, res, next) => {
    try {
        const error = catcher(req);
        if (error) res.redirect(`${process.env.URL_PRE_FIX}/users/${req.user.id}/profile`);

        const encodedData = req.query[RedirectRequestFields.Client_Oauth_Request];
        const decodedData = (encodedData && JSON.parse(decode(encodedData))) || {};

        if (decodedData.reqFunction && decodedData.callbackUrl) {
            const setCookies = () => {
                res.cookie('reqFunction', decodedData.reqFunction);
                res.cookie('callbackUrl', decodedData.callbackUrl);
            };
            switch (decodedData.reqFunction) {
                case ReqFunction.Verify_SMS:
                    setCookies();
                    return res.redirect(`${process.env.URL_PRE_FIX}/auth/verify-sms`);
                case ReqFunction.Two_FA_On:
                    setCookies();
                    return res.redirect(`${process.env.URL_PRE_FIX}/users/${req.user.id}/two-fa`);
                case ReqFunction.Upgrade:
                    setCookies();
                    return res.redirect(`${process.env.URL_PRE_FIX}/users/${req.user.id}/upgrade`);
                default:
                    return res.redirect(`${decodedData.callbackUrl}?error=${'Invalid request function!'}`);
            }
        }

        return res.render('checkRedirect', { email: req.user.email, client: decodedData, error: { message: null } });
    } catch (err) {
        _logger.error('Method:checkRedirect, Error:', err);
        return res.render('error', {
            error: { status: 500, message: err.message },
            layout: 'layouts/secondary',
        });
    }
};

const logout = async (req, res, next) => {
    try {
        const error = catcher(req);
        if (error) res.redirect(`${process.env.URL_PRE_FIX}/users/${req.user.id}/profile`);

        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');
        const tokens = req.cookies.tokens;
        if (!tokens) tokens = {};
        delete tokens[req.user.email];
        res.cookie('tokens', { ...tokens }, { maxAge: 1000 * 60 * 60 * 24 * 7 });

        return res.redirect(`${process.env.URL_PRE_FIX}/auth/login`);
    } catch (err) {
        _logger.error('Method:checkRedirect, Error:', err);
        return res.redirect(`${process.env.URL_PRE_FIX}/auth/login?error=${err.message}`);
    }
};

const getUpgrade = async (req, res, next) => {
    try {
        const error = catcher(req);
        if (error) return res.redirect(`${process.env.URL_PRE_FIX}/users/${req.user.id}/profile`);

        const user = await prisma.user.findUnique({ where: { id: req.user.id } });
        if (user.isSmsVerified) return res.redirect(`${process.env.URL_PRE_FIX}/users/${req.user.id}/profile`);

        return res.render('upgrade', {
            user: await prisma.user.findUnique({ where: { id: req.user.id }, select: userSelectForResponse }),
            hasPassword: user.password ? true : false,
            countries,
            error: { message: null },
        });
    } catch (err) {
        _logger.error('Method:getUpgrade, Error:', err);
        return res.render('error', {
            error: { status: 500, message: err.message },
            layout: 'layouts/secondary',
        });
    }
};

const postUpgrade = async (req, res, next) => {
    const user = await prisma.user.findUnique({ where: { id: req.user.id }, select: userSelectForResponse });

    const error = catcher(req);
    if (error)
        return res.render('upgrade', {
            user,
            countries,
            hasPassword: user.password ? true : false,
            error: { message: error },
        });

    delete req.body.confirmPassword;
    delete req.body.hasPassword;

    try {
        if (req.body.password) req.body.password = await bcrypt.hash(req.body.password, 10);
        let additional = {};
        if (req.file) {
            const file = req.file;
            const url = file.filename;
            additional['profileImageUrl'] = url;
            additional['profileImage'] = {
                create: {
                    name: file.filename,
                    mime: file.mimetype,
                    size: file.size,
                },
            };
        }

        const user = await prisma.user.update({
            where: { id: req.user.id },
            data: {
                ...req.body,
                phone: req.body.countryCode + req.body.phone,
                dob: new Date(req.body.dob),
                ...additional,
            },
            select: userSelectForResponse,
        });
        return res.redirect(`${process.env.URL_PRE_FIX}/auth/verify-sms`);
    } catch (err) {
        _logger.error('Method:postUpgrade, Error:', err);
        return res.render('upgrade', {
            user,
            countries,
            hasPassword: user.password ? true : false,
            error: { message: err.message },
        });
    }
};

const getUserInfo = async (req, res, next) => {
    const user = await prisma.user.findUnique({ where: { id: req.user.id }, select: userSelectForResponse });
    return res.status(200).json({ message: 'Success!', data: user });
};

module.exports = {
    registerGet,
    getCities,
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
    getUserInfo,
};
