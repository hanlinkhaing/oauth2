const { PrismaClient } = require('@prisma/client');
const express = require('express');
const router = express.Router();
const { query } = require('express-validator');
const { generateRandomCode } = require('../utils/random.code');
const { AuthCodeType, AuthType, RedirectRequestFields, ReqFunction, RegisterType } = require('../utils/enum');
const mailer = require('../mailer');
const catcher = require('../utils/validation.catcher');
const speakEasy = require('speakeasy');
const { updateUser, getUserTokens } = require('../services/user.service');
const { verifyCode } = require('../services/auth.service');
const { sendAuthSms } = require('../services/sms.service');
const { encode } = require('js-base64');
const bcrypt = require('bcrypt');

const jwt = require('jsonwebtoken');
const prisma = new PrismaClient();

const loginGet = (req, res, next) => {
    try {
        const users = getUserTokens(req);
        return res.render('login', {
            users,
            error: { message: req.query.error ?? null },
            layout: './layouts/secondary',
            email: '',
            password: '',
            requiredTFA: false,
        });
    } catch (err) {
        _logger.error('Method:loginGet, Error:', err);
        return res.render('login', {
            users: [],
            error: { message: req.query.error ?? null },
            layout: './layouts/secondary',
            email: '',
            password: '',
            requiredTFA: false,
        });
    }
};

const loginPost = (req, res, next) => {
    const user = req.user;
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
    const refreshToken = jwt.sign(
        {
            user: {
                id: user.id,
                email: user.email,
            },
        },
        process.env.JWT_REFRESH_TOKEN_KEY,
        { expiresIn: process.env.JWT_REFRESH_TOKEN_EXPIRATION }
    );
    let tokens = req.cookies.tokens;
    if (!tokens) tokens = {};
    res.cookie(
        'tokens',
        { ...tokens, [user.email]: { accessToken, refreshToken } },
        { maxAge: 1000 * 60 * 60 * 24 * 7 }
    );
    res.cookie('accessToken', accessToken, { maxAge: 1000 * 60 * 60 * 24 * 7 });
    res.cookie('refreshToken', refreshToken, { maxAge: 1000 * 60 * 60 * 24 * 7 });

    const query = req.query[RedirectRequestFields.Client_Oauth_Request]
        ? `?${RedirectRequestFields.Client_Oauth_Request}=${req.query[RedirectRequestFields.Client_Oauth_Request]}`
        : '';

    return res.redirect(`${process.env.URL_PRE_FIX}/users/${user.id}/redirect${query}`);
};

const socialLoginPost = async (req, res, next) => {
    const error = catcher(req);
    if (error) return res.status(400).json({ message: error });

    const { email, username } = req.body;
    const url = req.file.filename;
    let user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
        user = await prisma.user.create({
            data: {
                email,
                username: username,
                profileImageUrl: url,
                isEmailVerified: true,
                registerType: RegisterType.Social,
            },
        });
    } else if (!user.profileImageUrl) {
        user = await prisma.user.update({ where: { email }, data: { profileImageUrl: url, isEmailVerified: true } });
    } else {
        user = await prisma.user.update({ where: { email }, data: { isEmailVerified: true } });
    }
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
    const refreshToken = jwt.sign(
        {
            user: {
                id: user.id,
                email: user.email,
            },
        },
        process.env.JWT_REFRESH_TOKEN_KEY,
        { expiresIn: process.env.JWT_REFRESH_TOKEN_EXPIRATION }
    );
    let tokens = req.cookies.tokens;
    if (!tokens) tokens = {};
    res.cookie(
        'tokens',
        { ...tokens, [user.email]: { accessToken, refreshToken } },
        { maxAge: 1000 * 60 * 60 * 24 * 7 }
    );
    res.cookie('accessToken', accessToken, { maxAge: 1000 * 60 * 60 * 24 * 7 });
    res.cookie('refreshToken', refreshToken, { maxAge: 1000 * 60 * 60 * 24 * 7 });

    delete user.password;
    delete user.createdAt;
    delete user.updatedAt;

    return res.status(200).json({ message: `Login success!`, data: user });
};

const sendVerifyEmail = async (req, res, next) => {
    try {
        const error = catcher(req);
        if (error) return res.render('error', { error: { status: 400, message: error }, layout: 'layouts/secondary' });
        const user = await prisma.user.findFirst({
            where: { email: { equals: req.query.email, mode: 'insensitive' } },
        });
        if (!user)
            return res.render('error', {
                error: { status: 400, message: 'User not found!' },
                layout: 'layouts/secondary',
            });
        if (user.isEmailVerified)
            return res.render('error', {
                error: { status: 400, message: 'Email already verified!' },
                layout: 'layouts/secondary',
            });
        await prisma.authCode.deleteMany({ where: { type: AuthCodeType.EMAIL_VERIFY, userId: user.id } });
        const authCode = await prisma.authCode.create({
            data: {
                code: generateRandomCode(40),
                type: AuthCodeType.EMAIL_VERIFY,
                expDate: new Date(new Date().getTime() + 5 * 60000),
                userId: user.id,
            },
        });
        // await mailer.sendMail({
        //     from: process.env.MAIL_FROM,
        //     to: user.email,
        //     subject: 'Smiles - Email Verification',
        //     html: `<p>
        // Please click this
        // <a
        // href="${process.env.SERVER_DOMAIN}${process.env.URL_PRE_FIX}/auth/verify-email/${authCode.code}?email=${
        //         user.email
        //     }${
        //         req.query[RedirectRequestFields.Client_Oauth_Request]
        //             ? `&${RedirectRequestFields.Client_Oauth_Request}=${
        //                   req.query[RedirectRequestFields.Client_Oauth_Request]
        //               }`
        //             : ''
        //     }">link</a> to verify your account.</p>`,
        // });
        return res.render('emailVerify', { error: { message: null }, layout: 'layouts/secondary' });
    } catch (err) {
        _logger.error('Method:sendVerifyEmail, Error:', err);
        return res.render('error', {
            error: { status: 500, message: err.message },
            layout: 'layouts/secondary',
        });
    }
};

const getVerifyEmail = async (req, res, next) => {
    try {
        const error = catcher(req);
        if (error) return res.status(400).json({ message: error });
        const user = await prisma.user.findFirst({
            where: { email: { equals: req.query.email, mode: 'insensitive' } },
        });
        if (!user) return res.status(400).json({ message: 'User not found!' });
        if (user.isEmailVerified) return res.status(400).json({ message: 'Email already verified!' });

        await prisma.authCode.deleteMany({ where: { type: AuthCodeType.EMAIL_VERIFY, userId: user.id } });
        const authCode = await prisma.authCode.create({
            data: {
                code: generateRandomCode(40),
                type: AuthCodeType.EMAIL_VERIFY,
                expDate: new Date(new Date().getTime() + 5 * 60000),
                userId: user.id,
            },
        });
        // await mailer.sendMail({
        //     from: process.env.MAIL_FROM,
        //     to: user.email,
        //     subject: 'Smiles - Email Verification',
        //     html: `<p>
        // Please click this
        // <a
        // href="${process.env.SERVER_DOMAIN}${process.env.URL_PRE_FIX}/auth/verify-email/${authCode.code}?email=${
        //         user.email
        //     }${
        //         req.query[RedirectRequestFields.Client_Oauth_Request]
        //             ? `&${RedirectRequestFields.Client_Oauth_Request}=${
        //                   req.query[RedirectRequestFields.Client_Oauth_Request]
        //               }`
        //             : ''
        //     }">link</a> to verify your account.</p>`,
        // });
        return res.status(200).json({ message: 'Successfully send!' });
    } catch (err) {
        _logger.error('Method:getVerifyEmail, Error:', err);
        return res.status(500).json({ message: err.message });
    }
};

const verifyEmail = async (req, res, next) => {
    try {
        const error = catcher(req);
        if (error) return res.render('error', { error: { status: 400, message: error }, layout: 'layouts/secondary' });
        const code = req.params['verifyCode'];
        const user = await prisma.user.findFirst({
            where: { email: { equals: req.query.email, mode: 'insensitive' } },
        });
        if (!user)
            return res.render('error', {
                error: { status: 400, message: 'User not found!' },
                layout: 'layouts/secondary',
            });
        const authCode = await prisma.authCode.findFirst({
            where: {
                code: { equals: code },
                userId: user.id,
                type: AuthCodeType.EMAIL_VERIFY,
            },
        });
        if (!authCode)
            return res.render('error', {
                error: { status: 400, message: 'Invalid verification code!' },
                layout: 'layouts/secondary',
            });

        await updateUser(user.id, { isEmailVerified: true });
        await prisma.authCode.delete({
            where: { id: authCode.id },
        });

        const query = req.query[RedirectRequestFields.Client_Oauth_Request]
            ? `${RedirectRequestFields.Client_Oauth_Request}=${req.query[RedirectRequestFields.Client_Oauth_Request]}`
            : '';
        return res.redirect(`${process.env.URL_PRE_FIX}/auth/login?${query}`);
    } catch (err) {
        _logger.error('Method:verifyEmail, Error:', err);
        return res.render('error', {
            error: { status: 500, message: err.message },
            layout: 'layouts/secondary',
        });
    }
};

const bindVerifySMS = async (req, res, next) => {
    try {
        const user = await prisma.user.findFirst({
            where: { email: { equals: req.user.email, mode: 'insensitive' } },
        });
        if (!user.phone) return res.redirect(`${process.env.URL_PRE_FIX}/users/${user.id}/upgrade`);
        return res.render('smsVerify', { user, error: { message: null } });
    } catch (err) {
        _logger.error('Method:bindVerifySMS, Error:', err);
        return res.render('error', {
            error: { status: 500, message: err.message },
            layout: 'layouts/secondary',
        });
    }
};

const sendVerifySMS = async (req, res, next) => {
    try {
        const error = catcher(req);
        if (error) return res.status(400).json({ message: error });

        let { countryCode, phone } = req.body;
        phone = `+${countryCode.trim()}${phone.trim()}`;

        let user = await prisma.user.findFirst({ where: { email: { equals: req.query.email, mode: 'insensitive' } } });
        if (!user) return res.status(400).json({ message: 'User not found!' });
        if (user.isSmsVerified) return res.status(400).json({ message: 'SMS already verified!' });

        if (phone !== user.phone) {
            const phoneExisted = await prisma.user.findFirst({
                where: { phone, email: { not: user.email, mode: 'insensitive' } },
            });
            if (phoneExisted)
                return res.status(400).json({ message: 'This phone number is already taken by other account!' });
            user = await prisma.user.update({
                where: { id: user.id },
                data: { phone: phone, countryCode: `+${countryCode.trim()}` },
            });
        }

        await prisma.authCode.deleteMany({ where: { type: AuthCodeType.SMS_VERIFY, userId: user.id } });
        const authCode = await prisma.authCode.create({
            data: {
                code: generateRandomCode(6, true),
                type: AuthCodeType.SMS_VERIFY,
                expDate: new Date(new Date().getTime() + 5 * 60000),
                userId: user.id,
            },
        });
        sendAuthSms(user.phone, authCode.code);

        return res.status(200).json({ message: `Auth Code successfully send to your phone ${user.phone}` });
    } catch (err) {
        _logger.error('Method:sendVerifySms, Error:', err);
        return res.status(500).json({ message: err.message });
    }
};

const verifySMS = async (req, res, next) => {
    try {
        const error = catcher(req);
        if (error) return res.status(400).json({ message: error });

        const code = req.params['verifyCode'];

        const user = await prisma.user.findFirst({
            where: { email: { equals: req.query.email, mode: 'insensitive' } },
        });
        if (!user) return res.status(400).json({ message: 'User not found!' });

        const authCode = await prisma.authCode.findFirst({
            where: {
                code: { equals: code },
                userId: user.id,
                type: AuthCodeType.SMS_VERIFY,
            },
        });
        if (!authCode) return res.status(400).json({ message: 'Invalid verification code!' });

        await updateUser(user.id, { isSmsVerified: true });
        await prisma.authCode.delete({
            where: { id: authCode.id },
        });

        if (
            (req.cookies.reqFunction === ReqFunction.Verify_SMS || req.cookies.reqFunction === ReqFunction.Upgrade) &&
            req.cookies.callbackUrl
        ) {
            const callbackUrl = req.cookies.callbackUrl;
            res.clearCookie('reqFunction');
            res.clearCookie('callbackUrl');
            return res.status(200).json({ url: callbackUrl });
        }

        return res.status(200).json({ url: `${process.env.URL_PRE_FIX}/users/${user.id}/profile` });
    } catch (err) {
        _logger.error('Method:verifySms, Error:', err);
        return res.status(500).json({ message: err.message });
    }
};

const verifyAuthCode = async (req, res, next) => {
    try {
        const error = catcher(req);
        if (error) return res.status(400).json({ message: error });

        const user = await prisma.user.findFirst({
            where: { email: { equals: req.query.email, mode: 'insensitive' } },
        });

        const result = await verifyCode(req.params['verifyCode'], req.query.email);
        if (result) return res.status(400).json({ message: result });

        if (req.cookies.reqFunction === ReqFunction.Two_FA_On && req.cookies.callbackUrl) {
            const callbackUrl = req.cookies.callbackUrl;
            res.clearCookie('reqFunction');
            res.clearCookie('callbackUrl');
            return res.status(200).json({ url: callbackUrl });
        }

        return res.status(200).json({ url: `${process.env.URL_PRE_FIX}/users/${user.id}/two-fa` });
    } catch (err) {
        _logger.error('Method:verifyAuthCode, Error:', err);
        return res.status(500).json({ message: err.message });
    }
};

const bindReqForPass = async (req, res, next) => {
    return res.render('requestForgotPass', {
        error: { message: null },
        layout: 'layouts/secondary',
    });
};

const sendReqForPass = async (req, res, next) => {
    try {
        const error = catcher(req);
        if (error)
            return res.render('requestForgotPass', {
                error: { message: error },
                layout: 'layouts/secondary',
            });

        const user = await prisma.user.findFirst({
            where: { email: { equals: req.body.email, mode: 'insensitive' } },
        });
        if (!user)
            return res.render('requestForgotPass', {
                error: { message: 'User not found!' },
                layout: 'layouts/secondary',
            });

        const forgotCode = generateRandomCode(40);
        const forgotCodeExpAt = new Date().setMinutes(new Date().getMinutes() + 15).toPrecision();
        await prisma.user.update({ where: { id: user.id }, data: { password: null, forgotCode, forgotCodeExpAt } });

        // await mailer.sendMail({
        //     from: process.env.MAIL_FROM,
        //     to: user.email,
        //     subject: 'Smiles - Reset Password',
        //     html: `<p>
        // Please click this
        // <a
        // href="${process.env.SERVER_DOMAIN}${process.env.URL_PRE_FIX}/auth/request-forgot-pass/${forgotCode}${
        //         req.query[RedirectRequestFields.Client_Oauth_Request]
        //             ? `?${RedirectRequestFields.Client_Oauth_Request}=${
        //                   req.query[RedirectRequestFields.Client_Oauth_Request]
        //               }`
        //             : ''
        //     }">link
        // </a> to reset your password.</p>`,
        // });
        return res.render('successForgotPass', { error: { message: null }, layout: 'layouts/secondary' });
    } catch (err) {
        _logger.error('Method:sendReqForPass, Error:', err);
        return res.render('requestForgotPass', {
            error: { message: err.message },
            layout: 'layouts/secondary',
        });
    }
};

const getResetPassword = async (req, res, next) => {
    try {
        const error = catcher(req);
        if (error)
            return res.render('error', {
                error: { status: 400, message: error },
                layout: 'layouts/secondary',
            });

        const forgotCode = req.params['forgotCode'];
        const user = await prisma.user.findFirst({ where: { forgotCode } });
        if (!user)
            return res.render('error', {
                error: { status: 400, message: 'Invalid code!' },
                layout: 'layouts/secondary',
            });
        if (Date.now() > user.forgotCodeExpAt)
            return res.render('error', {
                error: { status: 400, message: 'Expired Code!' },
                layout: 'layouts/secondary',
            });

        return res.render('resetPass', {
            user: user,
            error: { message: null },
            layout: 'layouts/secondary',
        });
    } catch (err) {
        _logger.error('Method:getResetPassword, Error:', err);
        return res.render('error', {
            error: { status: 500, message: err.message },
            layout: 'layouts/secondary',
        });
    }
};

const resetPassword = async (req, res, next) => {
    try {
        const forgotCode = req.params['forgotCode'];
        const user = await prisma.user.findFirst({ where: { forgotCode } });

        const error = catcher(req);
        if (error)
            return res.render('resetPass', {
                error: { status: 400, message: error },
                layout: 'layouts/secondary',
                user,
            });

        if (!user)
            return res.render('error', {
                error: { status: 400, message: 'Invalid code!' },
                layout: 'layouts/secondary',
            });
        if (Date.now() > user.forgotCodeExpAt)
            return res.render('error', {
                error: { status: 400, message: 'Expired Code!' },
                layout: 'layouts/secondary',
            });

        const hashed = await bcrypt.hash(req.body.password, 10);
        await prisma.user.update({
            where: { id: user.id },
            data: {
                password: hashed,
                forgotCode: null,
                forgotCodeExpAt: null,
            },
        });

        return res.redirect(
            `${process.env.URL_PRE_FIX}/auth/login${
                req.query[RedirectRequestFields.Client_Oauth_Request]
                    ? `?${RedirectRequestFields.Client_Oauth_Request}=${
                          req.query[RedirectRequestFields.Client_Oauth_Request]
                      }`
                    : ''
            }`
        );
    } catch (err) {
        _logger.error('Method:resetPassword, Error:', err);
        return res.render('error', {
            error: { status: 400, message: err.message },
            layout: 'layouts/secondary',
        });
    }
};

module.exports = {
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
};
