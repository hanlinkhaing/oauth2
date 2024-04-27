const { PrismaClient, Prisma } = require('@prisma/client');
const axios = require('axios');
const bcrypt = require('bcrypt');
const catcher = require('../utils/validation.catcher');
const { encode, decode } = require('js-base64');
const { RedirectRequestFields, ReturnMessages, ReqFunction, Grants } = require('../utils/enum');
const { sendAuthCode, verifyCode } = require('../services/auth.service');

const prisma = new PrismaClient();

const getAuthorize = async (req, res, next) => {
    const error = catcher(req);
    if (error)
        return res.render('error', {
            error: { status: 400, message: error },
            layout: 'layouts/secondary',
        });

    const { client_id, scope, response_type, redirect_uri, type } = req.query;
    let to = '/auth/login';
    if (type && type === 'register') to = '/users/register';
    try {
        const encodedData = encode(JSON.stringify({ client_id, scope, response_type, redirect_uri }));
        return res.redirect(
            `${process.env.URL_PRE_FIX}${to}?${RedirectRequestFields.Client_Oauth_Request}=${encodedData}`
        );
    } catch (err) {
        _logger.error('Method:getAuthorize, Error:', err);
        return res.render('error', {
            error: { status: 500, message: err.message },
            layout: 'layouts/secondary',
        });
    }
};

const getAuthCode = async (req, res, next) => {
    try {
        const result = await sendAuthCode(req.user.email);
        if (result instanceof Error)
            return res
                .status(result.message === ReturnMessages.Internal_Server_Error ? 500 : 400)
                .json({ message: result.message });

        return res.status(200).json({ message: result });
    } catch (err) {
        _logger.error('Method:getAuthCode, Error:', err);
        return res.status(500).json({ message: err.message });
    }
};

const verifyAuthCode = async (req, res, next) => {
    try {
        const error = await verifyCode(req.params['verifyCode'], req.user.email);
        if (error)
            return res.status(error === ReturnMessages.Internal_Server_Error ? 500 : 400).json({ message: error });

        return res.status(200).json({ message: 'Success!' });
    } catch (err) {
        _logger.error('Method:verifyAuthCode, Error:', err);
        return res.status(500).json({ message: err.message });
    }
};

const clientRequest = async (req, res, next) => {
    try {
        const error = catcher(req);
        if (error)
            return res.render('error', {
                error: { status: 400, message: error },
                layout: 'layouts/secondary',
            });
        const reqFunction = req.query.reqFunction;
        const callbackUrl = req.query.callbackUrl;
        const user = await prisma.user.findFirst({
            where: { email: { equals: req.user.email, mode: 'insensitive' } },
        });
        switch (reqFunction) {
            case ReqFunction.Verify_SMS:
                if (user.isSmsVerified) return res.redirect(callbackUrl);
                break;
            case ReqFunction.Two_FA_On:
                if (user.authType) return res.redirect(callbackUrl);
                break;
            case ReqFunction.Upgrade:
                if (user.isSmsVerified) return res.redirect(callbackUrl);
                break;
        }
        const encodedData = encode(JSON.stringify(req.query));
        return res.redirect(
            `${process.env.URL_PRE_FIX}/auth/login?${RedirectRequestFields.Client_Oauth_Request}=${encodedData}`
        );
    } catch (err) {
        _logger.error('Method:clientRequest, Error:', err);
        return res.render('error', {
            error: { status: 500, message: err.message },
            layout: 'layouts/secondary',
        });
    }
};

const validateAccessTokenReq = async (req, res, next) => {
    try {
        const error = catcher(req);
        if (error) return res.status(400).json({ message: error });

        const isExist =
            Grants.Authorization_Code === req.body.grant_type && req.body.code
                ? await prisma.oAuthCode.findFirst({ where: { authorizationCode: req.body.code } })
                : Grants.Refresh_Token === req.body.grant_type && req.body.refresh_token
                ? await prisma.oAuthAccessToken.findFirst({ where: { refreshToken: req.body.refresh_token } })
                : null;

        if (!isExist) return res.status(400).json({ message: 'Invalid request body params!' });

        next();
    } catch (err) {
        _logger.error('Method:validateAccessTokenReq, Error:', err);
        return res.status(500).json({ message: err.message });
    }
};

module.exports = { getAuthorize, getAuthCode, verifyAuthCode, clientRequest, validateAccessTokenReq };
