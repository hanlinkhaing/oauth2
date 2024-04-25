const { PrismaClient, Prisma } = require('@prisma/client');
const prisma = new PrismaClient();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const selectAccessToken = {
    id: true,
    accessToken: true,
    accessTokenExpiresAt: true,
    refreshToken: true,
    refreshTokenExpiresAt: true,
    scope: true,
    createdAt: true,
};

const selectCode = {
    id: true,
    authorizationCode: true,
    expiresAt: true,
    redirectUri: true,
    scope: true,
    createdAt: true,
};

const selectClient = {
    id: true,
    clientId: true,
    clientSecret: true,
    redirectUris: true,
    scopes: true,
    grants: true,
    createdAt: true,
};

const selectUser = {
    id: true,
    username: true,
    email: true,
    password: true,
    phone: true,
    isEmailVerified: true,
    dob: true,
    postalCode: true,
    address1: true,
    address2: true,
    profileImageUrl: true,
    registerType: true,
    isEmailVerified: true,
    isSmsVerified: true,
};

module.exports = {
    generateAccessToken: async function (client, user, scope) {
        client = await prisma.oAuthClient.findUnique({
            where: {
                id: client.id,
            },
        });
        if (!client) return false;
        const accessToken = jwt.sign(
            {
                user: {
                    email: user.email,
                    clientId: client.clientId,
                    profileImageUrl: process.env.IMG_URL_PRE_FIX + user.profileImageUrl,
                    isSmsVerified: user.isSmsVerified,
                    isEmailVerified: user.isEmailVerified,
                    scope,
                },
            },
            client.privateKey,
            {
                expiresIn: process.env.OAUTH_ACCESS_TOKEN_EXP,
                algorithm: 'RS256',
            }
        );
        return accessToken;
    },

    getAccessToken: async function (accessToken) {
        const _accessToken = await prisma.oAuthAccessToken.findFirst({
            where: {
                accessToken: { equals: accessToken },
            },
            select: {
                ...selectAccessToken,
                user: { select: selectUser },
                client: { select: selectClient },
            },
        });
        if (!_accessToken) return false;
        if (!_accessToken.abs_user) _accessToken['user'] = {};
        _accessToken.client.redirectUris = _accessToken.client.redirectUris.split(',');
        _accessToken.client.grants = _accessToken.client.grants.split(',');
        return _accessToken;
    },

    getRefreshToken: async function (refreshToken) {
        const _refreshToken = await prisma.oAuthAccessToken.findFirst({
            where: {
                refreshToken: { equals: refreshToken },
            },
            select: {
                ...selectAccessToken,
                user: { select: selectUser },
                client: { select: selectClient },
            },
        });
        _refreshToken.client.redirectUris = _refreshToken.client.redirectUris.split(',');
        _refreshToken.client.grants = _refreshToken.client.grants.split(',');
        return _refreshToken;
    },

    getAuthorizationCode: async function (code) {
        const _code = await prisma.oAuthCode.findFirst({
            where: {
                authorizationCode: code,
            },
            select: {
                ...selectCode,
                user: { select: selectUser },
                client: { select: selectClient },
            },
        });
        _code.client.redirectUris = _code.client.redirectUris.split(',');
        _code.client.grants = _code.client.grants.split(',');
        return _code;
    },

    getClient: async function (clientId, clientSecret) {
        let where = { clientId };
        if (clientSecret) where['clientSecret'] = clientSecret;
        const result = await prisma.oAuthClient.findFirst({
            where: { ...where },
            select: { ...selectClient },
        });
        result.redirectUris = result.redirectUris.split(',');
        result.grants = result.grants.split(',');
        return result;
    },

    getUser: async function (username, password) {
        const user = await prisma.user.findFirst({
            where: {
                email: { equals: username, mode: 'insensitive' },
            },
        });
        if (!user) return false;
        const match = await bcrypt.compare(password, user.password);
        if (!match) return false;
        return user;
    },

    saveToken: async function (token, client, user) {
        const accessToken = await prisma.oAuthAccessToken.create({
            data: {
                accessToken: token.accessToken,
                accessTokenExpiresAt: token.accessTokenExpiresAt,
                refreshToken: token.refreshToken,
                refreshTokenExpiresAt: token.refreshTokenExpiresAt,
                redirectUri: token.redirectUri,
                scope: token.scope,
                userId: user.id,
                clientId: client.id,
                updatedAt: new Date(),
                createdAt: new Date(),
            },
            select: {
                ...selectAccessToken,
                user: { select: selectUser },
                client: { select: selectClient },
            },
        });
        if (!accessToken) return false;
        accessToken.client.redirectUris = accessToken.client.redirectUris.split(',');
        accessToken.client.grants = accessToken.client.grants.split(',');
        return accessToken;
    },

    saveAuthorizationCode: async function (code, client, user) {
        const authCode = await prisma.oAuthCode.create({
            data: {
                authorizationCode: code.authorizationCode,
                expiresAt: code.expiresAt,
                scope: code.scope,
                redirectUri: code.redirectUri,
                userId: user.id,
                clientId: client.id,
                updatedAt: new Date(),
                createdAt: new Date(),
            },
            select: {
                ...selectCode,
                user: { select: selectUser },
                client: { select: selectClient },
            },
        });

        try {
            const isExist = await prisma.usersUseClients.findFirst({
                where: {
                    AND: {
                        clientId: client.id,
                        userId: user.id,
                    },
                },
            });
            if (!isExist)
                await prisma.usersUseClients.create({
                    data: {
                        clientId: client.id,
                        userId: user.id,
                    },
                });
        } catch (err) {
            _logger.error(err);
        }

        authCode.client.redirectUris = authCode.client.redirectUris.split(',');
        authCode.client.grants = authCode.client.grants.split(',');
        return authCode;
    },

    revokeToken: async function (accessToken) {
        const deleted = await prisma.oAuthAccessToken.delete({
            where: { id: accessToken.id },
        });
        return deleted ? true : false;
    },

    revokeAuthorizationCode: async function (code) {
        const deleted = await prisma.oAuthCode.delete({
            where: { id: code.id },
        });
        return deleted ? true : false;
    },
};
