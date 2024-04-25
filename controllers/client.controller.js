const { PrismaClient, Prisma } = require('@prisma/client');
const bcrypt = require('bcrypt');
const uuidV4 = require('uuidv4');
const { generateKeyPairSync } = require('crypto');
const catcher = require('../utils/validation.catcher');
const { Grants } = require('../utils/enum');

const prisma = new PrismaClient();

const generateClient = async (req, res, next) => {
    try {
        const error = catcher(req);
        if (error) return res.redirect(`${process.env.URL_PRE_FIX}/clients?error=${error}`);

        const keys = generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem',
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem',
            },
        });

        const file = req.file;
        const url = file.filename;

        const client = await prisma.oAuthClient.create({
            data: {
                appName: req.body.appName,
                appType: req.body.appType,
                redirectUris: req.body.redirectUris,
                scopes: req.body.scopes,
                clientId: uuidV4.fromString(req.user.email + Date.now()),
                clientSecret: uuidV4.fromString(req.user.email + req.user.appName + Date.now()),
                publicKey: keys.publicKey,
                privateKey: keys.privateKey,
                grants: Grants.Authorization_Code + ',' + Grants.Refresh_Token,
                userId: req.user.id,
                appLogoUrl: url,
                logo: {
                    create: {
                        name: file.filename,
                        mime: file.mimetype,
                        size: file.size,
                    },
                },
            },
        });

        return res.redirect(`${process.env.URL_PRE_FIX}/clients`);
    } catch (err) {
        _logger.error('Method:generateClient, Error:', err);
        return res.redirect(`${process.env.URL_PRE_FIX}/clients?error=${err.message}`);
    }
};

const showClients = async (req, res, next) => {
    try {
        const user = await prisma.user.findFirst({
            where: { email: { equals: req.user.email, mode: 'insensitive' } },
        });
        const clients = await prisma.oAuthClient.findMany({
            where: { userId: user.id },
            select: {
                id: true,
                appLogoUrl: true,
                appName: true,
                appType: true,
                clientId: true,
                clientSecret: true,
                grants: true,
                publicKey: true,
                scopes: true,
                redirectUris: true,
            },
            orderBy: { id: 'asc' },
        });
        delete user.password;
        delete user.createdAt;
        delete user.updatedAt;
        return res.render('client', { user, clients, error: { message: null } });
    } catch (err) {
        _logger.error('Method:showClients, Error:', err);
        return res.render('error', {
            error: { status: 500, message: err.message },
            layout: 'layouts/secondary',
        });
    }
};

module.exports = { generateClient, showClients };
