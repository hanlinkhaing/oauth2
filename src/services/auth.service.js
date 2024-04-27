const { PrismaClient } = require('@prisma/client');
const { AuthCodeType, AuthType, ReturnMessages } = require('../utils/enum');
const speakEasy = require('speakeasy');
const prisma = new PrismaClient();
const { updateUser } = require('./user.service');
const { generateRandomCode } = require('../utils/random.code');
const { sendAuthSms } = require('./sms.service');

// if error exist, will return a string // if success, will return null
const verifyCode = async (incomingCode, email) => {
    try {
        const user = await prisma.user.findFirst({ where: { email: { equals: email, mode: 'insensitive' } } });
        if (!user) return ReturnMessages.User_Not_Found.message;
        const code = await prisma.authCode.findFirst({ where: { userId: user.id, type: AuthCodeType.TWO_FA } });
        if (!code) return 'Authentication code not found!';

        let type = code.code.length === 6 ? AuthType.SMS : AuthType.APP;
        const isDifferentType = user.authType !== type;
        let vResult = false;
        if (type === AuthType.APP) {
            const result = speakEasy.totp.verify({
                secret: code.code,
                encoding: 'base32',
                token: incomingCode,
            });
            if (result) vResult = true;
        } else if (type === AuthType.SMS && incomingCode === code.code) vResult = true;

        if (!vResult) return 'Auth code verification fail!';
        if (isDifferentType) await updateUser(user.id, { authType: type });
        return null;
    } catch (err) {
        _logger.error(err);
        return err.message || ReturnMessages.Internal_Server_Error.message;
    }
};

// if error exist, will return a string // if success, will return null
const sendAuthCode = async (email) => {
    try {
        const user = await prisma.user.findFirst({ where: { email: { equals: email, mode: 'insensitive' } } });
        if (!user) return new Error(ReturnMessages.User_Not_Found.message);

        let authCode = await prisma.authCode.findFirst({ where: { userId: user.id, type: AuthCodeType.TWO_FA } });
        if (!user.authType && !authCode) return new Error(ReturnMessages.Required_Two_FA.message);
        let message = '';
        if (user.authType === AuthType.APP || (authCode && authCode.code && authCode.code.length > 6)) {
            message = 'Get code from Authenticator App.';
        } else if (user.authType === AuthType.SMS || (authCode && authCode.code && authCode.code.length === 6)) {
            const code = generateRandomCode(6, true);
            if (authCode) authCode = await prisma.authCode.update({ where: { id: authCode.id }, data: { code } });
            else
                authCode = await prisma.authCode.create({
                    data: {
                        code,
                        type: AuthCodeType.TWO_FA,
                        userId: user.id,
                    },
                });
            sendAuthSms(user.phone, code);
            message = 'Check your sms to get code.';
        } else return new Error('Invalid auth code request!');

        return message;
    } catch (err) {
        _logger.error(err);
        return new Error(err.message || ReturnMessages.Internal_Server_Error.message);
    }
};

module.exports = { verifyCode, sendAuthCode };
