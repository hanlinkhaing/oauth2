const TeleSignSDK = require('telesignsdk');

const sendAuthSms = (phone, authCode) => {
    const customerId = process.env.SMS_APPLICATION_ID;
    const apiKey = process.env.SMS_API_KEY;
    const rest_endpoint = process.env.SMS_API_BASE_URL;
    const timeout = 10 * 1000; // 10 secs

    const client = new TeleSignSDK(
        customerId,
        apiKey,
        rest_endpoint,
        timeout // optional
    );

    const phoneNumber = phone.replace('+', '');
    const messageType = 'ARN';
    const message = 'Your code is ' + authCode;

    function messageCallback(error) {
        if (error === null) {
            console.log('sent sms successfully');
        } else {
            console.error('Unable to send message. ' + error);
        }
    }
    client.sms.message(messageCallback, phoneNumber, message, messageType);
};

module.exports = { sendAuthSms };
