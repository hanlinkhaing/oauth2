const AuthCodeType = {
    EMAIL_VERIFY: 'EMAIL_VERIFY',
    SMS_VERIFY: 'SMS_VERIFY',
    TWO_FA: 'TWO_FA',
};

const AuthType = {
    APP: 'APP',
    SMS: 'SMS',
};

const ReturnMessages = {
    Required_Two_FA: {
        status: 0,
        message: 'Required Two factor!',
    },
    Internal_Server_Error: {
        status: 500,
        message: 'Internal Server Error!',
    },
    User_Not_Found: {
        status: 400,
        message: 'User Not Found!',
    },
};

const RedirectRequestFields = {
    Client_Oauth_Request: 'client_oauth_request',
};

const Grants = {
    Authorization_Code: 'authorization_code',
    Refresh_Token: 'refresh_token',
};

const ReqFunction = {
    Verify_SMS: 'Verify_SMS',
    Two_FA_On: 'Two_FA_On',
    Upgrade: 'Upgrade',
};

const RegisterType = {
    Default: 'DEFAULT',
    Social: 'SOCIAL',
};

module.exports = { AuthCodeType, AuthType, ReturnMessages, RedirectRequestFields, Grants, ReqFunction, RegisterType };
