const nodemailer = require('nodemailer');

const transport = nodemailer.createTransport({
    service:'gmail',
    auth:{
        type:'OAuth2',
        user:"suhail22rm@gmail.com",
        clientId:process.env.NODE_MAILER_CLIENT_ID,
        clientSecret:process.env.NODE_MAILER_CLIENT_SECRET,
        refreshToken:process.env.NODE_MAILER_REFRESH_TOKEN
    }
});

module.exports = transport;