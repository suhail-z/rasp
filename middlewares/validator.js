const Joi = require('joi');

exports.validateInput = Joi.object({
    email:Joi.string().min(8).max(30).email({
        tlds: {
            allow:['com','net']
        }
    }).required(),
    password:Joi.string()
    .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$')).required().messages({
        'string.pattern.base':'password must contain atleast 1 lowercase,uppercase,special characters,numbers',
        'string.empty':'password cannot be empty'
})
});

exports.validateCode = Joi.object({
    email:Joi.string().min(8).max(30).email({
        tlds: {
            allow:['com','net']
        }
    }).required(),
    providedCode:Joi.number().required()
});