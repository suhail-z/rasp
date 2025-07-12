const { hash, compare } = require("bcryptjs");
const { createHmac } = require('crypto');

exports.hashPassword = (async(password,saltvalue)=>{
    const result =await hash(password,saltvalue);
    return result;
})
exports.verifyPassword = (async(password,hashedPassword)=>{
    const result = await compare(password,hashedPassword);
    return result;
});
exports.processHmac = async(key,value)=>{
    let result =  createHmac("sha256",key).update(value).digest("hex");
    return result;
};