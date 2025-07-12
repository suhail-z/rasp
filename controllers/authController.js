
const { validateInput, validateCode } = require("../middlewares/validator");
const User = require('../models/userModel');
const { hashPassword, verifyPassword, processHmac } = require("../utils/hashing");
const jwt = require('jsonwebtoken');
const transport = require("../middlewares/sendMail");
const { exist } = require("joi");

exports.signupSchema = (async(req,res)=>{
    const {email , password } = req.body;
    try{

        const {error, value} = validateInput.validate({email,password});

        if(error){
            return res.status(401).json({success:false,details:error.details[0].message})
        }
        const existingUser = await User.findOne({email});

        if(existingUser){
            return res.status(409).json({success:false,details:'mail id already exist'});
        }

        const hashedpass = await hashPassword(password,12);

        const newUser = new User({
            email,
            password:hashedpass
        });

        let result = await newUser.save();
        result.password = undefined;

        return res.status(201).json({success:true,details:'your account has been created successfully',userInfo:result});

    }
    catch(err){
        console.log('error creating a user acount', err);
        return res.status(500)
        .json({
            sucess:false,
            details:'internal server error'
        })
    }
});

exports.loginSchema = (async(req,res)=>{
    const {email,password} = req.body;

    try{
        const {error,value} = validateInput.validate({email,password});

        if(error){
            return res.status(400).json({success:false,details:error.details[0].message})
        }

        let existingUser =await User.findOne({email}).select('+password');

        if(!existingUser){
             return res.status(404).json({success:false,details:'mail id does not exist'});
        }
        const verified = await verifyPassword(password,existingUser.password);

        if(!verified){
            return res.status(401).json({success:false,details:'password does not match for provided mail id'});
        }
        const token = jwt.sign({
            userID:existingUser._id,
            email:existingUser.email,
            verified:existingUser.verified
        },
        process.env.SECRET,
        { expiresIn :'8h'}
    );

        return res.cookie('Authorization','Bearer '+token,{expires: new Date(Date.now() + 8* 3600000),httponly:process.env.NODE_ENV === 'production',secure:process.env.NODE_ENV === 'production',samesight : 'strict'}).status(200)
        .json({
            success:true,
            token,
            details:'login succesfull'
    })

    }
    catch(err){
          console.log('error creating a user acount', err);
        return res.status(500)
        .json({
            success:false,
            details:'internal server error'
        })
    }
});
exports.logout = (async(req,res)=>{
    res.clearCookie('Authorization').status(200).json({
        sucess:true,
        details:'logged out succesfully'
    })
});
exports.verifyUser = async(req,res)=>{
    const {email} = req.body;
    try{
        // const {error,value} = validateInput.validate({email});
        // if(error){
        //     return res.status(400).json({success:false,details:error.details[0].message});
        // }
        let existingUser = await User.findOne({email});

        if(!existingUser){
            return res.status(404).json({success:false,details:'mail id does not exist'});
        }
        if(existingUser.verified){
            return res.status(400).json({success:false,details:'user is already verified'});
        }
        const VerificationCode = Math.floor(Math.random() * 1000000).toString();

        let mailInfo = await transport.sendMail({
            from:process.env.NODE_MAILER_MAIL_ID,
            to:existingUser.email,
            subject:'Verification Code For Smedia',
            html:`<h1>`+VerificationCode +`</h1>`
        });
        
        if(mailInfo.accepted && mailInfo.accepted[0] === existingUser.email){
           
            const hashedCode = await processHmac(process.env.HMAC_KEY,VerificationCode);
            existingUser.verificationCode = hashedCode;
            existingUser.verificationCodeValidation = Date.now();
            
            await existingUser.save();
            
            return res.status(200).json({success:true,details:'verification code sent successfully'});
        }
        return res.status(400).json({success:false,details:'error  sending verification code'})

    }
    catch(err){
         console.log('error creating a user acount', err);
        return res.status(500)
        .json({
            success:false,
            details:'internal server error'
        })
    }
    
};
exports.confirmVerificationCode = async(req,res)=>{
    const {email,providedCode} = req.body;
    try{
         const {error,value} = validateCode.validate({email,providedCode});

         if(error){
            return res.status(400).json({success:false,details:error.details[0].message});
         }

         const existingUser = await User.findOne({email}).select('+verificationCode +verificationCodeValidation');

         if(!existingUser){
            return res.status(404).json({success:false,details:'mail id does not exist'});
        }
        if(existingUser.verified){
            return res.status(400).json({success:false,details:'user is already verified'});
        }
        if(!existingUser.verificationCode || !existingUser.verificationCodeValidation){
            
            return res.status(400).json({success:false,details:'error with the database / bad request'});
        }
        if(Date.now() - existingUser.verificationCodeValidation > 5 * 60 * 1000){
           return res.status(404).json({success:false,details:'verification code have expired'});
        }
        const code = providedCode.toString();
        const hashedProvidedCode = await processHmac(process.env.HMAC_KEY,code);
            if(hashedProvidedCode === existingUser.verificationCode){
               
                existingUser.verified=true;
                existingUser.verificationCode=undefined;
                existingUser.verificationCodeValidation=undefined;
                await existingUser.save();
                
                
               return res.status(200).json({success:true,details:'user mail id is verified successfully'})
            }
              return res.status(400).json({success:false,details:'invalid verification code'});
    }catch(error){
        console.log('error creating a user acount', error);
        return res.status(500)
        .json({
            success:false,
            details:'internal server error'
        })
    }
    
}