const express = require('express');
const {  signupSchema, loginSchema, logout, verifyUser, confirmVerificationCode } = require('../controllers/authController');
const router = express.Router();

router.post('/signup',signupSchema);

router.post('/login',loginSchema);

router.post('/logout',logout);

router.post('/verification',verifyUser);

router.post('/confirm-verification-code',confirmVerificationCode)

module.exports = router;