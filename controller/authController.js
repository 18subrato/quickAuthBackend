import User from '../models/userModel.js'
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import transporter from '../config/nodemailer.js'

export const register = async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.json({ success: false, message: 'Missing Details' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.json({ success: false, message: 'User Already Exists' });
        }

        const hashPassword = await bcrypt.hash(password, 10);

        const user = new User({
            name,
            email,
            password: hashPassword
        })

        await user.save();

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        })

        //sending email
        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome To Auth Website',
            text: `Welcome to Auth Website. You account has been created with email id:${email}`
        }

        await transporter.sendMail(mailOption);

        return res.json({success: true, message: 'Registration Successfull'});

    } catch (error) {
        res.json({ success: false, message: error.message });
    }
}


export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({ success: false, message: 'Missing Details' });
    }

    try {
        const existingUser = await User.findOne({ email });
        if (!existingUser) {
            return res.json({ success: false, message: 'User Not Found' });
        }

        const isMatch = await bcrypt.compare(password, existingUser.password);

        if (!isMatch) {
            return res.json({ success: false, message: 'Invalid Password' });
        }

        const token = jwt.sign({ id: existingUser._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        })

        return res.json({success: true, message:'Logging Successfull'});

    } catch (error) {
        res.json({ success: false, message: error.message });
    }
}

export const logout = async(req,res)=>{
    try {
        res.clearCookie('token',{
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        })

        return res.json({success: true, message: 'Logged Out'});

    } catch (error) {
        res.json({ success: false, message: error.message });
    }
}

export const sendVerifyOtp = async(req,res)=>{
    try {
        const userId  = req.user;
        const user = await User.findById(userId);


        if(user.isAccountVerified){
            return res.json({success: false, message: 'Account Already verified'});
        }

        const OTP = String(Math.floor(100000 + Math.random() * 900000));

        user.verifyOtp = OTP;
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 10000;
        await user.save();
        
        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            text: `Your OTP is ${OTP}. Verify your account using this OTP`
        }

        await transporter.sendMail(mailOption);

        return res.json({success: true, message: 'OTP Sent on your Email'})

    } catch (error) {
        res.json({success: false, message: error.message})
    }
}

export const verifyEmail = async(req,res)=>{
    try {
        const userId = req.user;
        const { OTP } = req.body;
        
        if(!userId || !OTP){
            return res.json({success: false, message: 'Missing Details'});
        }

        const user = await User.findById(userId);
        if(!user){
            return res.json({success: false, message: 'User not Found'});
        }

        if(user.verifyOtp === '' || user.verifyOtp !== OTP){
            return json({success: false, message: 'Invalid OTP'});
        }

        if(user.verifyOtpExpireAt < Date.now()){
            return res.json({success: false, message: 'OTP Expired'});
        }

        user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpireAt = 0;

        await user.save();

        return res.json({success: true, message: 'Email verified successfull'});

    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}

export const isAuthenticated = async(req,res)=>{
    try {
        return res.json({success: true});
    } catch (error) {
        return res.json({success: false, message: error.message})
    }
}

export const sendResetOtp = async(req,res)=>{
    const { email } = req.body;

    if(!email){
        return res.json({success: false, message: 'Email is Required'});
    }

    try {
        const user = await User.findOne({email})
        if(!user){
            return res.json({success: false, message: 'User not Found'});
        }

        const OTP = String(Math.floor(100000 + Math.random() * 900000));

        user.resetOtp = OTP;
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 10000;
        await user.save();
        
        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            text: `Your OTP for resetting your password is ${OTP}. Use this OTP to proceed with resetting your password`
        }

        await transporter.sendMail(mailOption);

        return res.json({success: true, message: 'OTP Sent to your Email'});

    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

export const resetPassword = async(req,res)=>{
    const { email, OTP, password } = req.body;
    const otp = OTP;
    const newPassword = password;

    if(!email || !otp || !newPassword){
        return res.json({success: false, message: 'Email, OTP and new password is required'});
    }

    try {

        const user = await User.findOne({email});
        if(!user){
            return res.json({success: false, message: 'User not Found'});
        }

        if(user.resetOtp === '' || user.resetOtp !== otp){
            return res.json({success: false, message: 'Invalid OTP'})
        }

        if(user.resetOtpExpireAt < Date.now()){
            return res.json({success: false, message: 'OTP Expired'});
        }

        const hashPassword = await bcrypt.hash(newPassword,10);
        user.password = hashPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;
        await user.save();

        return res.json({success: true, message: 'Password has been reset Successfully'});
        
    } catch (error) {
        return res.json({success: false, message: error.message});
    }

}