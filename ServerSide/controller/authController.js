import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/user.js';
import redisClient from '../config/redis.js';
import dotenv from 'dotenv';

import crypto from 'crypto';
import transporter from '../config/nodemailer.js';
import { OAuth2Client } from 'google-auth-library';
import { google } from 'googleapis';


dotenv.config();

const CACHE_EXPIRY = 3600;
const EMAIL_TOKEN_EXPIRY = 24 * 60 * 60 * 1000;
const PASSWORD_RESET_EXPIRY = 60 * 60 * 1000;

const oAuth2Client = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_CALLBACK_URL

);


async function generateUniqueUsername(baseUsername) {
    let username = baseUsername;
    let counter = 1;
    
    while (true) {
        const existingUser = await User.findOne({ username });
        if (!existingUser) {
            return username;
        }
        username = `${baseUsername}${counter}`;
        counter++;
    }
}

// Helper function to send emails remains the same
const sendEmail = async (to, subject, html) => {
    try {
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to,
            subject,
            html
        });
    } catch (error) {
        console.error('Email sending error:', error);
        throw new Error('Email sending failed');
    }
};

// Helper function to generate tokens
const generateTokens = (userId) => {
    const accessToken = jwt.sign({userId}, process.env.JWT_SECRET, {expiresIn: "1d"}); // 1 day
    const refreshToken = jwt.sign({userId}, process.env.JWT_REFRESH_SECRET, {expiresIn: "7d"}); // 7 days and store in cookie
    return { accessToken, refreshToken };
};

//Initiating Google OAuth2Client

export const googleAuth = async (req, res) => {
    try {
        const googleScopes = ['https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'];

        const authUrl = oAuth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: googleScopes,
            include_granted_scopes: true,
            prompt: 'consent'
        });

        res.status(200).json({ url: authUrl });
    } catch (error) {
        console.error('Google auth error:', error);
        res.status(500).json({ message: error.message || "Authentication failed" });
    }
};

// Handle Google OAuth Callback
export const googleCallback = async (req, res) => {
    const { code } = req.query;

    try {
        // Exchange code for tokens
        const { tokens } = await oAuth2Client.getToken(code);
        oAuth2Client.setCredentials(tokens);

        // Fetch user info
        const oauth2 = google.oauth2({ version: 'v2', auth: oAuth2Client });
        const { data } = await oauth2.userinfo.get();

        const { email, name, picture, id: googleId } = data;
        const normalizedEmail = email.toLowerCase();

        let user = await User.findOne({ email: normalizedEmail });

        if (user) {
            // if (user.authType === 'email') {
            //     return res.redirect(
            //         `${process.env.FRONTEND_URL}/auth/error?message=${encodeURIComponent(
            //             "This email is already registered with password authentication"
            //         )}`
            //     );
            // }

             if (user.authType === 'email') {
            await User.updateOne(
            { email: normalizedEmail },
            { googleId, isVerified: true, authType: 'google' }
        );
    }


            if (!user.googleId) {
                await User.updateOne({ email: normalizedEmail }, { googleId, isVerified: true });
            }
        } else {
            // Create a new user
            const username = await generateUniqueUsername(email.split('@')[0]);
            user = new User({
                username,
                name,
                email: normalizedEmail,
                googleId,
                isVerified: true,
                profilePicture: picture,
                authType: 'google'
            });
            await user.save();
        }

        // Cache user data in Redis
        const userToCache = { ...user.toObject(), password: undefined };
        await redisClient.set(`user:${user._id}`, JSON.stringify(userToCache), { EX: CACHE_EXPIRY });

        // Generate JWT tokens
        const { accessToken, refreshToken } = generateTokens(user._id);

        // Securely store refresh token
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "none",
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "none",
            maxAge: 24 * 60 * 60 * 1000 // 1 day
        });

        // Redirect to frontend with access token
        res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
    } catch (error) {
        console.error('Google callback error:', error);
        res.redirect(`${process.env.FRONTEND_URL}/auth/error?message=${encodeURIComponent(error.message || "Authentication failed")}`);
    }
};

// export const googleAuth = async (req, res) => {
//     const { token } = req.body;

//     try {
//         // Verify Google token
//         const ticket = await googleClient.verifyIdToken({
//             idToken: token,
//             audience: process.env.GOOGLE_CLIENT_ID
//         });

//         const { email, name, picture, sub: googleId } = ticket.getPayload();
//         const normalizedEmail = email.toLowerCase();

//         // Check if user exists
//         let user = await User.findOne({ email: normalizedEmail });

//         if (user) {
//             // Update existing user's Google ID if not set
//             if (!user.googleId) {
//                 user.googleId = googleId;
//                 user.isVerified = true; // Google accounts are pre-verified
//                 await user.save();
//             }
//         } else {
//             // Create new user
//             const username = email.split('@')[0]; // Generate username from email
//             user = new User({
//                 username,
//                 name,
//                 email: normalizedEmail,
//                 googleId,
//                 isVerified: true,
//                 profilePicture: picture,
//                 authType: 'google'
//             });
//             await user.save();
//         }

//         // Cache user data
//         const userToCache = {
//             ...user.toObject(),
//             password: undefined
//         };
//         await redisClient.set(`user:${user._id}`, JSON.stringify(userToCache), {EX: CACHE_EXPIRY});

//         // Generate tokens
//         const { accessToken, refreshToken } = generateTokens(user._id);

//         res.cookie("refreshToken", refreshToken, {
//             httpOnly: true,
//             secure: process.env.NODE_ENV === "production",
//             sameSite: "none",
//             maxAge: 7 * 24 * 60 * 60 * 1000
//         });

//         res.status(200).json({
//             message: "Logged in successfully with Google",
//             accessToken,
//             user: userToCache
//         });

//     } catch (error) {
//         console.error('Google auth error:', error);
//         res.status(500).json({ message: "Authentication failed" });
//     }
// };

// Modified register function to include authType
export const register = async (req, res) => {
    console.log("Request Body:", req.body);
    const { username, name, email, password } = req.body;

    if(!username || !name || !email || !password){
        return res.status(400).json({message: "Please fill all fields"});
    }

    try {
        const normalizedEmail = email.toLowerCase();
        const existingUser = await User.findOne({email: normalizedEmail});

        if(existingUser){
            return res.status(400).json({
                message: existingUser.authType === 'google' ? 
                    "This email is registered with Google. Please login with Google." : 
                    "User already exists"
            });
        }   

        const hashedPassword = await bcrypt.hash(password, 10);
        const emailVerificationToken = crypto.randomBytes(32).toString('hex');
        const emailVerificationExpiry = new Date(Date.now() + EMAIL_TOKEN_EXPIRY);

        const newUser = new User({
            username,
            name,
            email: normalizedEmail,
            password: hashedPassword,
            emailVerificationToken,
            emailVerificationExpiry,
            isVerified: false,
            authType: 'email'
        });

        await newUser.save();

        // Rest of the register function remains the same...
        // Send verification email
        const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${emailVerificationToken}`;
        await sendEmail(
            normalizedEmail,
            'Verify Your Email',
            `Please click <a href="${verificationUrl}">here</a> to verify your email. This link expires in 24 hours.`
        );

        const userToCache = {
            ...newUser.toObject(),
            password: undefined,
            emailVerificationToken: undefined
        };

        await redisClient.set(`user:${newUser._id}`, JSON.stringify(userToCache), {EX: CACHE_EXPIRY});

        const { accessToken, refreshToken } = generateTokens(newUser._id);

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "none",
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.status(201).json({
            message: "User created successfully. Please verify your email.",
            accessToken
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Something went wrong" });
    }
};

// Modified login function to handle different auth types
export const login = async (req, res) => {
    const { email, password } = req.body;
    if(!email || !password){
        return res.status(400).json({message: "Please fill all fields"});
    }

    try {
        const normalizedEmail = email.toLowerCase();
        const existingUser = await User.findOne({email: normalizedEmail});
        
        if(!existingUser){
            return res.status(400).json({message: "Invalid credentials"});
        }

        // Check if user is registered with Google
        if(existingUser.authType === 'google') {
            return res.status(400).json({
                message: "This email is registered with Google. Please login with Google."
            });
        }

        if (!existingUser.isVerified) {
            return res.status(400).json({message: "Please verify your email before logging in"});
        }

        const isPasswordCorrect = await bcrypt.compare(password, existingUser.password);
        if(!isPasswordCorrect){
            return res.status(400).json({message: "Invalid credentials"});
        }

        const userToCache = {
            ...existingUser.toObject(),
            password: undefined
        };
        await redisClient.set(`user:${existingUser._id}`, JSON.stringify(userToCache), {EX: CACHE_EXPIRY});

        const { accessToken, refreshToken } = generateTokens(existingUser._id);

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "none",
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.status(200).json({
            message: "Logged in successfully",
            accessToken,
            user: userToCache
        });
        
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Something went wrong" });
    }
};

export const logout = async (req, res) => {
    try {
        const { userId } = req.body;
        await redisClient.del(`user:${userId}`);
        res.clearCookie("refreshToken");
        res.status(200).json({message: "Logged out successfully"});
        
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Something went wrong" });
    }
};

export const getUser = async (req, res) => {
    try {
        const cachedUser = await redisClient.get(`user:${req.userId}`);
        if(cachedUser){
            return res.status(200).json({user: JSON.parse(cachedUser)});
        }

        const user = await User.findById(req.userId);
        if(!user){
            return res.status(404).json({message: "User not found"});
        }

        const userToCache = {
            ...user.toObject(),
            password: undefined
        };
        await redisClient.set(`user:${req.userId}`, JSON.stringify(userToCache), {EX: CACHE_EXPIRY});
        
        res.status(200).json({user: userToCache});
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Something went wrong" });
    }
};

export const resetPassword = async (req, res) => {
    const { token, newPassword } = req.body;

    try {
        const user = await User.findOne({
            passwordResetToken: token,
            passwordResetExpiry: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: "Invalid or expired reset token" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 12);
        user.password = hashedPassword;
        user.passwordResetToken = undefined;
        user.passwordResetExpiry = undefined;
        await user.save();

        // Update cache
        const userToCache = {
            ...user.toObject(),
            password: undefined
        };
        await redisClient.set(`user:${user._id}`, JSON.stringify(userToCache), {EX: CACHE_EXPIRY});

        res.status(200).json({ message: "Password reset successful" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Something went wrong" });
    }
};

export const forgotPassword = async (req, res) => {
    const { email } = req.body;

    try {
        const normalizedEmail = email.toLowerCase();
        const user = await User.findOne({ email: normalizedEmail });

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenExpiry = new Date(Date.now() + PASSWORD_RESET_EXPIRY);

        user.passwordResetToken = resetToken;
        user.passwordResetExpiry = resetTokenExpiry;
        await user.save();

        // Send password reset email
        const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`;
        await sendEmail(
            normalizedEmail,
            'Reset Your Password',
            `Please click <a href="${resetUrl}">here</a> to reset your password. This link expires in 1 hour.`
        );

        res.status(200).json({ message: "Password reset link sent to email" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Something went wrong" });
    }
};

export const verifyEmail = async (req, res) => {
    const { token } = req.body;

    try {
        const user = await User.findOne({
            emailVerificationToken: token,
            emailVerificationExpiry: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: "Invalid or expired verification token" });
        }

        user.isVerified = true;
        user.emailVerificationToken = undefined;
        user.emailVerificationExpiry = undefined;
        await user.save();

        // Update cache
        const userToCache = {
            ...user.toObject(),
            password: undefined
        };
        await redisClient.set(`user:${user._id}`, JSON.stringify(userToCache), {EX: CACHE_EXPIRY});

        res.status(200).json({ message: "Email verified successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Something went wrong" });
    }
};

//handling redis errors
redisClient.on("error", (error) => {
    console.error("Redis error:", error);
});