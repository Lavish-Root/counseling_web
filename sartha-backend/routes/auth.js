const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const User = require('../models/User');
const sendEmail = require('../utils/email');
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Generate 6 digit OTP
const generateOTP = () => {
    return Math.floor(100000 + Math.random() * 900000).toString();
};

// @route   POST /api/auth/send-otp
// @desc    Generate OTP and send it via email
// @access  Public
router.post('/send-otp', async (req, res) => {
    try {
        const { email, name, isRegistering } = req.body;

        if (!email) {
            return res.status(400).json({ message: 'Please provide an email address' });
        }

        const emailRegex = /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/;
        if (!email.match(emailRegex)) {
            return res.status(400).json({ message: 'Please provide a valid email address' });
        }

        let user = await User.findOne({ email });

        if (isRegistering && user && user.isVerified) {
            return res.status(400).json({ message: 'User already exists with this email' });
        }

        if (!isRegistering && !user) {
            return res.status(404).json({ message: 'No account found with this email' });
        }

        const otp = generateOTP();
        const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

        if (!user) {
            // Create a temporary unverified user shell
            user = new User({
                name: name || 'User',
                email,
                password: 'UNVERIFIED_TEMP_PASSWORD', // Will be overwritten in actual register flow
                isVerified: false,
                otp,
                otpExpires
            });
        } else {
            // Update existing user with new OTP
            user.otp = otp;
            user.otpExpires = otpExpires;
        }

        await user.save();

        // Send Email
        try {
            await sendEmail({
                email: user.email,
                subject: 'NextStep Counsel - Your Verification Code',
                message: `Your one-time verification code is: ${otp}. This code will expire in 10 minutes.`
            });

            res.status(200).json({ message: 'OTP sent to your email!' });
        } catch (error) {
            console.error('Email could not be sent', error);
            user.otp = undefined;
            user.otpExpires = undefined;
            await user.save();
            return res.status(500).json({ message: 'There was an error sending the email. Try again later.' });
        }

    } catch (err) {
        console.error(err.message);
        res.status(500).json({ message: 'Server error: ' + err.message });
    }
});

// @route   POST /api/auth/verify-otp
// @desc    Verify OTP for email
// @access  Public
router.post('/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;

        if (!email || !otp) {
            return res.status(400).json({ message: 'Please provide email and OTP' });
        }

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (user.otp !== otp) {
            return res.status(400).json({ message: 'Invalid OTP' });
        }

        if (user.otpExpires < Date.now()) {
            return res.status(400).json({ message: 'OTP has expired. Please request a new one.' });
        }

        // Mark as verified and clear OTP
        user.isVerified = true;
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();

        res.status(200).json({ message: 'Email verified successfully!' });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// @route   POST /api/auth/register
// @desc    Register a new user
// @access  Public
router.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Default validation
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'Please provide all required fields' });
        }

        // Validate email format
        const emailRegex = /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/;
        if (!email.match(emailRegex)) {
            return res.status(400).json({ message: 'Please provide a valid email address' });
        }

        // Check if user already exists
        let user = await User.findOne({ email });

        // If there's no user, they haven't requested an OTP
        if (!user) {
            return res.status(400).json({ message: 'Please verify your email first' });
        }

        // If they exist but aren't verified, block them
        if (!user.isVerified) {
            return res.status(400).json({ message: 'Please verify your email first' });
        }

        // If they exist AND the password doesn't match the UNVERIFIED_TEMP_PASSWORD, they are already a full user
        if (user.isVerified && user.password !== 'UNVERIFIED_TEMP_PASSWORD') {
            return res.status(400).json({ message: 'User already exists with this email' });
        }

        // Hash the actual password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Update the shell user
        user.name = name;
        user.password = hashedPassword;

        await user.save();

        // Create JWT Payload
        const payload = {
            user: {
                id: user.id,
                role: user.role
            }
        };

        // Sign Token
        jwt.sign(
            payload,
            process.env.JWT_SECRET || 'secret',
            { expiresIn: '7d' },
            (err, token) => {
                if (err) throw err;
                res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
            }
        );

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// @route   POST /api/auth/login
// @desc    Authenticate user & get token
// @access  Public
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Please provide both email and password' });
        }

        // Validate email format
        const emailRegex = /^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/;
        if (!email.match(emailRegex)) {
            return res.status(400).json({ message: 'Please provide a valid email address' });
        }

        // Check for user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid Credentials' });
        }

        // Match password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid Credentials' });
        }

        // Create JWT Payload
        const payload = {
            user: {
                id: user.id,
                role: user.role
            }
        };

        // Sign Token
        jwt.sign(
            payload,
            process.env.JWT_SECRET || 'secret',
            { expiresIn: '7d' },
            (err, token) => {
                if (err) throw err;
                res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
            }
        );

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// @route   POST /api/auth/reset-password
// @desc    Reset password using a verified email
// @access  Public
router.post('/reset-password', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Please provide email and new password' });
        }

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        if (!user.isVerified) {
            return res.status(403).json({ message: 'Please verify your email first' });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user.password = hashedPassword;
        // Reset verification flag so they must re-verify for future resets
        user.isVerified = false;

        await user.save();

        res.status(200).json({ message: 'Password reset successfully. Please log in.' });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// @route   POST /api/auth/google
// @desc    Authenticate user with Google token
// @access  Public
router.post('/google', async (req, res) => {
    try {
        const { token } = req.body;

        if (!token) {
            return res.status(400).json({ message: 'No Google token provided' });
        }

        // Verify token with Google
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        const { email, name, email_verified } = payload;

        if (!email_verified) {
            return res.status(400).json({ message: 'Google email is not verified' });
        }

        // Check for user
        let user = await User.findOne({ email });

        if (!user) {
            // Create user
            const salt = await bcrypt.genSalt(10);
            const randomPassword = Math.random().toString(36).slice(-10) + Math.random().toString(36).slice(-10);
            const hashedPassword = await bcrypt.hash(randomPassword, salt);

            user = new User({
                name: name,
                email: email,
                password: hashedPassword,
                isVerified: true
            });
            await user.save();
        } else if (!user.isVerified) {
            // If user existed as unverified shell, verify them now
            user.isVerified = true;
            user.name = name; // Update name just in case
            await user.save();
        }

        // Create JWT Payload
        const jwtPayload = {
            user: {
                id: user.id,
                role: user.role
            }
        };

        // Sign Token
        jwt.sign(
            jwtPayload,
            process.env.JWT_SECRET || 'secret',
            { expiresIn: '7d' },
            (err, signedToken) => {
                if (err) throw err;
                res.json({ token: signedToken, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
            }
        );

    } catch (err) {
        console.error('Google Auth Error:', err);
        res.status(500).json({ message: 'Server error during Google authentication' });
    }
});

module.exports = router;
