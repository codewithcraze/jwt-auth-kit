require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer'); // For email verification


class Auth {
    constructor() {
        this.secretKey = process.env.JWT_SECRET;
        this.tokenExpiry = process.env.JWT_EXPIRATION || '1h';
        this.refreshTokenExpiry = process.env.JWT_REFRESH_EXPIRATION || '7d';
        this.saltRounds = process.env.SALT_ROUNDS || 10;

        // Setup for nodemailer (Email verification)
        this.mailer = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });
    }

    // Hash user password
    async hashPassword(password) {
        if (!this.isValidPassword(password)) {
            throw new Error('Password does not meet complexity requirements.');
        }
        const salt = await bcrypt.genSalt(this.saltRounds);
        console.log(salt);
        return bcrypt.hash(password, salt);
    }

    // Verify user password
    async verifyPassword(password, hashedPassword) {
        return await bcrypt.compare(password, hashedPassword);
    }

    // Generate JWT Token and Refresh Token
    generateTokens(user) {
        const payload = { id: user.id, email: user.email, role: user.role, additionalData: user.additionalData };
        const accessToken = jwt.sign(payload, this.secretKey, { expiresIn: this.tokenExpiry });
        const refreshToken = jwt.sign(payload, this.secretKey, { expiresIn: this.refreshTokenExpiry });
        return { accessToken, refreshToken };
    }

    // Verify JWT Token
    verifyToken(token) {
        try {
            return jwt.verify(token, this.secretKey);
        } catch (err) {
            throw new Error('Invalid or expired token.');
        }
    }

    // Middleware to protect routes based on roles
    verifyRole(role) {
        return (req, res, next) => {
            try {
                const token = req.header('Authorization')?.replace('Bearer ', '');
                if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });
                const decoded = this.verifyToken(token);
                if (decoded.role !== role) {
                    return res.status(403).json({ message: 'Access denied. Insufficient permissions.' });
                }
                req.user = decoded;
                // Attach user data to request
                next();
            } catch (err) {
                res.status(400).json({ message: err.message, error: true });
            }
        };
    }

    // Refresh token
    refreshToken(token) {
        try {
            const decoded = jwt.verify(token, this.secretKey);
            const newTokens = this.generateTokens(decoded);
            return newTokens;
        } catch (err) {
            throw new Error('Invalid refresh token.');
        }
    }

    // Check if password meets complexity requirements
    isValidPassword(password) {
        const minLength = 8;
        const regex = /^(?=.*[a-zA-Z])(?=.*\d)(?=.*[!@#$%^&*]).+$/; // At least 1 letter, 1 number, and 1 special char
        return password.length >= minLength && regex.test(password);
    }

    // Send email for verification
    async sendVerificationEmail(user) {
        const verificationToken = jwt.sign({ id: user.id }, this.secretKey, { expiresIn: '24h' });
        const verificationUrl = `${process.env.BASE_URL}/verify-email?token=${verificationToken}`;

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Email Verification',
            text: `Please verify your email by clicking the following link: ${verificationUrl}`
        };
        try {
            await this.mailer.sendMail(mailOptions);
        } catch (err) {
            throw new Error('Failed to send verification email.');
        }
    }

    // Email verification route
    async verifyEmail(token) {
        try {
            const decoded = jwt.verify(token, this.secretKey);
            console.log(`Email verified for user ${decoded.id}`);
        } catch (err) {
            throw new Error('Invalid or expired email verification token.');
        }
    }
}

module.exports = Auth;
