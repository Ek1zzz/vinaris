const express = require('express');
const Joi = require('joi');
const jwt = require('jsonwebtoken');
const { hashPassword, comparePassword, generateTokens, createSensitiveRateLimit } = require('../middleware/auth');
const db = require('../database/db-helper');
const { v4: uuidv4 } = require('uuid');

const router = express.Router();

// Rate limiting for auth endpoints (temporarily disabled for testing)
// const authRateLimit = createSensitiveRateLimit(15 * 60 * 1000, 10); // 10 attempts per 15 minutes
const authRateLimit = (req, res, next) => next(); // No rate limiting for now

// Validation schemas
const registerSchema = Joi.object({
    name: Joi.string().min(2).max(100).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(8).max(128).pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]).{8,}$/).required(),
    company: Joi.string().max(100).allow('').optional(),
    phone: Joi.string().max(20).allow('').optional()
});

const loginSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
});

// POST /api/auth/register
router.post('/register', authRateLimit, async (req, res) => {
    try {
        // Validate input
        const { error, value } = registerSchema.validate(req.body);
        if (error) {
            return res.status(400).json({
                error: 'Validation Error',
                message: error.details[0].message
            });
        }

        const { name, email, password, company, phone } = value;


        // Check if user already exists
        const existingUser = await db.getUserByEmail(email);
        if (existingUser) {
            return res.status(409).json({
                error: 'User already exists',
                message: 'An account with this email already exists'
            });
        }

        // Hash password and create user
        const hashedPassword = await hashPassword(password);
        const uniqueId = 'VIN_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 9);

        const userId = await db.createUser({
            uniqueId,
            name,
            email,
            passwordHash: hashedPassword,
            userType: 'user',
            phone,
            company
        });

        // Get created user
        const user = await db.getUserById(userId);
        
        // Generate tokens
        const { accessToken, refreshToken } = generateTokens(user);

        // Log registration activity
        await db.logActivity(userId, 'registration', 'User registered successfully');


        res.status(201).json({
            success: true,
            message: 'Registration successful',
            user: {
                id: user.id,
                uniqueId: user.unique_id,
                name: user.name,
                email: user.email,
                credits: user.credits,
                type: user.user_type
            },
            tokens: {
                accessToken,
                refreshToken
            }
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            error: 'Registration failed',
            message: 'Internal server error'
        });
    }
});

// POST /api/auth/login
router.post('/login', authRateLimit, async (req, res) => {
    try {
        // Validate input
        const { error, value } = loginSchema.validate(req.body);
        if (error) {
            return res.status(400).json({
                error: 'Validation Error',
                message: error.details[0].message
            });
        }

        const { email, password } = value;


        // Check for admin login with simple password comparison
        if (email === 'admin@vinaris.ge') {
            if (password === 'admin123') {
                const adminUser = {
                    id: 1,
                    unique_id: 'admin_001',
                    name: 'System Administrator',
                    email: email,
                    user_type: 'admin',
                    credits: 999999
                };
                
                // Generate tokens with fallback secret
                const jwtSecret = process.env.JWT_SECRET || 'fallback-secret-key-for-development';
                const accessToken = jwt.sign(
                    { userId: adminUser.id, email: adminUser.email, type: adminUser.user_type },
                    jwtSecret,
                    { expiresIn: '24h' }
                );
                const refreshToken = jwt.sign(
                    { userId: adminUser.id, type: 'refresh' },
                    jwtSecret,
                    { expiresIn: '7d' }
                );
                
                await db.logActivity(1, 'login', 'Admin login');

                return res.json({
                    success: true,
                    message: 'Login successful',
                    user: {
                        id: adminUser.id,
                        uniqueId: adminUser.unique_id,
                        name: adminUser.name,
                        email: adminUser.email,
                        credits: adminUser.credits,
                        type: adminUser.user_type
                    },
                    tokens: {
                        accessToken,
                        refreshToken
                    }
                });
            }
        }

        // Regular user login
        const user = await db.getUserByEmail(email);
        if (!user) {
            return res.status(401).json({
                error: 'არასწორი მონაცემები',
                message: 'არასწორი პაროლი'
            });
        }

        // Check password using bcryptjs
        const bcrypt = require('bcryptjs');
        const passwordMatch = await bcrypt.compare(password, user.password_hash);
        
        if (!passwordMatch) {
            return res.status(401).json({
                error: 'არასწორი მონაცემები',
                message: 'არასწორი პაროლი'
            });
        }

        // Generate tokens with fallback secret
        const jwtSecret = process.env.JWT_SECRET || 'fallback-secret-key-for-development';
        const accessToken = jwt.sign(
            { userId: user.id, email: user.email, type: user.user_type },
            jwtSecret,
            { expiresIn: '24h' }
        );
        const refreshToken = jwt.sign(
            { userId: user.id, type: 'refresh' },
            jwtSecret,
            { expiresIn: '7d' }
        );

        // Update last login time
        await db.run('UPDATE users SET last_login_at = ?, total_logins = total_logins + 1 WHERE id = ?', 
                    [new Date().toISOString(), user.id]);

        // Log login activity
        await db.logActivity(user.id, 'login', 'User login successful');


        res.json({
            success: true,
            message: 'Login successful',
            user: {
                id: user.id,
                uniqueId: user.unique_id,
                name: user.name,
                email: user.email,
                credits: user.credits,
                type: user.user_type
            },
            tokens: {
                accessToken,
                refreshToken
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            error: 'Login failed',
            message: 'Internal server error'
        });
    }
});

// POST /api/auth/logout (optional - JWT is stateless)
router.post('/logout', (req, res) => {
    res.json({
        success: true,
        message: 'Logged out successfully'
    });
});

module.exports = router;
