/**
 * Authentication Middleware for VINaris API
 * Handles JWT token validation and user authorization
 */

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('../database/db-helper');
const { securityConfig, validatePassword, sanitizeInput, generateSecureToken } = require('../config/security');

// JWT token validation middleware
const authenticateToken = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
        
        if (!token) {
            return res.status(401).json({
                error: 'Access token required',
                message: 'Please provide a valid authentication token'
            });
        }
        
        // Verify JWT token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Get user from database
        const user = await db.getUserById(decoded.userId);
        
        if (!user || user.status !== 'active') {
            return res.status(401).json({
                error: 'Invalid token',
                message: 'User not found or account deactivated'
            });
        }
        
        // Add user to request object
        req.user = {
            id: user.id,
            uniqueId: user.unique_id,
            name: user.name,
            email: user.email,
            type: user.user_type,
            credits: user.credits
        };
        
        // Log user activity
        await db.logActivity(user.id, 'api_access', `API access: ${req.method} ${req.path}`, 
                           JSON.stringify({ ip: req.ip, userAgent: req.get('User-Agent') }));
        
        next();
        
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                error: 'Invalid token',
                message: 'Authentication token is invalid'
            });
        }
        
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                error: 'Token expired',
                message: 'Authentication token has expired'
            });
        }
        
        console.error('Authentication error:', error);
        return res.status(500).json({
            error: 'Authentication failed',
            message: 'Internal authentication error'
        });
    }
};

// Admin authorization middleware
const requireAdmin = (req, res, next) => {
    if (!req.user) {
        return res.status(401).json({
            error: 'Authentication required',
            message: 'Please authenticate first'
        });
    }
    
    if (req.user.type !== 'admin') {
        return res.status(403).json({
            error: 'Admin access required',
            message: 'This endpoint requires administrator privileges'
        });
    }
    
    next();
};

// User authorization middleware (user can only access their own data)
const requireOwnership = (req, res, next) => {
    const resourceUserId = req.params.userId || req.body.userId || req.query.userId;
    
    if (!req.user) {
        return res.status(401).json({
            error: 'Authentication required',
            message: 'Please authenticate first'
        });
    }
    
    // Admin can access any user's data
    if (req.user.type === 'admin') {
        return next();
    }
    
    // Regular users can only access their own data
    if (resourceUserId && resourceUserId !== req.user.id.toString()) {
        return res.status(403).json({
            error: 'Access denied',
            message: 'You can only access your own data'
        });
    }
    
    next();
};

// Enhanced password hashing utilities
const hashPassword = async (password) => {
    // Validate password strength before hashing
    const validation = validatePassword(password);
    if (!validation.isValid) {
        throw new Error(`Password validation failed: ${validation.errors.join(', ')}`);
    }
    
    const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || securityConfig.password.minLength;
    return await bcrypt.hash(password, saltRounds);
};

const comparePassword = async (password, hashedPassword) => {
    // Sanitize input to prevent timing attacks
    const sanitizedPassword = sanitizeInput(password);
    return await bcrypt.compare(sanitizedPassword, hashedPassword);
};

// Enhanced JWT token generation
const generateTokens = (user) => {
    const payload = {
        userId: user.id,
        email: user.email,
        type: user.user_type,
        iat: Math.floor(Date.now() / 1000),
        jti: generateSecureToken(16) // Unique token ID for revocation
    };
    
    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
        algorithm: securityConfig.jwt.algorithm,
        expiresIn: securityConfig.jwt.expiresIn,
        issuer: 'vinaris-api',
        audience: 'vinaris-client'
    });
    
    const refreshToken = jwt.sign({ 
        userId: user.id,
        type: 'refresh',
        jti: generateSecureToken(16)
    }, process.env.JWT_SECRET, {
        algorithm: securityConfig.jwt.algorithm,
        expiresIn: securityConfig.jwt.refreshExpiresIn,
        issuer: 'vinaris-api',
        audience: 'vinaris-client'
    });
    
    return { accessToken, refreshToken };
};

// Validate JWT token without middleware (for internal use)
const validateToken = (token) => {
    try {
        return jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
        return null;
    }
};

// Check if user has sufficient credits
const requireCredits = (minimumCredits = 1) => {
    return async (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({
                error: 'Authentication required',
                message: 'Please authenticate first'
            });
        }
        
        // Admins have unlimited credits
        if (req.user.type === 'admin') {
            return next();
        }
        
        // Get fresh credit balance from database
        try {
            const user = await db.getUserById(req.user.id);
            
            if (!user || user.credits < minimumCredits) {
                return res.status(402).json({
                    error: 'Insufficient credits',
                    message: `You need at least ${minimumCredits} credit(s) to perform this action`,
                    currentCredits: user ? user.credits : 0,
                    requiredCredits: minimumCredits
                });
            }
            
            // Update user credits in request object
            req.user.credits = user.credits;
            next();
            
        } catch (error) {
            console.error('Credit check error:', error);
            return res.status(500).json({
                error: 'Credit check failed',
                message: 'Unable to verify credit balance'
            });
        }
    };
};

// Rate limiting for sensitive operations
const createSensitiveRateLimit = (windowMs = 15 * 60 * 1000, max = 5) => {
    const rateLimit = require('express-rate-limit');
    
    return rateLimit({
        windowMs,
        max,
        message: {
            error: 'Too many attempts',
            message: 'Please wait before trying again',
            retryAfter: Math.ceil(windowMs / 1000)
        },
        standardHeaders: true,
        legacyHeaders: false,
    });
};

module.exports = {
    authenticateToken,
    requireAdmin,
    requireOwnership,
    requireCredits,
    hashPassword,
    comparePassword,
    generateTokens,
    validateToken,
    createSensitiveRateLimit
};
