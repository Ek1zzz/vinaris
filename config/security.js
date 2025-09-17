/**
 * VINaris Security Configuration
 * Centralized security settings and utilities
 */

const crypto = require('crypto');
const rateLimit = require('express-rate-limit');

// Security configuration
const securityConfig = {
    // Password requirements
    password: {
        minLength: 8,
        maxLength: 128,
        requireUppercase: true,
        requireLowercase: true,
        requireNumbers: true,
        requireSpecialChars: true,
        specialChars: '!@#$%^&*()_+-=[]{}|;:,.<>?',
        maxAttempts: 5,
        lockoutDuration: 15 * 60 * 1000, // 15 minutes
    },

    // Session security
    session: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        rolling: true,
    },

    // JWT security
    jwt: {
        algorithm: 'HS256',
        expiresIn: process.env.JWT_EXPIRES_IN || '24h',
        refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    },

    // Rate limiting
    rateLimits: {
        general: {
            windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
            max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100000, // Very high limit for development
            message: 'Too many requests from this IP, please try again later.',
        },
        auth: {
            windowMs: 15 * 60 * 1000, // 15 minutes
            max: parseInt(process.env.RATE_LIMIT_AUTH_MAX) || 10000, // Very high limit for development
            message: 'Too many authentication attempts, please try again later.',
            keyGenerator: (req) => {
                // Use email if available, otherwise fall back to IP
                const email = req.body?.email || req.query?.email;
                return email ? `auth:${email}` : `auth:${req.ip}`;
            },
        },
        api: {
            windowMs: 60 * 1000, // 1 minute
            max: 1000, // Much higher limit for development
            message: 'API rate limit exceeded, please slow down.',
        },
        upload: {
            windowMs: 60 * 1000, // 1 minute
            max: 100, // Higher limit for development
            message: 'Too many file uploads, please wait before trying again.',
        },
    },

    // File upload security
    upload: {
        maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024, // 10MB
        allowedTypes: (process.env.ALLOWED_FILE_TYPES || 'application/pdf').split(','),
        allowedExtensions: ['.pdf'],
        scanForMalware: true,
        quarantinePath: './uploads/quarantine/',
    },

    // CORS security
    cors: {
        origin: process.env.ENABLE_CORS === 'true' ? true : 
                (process.env.ALLOWED_ORIGINS || 'http://localhost:3000,http://localhost:3001').split(','),
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'X-CSRF-Token'],
        exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
    },

    // Security headers
    headers: {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    },

    // Input validation
    validation: {
        maxStringLength: 1000,
        maxArrayLength: 100,
        maxObjectDepth: 10,
        sanitizeHtml: true,
        escapeSpecialChars: true,
    },

    // Logging
    logging: {
        logFailedAttempts: true,
        logSuspiciousActivity: true,
        logSecurityEvents: true,
        retentionDays: 30,
    },
};

// Password validation function
function validatePassword(password) {
    const errors = [];
    const config = securityConfig.password;

    if (password.length < config.minLength) {
        errors.push(`Password must be at least ${config.minLength} characters long`);
    }
    if (password.length > config.maxLength) {
        errors.push(`Password must be no more than ${config.maxLength} characters long`);
    }
    if (config.requireUppercase && !/[A-Z]/.test(password)) {
        errors.push('Password must contain at least one uppercase letter');
    }
    if (config.requireLowercase && !/[a-z]/.test(password)) {
        errors.push('Password must contain at least one lowercase letter');
    }
    if (config.requireNumbers && !/\d/.test(password)) {
        errors.push('Password must contain at least one number');
    }
    if (config.requireSpecialChars && !new RegExp(`[${config.specialChars.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}]`).test(password)) {
        errors.push(`Password must contain at least one special character: ${config.specialChars}`);
    }

    return {
        isValid: errors.length === 0,
        errors
    };
}

// Input sanitization function
function sanitizeInput(input) {
    if (typeof input === 'string') {
        // Remove null bytes and control characters
        input = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
        
        // Escape HTML entities
        input = input
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;');
    }
    
    return input;
}

// Generate secure random string
function generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}

// Generate CSRF token
function generateCSRFToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Hash sensitive data
function hashSensitiveData(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

// Create rate limiters
function createRateLimiters() {
    return {
        general: rateLimit(securityConfig.rateLimits.general),
        auth: rateLimit(securityConfig.rateLimits.auth),
        api: rateLimit(securityConfig.rateLimits.api),
        upload: rateLimit(securityConfig.rateLimits.upload),
    };
}

// Validate file upload
function validateFileUpload(file) {
    const config = securityConfig.upload;
    const errors = [];

    if (file.size > config.maxFileSize) {
        errors.push(`File size must be less than ${config.maxFileSize / (1024 * 1024)}MB`);
    }

    if (!config.allowedTypes.includes(file.mimetype)) {
        errors.push(`File type ${file.mimetype} is not allowed`);
    }

    const extension = require('path').extname(file.originalname).toLowerCase();
    if (!config.allowedExtensions.includes(extension)) {
        errors.push(`File extension ${extension} is not allowed`);
    }

    return {
        isValid: errors.length === 0,
        errors
    };
}

// Check for suspicious patterns
function detectSuspiciousActivity(req) {
    const suspiciousPatterns = [
        /union.*select/i,
        /drop.*table/i,
        /insert.*into/i,
        /delete.*from/i,
        /update.*set/i,
        /script.*alert/i,
        /javascript:/i,
        /<script/i,
        /eval\(/i,
        /expression\(/i,
    ];

    const userAgent = req.get('User-Agent') || '';
    const url = req.originalUrl || '';
    const body = JSON.stringify(req.body) || '';

    for (const pattern of suspiciousPatterns) {
        if (pattern.test(userAgent) || pattern.test(url) || pattern.test(body)) {
            return true;
        }
    }

    return false;
}

module.exports = {
    securityConfig,
    validatePassword,
    sanitizeInput,
    generateSecureToken,
    generateCSRFToken,
    hashSensitiveData,
    createRateLimiters,
    validateFileUpload,
    detectSuspiciousActivity,
};
