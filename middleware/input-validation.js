/**
 * Enhanced Input Validation and Sanitization Middleware
 * Provides comprehensive input validation, sanitization, and XSS protection
 */

const Joi = require('joi');
const DOMPurify = require('isomorphic-dompurify');
const validator = require('validator');
const { securityConfig } = require('../config/security');

// Custom validation rules
const customValidators = {
    // VIN validation
    vin: Joi.string()
        .length(17)
        .pattern(/^[A-HJ-NPR-Z0-9]{17}$/)
        .required()
        .messages({
            'string.length': 'VIN must be exactly 17 characters',
            'string.pattern.base': 'VIN contains invalid characters'
        }),

    // Email validation with additional checks
    email: Joi.string()
        .email({ tlds: { allow: false } })
        .max(254)
        .required()
        .custom((value, helpers) => {
            if (validator.isEmail(value)) {
                return value.toLowerCase();
            }
            return helpers.error('string.email');
        }),

    // Strong password validation
    password: Joi.string()
        .min(securityConfig.password.minLength)
        .max(securityConfig.password.maxLength)
        .pattern(new RegExp(`^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[${securityConfig.password.specialChars.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}]).*$`))
        .required()
        .messages({
            'string.min': `Password must be at least ${securityConfig.password.minLength} characters`,
            'string.max': `Password must be no more than ${securityConfig.password.maxLength} characters`,
            'string.pattern.base': 'Password must contain uppercase, lowercase, number, and special character'
        }),

    // Phone number validation
    phone: Joi.string()
        .pattern(/^[\+]?[1-9][\d]{0,15}$/)
        .optional()
        .messages({
            'string.pattern.base': 'Invalid phone number format'
        }),

    // Credit amount validation
    credits: Joi.number()
        .integer()
        .min(1)
        .max(10000)
        .required()
        .messages({
            'number.min': 'Credits must be at least 1',
            'number.max': 'Credits cannot exceed 10,000'
        }),

    // File upload validation
    fileUpload: Joi.object({
        fieldname: Joi.string().required(),
        originalname: Joi.string().required(),
        encoding: Joi.string().required(),
        mimetype: Joi.string().valid(...securityConfig.upload.allowedTypes).required(),
        size: Joi.number().max(securityConfig.upload.maxFileSize).required(),
        buffer: Joi.binary().required()
    }),

    // SQL injection pattern detection
    sqlInjection: Joi.string().custom((value, helpers) => {
        const sqlPatterns = [
            /union.*select/i,
            /drop.*table/i,
            /insert.*into/i,
            /delete.*from/i,
            /update.*set/i,
            /or.*1=1/i,
            /'or'1'='1/i,
            /exec\s*\(/i,
            /execute\s*\(/i
        ];

        for (const pattern of sqlPatterns) {
            if (pattern.test(value)) {
                return helpers.error('string.sqlInjection');
            }
        }
        return value;
    }).messages({
        'string.sqlInjection': 'SQL injection attempt detected'
    }),

    // XSS pattern detection
    xss: Joi.string().custom((value, helpers) => {
        const xssPatterns = [
            /<script/i,
            /javascript:/i,
            /onload=/i,
            /onerror=/i,
            /onclick=/i,
            /onmouseover=/i,
            /onfocus=/i,
            /onblur=/i,
            /eval\(/i,
            /expression\(/i,
            /vbscript:/i,
            /data:text\/html/i
        ];

        for (const pattern of xssPatterns) {
            if (pattern.test(value)) {
                return helpers.error('string.xss');
            }
        }
        return value;
    }).messages({
        'string.xss': 'XSS attempt detected'
    })
};

// Validation schemas
const schemas = {
    // User registration
    userRegistration: Joi.object({
        name: Joi.string()
            .min(2)
            .max(100)
            .pattern(/^[a-zA-Z\s\-'\.]+$/)
            .required()
            .messages({
                'string.pattern.base': 'Name contains invalid characters',
                'string.min': 'Name must be at least 2 characters',
                'string.max': 'Name must be no more than 100 characters'
            }),
        email: customValidators.email,
        password: customValidators.password,
        phone: customValidators.phone,
        agreeToTerms: Joi.boolean().valid(true).required()
    }),

    // User login
    userLogin: Joi.object({
        email: customValidators.email,
        password: Joi.string().required(),
        rememberMe: Joi.boolean().default(false)
    }),

    // VIN check
    vinCheck: Joi.object({
        vin: customValidators.vin,
        plan: Joi.string().valid('basic', 'premium', 'business').default('basic')
    }),

    // Credit purchase
    creditPurchase: Joi.object({
        amount: Joi.number().positive().max(10000).required(),
        credits: customValidators.credits,
        paymentMethod: Joi.string().valid('bank_transfer', 'card', 'crypto').required(),
        bankReference: Joi.string().max(100).optional()
    }),

    // Admin operations
    adminUserUpdate: Joi.object({
        userId: Joi.number().integer().positive().required(),
        credits: Joi.number().integer().min(0).max(100000).optional(),
        status: Joi.string().valid('active', 'suspended', 'deleted').optional(),
        userType: Joi.string().valid('user', 'admin', 'moderator').optional()
    }),

    // File upload
    fileUpload: Joi.object({
        file: customValidators.fileUpload.required(),
        description: Joi.string().max(500).optional()
    }),

    // Search/filter parameters
    searchParams: Joi.object({
        query: Joi.string().max(200).optional(),
        page: Joi.number().integer().min(1).max(1000).default(1),
        limit: Joi.number().integer().min(1).max(100).default(20),
        sortBy: Joi.string().valid('created_at', 'name', 'email', 'credits').default('created_at'),
        sortOrder: Joi.string().valid('asc', 'desc').default('desc')
    }),

    // Security-related schemas
    twoFactorEnable: Joi.object({
        secret: Joi.string().required(),
        token: Joi.string().length(6).pattern(/^\d{6}$/).required()
    }),

    twoFactorDisable: Joi.object({
        token: Joi.string().length(6).pattern(/^\d{6}$/).required()
    }),

    twoFactorVerify: Joi.object({
        email: customValidators.email,
        token: Joi.string().length(6).pattern(/^\d{6}$/).required()
    }),

    ipWhitelistAdd: Joi.object({
        ipAddress: Joi.string().ip().required(),
        description: Joi.string().max(200).optional()
    }),

    accountUnlock: Joi.object({
        email: customValidators.email
    })
};

// Sanitization functions
const sanitizers = {
    // HTML sanitization using DOMPurify
    sanitizeHtml: (input) => {
        if (typeof input !== 'string') return input;
        return DOMPurify.sanitize(input, {
            ALLOWED_TAGS: [],
            ALLOWED_ATTR: [],
            KEEP_CONTENT: true
        });
    },

    // SQL injection prevention
    sanitizeSql: (input) => {
        if (typeof input !== 'string') return input;
        return input
            .replace(/['"\\]/g, '')
            .replace(/--/g, '')
            .replace(/\/\*/g, '')
            .replace(/\*\//g, '')
            .replace(/;/g, '');
    },

    // XSS prevention
    sanitizeXss: (input) => {
        if (typeof input !== 'string') return input;
        return input
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;')
            .replace(/\//g, '&#x2F;')
            .replace(/javascript:/gi, '')
            .replace(/on\w+\s*=/gi, '');
    },

    // General input sanitization
    sanitize: (input) => {
        if (typeof input !== 'string') return input;
        
        // Remove null bytes and control characters
        input = input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
        
        // Trim whitespace
        input = input.trim();
        
        // Apply all sanitizers
        input = sanitizers.sanitizeHtml(input);
        input = sanitizers.sanitizeSql(input);
        input = sanitizers.sanitizeXss(input);
        
        return input;
    },

    // Recursive sanitization for objects
    sanitizeObject: (obj) => {
        if (typeof obj === 'string') {
            return sanitizers.sanitize(obj);
        }
        
        if (Array.isArray(obj)) {
            return obj.map(item => sanitizers.sanitizeObject(item));
        }
        
        if (obj && typeof obj === 'object') {
            const sanitized = {};
            for (const [key, value] of Object.entries(obj)) {
                sanitized[sanitizers.sanitize(key)] = sanitizers.sanitizeObject(value);
            }
            return sanitized;
        }
        
        return obj;
    }
};

// Validation middleware factory
const createValidationMiddleware = (schema, options = {}) => {
    return (req, res, next) => {
        const { error, value } = schema.validate(req.body, {
            abortEarly: false,
            stripUnknown: true,
            ...options
        });

        if (error) {
            const errors = error.details.map(detail => ({
                field: detail.path.join('.'),
                message: detail.message,
                value: detail.context?.value
            }));

            return res.status(400).json({
                error: 'Validation Error',
                message: 'Invalid input data',
                details: errors
            });
        }

        // Sanitize the validated data
        req.body = sanitizers.sanitizeObject(value);
        next();
    };
};

// Sanitization middleware
const sanitizationMiddleware = (req, res, next) => {
    // Sanitize request body
    if (req.body) {
        req.body = sanitizers.sanitizeObject(req.body);
    }

    // Sanitize query parameters
    if (req.query) {
        req.query = sanitizers.sanitizeObject(req.query);
    }

    // Sanitize URL parameters
    if (req.params) {
        req.params = sanitizers.sanitizeObject(req.params);
    }

    next();
};

// Rate limiting for validation attempts
const validationRateLimit = require('express-rate-limit')({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50, // Max 50 validation attempts per IP per window
    message: 'Too many validation attempts, please try again later.',
    standardHeaders: true,
    legacyHeaders: false
});

module.exports = {
    customValidators,
    schemas,
    sanitizers,
    createValidationMiddleware,
    sanitizationMiddleware,
    validationRateLimit
};
