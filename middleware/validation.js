/**
 * Input Validation Middleware for VINaris API
 * Comprehensive input sanitization and validation
 */

const Joi = require('joi');
const { sanitizeInput, securityConfig } = require('../config/security');

// Common validation schemas
const schemas = {
    email: Joi.string().email().max(255).required(),
    password: Joi.string().min(8).max(128).pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]).{8,}$/).required(),
    name: Joi.string().min(2).max(100).pattern(/^[a-zA-Z\s\-'\.]+$/).required(),
    vin: Joi.string().length(17).pattern(/^[A-HJ-NPR-Z0-9]{17}$/).required(),
    phone: Joi.string().pattern(/^[\+]?[1-9][\d]{0,15}$/).allow('').optional(),
    company: Joi.string().max(100).allow('').optional(),
    id: Joi.number().integer().positive().required(),
    uuid: Joi.string().uuid().required(),
    pagination: {
        limit: Joi.number().integer().min(1).max(100).default(20),
        offset: Joi.number().integer().min(0).default(0)
    }
};

// Input sanitization middleware
const sanitizeInputs = (req, res, next) => {
    try {
        // Sanitize body
        if (req.body && typeof req.body === 'object') {
            req.body = sanitizeObject(req.body);
        }
        
        // Sanitize query parameters
        if (req.query && typeof req.query === 'object') {
            req.query = sanitizeObject(req.query);
        }
        
        // Sanitize params
        if (req.params && typeof req.params === 'object') {
            req.params = sanitizeObject(req.params);
        }
        
        next();
    } catch (error) {
        res.status(400).json({
            error: 'Input sanitization failed',
            message: 'Invalid input data'
        });
    }
};

// Recursively sanitize object properties
function sanitizeObject(obj) {
    if (Array.isArray(obj)) {
        return obj.map(item => sanitizeObject(item));
    }
    
    if (obj && typeof obj === 'object') {
        const sanitized = {};
        for (const [key, value] of Object.entries(obj)) {
            const sanitizedKey = sanitizeInput(key);
            sanitized[sanitizedKey] = sanitizeObject(value);
        }
        return sanitized;
    }
    
    if (typeof obj === 'string') {
        return sanitizeInput(obj);
    }
    
    return obj;
}

// Generic validation middleware
const validate = (schema, property = 'body') => {
    return (req, res, next) => {
        const { error, value } = schema.validate(req[property], { 
            abortEarly: false,
            stripUnknown: true,
            convert: true
        });
        
        if (error) {
            const errors = error.details.map(detail => ({
                field: detail.path.join('.'),
                message: detail.message,
                value: detail.context?.value
            }));
            
            return res.status(400).json({
                error: 'Validation failed',
                message: 'Invalid input data',
                details: errors
            });
        }
        
        req[property] = value;
        next();
    };
};

// VIN validation middleware
const validateVIN = (req, res, next) => {
    const vin = req.body.vin || req.params.vin || req.query.vin;
    
    if (!vin) {
        return res.status(400).json({
            error: 'VIN required',
            message: 'VIN parameter is required'
        });
    }
    
    const vinRegex = /^[A-HJ-NPR-Z0-9]{17}$/;
    if (!vinRegex.test(vin.toUpperCase())) {
        return res.status(400).json({
            error: 'Invalid VIN format',
            message: 'VIN must be exactly 17 characters and contain only valid characters (A-H, J-N, P-R, T-Z, 0-9)'
        });
    }
    
    req.body.vin = vin.toUpperCase();
    next();
};

// File upload validation
const validateFileUpload = (req, res, next) => {
    if (!req.file) {
        return res.status(400).json({
            error: 'No file uploaded',
            message: 'File is required'
        });
    }
    
    const { validateFileUpload: validateFile } = require('../config/security');
    const validation = validateFile(req.file);
    
    if (!validation.isValid) {
        return res.status(400).json({
            error: 'File validation failed',
            message: 'Invalid file',
            details: validation.errors
        });
    }
    
    next();
};

// SQL injection prevention
const preventSQLInjection = (req, res, next) => {
    const dangerousPatterns = [
        /union.*select/i,
        /drop.*table/i,
        /insert.*into/i,
        /delete.*from/i,
        /update.*set/i,
        /create.*table/i,
        /alter.*table/i,
        /exec\s*\(/i,
        /execute\s*\(/i,
        /sp_/i,
        /xp_/i,
        /--/,
        /\/\*/,
        /\*\//,
        /'/,
        /"/,
        /;/,
        /<script/i,
        /javascript:/i
    ];
    
    const checkString = (str) => {
        if (typeof str !== 'string') return false;
        return dangerousPatterns.some(pattern => pattern.test(str));
    };
    
    const checkObject = (obj) => {
        if (Array.isArray(obj)) {
            return obj.some(item => checkObject(item));
        }
        
        if (obj && typeof obj === 'object') {
            return Object.values(obj).some(value => checkObject(value));
        }
        
        return checkString(obj);
    };
    
    if (checkObject(req.body) || checkObject(req.query) || checkObject(req.params)) {
        console.warn(`SQL injection attempt detected from ${req.ip}: ${req.method} ${req.originalUrl}`);
        return res.status(400).json({
            error: 'Invalid input',
            message: 'Suspicious input detected'
        });
    }
    
    next();
};

// XSS prevention
const preventXSS = (req, res, next) => {
    const xssPatterns = [
        /<script[^>]*>.*?<\/script>/gi,
        /<iframe[^>]*>.*?<\/iframe>/gi,
        /<object[^>]*>.*?<\/object>/gi,
        /<embed[^>]*>.*?<\/embed>/gi,
        /<link[^>]*>.*?<\/link>/gi,
        /<meta[^>]*>.*?<\/meta>/gi,
        /javascript:/gi,
        /vbscript:/gi,
        /onload\s*=/gi,
        /onerror\s*=/gi,
        /onclick\s*=/gi,
        /onmouseover\s*=/gi,
        /expression\s*\(/gi,
        /eval\s*\(/gi
    ];
    
    const checkForXSS = (obj) => {
        if (Array.isArray(obj)) {
            return obj.some(item => checkForXSS(item));
        }
        
        if (obj && typeof obj === 'object') {
            return Object.values(obj).some(value => checkForXSS(value));
        }
        
        if (typeof obj === 'string') {
            return xssPatterns.some(pattern => pattern.test(obj));
        }
        
        return false;
    };
    
    if (checkForXSS(req.body) || checkForXSS(req.query) || checkForXSS(req.params)) {
        console.warn(`XSS attempt detected from ${req.ip}: ${req.method} ${req.originalUrl}`);
        return res.status(400).json({
            error: 'Invalid input',
            message: 'Potentially malicious input detected'
        });
    }
    
    next();
};

module.exports = {
    schemas,
    sanitizeInputs,
    validate,
    validateVIN,
    validateFileUpload,
    preventSQLInjection,
    preventXSS
};
