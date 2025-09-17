/**
 * Enhanced Security Headers Middleware
 * Implements comprehensive security headers and Content Security Policy
 */

const helmet = require('helmet');

// Content Security Policy configuration
const cspDirectives = {
    defaultSrc: ["'self'"],
    scriptSrc: [
        "'self'",
        "'unsafe-inline'", // Required for inline scripts
        "https://cdnjs.cloudflare.com",
        "https://code.jquery.com"
    ],
    styleSrc: [
        "'self'",
        "'unsafe-inline'", // Required for inline styles
        "https://fonts.googleapis.com",
        "https://cdnjs.cloudflare.com"
    ],
    fontSrc: [
        "'self'",
        "https://fonts.gstatic.com",
        "https://cdnjs.cloudflare.com"
    ],
    imgSrc: [
        "'self'",
        "data:",
        "https:",
        "blob:"
    ],
    connectSrc: [
        "'self'",
        "https://vpic.nhtsa.dot.gov",
        "https://api.vinaris.ge"
    ],
    mediaSrc: ["'self'"],
    objectSrc: ["'none'"],
    childSrc: ["'none'"],
    frameSrc: ["'none'"],
    workerSrc: ["'self'"],
    manifestSrc: ["'self'"],
    formAction: ["'self'"],
    baseUri: ["'self'"],
    upgradeInsecureRequests: []
};

// Security headers configuration
const securityHeaders = {
    // Prevent MIME type sniffing
    'X-Content-Type-Options': 'nosniff',
    
    // Prevent clickjacking
    'X-Frame-Options': 'DENY',
    
    // XSS Protection
    'X-XSS-Protection': '1; mode=block',
    
    // Referrer Policy
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    
    // Permissions Policy
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
    
    // Cross-Origin Policies
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    
    // Cache Control for sensitive pages
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0',
    
    // Server information hiding
    'Server': 'VINaris/1.0',
    
    // Content Security Policy
    'Content-Security-Policy': Object.entries(cspDirectives)
        .map(([key, values]) => `${key} ${values.join(' ')}`)
        .join('; ')
};

// HSTS configuration for production
const hstsConfig = {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
};

// Create security middleware
const createSecurityHeaders = () => {
    return (req, res, next) => {
        // Apply all security headers
        Object.entries(securityHeaders).forEach(([key, value]) => {
            res.setHeader(key, value);
        });
        
        // Apply HSTS in production
        if (process.env.NODE_ENV === 'production') {
            res.setHeader('Strict-Transport-Security', 
                `max-age=${hstsConfig.maxAge}; includeSubDomains; preload`);
        }
        
        // Additional security for API endpoints
        if (req.path.startsWith('/api/')) {
            res.setHeader('X-Content-Type-Options', 'nosniff');
            res.setHeader('X-Frame-Options', 'DENY');
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        }
        
        next();
    };
};

// Helmet configuration
const helmetConfig = helmet({
    contentSecurityPolicy: {
        directives: cspDirectives
    },
    hsts: process.env.NODE_ENV === 'production' ? hstsConfig : false,
    noSniff: true,
    xssFilter: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    crossOriginEmbedderPolicy: { policy: 'require-corp' },
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    hidePoweredBy: true,
    frameguard: { action: 'deny' }
});

module.exports = {
    createSecurityHeaders,
    helmetConfig,
    cspDirectives,
    securityHeaders
};
