/**
 * VINaris Backend API Server
 * Professional VIN checking service with authentication, payments, and real VIN data
 */

require('dotenv').config();

// Set development mode to disable rate limiting
process.env.NODE_ENV = process.env.NODE_ENV || 'development';
process.env.DISABLE_RATE_LIMITING = process.env.DISABLE_RATE_LIMITING || 'true';

// Load development configuration if no .env file exists
if (!process.env.NODE_ENV) {
    const devConfig = require('./config/development');
    Object.keys(devConfig).forEach(key => {
        if (!process.env[key]) {
            process.env[key] = devConfig[key];
        }
    });
}
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

// Import database and utilities
const db = require('./database/db-helper');
const { getConfig } = require('./database/config');

// Import routes (we'll create these)
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const vinRoutes = require('./routes/vin');
const adminRoutes = require('./routes/admin');
const paymentRoutes = require('./routes/payments');
const securityRoutes = require('./routes/security');

const app = express();
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || 'localhost';

// =================== MIDDLEWARE SETUP ===================

// Enhanced security middleware
const { securityConfig, createRateLimiters, detectSuspiciousActivity } = require('./config/security');
const { 
    deviceFingerprintMiddleware, 
    accountLockoutMiddleware, 
    ipWhitelistMiddleware, 
    threatDetectionMiddleware,
    createAdvancedRateLimit 
} = require('./middleware/advanced-security');
const { createSecurityHeaders, helmetConfig } = require('./middleware/security-headers');
const { sanitizationMiddleware, validationRateLimit } = require('./middleware/input-validation');
const securityMonitor = require('./services/security-monitor');

// Enhanced security headers
app.use(helmetConfig);
app.use(createSecurityHeaders());

// Body parsing middleware (must come before security middleware that needs req.body)
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Input sanitization middleware (temporarily disabled for testing)
// app.use(sanitizationMiddleware);

// Device fingerprinting (temporarily disabled for testing)
// app.use(deviceFingerprintMiddleware);

// IP whitelist check (temporarily disabled for testing)
// app.use(ipWhitelistMiddleware);

// Advanced threat detection (temporarily disabled for testing)
// app.use(threatDetectionMiddleware);

// Additional security headers
app.use((req, res, next) => {
    // Add custom security headers
    Object.entries(securityConfig.headers).forEach(([key, value]) => {
        res.setHeader(key, value);
    });
    
    // Detect suspicious activity (temporarily disabled for testing)
    // if (detectSuspiciousActivity(req)) {
    //     console.warn(`Suspicious activity detected from ${req.ip}: ${req.method} ${req.originalUrl}`);
    //     return res.status(400).json({
    //         error: 'Request blocked',
    //         message: 'Suspicious activity detected'
    //     });
    // }
    
    next();
});

// Simplified CORS configuration for development
const corsOptions = {
    origin: true, // Allow all origins in development
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'X-CSRF-Token'],
    exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
    maxAge: 86400 // 24 hours
};

app.use(cors(corsOptions));

// Enhanced rate limiting - Configure based on environment
if (process.env.NODE_ENV === 'development' || process.env.DISABLE_RATE_LIMITING === 'true') {
    // No rate limiting for development
    console.log('🚫 Rate limiting disabled for development');
    const noRateLimit = (req, res, next) => next();
    app.use('/api', noRateLimit);
} else {
    // Production rate limiting
    console.log('🛡️ Rate limiting enabled for production');
    const rateLimiters = createRateLimiters();
    
    // Apply different rate limits to different endpoints
    // Order matters - more specific routes should come first
    app.use('/api/auth', rateLimiters.auth);
    app.use('/api/vin', rateLimiters.api);
    app.use('/api/admin/upload', rateLimiters.upload);
    app.use('/api', rateLimiters.general);
}

// Body parsing middleware already applied above

// Static file serving
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/static', express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname)); // Serve all static files from root directory

// Request logging middleware
app.use((req, res, next) => {
    if (process.env.DEBUG_MODE === 'true') {
        console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - ${req.ip}`);
    }
    next();
});

// =================== ROUTES ===================

// Health check endpoint
app.get('/api/health', async (req, res) => {
    try {
        // Test database connection
        await db.connect();
        const stats = await db.getSystemStats();
        db.keepAlive();
        
        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            version: '1.0.0',
            database: 'connected',
            stats: {
                totalUsers: stats.totalUsers,
                totalRequests: stats.totalRequests,
                pendingRequests: stats.pendingRequests
            }
        });
    } catch (error) {
        console.error('Health check failed:', error);
        res.status(503).json({
            status: 'unhealthy',
            error: 'Database connection failed',
            timestamp: new Date().toISOString()
        });
    }
});

// API Documentation endpoint
app.get('/api', (req, res) => {
    res.json({
        name: 'VINaris API',
        version: '1.0.0',
        description: 'Professional VIN checking service API',
        endpoints: {
            authentication: {
                'POST /api/auth/register': 'Register new user',
                'POST /api/auth/login': 'User login',
                'POST /api/auth/logout': 'User logout',
                'POST /api/auth/refresh': 'Refresh JWT token'
            },
            users: {
                'GET /api/users/profile': 'Get user profile',
                'PUT /api/users/profile': 'Update user profile',
                'GET /api/users/credits': 'Get credit balance',
                'GET /api/users/history': 'Get request history'
            },
            vin: {
                'POST /api/vin/check': 'Submit VIN request',
                'GET /api/vin/requests': 'Get user requests',
                'GET /api/vin/request/:id': 'Get specific request',
                'POST /api/vin/generate-pdf/:id': 'Generate PDF report',
                'GET /api/vin/download/:id': 'Download PDF report'
            },
            payments: {
                'POST /api/payments/create': 'Create payment intent',
                'POST /api/payments/confirm': 'Confirm payment',
                'GET /api/payments/history': 'Payment history'
            },
            admin: {
                'GET /api/admin/dashboard': 'Admin dashboard stats',
                'GET /api/admin/users': 'Manage users',
                'GET /api/admin/requests': 'Manage requests',
                'PUT /api/admin/credits/:userId': 'Adjust user credits'
            }
        },
        documentation: 'Visit /api/docs for detailed API documentation',
        support: 'Contact support@vinaris.ge for technical assistance'
    });
});

// Mount route handlers
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/vin', vinRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/payments', paymentRoutes);
app.use('/api/security', securityRoutes);

// Serve frontend static files in production
if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.join(__dirname, 'public')));
    
    app.get('*', (req, res) => {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    });
}

// =================== ERROR HANDLING ===================

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({
        error: 'Endpoint not found',
        message: `The endpoint ${req.method} ${req.originalUrl} does not exist`,
        availableEndpoints: '/api'
    });
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('Global error handler:', error);
    
    // Validation errors
    if (error.isJoi) {
        return res.status(400).json({
            error: 'Validation Error',
            message: error.details[0].message,
            details: error.details
        });
    }
    
    // JWT errors
    if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({
            error: 'Authentication Error',
            message: 'Invalid or expired token'
        });
    }
    
    // Database errors
    if (error.code === 'SQLITE_CONSTRAINT') {
        return res.status(409).json({
            error: 'Database Constraint Error',
            message: 'The operation violates a database constraint'
        });
    }
    
    // Default server error
    res.status(500).json({
        error: 'Internal Server Error',
        message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong',
        timestamp: new Date().toISOString()
    });
});

// =================== SERVER STARTUP ===================

async function startServer() {
    try {
        // Initialize database
        console.log('🔄 Initializing database...');
        await db.connect();
        
        // Test database connection
        const stats = await db.getSystemStats();
        console.log('✅ Database connected successfully');
        console.log(`📊 Database stats: ${stats.totalUsers} users, ${stats.totalRequests} requests`);
        
        db.keepAlive();
        
        // Create upload directory if it doesn't exist
        const uploadDir = process.env.UPLOAD_PATH || './uploads';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
            console.log(`📁 Created upload directory: ${uploadDir}`);
        }
        
        // Start the server
        const server = app.listen(PORT, HOST, () => {
            console.log('🚀 VINaris API Server Started');
            console.log('=====================================');
            console.log(`🌐 Server running at: http://${HOST}:${PORT}`);
            console.log(`📚 API Documentation: http://${HOST}:${PORT}/api`);
            console.log(`🏥 Health Check: http://${HOST}:${PORT}/api/health`);
            console.log(`🔧 Environment: ${process.env.NODE_ENV}`);
            console.log('=====================================');
            
            if (process.env.NODE_ENV === 'development') {
                console.log('💡 Development Tips:');
                console.log('   - Test endpoints with Postman or curl');
                console.log('   - View database: sqlite3 database/vinaris.db');
                console.log('   - Backup database: npm run backup');
                console.log('   - API docs available at /api endpoint');
            }
        });
        
        // Graceful shutdown
        process.on('SIGTERM', () => {
            console.log('🛑 SIGTERM received, shutting down gracefully...');
            server.close(() => {
                console.log('✅ Server closed');
                process.exit(0);
            });
        });
        
        process.on('SIGINT', () => {
            console.log('🛑 SIGINT received, shutting down gracefully...');
            server.close(() => {
                console.log('✅ Server closed');
                process.exit(0);
            });
        });
        
    } catch (error) {
        console.error('❌ Failed to start server:', error);
        process.exit(1);
    }
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    process.exit(1);
});

// Start the server
startServer();

module.exports = app;
