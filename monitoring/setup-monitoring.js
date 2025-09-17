/**
 * VINaris Monitoring and Logging Setup
 * Production monitoring configuration
 */

const winston = require('winston');
const path = require('path');

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, '../logs');
if (!require('fs').existsSync(logsDir)) {
    require('fs').mkdirSync(logsDir, { recursive: true });
}

// Winston Logger Configuration
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'vinaris-api' },
    transports: [
        // Write all logs with level 'error' and below to error.log
        new winston.transports.File({ 
            filename: path.join(logsDir, 'error.log'), 
            level: 'error',
            maxsize: 5242880, // 5MB
            maxFiles: 5,
        }),
        
        // Write all logs with level 'info' and below to combined.log
        new winston.transports.File({ 
            filename: path.join(logsDir, 'combined.log'),
            maxsize: 5242880, // 5MB
            maxFiles: 5,
        }),
        
        // Security logs
        new winston.transports.File({ 
            filename: path.join(logsDir, 'security.log'), 
            level: 'warn',
            maxsize: 5242880, // 5MB
            maxFiles: 10,
        }),
        
        // Audit logs
        new winston.transports.File({ 
            filename: path.join(logsDir, 'audit.log'),
            maxsize: 5242880, // 5MB
            maxFiles: 20,
        })
    ],
});

// Add console logging in development
if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.simple()
    }));
}

// Performance Monitoring
class PerformanceMonitor {
    constructor() {
        this.metrics = {
            requests: 0,
            errors: 0,
            responseTime: [],
            activeUsers: 0,
            memoryUsage: process.memoryUsage()
        };
    }
    
    recordRequest(responseTime) {
        this.metrics.requests++;
        this.metrics.responseTime.push(responseTime);
        
        // Keep only last 1000 response times
        if (this.metrics.responseTime.length > 1000) {
            this.metrics.responseTime.shift();
        }
    }
    
    recordError() {
        this.metrics.errors++;
    }
    
    getStats() {
        const avgResponseTime = this.metrics.responseTime.length > 0 
            ? this.metrics.responseTime.reduce((a, b) => a + b, 0) / this.metrics.responseTime.length 
            : 0;
            
        return {
            ...this.metrics,
            avgResponseTime: Math.round(avgResponseTime),
            errorRate: this.metrics.requests > 0 ? (this.metrics.errors / this.metrics.requests) * 100 : 0,
            memoryUsage: process.memoryUsage()
        };
    }
}

// Security Monitoring
class SecurityMonitor {
    constructor() {
        this.failedAttempts = new Map();
        this.blockedIPs = new Set();
        this.suspiciousActivity = [];
    }
    
    recordFailedLogin(ip, email) {
        const key = `${ip}-${email}`;
        const attempts = this.failedAttempts.get(key) || 0;
        this.failedAttempts.set(key, attempts + 1);
        
        if (attempts >= 5) {
            this.blockedIPs.add(ip);
            logger.warn('IP blocked for excessive failed login attempts', { ip, email, attempts });
        }
        
        logger.warn('Failed login attempt', { ip, email, attempts: attempts + 1 });
    }
    
    recordSuspiciousActivity(ip, activity, details) {
        this.suspiciousActivity.push({
            timestamp: new Date(),
            ip,
            activity,
            details
        });
        
        logger.warn('Suspicious activity detected', { ip, activity, details });
    }
    
    isBlocked(ip) {
        return this.blockedIPs.has(ip);
    }
    
    clearBlockedIP(ip) {
        this.blockedIPs.delete(ip);
    }
}

// Health Check Monitoring
class HealthMonitor {
    constructor() {
        this.checks = {
            database: { status: 'unknown', lastCheck: null },
            diskSpace: { status: 'unknown', lastCheck: null },
            memory: { status: 'unknown', lastCheck: null },
            api: { status: 'unknown', lastCheck: null }
        };
    }
    
    async checkDatabase() {
        try {
            const db = require('../database/db-helper');
            await db.connect();
            await db.getSystemStats();
            await db.close();
            
            this.checks.database = { status: 'healthy', lastCheck: new Date() };
            return true;
        } catch (error) {
            this.checks.database = { status: 'unhealthy', lastCheck: new Date(), error: error.message };
            logger.error('Database health check failed', { error: error.message });
            return false;
        }
    }
    
    checkDiskSpace() {
        try {
            const fs = require('fs');
            const stats = fs.statSync(__dirname);
            const freeSpace = require('child_process').execSync('df -h /').toString();
            
            this.checks.diskSpace = { status: 'healthy', lastCheck: new Date(), freeSpace };
            return true;
        } catch (error) {
            this.checks.diskSpace = { status: 'unhealthy', lastCheck: new Date(), error: error.message };
            return false;
        }
    }
    
    checkMemory() {
        try {
            const memUsage = process.memoryUsage();
            const memUsagePercent = (memUsage.heapUsed / memUsage.heapTotal) * 100;
            
            const status = memUsagePercent > 90 ? 'critical' : memUsagePercent > 80 ? 'warning' : 'healthy';
            
            this.checks.memory = { 
                status, 
                lastCheck: new Date(), 
                usage: memUsagePercent,
                details: memUsage
            };
            
            if (status !== 'healthy') {
                logger.warn('Memory usage high', { usage: memUsagePercent, details: memUsage });
            }
            
            return status === 'healthy';
        } catch (error) {
            this.checks.memory = { status: 'unhealthy', lastCheck: new Date(), error: error.message };
            return false;
        }
    }
    
    async runAllChecks() {
        await this.checkDatabase();
        this.checkDiskSpace();
        this.checkMemory();
        
        const allHealthy = Object.values(this.checks).every(check => check.status === 'healthy');
        
        if (!allHealthy) {
            logger.error('Health check failed', { checks: this.checks });
        }
        
        return allHealthy;
    }
    
    getHealthStatus() {
        return {
            overall: Object.values(this.checks).every(check => check.status === 'healthy') ? 'healthy' : 'unhealthy',
            checks: this.checks,
            timestamp: new Date()
        };
    }
}

// Initialize monitoring instances
const performanceMonitor = new PerformanceMonitor();
const securityMonitor = new SecurityMonitor();
const healthMonitor = new HealthMonitor();

// Log rotation function
function setupLogRotation() {
    const cron = require('node-cron');
    
    // Run health checks every 5 minutes
    cron.schedule('*/5 * * * *', async () => {
        await healthMonitor.runAllChecks();
    });
    
    // Clean old logs daily
    cron.schedule('0 2 * * *', () => {
        const retentionDays = process.env.LOG_RETENTION_DAYS || 30;
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - retentionDays);
        
        // Clean old log files
        const fs = require('fs');
        const logFiles = fs.readdirSync(logsDir);
        
        logFiles.forEach(file => {
            const filePath = path.join(logsDir, file);
            const stats = fs.statSync(filePath);
            
            if (stats.mtime < cutoffDate) {
                fs.unlinkSync(filePath);
                logger.info('Deleted old log file', { file });
            }
        });
    });
}

// Export monitoring functions
module.exports = {
    logger,
    performanceMonitor,
    securityMonitor,
    healthMonitor,
    setupLogRotation
};
