/**
 * Advanced Security Middleware for VINaris
 * Implements comprehensive security measures including 2FA, device fingerprinting,
 * account lockout, IP whitelisting, and advanced threat detection
 */

const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { securityConfig, detectSuspiciousActivity } = require('../config/security');
const db = require('../database/db-helper');

// =================== DEVICE FINGERPRINTING ===================

class DeviceFingerprint {
    static generate(req) {
        const components = [
            req.get('User-Agent') || '',
            req.get('Accept-Language') || '',
            req.get('Accept-Encoding') || '',
            req.ip,
            req.get('X-Forwarded-For') || '',
            req.get('X-Real-IP') || ''
        ];
        
        const fingerprint = crypto
            .createHash('sha256')
            .update(components.join('|'))
            .digest('hex');
            
        return fingerprint;
    }
    
    static async validateDevice(userId, fingerprint, req) {
        try {
            await db.connect();
            
            // Check if device is already registered
            const device = await db.get('SELECT * FROM user_devices WHERE user_id = ? AND fingerprint = ?', 
                                     [userId, fingerprint]);
            
            if (device) {
                // Update last seen
                await db.run('UPDATE user_devices SET last_seen = ?, is_active = 1 WHERE id = ?', 
                           [new Date().toISOString(), device.id]);
                return { isValid: true, isNew: false };
            }
            
            // Check if user has reached device limit
            const deviceCount = await db.get('SELECT COUNT(*) as count FROM user_devices WHERE user_id = ? AND is_active = 1', 
                                           [userId]);
            
            if (deviceCount.count >= 5) { // Max 5 devices per user
                return { isValid: false, reason: 'device_limit_exceeded' };
            }
            
            // Register new device
            await db.run(`INSERT INTO user_devices (user_id, fingerprint, device_info, first_seen, last_seen, is_active) 
                         VALUES (?, ?, ?, ?, ?, ?)`, 
                        [userId, fingerprint, JSON.stringify({
                            userAgent: req.get('User-Agent'),
                            ip: req.ip,
                            language: req.get('Accept-Language')
                        }), new Date().toISOString(), new Date().toISOString(), 1]);
            
            return { isValid: true, isNew: true };
            
        } catch (error) {
            console.error('Device validation error:', error);
            return { isValid: false, reason: 'validation_error' };
        } finally {
            db.keepAlive();
        }
    }
}

// =================== ACCOUNT LOCKOUT PROTECTION ===================

class AccountLockout {
    static async checkLockout(email, ip) {
        try {
            await db.connect();
            
            // Check IP-based lockout
            const ipAttempts = await db.get(`SELECT COUNT(*) as count FROM failed_attempts 
                                           WHERE ip_address = ? AND created_at > datetime('now', '-15 minutes')`, 
                                          [ip]);
            
            if (ipAttempts.count >= 10) {
                return { isLocked: true, reason: 'ip_lockout', unlockTime: new Date(Date.now() + 15 * 60 * 1000) };
            }
            
            // Check email-based lockout
            const emailAttempts = await db.get(`SELECT COUNT(*) as count FROM failed_attempts 
                                              WHERE email = ? AND created_at > datetime('now', '-15 minutes')`, 
                                             [email]);
            
            if (emailAttempts.count >= 5) {
                return { isLocked: true, reason: 'email_lockout', unlockTime: new Date(Date.now() + 15 * 60 * 1000) };
            }
            
            return { isLocked: false };
            
        } catch (error) {
            console.error('Lockout check error:', error);
            return { isLocked: false };
        } finally {
            db.keepAlive();
        }
    }
    
    static async recordFailedAttempt(email, ip, reason) {
        try {
            await db.connect();
            await db.run(`INSERT INTO failed_attempts (email, ip_address, reason, created_at) 
                         VALUES (?, ?, ?, ?)`, 
                        [email, ip, reason, new Date().toISOString()]);
        } catch (error) {
            console.error('Failed attempt logging error:', error);
        } finally {
            db.keepAlive();
        }
    }
    
    static async clearFailedAttempts(email, ip) {
        try {
            await db.connect();
            await db.run('DELETE FROM failed_attempts WHERE email = ? OR ip_address = ?', [email, ip]);
        } catch (error) {
            console.error('Clear attempts error:', error);
        } finally {
            db.keepAlive();
        }
    }
}

// =================== TWO-FACTOR AUTHENTICATION ===================

class TwoFactorAuth {
    static generateSecret(userEmail) {
        return speakeasy.generateSecret({
            name: `VINaris (${userEmail})`,
            issuer: 'VINaris',
            length: 32
        });
    }
    
    static async generateQRCode(secret) {
        try {
            return await QRCode.toDataURL(secret.otpauth_url);
        } catch (error) {
            console.error('QR Code generation error:', error);
            return null;
        }
    }
    
    static verifyToken(secret, token) {
        return speakeasy.totp.verify({
            secret: secret.base32,
            encoding: 'base32',
            token: token,
            window: 2 // Allow 2 time windows for clock drift
        });
    }
    
    static async enable2FA(userId, secret, token) {
        try {
            // Verify the token first
            if (!this.verifyToken(secret, token)) {
                return { success: false, message: 'Invalid verification code' };
            }
            
            await db.connect();
            
            // Store the secret
            await db.run('UPDATE users SET two_factor_secret = ?, two_factor_enabled = 1 WHERE id = ?', 
                        [secret.base32, userId]);
            
            db.keepAlive();
            
            return { success: true, message: '2FA enabled successfully' };
            
        } catch (error) {
            console.error('2FA enable error:', error);
            return { success: false, message: 'Failed to enable 2FA' };
        }
    }
    
    static async disable2FA(userId, token) {
        try {
            await db.connect();
            
            // Get user's 2FA secret
            const user = await db.get('SELECT two_factor_secret FROM users WHERE id = ?', [userId]);
            
            if (!user.two_factor_secret) {
                return { success: false, message: '2FA not enabled' };
            }
            
            // Verify the token
            if (!this.verifyToken({ base32: user.two_factor_secret }, token)) {
                return { success: false, message: 'Invalid verification code' };
            }
            
            // Disable 2FA
            await db.run('UPDATE users SET two_factor_secret = NULL, two_factor_enabled = 0 WHERE id = ?', [userId]);
            
            db.keepAlive();
            
            return { success: true, message: '2FA disabled successfully' };
            
        } catch (error) {
            console.error('2FA disable error:', error);
            return { success: false, message: 'Failed to disable 2FA' };
        }
    }
}

// =================== IP WHITELISTING ===================

class IPWhitelist {
    static async isWhitelisted(ip, userId = null) {
        try {
            await db.connect();
            
            // Check global whitelist
            const globalWhitelist = await db.get('SELECT COUNT(*) as count FROM ip_whitelist WHERE ip_address = ? AND is_global = 1', [ip]);
            
            if (globalWhitelist.count > 0) {
                return { isWhitelisted: true, reason: 'global' };
            }
            
            // Check user-specific whitelist
            if (userId) {
                const userWhitelist = await db.get('SELECT COUNT(*) as count FROM ip_whitelist WHERE ip_address = ? AND user_id = ?', [ip, userId]);
                
                if (userWhitelist.count > 0) {
                    return { isWhitelisted: true, reason: 'user' };
                }
            }
            
            return { isWhitelisted: false };
            
        } catch (error) {
            console.error('IP whitelist check error:', error);
            return { isWhitelisted: false };
        } finally {
            db.keepAlive();
        }
    }
    
    static async addToWhitelist(ip, userId = null, description = '') {
        try {
            await db.connect();
            
            await db.run(`INSERT INTO ip_whitelist (ip_address, user_id, is_global, description, created_at) 
                         VALUES (?, ?, ?, ?, ?)`, 
                        [ip, userId, userId ? 0 : 1, description, new Date().toISOString()]);
            
            return { success: true };
            
        } catch (error) {
            console.error('Add to whitelist error:', error);
            return { success: false, message: 'Failed to add IP to whitelist' };
        } finally {
            db.keepAlive();
        }
    }
}

// =================== ADVANCED THREAT DETECTION ===================

class ThreatDetection {
    static async analyzeRequest(req, user = null) {
        const threats = [];
        const riskScore = 0;
        
        // Check for SQL injection patterns
        const sqlPatterns = [
            /union.*select/i,
            /drop.*table/i,
            /insert.*into/i,
            /delete.*from/i,
            /update.*set/i,
            /or.*1=1/i,
            /'or'1'='1/i
        ];
        
        const requestData = JSON.stringify(req.body) + req.originalUrl + req.get('User-Agent');
        
        for (const pattern of sqlPatterns) {
            if (pattern.test(requestData)) {
                threats.push('sql_injection_attempt');
                riskScore += 50;
            }
        }
        
        // Check for XSS patterns
        const xssPatterns = [
            /<script/i,
            /javascript:/i,
            /onload=/i,
            /onerror=/i,
            /onclick=/i,
            /eval\(/i,
            /expression\(/i
        ];
        
        for (const pattern of xssPatterns) {
            if (pattern.test(requestData)) {
                threats.push('xss_attempt');
                riskScore += 30;
            }
        }
        
        // Check for suspicious user agent
        const suspiciousUserAgents = [
            /bot/i,
            /crawler/i,
            /scraper/i,
            /wget/i,
            /curl/i,
            /python/i,
            /php/i
        ];
        
        const userAgent = req.get('User-Agent') || '';
        for (const pattern of suspiciousUserAgents) {
            if (pattern.test(userAgent)) {
                threats.push('suspicious_user_agent');
                riskScore += 20;
            }
        }
        
        // Check for rapid requests
        if (user) {
            const recentRequests = await this.getRecentRequestCount(user.id, 60); // Last minute
            if (recentRequests > 30) {
                threats.push('rapid_requests');
                riskScore += 40;
            }
        }
        
        return {
            threats,
            riskScore,
            isHighRisk: riskScore > 70,
            isMediumRisk: riskScore > 40 && riskScore <= 70,
            isLowRisk: riskScore > 0 && riskScore <= 40
        };
    }
    
    static async getRecentRequestCount(userId, seconds) {
        try {
            await db.connect();
            const result = await db.get(`SELECT COUNT(*) as count FROM user_activities 
                                       WHERE user_id = ? AND created_at > datetime('now', '-${seconds} seconds')`, 
                                      [userId]);
            db.keepAlive();
            return result.count;
        } catch (error) {
            console.error('Recent request count error:', error);
            return 0;
        }
    }
    
    static async logThreat(userId, ip, threats, riskScore, requestData) {
        try {
            await db.connect();
            await db.run(`INSERT INTO security_threats (user_id, ip_address, threats, risk_score, request_data, created_at) 
                         VALUES (?, ?, ?, ?, ?, ?)`, 
                        [userId, ip, JSON.stringify(threats), riskScore, JSON.stringify(requestData), new Date().toISOString()]);
            db.keepAlive();
        } catch (error) {
            console.error('Threat logging error:', error);
        }
    }
}

// =================== MIDDLEWARE FUNCTIONS ===================

// Device fingerprinting middleware
const deviceFingerprintMiddleware = async (req, res, next) => {
    if (process.env.ENABLE_DEVICE_FINGERPRINTING === 'true') {
        req.deviceFingerprint = DeviceFingerprint.generate(req);
    }
    next();
};

// Account lockout middleware
const accountLockoutMiddleware = async (req, res, next) => {
    if (process.env.ENABLE_ACCOUNT_LOCKOUT === 'true' && req.body && req.body.email) {
        try {
            const lockoutStatus = await AccountLockout.checkLockout(req.body.email, req.ip);
            
            if (lockoutStatus.isLocked) {
                return res.status(423).json({
                    error: 'Account temporarily locked',
                    message: `Too many failed attempts. Please try again after ${lockoutStatus.unlockTime.toISOString()}`,
                    unlockTime: lockoutStatus.unlockTime
                });
            }
        } catch (error) {
            console.error('Account lockout check error:', error);
            // Continue if lockout check fails
        }
    }
    next();
};

// IP whitelist middleware
const ipWhitelistMiddleware = async (req, res, next) => {
    if (process.env.ENABLE_IP_WHITELIST === 'true') {
        try {
            const whitelistStatus = await IPWhitelist.isWhitelisted(req.ip, req.user?.id);
            
            if (!whitelistStatus.isWhitelisted) {
                return res.status(403).json({
                    error: 'Access denied',
                    message: 'Your IP address is not whitelisted'
                });
            }
        } catch (error) {
            console.error('IP whitelist check error:', error);
            // Continue if whitelist check fails
        }
    }
    next();
};

// Advanced threat detection middleware
const threatDetectionMiddleware = async (req, res, next) => {
    try {
        const analysis = await ThreatDetection.analyzeRequest(req, req.user);
        
        if (analysis.isHighRisk) {
            await ThreatDetection.logThreat(req.user?.id, req.ip, analysis.threats, analysis.riskScore, {
                url: req.originalUrl,
                method: req.method,
                body: req.body,
                userAgent: req.get('User-Agent')
            });
            
            return res.status(400).json({
                error: 'Request blocked',
                message: 'Suspicious activity detected',
                threats: analysis.threats
            });
        }
        
        if (analysis.isMediumRisk) {
            await ThreatDetection.logThreat(req.user?.id, req.ip, analysis.threats, analysis.riskScore, {
                url: req.originalUrl,
                method: req.method,
                body: req.body,
                userAgent: req.get('User-Agent')
            });
        }
    } catch (error) {
        console.error('Threat detection error:', error);
        // Continue if threat detection fails
    }
    
    next();
};

// Enhanced rate limiting with IP-based and user-based limits
const createAdvancedRateLimit = (options) => {
    return rateLimit({
        ...options,
        keyGenerator: (req) => {
            // Use user ID if authenticated, otherwise IP
            return req.user ? `user:${req.user.id}` : `ip:${req.ip}`;
        },
        skip: (req) => {
            // Skip rate limiting for whitelisted IPs
            return process.env.ENABLE_IP_WHITELIST === 'true' && 
                   IPWhitelist.isWhitelisted(req.ip, req.user?.id).then(result => result.isWhitelisted);
        }
    });
};

module.exports = {
    DeviceFingerprint,
    AccountLockout,
    TwoFactorAuth,
    IPWhitelist,
    ThreatDetection,
    deviceFingerprintMiddleware,
    accountLockoutMiddleware,
    ipWhitelistMiddleware,
    threatDetectionMiddleware,
    createAdvancedRateLimit
};
