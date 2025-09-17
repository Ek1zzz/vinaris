/**
 * Security Routes for VINaris
 * Handles 2FA, device management, security settings, and monitoring
 */

const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const { createValidationMiddleware, schemas } = require('../middleware/input-validation');
const { TwoFactorAuth, DeviceFingerprint, IPWhitelist, AccountLockout } = require('../middleware/advanced-security');
const securityMonitor = require('../services/security-monitor');
const db = require('../database/db-helper');

const router = express.Router();

// =================== TWO-FACTOR AUTHENTICATION ===================

// GET /api/security/2fa/setup - Get 2FA setup data
router.get('/2fa/setup', authenticateToken, async (req, res) => {
    try {
        const secret = TwoFactorAuth.generateSecret(req.user.email);
        const qrCode = await TwoFactorAuth.generateQRCode(secret);
        
        res.json({
            success: true,
            secret: secret.base32,
            qrCode: qrCode,
            manualEntryKey: secret.base32
        });
    } catch (error) {
        console.error('2FA setup error:', error);
        res.status(500).json({
            error: '2FA setup failed',
            message: 'Unable to generate 2FA setup data'
        });
    }
});

// POST /api/security/2fa/enable - Enable 2FA
router.post('/2fa/enable', authenticateToken, createValidationMiddleware(schemas.twoFactorEnable), async (req, res) => {
    try {
        const { secret, token } = req.body;
        
        const result = await TwoFactorAuth.enable2FA(req.user.id, { base32: secret }, token);
        
        if (result.success) {
            await securityMonitor.logAuditEvent({
                action: '2fa_enabled',
                resource: 'user_account',
                userId: req.user.id,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                details: { method: 'TOTP' }
            });
        }
        
        res.json(result);
    } catch (error) {
        console.error('2FA enable error:', error);
        res.status(500).json({
            error: '2FA enable failed',
            message: 'Unable to enable 2FA'
        });
    }
});

// POST /api/security/2fa/disable - Disable 2FA
router.post('/2fa/disable', authenticateToken, createValidationMiddleware(schemas.twoFactorDisable), async (req, res) => {
    try {
        const { token } = req.body;
        
        const result = await TwoFactorAuth.disable2FA(req.user.id, token);
        
        if (result.success) {
            await securityMonitor.logAuditEvent({
                action: '2fa_disabled',
                resource: 'user_account',
                userId: req.user.id,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });
        }
        
        res.json(result);
    } catch (error) {
        console.error('2FA disable error:', error);
        res.status(500).json({
            error: '2FA disable failed',
            message: 'Unable to disable 2FA'
        });
    }
});

// POST /api/security/2fa/verify - Verify 2FA token
router.post('/2fa/verify', createValidationMiddleware(schemas.twoFactorVerify), async (req, res) => {
    try {
        const { email, token } = req.body;
        
        await db.connect();
        const user = await db.getUserByEmail(email);
        
        if (!user || !user.two_factor_enabled) {
            db.keepAlive();
            return res.status(400).json({
                error: '2FA not enabled',
                message: 'Two-factor authentication is not enabled for this account'
            });
        }
        
        const isValid = TwoFactorAuth.verifyToken({ base32: user.two_factor_secret }, token);
        
        if (isValid) {
            await securityMonitor.logAuditEvent({
                action: '2fa_verified',
                resource: 'user_account',
                userId: user.id,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });
            
            res.json({ success: true, message: '2FA token verified' });
        } else {
            await securityMonitor.logSecurityEvent({
                level: 'warning',
                category: 'authentication',
                message: 'Invalid 2FA token provided',
                userId: user.id,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                riskScore: 30
            });
            
            res.status(400).json({
                error: 'Invalid token',
                message: 'The 2FA token is invalid or expired'
            });
        }
        
        db.keepAlive();
    } catch (error) {
        console.error('2FA verify error:', error);
        res.status(500).json({
            error: '2FA verification failed',
            message: 'Unable to verify 2FA token'
        });
    }
});

// =================== DEVICE MANAGEMENT ===================

// GET /api/security/devices - Get user's registered devices
router.get('/devices', authenticateToken, async (req, res) => {
    try {
        await db.connect();
        const devices = await db.all('SELECT * FROM user_devices WHERE user_id = ? ORDER BY last_seen DESC', [req.user.id]);
        db.keepAlive();
        
        res.json({
            success: true,
            devices: devices.map(device => ({
                id: device.id,
                fingerprint: device.fingerprint,
                deviceInfo: JSON.parse(device.device_info || '{}'),
                firstSeen: device.first_seen,
                lastSeen: device.last_seen,
                isActive: device.is_active
            }))
        });
    } catch (error) {
        console.error('Get devices error:', error);
        res.status(500).json({
            error: 'Failed to get devices',
            message: 'Unable to retrieve device information'
        });
    }
});

// DELETE /api/security/devices/:deviceId - Remove a device
router.delete('/devices/:deviceId', authenticateToken, async (req, res) => {
    try {
        const { deviceId } = req.params;
        
        await db.connect();
        const device = await db.get('SELECT * FROM user_devices WHERE id = ? AND user_id = ?', [deviceId, req.user.id]);
        
        if (!device) {
            db.keepAlive();
            return res.status(404).json({
                error: 'Device not found',
                message: 'The specified device was not found'
            });
        }
        
        await db.run('DELETE FROM user_devices WHERE id = ?', [deviceId]);
        db.keepAlive();
        
        await securityMonitor.logAuditEvent({
            action: 'device_removed',
            resource: 'user_device',
            userId: req.user.id,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            details: { deviceId, fingerprint: device.fingerprint }
        });
        
        res.json({ success: true, message: 'Device removed successfully' });
    } catch (error) {
        console.error('Remove device error:', error);
        res.status(500).json({
            error: 'Failed to remove device',
            message: 'Unable to remove the device'
        });
    }
});

// =================== IP WHITELIST MANAGEMENT ===================

// GET /api/security/ip-whitelist - Get IP whitelist
router.get('/ip-whitelist', authenticateToken, async (req, res) => {
    try {
        await db.connect();
        const whitelist = await db.all('SELECT * FROM ip_whitelist WHERE user_id = ? OR is_global = 1 ORDER BY created_at DESC', [req.user.id]);
        db.keepAlive();
        
        res.json({
            success: true,
            whitelist: whitelist.map(entry => ({
                id: entry.id,
                ipAddress: entry.ip_address,
                description: entry.description,
                isGlobal: entry.is_global,
                createdAt: entry.created_at
            }))
        });
    } catch (error) {
        console.error('Get IP whitelist error:', error);
        res.status(500).json({
            error: 'Failed to get IP whitelist',
            message: 'Unable to retrieve IP whitelist'
        });
    }
});

// POST /api/security/ip-whitelist - Add IP to whitelist
router.post('/ip-whitelist', authenticateToken, createValidationMiddleware(schemas.ipWhitelistAdd), async (req, res) => {
    try {
        const { ipAddress, description } = req.body;
        
        const result = await IPWhitelist.addToWhitelist(ipAddress, req.user.id, description);
        
        if (result.success) {
            await securityMonitor.logAuditEvent({
                action: 'ip_whitelist_added',
                resource: 'ip_whitelist',
                userId: req.user.id,
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                details: { ipAddress, description }
            });
        }
        
        res.json(result);
    } catch (error) {
        console.error('Add IP to whitelist error:', error);
        res.status(500).json({
            error: 'Failed to add IP to whitelist',
            message: 'Unable to add IP to whitelist'
        });
    }
});

// DELETE /api/security/ip-whitelist/:id - Remove IP from whitelist
router.delete('/ip-whitelist/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        await db.connect();
        await db.run('DELETE FROM ip_whitelist WHERE id = ? AND user_id = ?', [id, req.user.id]);
        db.keepAlive();
        
        await securityMonitor.logAuditEvent({
            action: 'ip_whitelist_removed',
            resource: 'ip_whitelist',
            userId: req.user.id,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            details: { whitelistId: id }
        });
        
        res.json({ success: true, message: 'IP removed from whitelist' });
    } catch (error) {
        console.error('Remove IP from whitelist error:', error);
        res.status(500).json({
            error: 'Failed to remove IP from whitelist',
            message: 'Unable to remove IP from whitelist'
        });
    }
});

// =================== SECURITY MONITORING ===================

// GET /api/security/events - Get security events
router.get('/events', authenticateToken, async (req, res) => {
    try {
        const filters = {
            userId: req.user.id,
            ...req.query
        };
        
        const events = await securityMonitor.getSecurityEvents(filters);
        
        res.json({
            success: true,
            events: events
        });
    } catch (error) {
        console.error('Get security events error:', error);
        res.status(500).json({
            error: 'Failed to get security events',
            message: 'Unable to retrieve security events'
        });
    }
});

// GET /api/security/audit-logs - Get audit logs
router.get('/audit-logs', authenticateToken, async (req, res) => {
    try {
        const filters = {
            userId: req.user.id,
            ...req.query
        };
        
        const logs = await securityMonitor.getAuditLogs(filters);
        
        res.json({
            success: true,
            logs: logs
        });
    } catch (error) {
        console.error('Get audit logs error:', error);
        res.status(500).json({
            error: 'Failed to get audit logs',
            message: 'Unable to retrieve audit logs'
        });
    }
});

// =================== ACCOUNT SECURITY ===================

// POST /api/security/account/unlock - Unlock account (admin only)
router.post('/account/unlock', authenticateToken, createValidationMiddleware(schemas.accountUnlock), async (req, res) => {
    try {
        if (req.user.type !== 'admin') {
            return res.status(403).json({
                error: 'Access denied',
                message: 'Admin privileges required'
            });
        }
        
        const { email } = req.body;
        
        await AccountLockout.clearFailedAttempts(email, null);
        
        await securityMonitor.logAuditEvent({
            action: 'account_unlocked',
            resource: 'user_account',
            userId: req.user.id,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            details: { targetEmail: email }
        });
        
        res.json({ success: true, message: 'Account unlocked successfully' });
    } catch (error) {
        console.error('Unlock account error:', error);
        res.status(500).json({
            error: 'Failed to unlock account',
            message: 'Unable to unlock the account'
        });
    }
});

// GET /api/security/status - Get security status
router.get('/status', authenticateToken, async (req, res) => {
    try {
        await db.connect();
        const user = await db.get('SELECT * FROM users WHERE id = ?', [req.user.id]);
        db.keepAlive();
        
        res.json({
            success: true,
            security: {
                twoFactorEnabled: user.two_factor_enabled || false,
                failedLoginAttempts: user.failed_login_attempts || 0,
                lockedUntil: user.locked_until,
                lastPasswordChange: user.last_password_change,
                passwordStrength: user.password_strength || 0
            }
        });
    } catch (error) {
        console.error('Get security status error:', error);
        res.status(500).json({
            error: 'Failed to get security status',
            message: 'Unable to retrieve security status'
        });
    }
});

module.exports = router;
