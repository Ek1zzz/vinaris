/**
 * Security Monitoring and Audit Logging Service
 * Comprehensive security event monitoring and logging
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const db = require('../database/db-helper');

class SecurityMonitor {
    constructor() {
        this.logDir = path.join(__dirname, '../logs/security');
        this.auditDir = path.join(__dirname, '../logs/audit');
        this.ensureLogDirectories();
    }

    ensureLogDirectories() {
        [this.logDir, this.auditDir].forEach(dir => {
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
        });
    }

    // Log security events
    async logSecurityEvent(event) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            eventId: crypto.randomUUID(),
            level: event.level || 'info',
            category: event.category || 'security',
            message: event.message,
            userId: event.userId || null,
            ip: event.ip || null,
            userAgent: event.userAgent || null,
            details: event.details || {},
            riskScore: event.riskScore || 0
        };

        // Log to database
        try {
            await db.connect();
            await db.run(`INSERT INTO security_events 
                         (event_id, level, category, message, user_id, ip_address, user_agent, details, risk_score, created_at) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                        [logEntry.eventId, logEntry.level, logEntry.category, logEntry.message, 
                         logEntry.userId, logEntry.ip, logEntry.userAgent, JSON.stringify(logEntry.details), 
                         logEntry.riskScore, logEntry.timestamp]);
            await db.close();
        } catch (error) {
            console.error('Database logging error:', error);
        }

        // Log to file
        this.writeToFile('security', logEntry);

        // Send alerts for high-risk events
        if (event.riskScore > 70) {
            await this.sendSecurityAlert(logEntry);
        }
    }

    // Log audit events
    async logAuditEvent(event) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            eventId: crypto.randomUUID(),
            action: event.action,
            resource: event.resource || null,
            userId: event.userId || null,
            ip: event.ip || null,
            userAgent: event.userAgent || null,
            details: event.details || {},
            result: event.result || 'success',
            changes: event.changes || {}
        };

        // Log to database
        try {
            await db.connect();
            await db.run(`INSERT INTO audit_logs 
                         (event_id, action, resource, user_id, ip_address, user_agent, details, result, changes, created_at) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                        [logEntry.eventId, logEntry.action, logEntry.resource, logEntry.userId, 
                         logEntry.ip, logEntry.userAgent, JSON.stringify(logEntry.details), 
                         logEntry.result, JSON.stringify(logEntry.changes), logEntry.timestamp]);
            await db.close();
        } catch (error) {
            console.error('Database audit logging error:', error);
        }

        // Log to file
        this.writeToFile('audit', logEntry);
    }

    // Write log entry to file
    writeToFile(type, logEntry) {
        const filename = `${type}-${new Date().toISOString().split('T')[0]}.log`;
        const filepath = path.join(type === 'security' ? this.logDir : this.auditDir, filename);
        const logLine = JSON.stringify(logEntry) + '\n';

        fs.appendFileSync(filepath, logLine);
    }

    // Send security alert
    async sendSecurityAlert(logEntry) {
        // In production, this would send email/SMS alerts
        console.warn('🚨 SECURITY ALERT:', {
            level: logEntry.level,
            message: logEntry.message,
            userId: logEntry.userId,
            ip: logEntry.ip,
            riskScore: logEntry.riskScore,
            timestamp: logEntry.timestamp
        });

        // Log to critical security file
        const criticalFile = path.join(this.logDir, 'critical-security.log');
        fs.appendFileSync(criticalFile, JSON.stringify(logEntry) + '\n');
    }

    // Get security events
    async getSecurityEvents(filters = {}) {
        try {
            await db.connect();
            
            let query = 'SELECT * FROM security_events WHERE 1=1';
            const params = [];

            if (filters.userId) {
                query += ' AND user_id = ?';
                params.push(filters.userId);
            }

            if (filters.level) {
                query += ' AND level = ?';
                params.push(filters.level);
            }

            if (filters.category) {
                query += ' AND category = ?';
                params.push(filters.category);
            }

            if (filters.startDate) {
                query += ' AND created_at >= ?';
                params.push(filters.startDate);
            }

            if (filters.endDate) {
                query += ' AND created_at <= ?';
                params.push(filters.endDate);
            }

            query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
            params.push(filters.limit || 100, filters.offset || 0);

            const events = await db.all(query, params);
            await db.close();

            return events;
        } catch (error) {
            console.error('Get security events error:', error);
            return [];
        }
    }

    // Get audit logs
    async getAuditLogs(filters = {}) {
        try {
            await db.connect();
            
            let query = 'SELECT * FROM audit_logs WHERE 1=1';
            const params = [];

            if (filters.userId) {
                query += ' AND user_id = ?';
                params.push(filters.userId);
            }

            if (filters.action) {
                query += ' AND action = ?';
                params.push(filters.action);
            }

            if (filters.resource) {
                query += ' AND resource = ?';
                params.push(filters.resource);
            }

            if (filters.startDate) {
                query += ' AND created_at >= ?';
                params.push(filters.startDate);
            }

            if (filters.endDate) {
                query += ' AND created_at <= ?';
                params.push(filters.endDate);
            }

            query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
            params.push(filters.limit || 100, filters.offset || 0);

            const logs = await db.all(query, params);
            await db.close();

            return logs;
        } catch (error) {
            console.error('Get audit logs error:', error);
            return [];
        }
    }

    // Generate security report
    async generateSecurityReport(startDate, endDate) {
        try {
            await db.connect();

            // Get security events summary
            const eventsSummary = await db.get(`
                SELECT 
                    level,
                    category,
                    COUNT(*) as count,
                    AVG(risk_score) as avg_risk_score
                FROM security_events 
                WHERE created_at BETWEEN ? AND ?
                GROUP BY level, category
                ORDER BY count DESC
            `, [startDate, endDate]);

            // Get top IPs with security events
            const topIPs = await db.all(`
                SELECT 
                    ip_address,
                    COUNT(*) as event_count,
                    MAX(risk_score) as max_risk_score
                FROM security_events 
                WHERE created_at BETWEEN ? AND ?
                GROUP BY ip_address
                ORDER BY event_count DESC
                LIMIT 10
            `, [startDate, endDate]);

            // Get user security activity
            const userActivity = await db.all(`
                SELECT 
                    u.email,
                    u.name,
                    COUNT(se.id) as security_events,
                    MAX(se.risk_score) as max_risk_score
                FROM users u
                LEFT JOIN security_events se ON u.id = se.user_id 
                    AND se.created_at BETWEEN ? AND ?
                GROUP BY u.id, u.email, u.name
                HAVING COUNT(se.id) > 0
                ORDER BY security_events DESC
                LIMIT 20
            `, [startDate, endDate]);

            await db.close();

            return {
                period: { startDate, endDate },
                eventsSummary,
                topIPs,
                userActivity,
                generatedAt: new Date().toISOString()
            };

        } catch (error) {
            console.error('Generate security report error:', error);
            return null;
        }
    }

    // Clean old logs
    async cleanOldLogs(retentionDays = 30) {
        try {
            await db.connect();
            
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - retentionDays);
            
            // Clean database logs
            await db.run('DELETE FROM security_events WHERE created_at < ?', [cutoffDate.toISOString()]);
            await db.run('DELETE FROM audit_logs WHERE created_at < ?', [cutoffDate.toISOString()]);
            
            await db.close();

            // Clean file logs
            this.cleanOldLogFiles(retentionDays);

        } catch (error) {
            console.error('Clean old logs error:', error);
        }
    }

    // Clean old log files
    cleanOldLogFiles(retentionDays) {
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

        [this.logDir, this.auditDir].forEach(dir => {
            if (fs.existsSync(dir)) {
                const files = fs.readdirSync(dir);
                files.forEach(file => {
                    const filePath = path.join(dir, file);
                    const stats = fs.statSync(filePath);
                    
                    if (stats.mtime < cutoffDate) {
                        fs.unlinkSync(filePath);
                    }
                });
            }
        });
    }
}

module.exports = new SecurityMonitor();
