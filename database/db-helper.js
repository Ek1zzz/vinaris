/**
 * VINaris Database Helper
 * Simple SQLite database operations for development
 * Easy to migrate to PostgreSQL later
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');

class DatabaseHelper {
    constructor() {
        this.dbPath = path.join(__dirname, 'vinaris.db');
        this.db = null;
        this.isConnecting = false;
    }

    // Connect to database
    async connect() {
        // Always create a fresh connection for each operation
        if (this.db) {
            try {
                this.db.close();
            } catch (e) {
                // Ignore close errors
            }
            this.db = null;
        }
        
        return new Promise((resolve, reject) => {
            this.db = new sqlite3.Database(this.dbPath, (err) => {
                if (err) {
                    console.error('Database connection error:', err);
                    reject(err);
                } else {
                    console.log('✅ Connected to SQLite database');
                    resolve();
                }
            });
        });
    }

    // Close database connection (only when shutting down)
    close() {
        return new Promise((resolve) => {
            if (this.db && this.db.open) {
                this.db.close((err) => {
                    if (err && err.code !== 'SQLITE_MISUSE') {
                        console.error('Database close error:', err);
                    } else if (!err) {
                        console.log('📤 Database connection closed');
                    }
                    this.db = null;
                    resolve();
                });
            } else {
                resolve();
            }
        });
    }

    // Close connection after operation to avoid SQLITE_MISUSE errors
    keepAlive() {
        // Close the connection after each operation to ensure clean state
        if (this.db && this.db.open) {
            try {
                this.db.close();
                console.log('📤 Database connection closed');
            } catch (e) {
                // Ignore close errors
            }
            this.db = null;
        }
    }

    // Run a query
    async run(sql, params = []) {
        return new Promise((resolve, reject) => {
            const db = new sqlite3.Database(this.dbPath, (err) => {
                if (err) {
                    reject(err);
                    return;
                }
                
                db.run(sql, params, function(err) {
                    if (err) {
                        reject(err);
                    } else {
                        resolve({
                            id: this.lastID,
                            changes: this.changes
                        });
                    }
                    db.close();
                });
            });
        });
    }

    // Get single row
    async get(sql, params = []) {
        return new Promise((resolve, reject) => {
            const db = new sqlite3.Database(this.dbPath, (err) => {
                if (err) {
                    reject(err);
                    return;
                }
                
                db.get(sql, params, (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                    db.close();
                });
            });
        });
    }

    // Get multiple rows
    async all(sql, params = []) {
        return new Promise((resolve, reject) => {
            const db = new sqlite3.Database(this.dbPath, (err) => {
                if (err) {
                    reject(err);
                    return;
                }
                
                db.all(sql, params, (err, rows) => {
                    if (err) reject(err);
                    else resolve(rows);
                    db.close();
                });
            });
        });
    }

    // User operations
    async createUser(userData) {
        const sql = `
            INSERT INTO users (unique_id, name, email, password_hash, user_type, phone, company)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        const params = [
            userData.uniqueId,
            userData.name,
            userData.email,
            userData.passwordHash,
            userData.userType || 'user',
            userData.phone || null,
            userData.company || null
        ];
        
        const result = await this.run(sql, params);
        
        // Add welcome credits
        if (userData.userType !== 'admin') {
            await this.addCredits(result.id, 3, 'Welcome bonus', 'system');
        }
        
        return result.id;
    }

    async getUserByEmail(email) {
        const sql = 'SELECT * FROM users WHERE email = ? AND status = "active"';
        return await this.get(sql, [email]);
    }

    async getUserById(userId) {
        const sql = 'SELECT * FROM users WHERE id = ?';
        return await this.get(sql, [userId]);
    }

    // VIN request operations
    async createVinRequest(requestData) {
        const sql = `
            INSERT INTO vin_requests (
                request_id, user_id, vin, plan, user_agent, source, ip_address
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        const params = [
            requestData.requestId,
            requestData.userId,
            requestData.vin.toUpperCase(),
            requestData.plan,
            requestData.userAgent || null,
            requestData.source || 'web',
            requestData.ipAddress || null
        ];
        
        const result = await this.run(sql, params);
        
        // Deduct credit
        await this.deductCredits(requestData.userId, 1, `VIN Check - ${requestData.vin}`);
        
        return result.id;
    }

    async getVinRequestsByUser(userId) {
        const sql = `
            SELECT * FROM vin_requests 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        `;
        return await this.all(sql, [userId]);
    }

    async getAllVinRequests() {
        const sql = `
            SELECT vr.*, u.name as user_name, u.email as user_email
            FROM vin_requests vr
            JOIN users u ON vr.user_id = u.id
            ORDER BY vr.created_at DESC
        `;
        return await this.all(sql);
    }

    async updateVinRequestStatus(requestId, status, adminId = null, notes = '') {
        const sql = `
            UPDATE vin_requests 
            SET status = ?, processed_by = ?, processing_notes = ?, processed_at = ?, updated_at = CURRENT_TIMESTAMP
            WHERE request_id = ?
        `;
        // Set processed_at for any non-pending status (processed, rejected, delivered)
        const processedAt = status !== 'pending' ? new Date().toISOString() : null;
        return await this.run(sql, [status, adminId, notes, processedAt, requestId]);
    }

    // Credit operations
    async addCredits(userId, amount, reason, paymentMethod = 'admin', adminId = null) {
        const user = await this.getUserById(userId);
        if (!user) throw new Error('User not found');

        const balanceBefore = user.credits;
        const balanceAfter = balanceBefore + amount;

        // Update user credits
        await this.run('UPDATE users SET credits = ? WHERE id = ?', [balanceAfter, userId]);

        // Log transaction
        const transactionId = 'TXN_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 9);
        await this.run(`
            INSERT INTO credit_transactions (
                transaction_id, user_id, amount, transaction_type, reason, 
                payment_method, admin_id, balance_before, balance_after
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [transactionId, userId, amount, 'admin_adjustment', reason, paymentMethod, adminId, balanceBefore, balanceAfter]);

        return balanceAfter;
    }

    async deductCredits(userId, amount, reason) {
        const user = await this.getUserById(userId);
        if (!user) throw new Error('User not found');
        if (user.credits < amount) throw new Error('Insufficient credits');

        const balanceBefore = user.credits;
        const balanceAfter = balanceBefore - amount;

        // Update user credits
        await this.run('UPDATE users SET credits = ?, total_credits_spent = total_credits_spent + ? WHERE id = ?', 
                      [balanceAfter, amount, userId]);

        // Log transaction
        const transactionId = 'TXN_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 9);
        await this.run(`
            INSERT INTO credit_transactions (
                transaction_id, user_id, amount, transaction_type, reason, 
                payment_method, balance_before, balance_after
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [transactionId, userId, -amount, 'deduction', reason, 'system', balanceBefore, balanceAfter]);

        return balanceAfter;
    }

    async getCreditTransactions(userId) {
        const sql = `
            SELECT * FROM credit_transactions 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        `;
        return await this.all(sql, [userId]);
    }

    // Activity logging
    async logActivity(userId, activityType, description, metadata = null) {
        const sql = `
            INSERT INTO user_activities (user_id, activity_type, description, metadata)
            VALUES (?, ?, ?, ?)
        `;
        return await this.run(sql, [userId, activityType, description, metadata]);
    }

    async getUserActivities(userId, limit = 50) {
        const sql = `
            SELECT * FROM user_activities 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT ?
        `;
        return await this.all(sql, [userId, limit]);
    }

    // Admin operations
    async getAllUsers() {
        const sql = `
            SELECT u.*, 
                   COUNT(vr.id) as total_requests,
                   COUNT(CASE WHEN vr.status = 'pending' THEN 1 END) as pending_requests
            FROM users u
            LEFT JOIN vin_requests vr ON u.id = vr.user_id
            WHERE u.status = 'active'
            GROUP BY u.id
            ORDER BY u.created_at DESC
        `;
        return await this.all(sql);
    }

    async getSystemStats() {
        const stats = {};
        
        // User stats
        stats.totalUsers = (await this.get('SELECT COUNT(*) as count FROM users WHERE status = "active"')).count;
        stats.totalAdmins = (await this.get('SELECT COUNT(*) as count FROM users WHERE user_type = "admin"')).count;
        
        // Request stats
        stats.totalRequests = (await this.get('SELECT COUNT(*) as count FROM vin_requests')).count;
        stats.pendingRequests = (await this.get('SELECT COUNT(*) as count FROM vin_requests WHERE status = "pending"')).count;
        stats.processedRequests = (await this.get('SELECT COUNT(*) as count FROM vin_requests WHERE status = "processed"')).count;
        
        // Credit stats
        stats.totalCreditsIssued = (await this.get('SELECT SUM(total_credits_earned) as total FROM users')).total || 0;
        stats.totalCreditsSpent = (await this.get('SELECT SUM(total_credits_spent) as total FROM users')).total || 0;
        
        // Recent activity
        stats.recentRequests = await this.all(`
            SELECT vr.*, u.name as user_name 
            FROM vin_requests vr 
            JOIN users u ON vr.user_id = u.id 
            ORDER BY vr.created_at DESC 
            LIMIT 10
        `);
        
        return stats;
    }

    // Admin settings
    async getSetting(key) {
        const result = await this.get('SELECT setting_value FROM admin_settings WHERE setting_key = ?', [key]);
        return result ? result.setting_value : null;
    }

    async setSetting(key, value, adminId = null) {
        const sql = `
            INSERT OR REPLACE INTO admin_settings (setting_key, setting_value, updated_by)
            VALUES (?, ?, ?)
        `;
        return await this.run(sql, [key, value, adminId]);
    }
}

// Export singleton instance
const db = new DatabaseHelper();

module.exports = db;

// CLI usage
if (require.main === module) {
    const action = process.argv[2];
    
    (async () => {
        await db.connect();
        
        try {
            switch (action) {
                case 'test':
                    console.log('🧪 Testing database operations...');
                    const stats = await db.getSystemStats();
                    console.log('System Stats:', JSON.stringify(stats, null, 2));
                    break;
                    
                case 'users':
                    const users = await db.getAllUsers();
                    console.log('👥 All Users:');
                    users.forEach(user => {
                        console.log(`${user.id}: ${user.name} (${user.email}) - ${user.credits} credits`);
                    });
                    break;
                    
                case 'requests':
                    const requests = await db.getAllVinRequests();
                    console.log('🚗 All VIN Requests:');
                    requests.forEach(req => {
                        console.log(`${req.request_id}: ${req.vin} (${req.status}) by ${req.user_name}`);
                    });
                    break;
                    
                default:
                    console.log('Usage: node db-helper.js [test|users|requests]');
            }
        } catch (error) {
            console.error('Database operation error:', error);
        } finally {
            await db.close();
        }
    })();
}
