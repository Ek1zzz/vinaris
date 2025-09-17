const Database = require('better-sqlite3');
const path = require('path');

console.log('🔄 Setting up database...');

// Create database
const dbPath = path.join(__dirname, 'database', 'vinaris.db');
const db = new Database(dbPath);

// Create users table
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        unique_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        user_type TEXT DEFAULT 'user',
        credits INTEGER DEFAULT 3,
        status TEXT DEFAULT 'active',
        phone TEXT,
        company TEXT,
        address TEXT,
        total_vin_checked INTEGER DEFAULT 0,
        total_credits_earned INTEGER DEFAULT 3,
        total_credits_spent INTEGER DEFAULT 0,
        total_logins INTEGER DEFAULT 0,
        email_notifications BOOLEAN DEFAULT 1,
        sms_notifications BOOLEAN DEFAULT 0,
        marketing_emails BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        last_activity DATETIME,
        login_count INTEGER DEFAULT 0,
        failed_login_attempts INTEGER DEFAULT 0,
        account_locked_until DATETIME,
        password_reset_token TEXT,
        password_reset_expires DATETIME,
        email_verified BOOLEAN DEFAULT 0,
        email_verification_token TEXT,
        two_factor_secret TEXT,
        two_factor_enabled BOOLEAN DEFAULT 0,
        backup_codes TEXT,
        preferred_language TEXT DEFAULT 'en',
        timezone TEXT DEFAULT 'UTC',
        profile_picture TEXT,
        notes TEXT
    );
`);

// Create other necessary tables
db.exec(`
    CREATE TABLE IF NOT EXISTS vin_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        vin_code TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        plan_type TEXT NOT NULL,
        credits_used INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        completed_at DATETIME,
        pdf_path TEXT,
        vehicle_info TEXT,
        error_message TEXT,
        priority INTEGER DEFAULT 0,
        processing_notes TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS credit_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        transaction_type TEXT NOT NULL,
        amount INTEGER NOT NULL,
        balance_after INTEGER NOT NULL,
        description TEXT,
        reference_id TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        created_by TEXT DEFAULT 'system',
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
`);

console.log('✅ Database tables created successfully!');
db.close();
console.log('✅ Database setup complete!');
