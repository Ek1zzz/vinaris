-- VINaris Database Schema
-- SQLite version (easily portable to PostgreSQL)

-- Enable foreign key constraints
PRAGMA foreign_keys = ON;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    unique_id TEXT UNIQUE NOT NULL, -- VIN_timestamp_random format
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    user_type TEXT DEFAULT 'user' CHECK (user_type IN ('user', 'admin')),
    credits INTEGER DEFAULT 3,
    status TEXT DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleted')),
    
    -- Profile information
    phone TEXT,
    company TEXT,
    address TEXT,
    
    -- Statistics
    total_vin_checked INTEGER DEFAULT 0,
    total_credits_earned INTEGER DEFAULT 3,
    total_credits_spent INTEGER DEFAULT 0,
    total_logins INTEGER DEFAULT 0,
    
    -- Preferences
    email_notifications BOOLEAN DEFAULT 1,
    sms_notifications BOOLEAN DEFAULT 0,
    preferred_plan TEXT DEFAULT 'basic',
    
    -- Timestamps
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login_at DATETIME,
    last_activity_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- VIN requests table
CREATE TABLE IF NOT EXISTS vin_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT UNIQUE NOT NULL, -- REQ_timestamp_random format
    user_id INTEGER NOT NULL,
    vin TEXT NOT NULL,
    plan TEXT NOT NULL CHECK (plan IN ('basic', 'premium', 'business')),
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'processed', 'rejected', 'cancelled')),
    priority TEXT DEFAULT 'normal' CHECK (priority IN ('low', 'normal', 'high', 'urgent')),
    
    -- Processing information
    processed_by INTEGER, -- admin user ID
    processing_notes TEXT,
    estimated_completion_time DATETIME,
    
    -- PDF and results
    pdf_filename TEXT,
    pdf_path TEXT,
    pdf_size INTEGER,
    report_data TEXT, -- JSON string with VIN data
    
    -- Metadata
    user_agent TEXT,
    source TEXT DEFAULT 'web',
    ip_address TEXT,
    
    -- Timestamps
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    processed_at DATETIME,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (processed_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Credit transactions table
CREATE TABLE IF NOT EXISTS credit_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    amount INTEGER NOT NULL, -- Positive for credit, negative for debit
    transaction_type TEXT NOT NULL CHECK (transaction_type IN ('purchase', 'bonus', 'deduction', 'refund', 'admin_adjustment')),
    reason TEXT NOT NULL,
    payment_method TEXT, -- stripe, paypal, admin, etc.
    payment_reference TEXT, -- External payment ID
    admin_id INTEGER, -- If admin performed the transaction
    
    -- Balance tracking
    balance_before INTEGER NOT NULL,
    balance_after INTEGER NOT NULL,
    
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE SET NULL
);

-- User activities/audit log table
CREATE TABLE IF NOT EXISTS user_activities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    activity_type TEXT NOT NULL, -- login, logout, vin_request, credit_purchase, etc.
    description TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    metadata TEXT, -- JSON string for additional data
    
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Admin settings table
CREATE TABLE IF NOT EXISTS admin_settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_key TEXT UNIQUE NOT NULL,
    setting_value TEXT NOT NULL,
    description TEXT,
    updated_by INTEGER,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
);

-- VIN data cache table (for caching API responses)
CREATE TABLE IF NOT EXISTS vin_data_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vin TEXT UNIQUE NOT NULL,
    data_source TEXT NOT NULL, -- nhtsa, carfax, autocheck, etc.
    cached_data TEXT NOT NULL, -- JSON string
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Payment records table
CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payment_id TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    amount_cents INTEGER NOT NULL, -- Store in cents to avoid decimal issues
    currency TEXT DEFAULT 'USD',
    payment_method TEXT NOT NULL, -- stripe, paypal, etc.
    payment_status TEXT NOT NULL CHECK (payment_status IN ('pending', 'completed', 'failed', 'refunded')),
    payment_reference TEXT, -- External payment system ID
    credits_purchased INTEGER NOT NULL,
    
    -- Payment metadata
    metadata TEXT, -- JSON string
    
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- API usage tracking table
CREATE TABLE IF NOT EXISTS api_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER,
    api_provider TEXT NOT NULL, -- nhtsa, carfax, etc.
    endpoint TEXT NOT NULL,
    request_data TEXT, -- JSON
    response_data TEXT, -- JSON
    response_time_ms INTEGER,
    status_code INTEGER,
    success BOOLEAN DEFAULT 0,
    cost_cents INTEGER DEFAULT 0, -- API call cost
    
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (request_id) REFERENCES vin_requests(id) ON DELETE SET NULL
);

-- Payment requests table
CREATE TABLE IF NOT EXISTS payment_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payment_request_id TEXT UNIQUE NOT NULL, -- REQ_timestamp_random format
    user_id INTEGER NOT NULL,
    amount DECIMAL(10,2) NOT NULL,
    credits INTEGER NOT NULL,
    currency TEXT DEFAULT 'GEL',
    payment_method TEXT DEFAULT 'bank_transfer',
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'verified', 'approved', 'rejected', 'cancelled')),
    
    -- Payment details
    invoice_number TEXT, -- Invoice number for bank transfer
    bank_reference TEXT, -- Bank transaction reference
    payment_date DATE,
    payment_time TIME,
    payment_amount DECIMAL(10,2),
    
    -- Verification details
    verified_by INTEGER, -- Admin who verified
    verified_at DATETIME,
    verification_notes TEXT,
    
    -- User provided details
    user_notes TEXT,
    contact_phone TEXT,
    
    -- Timestamps
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (verified_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_unique_id ON users(unique_id);
CREATE INDEX IF NOT EXISTS idx_vin_requests_user_id ON vin_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_vin_requests_status ON vin_requests(status);
CREATE INDEX IF NOT EXISTS idx_vin_requests_vin ON vin_requests(vin);
CREATE INDEX IF NOT EXISTS idx_vin_requests_created_at ON vin_requests(created_at);
CREATE INDEX IF NOT EXISTS idx_credit_transactions_user_id ON credit_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_credit_transactions_created_at ON credit_transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_user_activities_user_id ON user_activities(user_id);
CREATE INDEX IF NOT EXISTS idx_user_activities_created_at ON user_activities(created_at);
CREATE INDEX IF NOT EXISTS idx_vin_data_cache_vin ON vin_data_cache(vin);
CREATE INDEX IF NOT EXISTS idx_vin_data_cache_expires_at ON vin_data_cache(expires_at);
CREATE INDEX IF NOT EXISTS idx_payment_requests_user_id ON payment_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_payment_requests_status ON payment_requests(status);
CREATE INDEX IF NOT EXISTS idx_payment_requests_created_at ON payment_requests(created_at);
CREATE INDEX IF NOT EXISTS idx_payment_requests_payment_request_id ON payment_requests(payment_request_id);

-- Create triggers for updated_at timestamps
CREATE TRIGGER IF NOT EXISTS update_users_updated_at 
    AFTER UPDATE ON users
    BEGIN
        UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER IF NOT EXISTS update_vin_requests_updated_at 
    AFTER UPDATE ON vin_requests
    BEGIN
        UPDATE vin_requests SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER IF NOT EXISTS update_payment_requests_updated_at 
    AFTER UPDATE ON payment_requests
    BEGIN
        UPDATE payment_requests SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER IF NOT EXISTS update_payments_updated_at 
    AFTER UPDATE ON payments
    BEGIN
        UPDATE payments SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;
