-- Security Features Migration
-- Adds tables for advanced security features

-- User devices table for device fingerprinting
CREATE TABLE IF NOT EXISTS user_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    fingerprint VARCHAR(255) NOT NULL,
    device_info TEXT,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    is_active BOOLEAN DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, fingerprint)
);

-- Failed login attempts tracking
CREATE TABLE IF NOT EXISTS failed_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email VARCHAR(255),
    ip_address VARCHAR(45) NOT NULL,
    reason VARCHAR(100),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- IP whitelist table
CREATE TABLE IF NOT EXISTS ip_whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address VARCHAR(45) NOT NULL,
    user_id INTEGER,
    is_global BOOLEAN DEFAULT 0,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(ip_address, user_id)
);

-- Security events logging
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id VARCHAR(36) NOT NULL UNIQUE,
    level VARCHAR(20) NOT NULL,
    category VARCHAR(50) NOT NULL,
    message TEXT NOT NULL,
    user_id INTEGER,
    ip_address VARCHAR(45),
    user_agent TEXT,
    details TEXT,
    risk_score INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id VARCHAR(36) NOT NULL UNIQUE,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100),
    user_id INTEGER,
    ip_address VARCHAR(45),
    user_agent TEXT,
    details TEXT,
    result VARCHAR(20) DEFAULT 'success',
    changes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Security threats table
CREATE TABLE IF NOT EXISTS security_threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    ip_address VARCHAR(45) NOT NULL,
    threats TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    request_data TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Two-factor authentication backup codes
CREATE TABLE IF NOT EXISTS two_factor_backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code_hash VARCHAR(255) NOT NULL,
    used BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Session management table
CREATE TABLE IF NOT EXISTS user_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token VARCHAR(255) NOT NULL UNIQUE,
    device_fingerprint VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    is_active BOOLEAN DEFAULT 1,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Add security columns to users table
ALTER TABLE users ADD COLUMN two_factor_secret VARCHAR(255);
ALTER TABLE users ADD COLUMN two_factor_enabled BOOLEAN DEFAULT 0;
ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until DATETIME;
ALTER TABLE users ADD COLUMN last_password_change DATETIME;
ALTER TABLE users ADD COLUMN password_strength INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN security_questions TEXT;
ALTER TABLE users ADD COLUMN backup_codes_generated BOOLEAN DEFAULT 0;

-- Add security columns to vin_requests table
ALTER TABLE vin_requests ADD COLUMN security_scan_result TEXT;
ALTER TABLE vin_requests ADD COLUMN risk_score INTEGER DEFAULT 0;
ALTER TABLE vin_requests ADD COLUMN device_fingerprint VARCHAR(255);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_devices_user_id ON user_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_user_devices_fingerprint ON user_devices(fingerprint);
CREATE INDEX IF NOT EXISTS idx_failed_attempts_email ON failed_attempts(email);
CREATE INDEX IF NOT EXISTS idx_failed_attempts_ip ON failed_attempts(ip_address);
CREATE INDEX IF NOT EXISTS idx_failed_attempts_created ON failed_attempts(created_at);
CREATE INDEX IF NOT EXISTS idx_ip_whitelist_ip ON ip_whitelist(ip_address);
CREATE INDEX IF NOT EXISTS idx_security_events_user ON security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_ip ON security_events(ip_address);
CREATE INDEX IF NOT EXISTS idx_security_events_created ON security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_security_events_level ON security_events(level);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_security_threats_user ON security_threats(user_id);
CREATE INDEX IF NOT EXISTS idx_security_threats_ip ON security_threats(ip_address);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON user_sessions(is_active);

-- Insert default security settings
INSERT OR IGNORE INTO admin_settings (setting_key, setting_value, description) VALUES 
('security_enabled', 'true', 'Enable advanced security features'),
('two_factor_required', 'false', 'Require 2FA for all users'),
('account_lockout_enabled', 'true', 'Enable account lockout after failed attempts'),
('device_fingerprinting', 'true', 'Enable device fingerprinting'),
('ip_whitelist_enabled', 'false', 'Enable IP whitelisting'),
('max_failed_attempts', '5', 'Maximum failed login attempts before lockout'),
('lockout_duration_minutes', '15', 'Account lockout duration in minutes'),
('session_timeout_minutes', '60', 'Session timeout in minutes'),
('password_min_length', '12', 'Minimum password length'),
('password_require_special', 'true', 'Require special characters in password'),
('security_log_retention_days', '30', 'Security log retention period'),
('audit_log_retention_days', '90', 'Audit log retention period'),
('enable_threat_detection', 'true', 'Enable advanced threat detection'),
('max_devices_per_user', '5', 'Maximum devices per user'),
('enable_encryption', 'true', 'Enable data encryption for sensitive fields');
