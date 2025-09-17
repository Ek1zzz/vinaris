-- Initial data migration for VINaris
-- This migration adds default admin settings and system configurations

-- Insert default admin settings
INSERT OR REPLACE INTO admin_settings (setting_key, setting_value, description) VALUES
    ('default_credits', '3', 'Default credits given to new users'),
    ('auto_processing', 'false', 'Automatically process VIN requests'),
    ('email_notifications', 'true', 'Send email notifications to users'),
    ('max_vin_requests_per_day', '10', 'Maximum VIN requests per user per day'),
    ('maintenance_mode', 'false', 'Enable maintenance mode'),
    ('api_rate_limit', '100', 'API requests per minute limit'),
    ('session_timeout_minutes', '60', 'User session timeout in minutes'),
    ('pdf_storage_path', '/uploads/pdfs/', 'Path for storing PDF files'),
    ('supported_plans', 'basic,premium,business', 'Comma-separated list of supported plans'),
    ('basic_plan_price', '999', 'Basic plan price in cents ($9.99)'),
    ('premium_plan_price', '2499', 'Premium plan price in cents ($24.99)'),
    ('business_plan_price', '19900', 'Business plan price in cents ($199.00)'),
    ('vin_check_cost', '1', 'Credits required per VIN check'),
    ('welcome_credits', '3', 'Free credits given to new users'),
    ('low_credit_threshold', '2', 'Show warning when credits below this number');

-- Create default admin user (password will be hashed in real implementation)
-- For now, storing plain text for development (CHANGE THIS IN PRODUCTION!)
INSERT OR REPLACE INTO users (
    unique_id, 
    name, 
    email, 
    password_hash, 
    user_type, 
    credits,
    total_credits_earned,
    created_at,
    last_activity_at
) VALUES (
    'admin_001',
    'System Administrator',
    'admin@vinaris.ge',
    'admin123', -- In production, this should be bcrypt hashed
    'admin',
    999999,
    999999,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- Insert sample user for testing
INSERT OR REPLACE INTO users (
    unique_id,
    name,
    email,
    password_hash,
    user_type,
    credits,
    total_credits_earned,
    phone,
    company,
    created_at,
    last_activity_at
) VALUES (
    'user_sample_001',
    'Test User',
    'test@example.com',
    'password123', -- In production, this should be bcrypt hashed
    'user',
    5,
    8,
    '+995 555 123 456',
    'Test Company LLC',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

-- Insert welcome credit transaction for sample user
INSERT INTO credit_transactions (
    transaction_id,
    user_id,
    amount,
    transaction_type,
    reason,
    payment_method,
    balance_before,
    balance_after
) VALUES (
    'TXN_' || strftime('%s', 'now') || '_welcome',
    (SELECT id FROM users WHERE email = 'test@example.com'),
    3,
    'bonus',
    'Welcome bonus for new user',
    'system',
    0,
    3
);

-- Insert sample VIN request
INSERT INTO vin_requests (
    request_id,
    user_id,
    vin,
    plan,
    status,
    estimated_completion_time,
    user_agent,
    source
) VALUES (
    'REQ_' || strftime('%s', 'now') || '_sample',
    (SELECT id FROM users WHERE email = 'test@example.com'),
    '1HGCM82633A004352',
    'premium',
    'pending',
    datetime('now', '+2 hours'),
    'Mozilla/5.0 (Sample User Agent)',
    'web'
);

-- Insert sample activity logs
INSERT INTO user_activities (user_id, activity_type, description) VALUES
    ((SELECT id FROM users WHERE email = 'admin@vinaris.ge'), 'system_init', 'System initialized with default admin user'),
    ((SELECT id FROM users WHERE email = 'test@example.com'), 'user_created', 'Sample user account created'),
    ((SELECT id FROM users WHERE email = 'test@example.com'), 'vin_request_created', 'Sample VIN request submitted');

-- Insert cached VIN data sample (for testing)
INSERT INTO vin_data_cache (
    vin,
    data_source,
    cached_data,
    expires_at
) VALUES (
    '1HGCM82633A004352',
    'nhtsa',
    '{"make":"HONDA","model":"ACCORD","year":"2003","bodyClass":"SEDAN 4-DOOR","engineInfo":"2.4L L4 DOHC 16V","transmission":"AUTOMATIC"}',
    datetime('now', '+24 hours')
);
