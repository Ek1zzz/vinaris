-- Test data for VINaris development
-- Run this to populate database with sample data for testing

-- Additional test users
INSERT INTO users (unique_id, name, email, password_hash, user_type, credits, phone, company) VALUES
    ('user_dealer_001', 'John Dealer', 'dealer@example.com', 'dealer123', 'user', 15, '+995 555 000 111', 'Auto Dealer LLC'),
    ('user_customer_001', 'Jane Customer', 'jane@example.com', 'customer123', 'user', 2, '+995 555 000 222', null),
    ('user_business_001', 'Business User', 'business@example.com', 'business123', 'user', 25, '+995 555 000 333', 'Fleet Management Inc');

-- Sample VIN requests with various statuses
INSERT INTO vin_requests (request_id, user_id, vin, plan, status, processing_notes, user_agent) VALUES
    ('REQ_' || strftime('%s', 'now') || '_001', 
     (SELECT id FROM users WHERE email = 'dealer@example.com'), 
     '1HGCM82633A004353', 'premium', 'processed', 'Clean vehicle history', 'Sample Browser 1.0'),
    
    ('REQ_' || strftime('%s', 'now') || '_002', 
     (SELECT id FROM users WHERE email = 'jane@example.com'), 
     '1HGCM82633A004354', 'basic', 'processing', 'Currently gathering data', 'Sample Browser 1.0'),
    
    ('REQ_' || strftime('%s', 'now') || '_003', 
     (SELECT id FROM users WHERE email = 'business@example.com'), 
     '1HGCM82633A004355', 'business', 'pending', null, 'Sample Browser 1.0'),
    
    ('REQ_' || strftime('%s', 'now') || '_004', 
     (SELECT id FROM users WHERE email = 'dealer@example.com'), 
     '1HGCM82633A004356', 'premium', 'rejected', 'Invalid VIN number format', 'Sample Browser 1.0'),
    
    ('REQ_' || strftime('%s', 'now') || '_005', 
     (SELECT id FROM users WHERE email = 'jane@example.com'), 
     '1HGCM82633A004357', 'basic', 'processed', 'Report delivered successfully', 'Sample Browser 1.0');

-- Sample credit transactions
INSERT INTO credit_transactions (transaction_id, user_id, amount, transaction_type, reason, payment_method, balance_before, balance_after) VALUES
    ('TXN_purchase_001', 
     (SELECT id FROM users WHERE email = 'dealer@example.com'), 
     10, 'purchase', 'Credit purchase via Stripe', 'stripe', 3, 13),
    
    ('TXN_purchase_002', 
     (SELECT id FROM users WHERE email = 'business@example.com'), 
     20, 'purchase', 'Bulk credit purchase', 'paypal', 3, 23),
    
    ('TXN_deduction_001', 
     (SELECT id FROM users WHERE email = 'dealer@example.com'), 
     -1, 'deduction', 'VIN Check - 1HGCM82633A004353', 'system', 13, 12),
    
    ('TXN_bonus_001', 
     (SELECT id FROM users WHERE email = 'jane@example.com'), 
     2, 'bonus', 'Referral bonus', 'system', 3, 5);

-- Sample user activities
INSERT INTO user_activities (user_id, activity_type, description, metadata) VALUES
    ((SELECT id FROM users WHERE email = 'dealer@example.com'), 'login', 'User logged in', '{"ip": "192.168.1.100"}'),
    ((SELECT id FROM users WHERE email = 'dealer@example.com'), 'vin_request', 'VIN request submitted', '{"vin": "1HGCM82633A004353", "plan": "premium"}'),
    ((SELECT id FROM users WHERE email = 'dealer@example.com'), 'credit_purchase', 'Credits purchased', '{"amount": 10, "method": "stripe"}'),
    ((SELECT id FROM users WHERE email = 'jane@example.com'), 'login', 'User logged in', '{"ip": "192.168.1.101"}'),
    ((SELECT id FROM users WHERE email = 'jane@example.com'), 'profile_update', 'Profile information updated', '{"fields": ["phone", "company"]}'),
    ((SELECT id FROM users WHERE email = 'business@example.com'), 'registration', 'User registered', '{"source": "web", "referrer": "google"}');

-- Sample VIN data cache
INSERT INTO vin_data_cache (vin, data_source, cached_data, expires_at) VALUES
    ('1HGCM82633A004353', 'nhtsa', 
     '{"make":"HONDA","model":"ACCORD","year":"2003","bodyClass":"SEDAN 4-DOOR","engineInfo":"2.4L L4 DOHC 16V","displacement":"2.4L","cylinders":"4","fuel":"GASOLINE","transmission":"AUTOMATIC","driveTrain":"FWD"}', 
     datetime('now', '+24 hours')),
    
    ('1HGCM82633A004354', 'carfax', 
     '{"accidents":[{"date":"2018-05-15","damage":"Minor","severity":"Low"}],"owners":2,"serviceRecords":5,"titleIssues":"None","marketValue":{"retail":"$8,500","trade":"$6,200"}}', 
     datetime('now', '+12 hours')),
    
    ('1HGCM82633A004355', 'autocheck', 
     '{"score":85,"accidents":0,"owners":1,"auctionHistory":[],"titleBrand":"Clean","lastReported":"2024-01-15"}', 
     datetime('now', '+6 hours'));

-- Sample payment records
INSERT INTO payments (payment_id, user_id, amount_cents, currency, payment_method, payment_status, credits_purchased, metadata) VALUES
    ('pay_stripe_001', 
     (SELECT id FROM users WHERE email = 'dealer@example.com'), 
     2999, 'USD', 'stripe', 'completed', 10, 
     '{"stripe_payment_id": "pi_1234567890", "card_last4": "4242"}'),
    
    ('pay_paypal_001', 
     (SELECT id FROM users WHERE email = 'business@example.com'), 
     5999, 'USD', 'paypal', 'completed', 20, 
     '{"paypal_payment_id": "PAY-1234567890", "payer_email": "business@example.com"}'),
    
    ('pay_stripe_002', 
     (SELECT id FROM users WHERE email = 'jane@example.com'), 
     999, 'USD', 'stripe', 'failed', 3, 
     '{"stripe_payment_id": "pi_failed_001", "error": "card_declined"}');

-- Sample API usage tracking
INSERT INTO api_usage (request_id, api_provider, endpoint, request_data, response_data, response_time_ms, status_code, success, cost_cents) VALUES
    ((SELECT id FROM vin_requests WHERE vin = '1HGCM82633A004353'), 
     'nhtsa', '/vehicles/decodevin', 
     '{"vin": "1HGCM82633A004353"}', 
     '{"make": "HONDA", "model": "ACCORD"}', 
     250, 200, 1, 0),
    
    ((SELECT id FROM vin_requests WHERE vin = '1HGCM82633A004354'), 
     'carfax', '/vehicle-history', 
     '{"vin": "1HGCM82633A004354"}', 
     '{"accidents": 1, "owners": 2}', 
     1250, 200, 1, 500),
    
    ((SELECT id FROM vin_requests WHERE vin = '1HGCM82633A004355'), 
     'autocheck', '/score', 
     '{"vin": "1HGCM82633A004355"}', 
     '{"score": 85}', 
     800, 200, 1, 300);
