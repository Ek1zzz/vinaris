<?php
/**
 * Database initialization script for VINaris
 * Creates all necessary tables and demo data
 */

$db_path = __DIR__ . '/vinaris.db';

try {
    $pdo = new PDO("sqlite:$db_path");
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    
    // Create users table
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'user',
            credits INTEGER DEFAULT 10,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");
    
    // Create VIN requests table
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS vin_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            vin TEXT NOT NULL,
            plan TEXT NOT NULL DEFAULT 'basic',
            status TEXT NOT NULL DEFAULT 'pending',
            vin_data TEXT,
            carfax_data TEXT,
            report_url TEXT,
            credits_used INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            completed_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ");
    
    // Create VIN data cache table
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS vin_data_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vin TEXT UNIQUE NOT NULL,
            cached_data TEXT NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");
    
    // Create Carfax data table
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS carfax_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vin TEXT UNIQUE NOT NULL,
            vehicle_info TEXT,
            accident_history TEXT,
            service_records TEXT,
            ownership_history TEXT,
            title_info TEXT,
            recall_info TEXT,
            raw_data TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");
    
    // Create admin logs table
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS admin_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            target_user_id INTEGER,
            details TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (admin_id) REFERENCES users (id),
            FOREIGN KEY (target_user_id) REFERENCES users (id)
        )
    ");
    
    // Create system settings table
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS system_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            setting_key TEXT UNIQUE NOT NULL,
            setting_value TEXT NOT NULL,
            description TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");
    
    // Insert demo users
    $demoUsers = [
        ['admin@vinaris.ge', password_hash('admin123', PASSWORD_DEFAULT), 'System Administrator', 'admin', 999999],
        ['manager@vinaris.ge', password_hash('manager123', PASSWORD_DEFAULT), 'Manager User', 'admin', 500],
        ['john.doe@example.com', password_hash('password123', PASSWORD_DEFAULT), 'John Doe', 'user', 50],
        ['jane.smith@example.com', password_hash('password123', PASSWORD_DEFAULT), 'Jane Smith', 'user', 25],
        ['mike.wilson@example.com', password_hash('password123', PASSWORD_DEFAULT), 'Mike Wilson', 'user', 15],
        ['sarah.jones@example.com', password_hash('password123', PASSWORD_DEFAULT), 'Sarah Jones', 'user', 30],
        ['demo@vinaris.ge', password_hash('demo123', PASSWORD_DEFAULT), 'Demo User', 'user', 100],
        ['test@vinaris.ge', password_hash('test123', PASSWORD_DEFAULT), 'Test User', 'user', 5]
    ];
    
    $stmt = $pdo->prepare("INSERT OR IGNORE INTO users (email, password_hash, name, type, credits) VALUES (?, ?, ?, ?, ?)");
    foreach ($demoUsers as $user) {
        $stmt->execute($user);
    }
    
    // Insert system settings
    $settings = [
        ['vin_check_cost', '1', 'Cost in credits for basic VIN check'],
        ['premium_vin_cost', '5', 'Cost in credits for premium VIN check'],
        ['admin_email', 'admin@vinaris.ge', 'Primary admin email'],
        ['max_vin_checks_per_day', '100', 'Maximum VIN checks per user per day'],
        ['vin_cache_duration', '24', 'VIN data cache duration in hours']
    ];
    
    $stmt = $pdo->prepare("INSERT OR IGNORE INTO system_settings (setting_key, setting_value, description) VALUES (?, ?, ?)");
    foreach ($settings as $setting) {
        $stmt->execute($setting);
    }
    
    // Insert some sample VIN requests
    $sampleRequests = [
        [2, '1HGCM82633A004352', 'basic', 'completed', '{"make":"HONDA","model":"Accord","year":"2003"}', null, null, 1, '2025-09-08 10:00:00', '2025-09-08 10:01:00'],
        [3, '1HGBH41JXMN109186', 'premium', 'completed', '{"make":"HONDA","model":"Civic","year":"2021"}', '{"accidents":0,"services":5}', null, 5, '2025-09-08 10:30:00', '2025-09-08 10:32:00'],
        [4, '1FTFW1ET5DFC12345', 'basic', 'pending', null, null, null, 1, '2025-09-08 11:00:00', null]
    ];
    
    $stmt = $pdo->prepare("INSERT OR IGNORE INTO vin_requests (user_id, vin, plan, status, vin_data, carfax_data, report_url, credits_used, created_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    foreach ($sampleRequests as $request) {
        $stmt->execute($request);
    }
    
    echo "Database initialized successfully!\n";
    echo "Tables created: users, vin_requests, vin_data_cache, carfax_data, admin_logs, system_settings\n";
    echo "Demo users inserted: " . count($demoUsers) . "\n";
    echo "Sample VIN requests inserted: " . count($sampleRequests) . "\n";
    
} catch (PDOException $e) {
    echo "Database initialization failed: " . $e->getMessage() . "\n";
}
?>
