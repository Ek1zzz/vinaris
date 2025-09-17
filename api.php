<?php
/**
 * VINaris API Backend for XAMPP/Apache
 * This file provides API endpoints that work with your existing frontend
 */

// Configure session settings
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 0); // Set to 1 for HTTPS
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_samesite', 'Lax');
ini_set('session.cookie_path', '/');
ini_set('session.cookie_domain', '');

// Start session at the beginning
session_start();

// Enhanced security headers
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');

// Secure CORS headers
$allowed_origins = [
    'http://localhost',
    'http://localhost:3000',
    'http://localhost:3001', 
    'http://localhost:8080',
    'https://vinaris.ge',
    'https://www.vinaris.ge'
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (in_array($origin, $allowed_origins)) {
    header("Access-Control-Allow-Origin: $origin");
} else {
    // For localhost development, allow localhost origins
    if (strpos($origin, 'localhost') !== false || strpos($origin, '127.0.0.1') !== false) {
        header("Access-Control-Allow-Origin: $origin");
    } else {
        header('Access-Control-Allow-Origin: null');
    }
}

header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, Accept, X-CSRF-Token');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Max-Age: 86400');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Simple routing
$request_uri = $_SERVER['REQUEST_URI'];
$path = parse_url($request_uri, PHP_URL_PATH);

// Remove the base path to get the API endpoint
if (strpos($path, '/Vinaris/api.php') === 0) {
    $path = substr($path, strlen('/Vinaris/api.php'));
} elseif (strpos($path, '/api.php') === 0) {
    $path = substr($path, strlen('/api.php'));
}

// Ensure path starts with /
if ($path && $path[0] !== '/') {
    $path = '/' . $path;
}

// Database connection
$db_path = __DIR__ . '/database/vinaris.db';
$pdo = new PDO("sqlite:$db_path");
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Initialize database if it doesn't exist
try {
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
    
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS vin_data_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vin TEXT UNIQUE NOT NULL,
            data_source TEXT NOT NULL,
            cached_data TEXT NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ");
    
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS credit_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_id TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            transaction_type TEXT NOT NULL CHECK (transaction_type IN ('purchase', 'bonus', 'deduction', 'refund', 'admin_adjustment')),
            reason TEXT NOT NULL,
            payment_method TEXT,
            payment_reference TEXT,
            admin_id INTEGER,
            balance_before INTEGER NOT NULL,
            balance_after INTEGER NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE SET NULL
        )
    ");
    
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS user_activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            activity_type TEXT NOT NULL,
            description TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            metadata TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ");
    
    // Insert demo users if they don't exist
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM users");
    $stmt->execute();
    $userCount = $stmt->fetchColumn();
    
    if ($userCount == 0) {
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
        
        $stmt = $pdo->prepare("INSERT INTO users (email, password_hash, name, type, credits) VALUES (?, ?, ?, ?, ?)");
        foreach ($demoUsers as $user) {
            $stmt->execute($user);
        }
    }
} catch (Exception $e) {
    // Database already exists or error occurred
}

function findUserByCredentials($email, $password) {
    global $pdo;
    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($user && password_verify($password, $user['password_hash'])) {
        return $user;
    }
    return null;
}

// Helper functions
function jsonResponse($data, $status = 200) {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit();
}

function sendPDFEmail($request, $adminName) {
    try {
        $to = $request['user_email'];
        $subject = "VINaris - Your VIN Report is Ready (Request #{$request['request_id']})";
        
        // Parse VIN report data
        $reportData = json_decode($request['report_data'], true);
        $vinInfo = '';
        if ($reportData) {
            $vinInfo = "
                <h3>Vehicle Information:</h3>
                <ul>
                    <li><strong>Make:</strong> " . ($reportData['make'] ?? 'N/A') . "</li>
                    <li><strong>Model:</strong> " . ($reportData['model'] ?? 'N/A') . "</li>
                    <li><strong>Year:</strong> " . ($reportData['year'] ?? 'N/A') . "</li>
                    <li><strong>Body Class:</strong> " . ($reportData['bodyClass'] ?? 'N/A') . "</li>
                    <li><strong>Engine:</strong> " . ($reportData['engineInfo'] ?? 'N/A') . "</li>
                    <li><strong>Transmission:</strong> " . ($reportData['transmission'] ?? 'N/A') . "</li>
                </ul>
            ";
        }
        
        $message = "
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: #dc3545; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background: #f8f9fa; }
                    .footer { padding: 20px; text-align: center; color: #666; font-size: 12px; }
                    .button { display: inline-block; background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 10px 0; }
                    .info-box { background: white; padding: 15px; border-radius: 5px; margin: 10px 0; border-left: 4px solid #007bff; }
                </style>
            </head>
            <body>
                <div class='container'>
                    <div class='header'>
                        <h1>VINaris</h1>
                        <p>Your VIN Report is Ready!</p>
                    </div>
                    <div class='content'>
                        <p>Dear {$request['user_name']},</p>
                        
                        <p>Your VIN report has been completed and is ready for download. Here are the details:</p>
                        
                        <div class='info-box'>
                            <h3>Request Information:</h3>
                            <ul>
                                <li><strong>Request ID:</strong> {$request['request_id']}</li>
                                <li><strong>VIN Number:</strong> {$request['vin']}</li>
                                <li><strong>Plan:</strong> " . strtoupper($request['plan']) . "</li>
                                <li><strong>Processed by:</strong> {$adminName}</li>
                                <li><strong>Completed:</strong> " . date('Y-m-d H:i:s') . "</li>
                            </ul>
                        </div>
                        
                        {$vinInfo}
                        
                        <p><strong>Your PDF report is attached to this email.</strong></p>
                        
                        <p>If you have any questions or need assistance, please don't hesitate to contact our support team.</p>
                        
                        <p>Thank you for using VINaris!</p>
                    </div>
                    <div class='footer'>
                        <p>This is an automated message from VINaris VIN Check System</p>
                        <p>© 2025 VINaris. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
        ";
        
        // Email headers
        $headers = [
            'MIME-Version: 1.0',
            'Content-type: text/html; charset=UTF-8',
            'From: VINaris <noreply@vinaris.ge>',
            'Reply-To: support@vinaris.ge',
            'X-Mailer: PHP/' . phpversion()
        ];
        
        // PDF file path
        $pdfPath = __DIR__ . '/uploads/pdfs/' . $request['pdf_filename'];
        
        if (!file_exists($pdfPath)) {
            error_log("PDF file not found: {$pdfPath}");
            return false;
        }
        
        // Create boundary for multipart email
        $boundary = md5(uniqid(time()));
        $headers[] = "Content-Type: multipart/mixed; boundary=\"{$boundary}\"";
        
        // Email body with attachment
        $emailBody = "--{$boundary}\r\n";
        $emailBody .= "Content-Type: text/html; charset=UTF-8\r\n";
        $emailBody .= "Content-Transfer-Encoding: 7bit\r\n\r\n";
        $emailBody .= $message . "\r\n\r\n";
        
        // Add PDF attachment
        $emailBody .= "--{$boundary}\r\n";
        $emailBody .= "Content-Type: application/pdf; name=\"{$request['pdf_filename']}\"\r\n";
        $emailBody .= "Content-Transfer-Encoding: base64\r\n";
        $emailBody .= "Content-Disposition: attachment; filename=\"{$request['pdf_filename']}\"\r\n\r\n";
        $emailBody .= chunk_split(base64_encode(file_get_contents($pdfPath))) . "\r\n";
        $emailBody .= "--{$boundary}--\r\n";
        
        // Send email
        $success = mail($to, $subject, $emailBody, implode("\r\n", $headers));
        
        if ($success) {
            error_log("PDF email sent successfully to {$to} for request {$request['request_id']}");
        } else {
            error_log("Failed to send PDF email to {$to} for request {$request['request_id']}");
        }
        
        return $success;
        
    } catch (Exception $e) {
        error_log("Email sending error: " . $e->getMessage());
        return false;
    }
}

function getAuthUser() {
    if (!isset($_SESSION['user']) || empty($_SESSION['user'])) {
        return null;
    }
    return $_SESSION['user'];
}

function validateInput($data, $required_fields = []) {
    foreach ($required_fields as $field) {
        if (!isset($data[$field]) || empty(trim($data[$field]))) {
            return "Missing required field: $field";
        }
    }
    return null;
}

function sanitizeInput($input) {
    if (is_array($input)) {
        return array_map('sanitizeInput', $input);
    }
    
    // Remove null bytes and control characters
    $input = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $input);
    
    // Trim whitespace
    $input = trim($input);
    
    // Escape HTML entities
    $input = htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    
    return $input;
}

function validatePassword($password) {
    $errors = [];
    
    if (strlen($password) < 8) {
        $errors[] = 'Password must be at least 8 characters long';
    }
    if (strlen($password) > 128) {
        $errors[] = 'Password must be no more than 128 characters long';
    }
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = 'Password must contain at least one uppercase letter';
    }
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = 'Password must contain at least one lowercase letter';
    }
    if (!preg_match('/\d/', $password)) {
        $errors[] = 'Password must contain at least one number';
    }
    if (!preg_match('/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/', $password)) {
        $errors[] = 'Password must contain at least one special character';
    }
    
    return [
        'isValid' => empty($errors),
        'errors' => $errors
    ];
}

function preventSQLInjection($input) {
    $dangerousPatterns = [
        '/union.*select/i',
        '/drop.*table/i',
        '/insert.*into/i',
        '/delete.*from/i',
        '/update.*set/i',
        '/create.*table/i',
        '/alter.*table/i',
        '/exec\s*\(/i',
        '/execute\s*\(/i',
        '/sp_/i',
        '/xp_/i',
        '/--/',
        '/\/\*/',
        '/\*\//',
        '/\x27/',
        '/\x22/',
        '/;/',
        '/<script/i',
        '/javascript:/i'
    ];
    
    if (is_array($input)) {
        foreach ($input as $value) {
            if (preventSQLInjection($value)) {
                return true;
            }
        }
        return false;
    }
    
    if (is_string($input)) {
        foreach ($dangerousPatterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }
    }
    
    return false;
}

// Route handling
switch ($_SERVER['REQUEST_METHOD']) {
    case 'GET':
        switch ($path) {
            case '/health':
                jsonResponse([
                    'status' => 'healthy',
                    'timestamp' => date('c'),
                    'version' => '1.0.0',
                    'database' => 'connected',
                    'server' => 'Apache/PHP'
                ]);
                break;
                
            case '/users/profile':
                $user = getAuthUser();
                if (!$user) {
                    jsonResponse(['error' => 'Not authenticated'], 401);
                }
                jsonResponse(['success' => true, 'user' => $user]);
                break;
                
            case '/users/requests':
                $user = getAuthUser();
                if (!$user) {
                    jsonResponse(['error' => 'Not authenticated'], 401);
                }
                
                try {
                    $stmt = $pdo->prepare("
                        SELECT 
                            request_id as id,
                            vin,
                            plan,
                            status,
                            report_data,
                            pdf_filename,
                            created_at,
                            updated_at
                        FROM vin_requests 
                        WHERE user_id = ? 
                        ORDER BY created_at DESC
                    ");
                    $stmt->execute([$user['id']]);
                    $requests = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    
                    jsonResponse(['success' => true, 'requests' => $requests]);
                } catch (Exception $e) {
                    error_log("Error fetching user requests: " . $e->getMessage());
                    jsonResponse(['error' => 'Failed to fetch requests'], 500);
                }
                break;
                
                
            case '/users/credits':
                $user = getAuthUser();
                if (!$user) {
                    jsonResponse(['error' => 'Not authenticated'], 401);
                }
                jsonResponse(['success' => true, 'credits' => $user['credits'] ?? 10]);
                break;
                
            case '/users/credit-transactions':
                $user = getAuthUser();
                if (!$user) {
                    jsonResponse(['error' => 'Not authenticated'], 401);
                }
                
                $limit = min(intval($_GET['limit'] ?? 50), 100);
                $offset = intval($_GET['offset'] ?? 0);
                
                $query = "SELECT ct.*, u.name as user_name, a.name as admin_name
                         FROM credit_transactions ct 
                         LEFT JOIN users u ON ct.user_id = u.id 
                         LEFT JOIN users a ON ct.admin_id = a.id
                         WHERE ct.user_id = ?
                         ORDER BY ct.created_at DESC 
                         LIMIT ? OFFSET ?";
                
                $stmt = $pdo->prepare($query);
                $stmt->execute([$user['id'], $limit, $offset]);
                $transactions = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                // Get total count for pagination
                $countQuery = "SELECT COUNT(*) FROM credit_transactions WHERE user_id = ?";
                $countStmt = $pdo->prepare($countQuery);
                $countStmt->execute([$user['id']]);
                $totalCount = $countStmt->fetchColumn();
                
                jsonResponse([
                    'success' => true,
                    'transactions' => $transactions,
                    'total' => $totalCount,
                    'limit' => $limit,
                    'offset' => $offset
                ]);
                break;
                
            case '/users/history':
                $user = getAuthUser();
                if (!$user) {
                    jsonResponse(['error' => 'Not authenticated'], 401);
                }
                
                $stmt = $pdo->prepare("SELECT * FROM vin_requests WHERE user_id = ? ORDER BY created_at DESC");
                $stmt->execute([$user['id']]);
                $requests = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                jsonResponse(['success' => true, 'requests' => $requests]);
                break;
                
            case '/users/payment-requests':
                $user = getAuthUser();
                if (!$user) {
                    jsonResponse(['error' => 'Not authenticated'], 401);
                }
                
                $limit = min(intval($_GET['limit'] ?? 20), 50);
                $offset = intval($_GET['offset'] ?? 0);
                
                $stmt = $pdo->prepare("
                    SELECT pr.*, u.name as user_name 
                    FROM payment_requests pr 
                    LEFT JOIN users u ON pr.user_id = u.id 
                    WHERE pr.user_id = ? 
                    ORDER BY pr.created_at DESC 
                    LIMIT ? OFFSET ?
                ");
                $stmt->execute([$user['id'], $limit, $offset]);
                $requests = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                // Get total count
                $countStmt = $pdo->prepare("SELECT COUNT(*) FROM payment_requests WHERE user_id = ?");
                $countStmt->execute([$user['id']]);
                $totalCount = $countStmt->fetchColumn();
                
                jsonResponse([
                    'success' => true,
                    'requests' => $requests,
                    'total' => $totalCount,
                    'limit' => $limit,
                    'offset' => $offset
                ]);
                break;
                
                
            case '/admin/requests':
                $user = getAuthUser();
                if (!$user || ($user['user_type'] !== 'admin' && $user['type'] !== 'admin')) {
                    jsonResponse(['error' => 'Admin access required'], 403);
                }
                
                $stmt = $pdo->query("
                    SELECT vr.*, u.name as user_name, u.email as user_email 
                    FROM vin_requests vr 
                    JOIN users u ON vr.user_id = u.id 
                    ORDER BY vr.created_at DESC
                ");
                $requests = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                jsonResponse(['success' => true, 'requests' => $requests]);
                break;
                
            case '/admin/users':
                $user = getAuthUser();
                if (!$user || ($user['user_type'] !== 'admin' && $user['type'] !== 'admin')) {
                    jsonResponse(['error' => 'Admin access required'], 403);
                }
                
                try {
                    $stmt = $pdo->query("SELECT id, email, name, user_type, credits, created_at FROM users ORDER BY created_at DESC");
                    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    
                    jsonResponse(['success' => true, 'users' => $users]);
                } catch (Exception $e) {
                    jsonResponse(['error' => 'Database error', 'message' => $e->getMessage()], 500);
                }
                break;
                
            case '/admin/cache':
                $user = getAuthUser();
                if (!$user || ($user['user_type'] !== 'admin' && $user['type'] !== 'admin')) {
                    jsonResponse(['error' => 'Admin access required'], 403);
                }
                
                $stmt = $pdo->query("SELECT vin, data_source, cached_data, expires_at, created_at FROM vin_data_cache ORDER BY created_at DESC");
                $cache = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                jsonResponse(['success' => true, 'cache' => $cache]);
                break;
                
            case '/demo/users':
                // List all demo users (for testing purposes)
                $stmt = $pdo->query("SELECT id, email, name, type, credits, created_at FROM users ORDER BY type, name");
                $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
                jsonResponse([
                    'success' => true,
                    'users' => $users,
                    'count' => count($users)
                ]);
                break;
                
            case '/admin/credit-transactions':
                $user = getAuthUser();
                if (!$user || ($user['user_type'] !== 'admin' && $user['type'] !== 'admin')) {
                    jsonResponse(['error' => 'Admin access required'], 403);
                }
                
                $userId = $_GET['user_id'] ?? null;
                $limit = min(intval($_GET['limit'] ?? 50), 100);
                $offset = intval($_GET['offset'] ?? 0);
                
                $query = "SELECT ct.*, u.name as user_name, a.name as admin_name 
                         FROM credit_transactions ct 
                         LEFT JOIN users u ON ct.user_id = u.id 
                         LEFT JOIN users a ON ct.admin_id = a.id";
                $params = [];
                
                if ($userId) {
                    $query .= " WHERE ct.user_id = ?";
                    $params[] = $userId;
                }
                
                $query .= " ORDER BY ct.created_at DESC LIMIT ? OFFSET ?";
                $params[] = $limit;
                $params[] = $offset;
                
                $stmt = $pdo->prepare($query);
                $stmt->execute($params);
                $transactions = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                // Get total count for pagination
                $countQuery = "SELECT COUNT(*) FROM credit_transactions";
                if ($userId) {
                    $countQuery .= " WHERE user_id = ?";
                }
                $countStmt = $pdo->prepare($countQuery);
                $countStmt->execute($userId ? [$userId] : []);
                $totalCount = $countStmt->fetchColumn();
                
                jsonResponse([
                    'success' => true,
                    'transactions' => $transactions,
                    'total' => $totalCount,
                    'limit' => $limit,
                    'offset' => $offset
                ]);
                break;
                
            case '/admin/activities':
                $user = getAuthUser();
                if (!$user || ($user['user_type'] !== 'admin' && $user['type'] !== 'admin')) {
                    jsonResponse(['error' => 'Admin access required'], 403);
                }
                
                $userId = $_GET['user_id'] ?? null;
                $limit = min(intval($_GET['limit'] ?? 50), 100);
                $offset = intval($_GET['offset'] ?? 0);
                
                $query = "SELECT ua.*, u.name as user_name 
                         FROM user_activities ua 
                         LEFT JOIN users u ON ua.user_id = u.id";
                $params = [];
                
                if ($userId) {
                    $query .= " WHERE ua.user_id = ?";
                    $params[] = $userId;
                }
                
                $query .= " ORDER BY ua.created_at DESC LIMIT ? OFFSET ?";
                $params[] = $limit;
                $params[] = $offset;
                
                $stmt = $pdo->prepare($query);
                $stmt->execute($params);
                $activities = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                // Get total count for pagination
                $countQuery = "SELECT COUNT(*) FROM user_activities";
                if ($userId) {
                    $countQuery .= " WHERE user_id = ?";
                }
                $countStmt = $pdo->prepare($countQuery);
                $countStmt->execute($userId ? [$userId] : []);
                $totalCount = $countStmt->fetchColumn();
                
                jsonResponse([
                    'success' => true,
                    'activities' => $activities,
                    'total' => $totalCount,
                    'limit' => $limit,
                    'offset' => $offset
                ]);
                break;
                
            case '/admin/payment-requests':
                $user = getAuthUser();
                if (!$user || ($user['user_type'] !== 'admin' && $user['type'] !== 'admin')) {
                    jsonResponse(['error' => 'Admin access required'], 403);
                }
                
                $status = $_GET['status'] ?? null;
                $limit = min(intval($_GET['limit'] ?? 50), 100);
                $offset = intval($_GET['offset'] ?? 0);
                
                $query = "SELECT pr.*, u.name as user_name, u.email as user_email,
                         a.name as verified_by_name
                         FROM payment_requests pr 
                         LEFT JOIN users u ON pr.user_id = u.id 
                         LEFT JOIN users a ON pr.verified_by = a.id";
                $params = [];
                
                if ($status) {
                    $query .= " WHERE pr.status = ?";
                    $params[] = $status;
                }
                
                $query .= " ORDER BY pr.created_at DESC LIMIT ? OFFSET ?";
                $params[] = $limit;
                $params[] = $offset;
                
                $stmt = $pdo->prepare($query);
                $stmt->execute($params);
                $requests = $stmt->fetchAll(PDO::FETCH_ASSOC);
                
                // Get total count for pagination
                $countQuery = "SELECT COUNT(*) FROM payment_requests";
                if ($status) {
                    $countQuery .= " WHERE status = ?";
                }
                $countStmt = $pdo->prepare($countQuery);
                $countStmt->execute($status ? [$status] : []);
                $totalCount = $countStmt->fetchColumn();
                
                jsonResponse([
                    'success' => true,
                    'requests' => $requests,
                    'total' => $totalCount,
                    'limit' => $limit,
                    'offset' => $offset
                ]);
                break;
                
                
            default:
                jsonResponse(['error' => 'Endpoint not found'], 404);
        }
        break;
        
    case 'POST':
        switch ($path) {
            case '/admin/payment-request':
                $user = getAuthUser();
                if (!$user || ($user['user_type'] !== 'admin' && $user['type'] !== 'admin')) {
                    jsonResponse(['error' => 'Admin access required'], 403);
                }
                
                // Update payment request status
                $raw_input = file_get_contents('php://input');
                $input = json_decode($raw_input, true);
                
                if (json_last_error() !== JSON_ERROR_NONE) {
                    jsonResponse(['error' => 'Invalid JSON data'], 400);
                }
                
                $validation_error = validateInput($input, ['payment_id', 'status']);
                if ($validation_error) {
                    jsonResponse(['error' => $validation_error], 400);
                }
                
                try {
                    $pdo->beginTransaction();
                    
                    // Update payment request
                    $stmt = $pdo->prepare("
                        UPDATE payment_requests 
                        SET status = ?, verified_by = ?, verified_at = ?, verification_notes = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE payment_id = ?
                    ");
                    $stmt->execute([
                        $input['status'],
                        $user['id'],
                        date('Y-m-d H:i:s'),
                        $input['verification_notes'] ?? '',
                        $input['payment_id']
                    ]);
                    
                    // If approved, add credits to user
                    if ($input['status'] === 'approved') {
                        // Get payment request details
                        $paymentStmt = $pdo->prepare("SELECT user_id, credits FROM payment_requests WHERE payment_id = ?");
                        $paymentStmt->execute([$input['payment_id']]);
                        $payment = $paymentStmt->fetch(PDO::FETCH_ASSOC);
                        
                        if ($payment) {
                            // Update user credits
                            $updateCreditsStmt = $pdo->prepare("UPDATE users SET credits = credits + ? WHERE id = ?");
                            $updateCreditsStmt->execute([$payment['credits'], $payment['user_id']]);
                            
                            // Get updated user credits
                            $userStmt = $pdo->prepare("SELECT credits FROM users WHERE id = ?");
                            $userStmt->execute([$payment['user_id']]);
                            $userCredits = $userStmt->fetch(PDO::FETCH_ASSOC);
                            
                            // Log credit transaction
                            $transactionId = 'TXN_' . time() . '_' . bin2hex(random_bytes(4));
                            $transactionStmt = $pdo->prepare("
                                INSERT INTO credit_transactions (
                                    transaction_id, user_id, amount, transaction_type, reason, 
                                    payment_method, admin_id, balance_before, balance_after
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ");
                            $transactionStmt->execute([
                                $transactionId,
                                $payment['user_id'],
                                $payment['credits'],
                                'purchase',
                                'Payment approved - ' . $input['payment_id'],
                                'bank_transfer',
                                $user['id'],
                                $userCredits['credits'] - $payment['credits'],
                                $userCredits['credits']
                            ]);
                        }
                    }
                    
                    $pdo->commit();
                    
                    jsonResponse([
                        'success' => true,
                        'message' => 'Payment request updated successfully'
                    ]);
                } catch (Exception $e) {
                    $pdo->rollBack();
                    jsonResponse(['error' => 'Failed to update payment request: ' . $e->getMessage()], 500);
                }
                break;
                
            case '/users/payment-request':
                $user = getAuthUser();
                if (!$user) {
                    jsonResponse(['error' => 'Not authenticated'], 401);
                }
                
                // Create new payment request
                $raw_input = file_get_contents('php://input');
                $input = json_decode($raw_input, true);
                
                if (json_last_error() !== JSON_ERROR_NONE) {
                    jsonResponse(['error' => 'Invalid JSON data'], 400);
                }
                
                $validation_error = validateInput($input, ['amount', 'credits', 'payment_date', 'payment_time', 'invoice_number']);
                if ($validation_error) {
                    jsonResponse(['error' => $validation_error], 400);
                }
                
                try {
                    $paymentId = 'PAY_' . time() . '_' . bin2hex(random_bytes(4));
                    
                    $stmt = $pdo->prepare("
                        INSERT INTO payment_requests (
                            payment_request_id, user_id, amount, credits, currency, payment_method,
                            invoice_number, bank_reference, payment_date, payment_time, payment_amount,
                            user_notes, contact_phone
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ");
                    
                    $stmt->execute([
                        $paymentId,
                        $user['id'],
                        $input['amount'],
                        $input['credits'],
                        $input['currency'] ?? 'GEL',
                        $input['payment_method'] ?? 'bank_transfer',
                        $input['invoice_number'],
                        $input['bank_reference'] ?? '',
                        $input['payment_date'],
                        $input['payment_time'],
                        $input['amount'],
                        $input['user_notes'] ?? '',
                        $input['contact_phone'] ?? ''
                    ]);
                    
                    jsonResponse([
                        'success' => true,
                        'message' => 'Payment request submitted successfully',
                        'payment_id' => $paymentId
                    ]);
                } catch (Exception $e) {
                    jsonResponse(['error' => 'Failed to create payment request: ' . $e->getMessage()], 500);
                }
                break;
                
            case '/auth/login':
                try {
                    $raw_input = file_get_contents('php://input');
                    $input = json_decode($raw_input, true);
                    
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        jsonResponse(['error' => 'Invalid JSON data', 'message' => 'Request body must be valid JSON'], 400);
                    }
                    
                    // Check for SQL injection attempts
                    if (preventSQLInjection($input)) {
                        jsonResponse(['error' => 'Invalid input', 'message' => 'Suspicious input detected'], 400);
                    }
                    
                    // Validate required fields
                    $validation_error = validateInput($input, ['email', 'password']);
                    if ($validation_error) {
                        jsonResponse(['error' => 'Validation failed', 'message' => $validation_error], 400);
                    }
                    
                    $email = sanitizeInput($input['email']);
                    $password = $input['password']; // Don't sanitize password for comparison
                    
                    // Validate email format
                    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                        jsonResponse(['error' => 'Invalid email format'], 400);
                    }
                    
                    // Rate limiting for login attempts
                    $login_attempts_key = 'login_attempts_' . hash('sha256', $_SERVER['REMOTE_ADDR']);
                    $login_attempts = $_SESSION[$login_attempts_key] ?? 0;
                    $last_attempt = $_SESSION[$login_attempts_key . '_time'] ?? 0;
                    
                    if ($login_attempts >= 5 && (time() - $last_attempt) < 900) { // 15 minutes
                        jsonResponse(['error' => 'Too many attempts', 'message' => 'Please wait 15 minutes before trying again'], 429);
                    }
                    
                    // Check demo users
                    $user = findUserByCredentials($email, $password);
                    
                    if ($user) {
                        // Reset login attempts on successful login
                        unset($_SESSION[$login_attempts_key]);
                        unset($_SESSION[$login_attempts_key . '_time']);
                        
                        // Regenerate session ID for security
                        session_regenerate_id(true);
                        
                        $_SESSION['user'] = [
                            'id' => $user['id'],
                            'uniqueId' => $user['user_type'] . '_' . $user['id'],
                            'name' => $user['name'],
                            'email' => $user['email'],
                            'credits' => $user['credits'],
                            'type' => $user['user_type'],
                            'user_type' => $user['user_type'], // Add this for compatibility
                            'loginTime' => time(),
                            'lastActivity' => time()
                        ];
                        
                        // Log successful login
                        error_log("Successful login: {$email} from {$_SERVER['REMOTE_ADDR']}");
                        
                        jsonResponse([
                            'success' => true,
                            'message' => 'Login successful',
                            'user' => $_SESSION['user']
                        ]);
                    } else {
                        // Increment failed login attempts
                        $_SESSION[$login_attempts_key] = $login_attempts + 1;
                        $_SESSION[$login_attempts_key . '_time'] = time();
                        
                        // Log failed login attempt
                        error_log("Failed login attempt: {$email} from {$_SERVER['REMOTE_ADDR']}");
                        
                        jsonResponse(['error' => 'Invalid credentials', 'message' => 'Email or password is incorrect'], 401);
                    }
                } catch (Exception $e) {
                    jsonResponse(['error' => 'Login failed', 'message' => 'An error occurred during login'], 500);
                }
                break;
                
            case '/auth/register':
                try {
                    $raw_input = file_get_contents('php://input');
                    $input = json_decode($raw_input, true);
                    
                    if (json_last_error() !== JSON_ERROR_NONE) {
                        jsonResponse(['error' => 'Invalid JSON data', 'message' => 'Request body must be valid JSON'], 400);
                    }
                    
                    // Validate required fields
                    $validation_error = validateInput($input, ['name', 'email', 'password']);
                    if ($validation_error) {
                        jsonResponse(['error' => 'Validation failed', 'message' => $validation_error], 400);
                    }
                    
                    $name = sanitizeInput($input['name']);
                    $email = sanitizeInput($input['email']);
                    $password = sanitizeInput($input['password']);
                    
                    // Validate email format
                    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                        jsonResponse(['error' => 'Invalid email format'], 400);
                    }
                    
                    // Validate password strength
                    if (strlen($password) < 6) {
                        jsonResponse(['error' => 'Password too short', 'message' => 'Password must be at least 6 characters long'], 400);
                    }
                    
                // Demo registration
                $_SESSION['user'] = [
                    'id' => rand(100, 999),
                    'uniqueId' => 'user_' . time(),
                    'name' => $name,
                    'email' => $email,
                    'credits' => 5,
                    'type' => 'user',
                    'user_type' => 'user', // Add this for compatibility
                    'loginTime' => time()
                ];
                    jsonResponse([
                        'success' => true,
                        'message' => 'Registration successful',
                        'user' => $_SESSION['user']
                    ]);
                } catch (Exception $e) {
                    jsonResponse(['error' => 'Registration failed', 'message' => 'An error occurred during registration'], 500);
                }
                break;
                
            case '/users/profile/update':
                $user = getAuthUser();
                if (!$user) {
                    jsonResponse(['error' => 'Not authenticated'], 401);
                }
                
                $input = json_decode(file_get_contents('php://input'), true);
                if (!$input) {
                    jsonResponse(['error' => 'Invalid JSON data'], 400);
                }
                
                try {
                    $updateFields = [];
                    $allowedFields = ['name', 'phone', 'company', 'address'];
                    
                    foreach ($allowedFields as $field) {
                        if (isset($input[$field])) {
                            $updateFields[$field] = sanitizeInput($input[$field]);
                        }
                    }
                    
                    if (empty($updateFields)) {
                        jsonResponse(['error' => 'No valid fields to update'], 400);
                    }
                    
                    // Update user in database
                    $setClause = implode(' = ?, ', array_keys($updateFields)) . ' = ?';
                    $values = array_values($updateFields);
                    $values[] = $user['id'];
                    
                    $stmt = $pdo->prepare("UPDATE users SET $setClause, updated_at = datetime('now') WHERE id = ?");
                    $stmt->execute($values);
                    
                    // Update session data
                    foreach ($updateFields as $field => $value) {
                        $_SESSION['user'][$field] = $value;
                    }
                    
                    jsonResponse([
                        'success' => true,
                        'message' => 'Profile updated successfully',
                        'user' => $_SESSION['user']
                    ]);
                    
                } catch (Exception $e) {
                    jsonResponse(['error' => 'Failed to update profile: ' . $e->getMessage()], 500);
                }
                break;
                
            case '/auth/logout':
                // Clear session
                session_destroy();
                jsonResponse([
                    'success' => true,
                    'message' => 'Logout successful'
                ]);
                break;
                
            case '/vin/check':
                $user = getAuthUser();
                if (!$user) {
                    jsonResponse(['error' => 'Not authenticated'], 401);
                }
                
                $input = json_decode(file_get_contents('php://input'), true);
                $vin = strtoupper($input['vin'] ?? '');
                $plan = $input['plan'] ?? 'basic';
                
                if (empty($vin) || strlen($vin) !== 17) {
                    jsonResponse(['error' => 'Invalid VIN'], 400);
                }
                
                // Calculate credits based on plan
                $creditsUsed = ($plan === 'premium') ? 5 : 1;
                
                // Check if user has enough credits
                if ($user['credits'] < $creditsUsed) {
                    jsonResponse(['error' => 'Insufficient credits'], 400);
                }
                
                // Check for duplicate VIN request by this user
                $stmt = $pdo->prepare("SELECT request_id, created_at FROM vin_requests WHERE user_id = ? AND vin = ? ORDER BY created_at DESC LIMIT 1");
                $stmt->execute([$user['id'], $vin]);
                $existingRequest = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($existingRequest) {
                    // Use database time comparison to avoid timezone issues
                    $stmt = $pdo->prepare("SELECT (strftime('%s', 'now') - strftime('%s', created_at)) as time_diff FROM vin_requests WHERE request_id = ?");
                    $stmt->execute([$existingRequest['request_id']]);
                    $timeResult = $stmt->fetch(PDO::FETCH_ASSOC);
                    $timeDiff = $timeResult['time_diff'];
                    
                    if ($timeDiff < 3600) { // 1 hour cooldown
                        $remainingTime = 3600 - $timeDiff;
                        $minutes = ceil($remainingTime / 60);
                        jsonResponse(['error' => "You have already checked this VIN recently. Please wait {$minutes} minutes before checking again."], 400);
                    }
                }
                
                try {
                    // Check if VIN data is cached
                    $stmt = $pdo->prepare("SELECT * FROM vin_data_cache WHERE vin = ? AND expires_at > datetime('now')");
                    $stmt->execute([$vin]);
                    $cachedData = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($cachedData) {
                    $vinData = json_decode($cachedData['cached_data'], true);
                } else {
                    // Generate demo VIN data (replace with real API calls)
                    $vinData = [
                        'make' => 'HONDA',
                        'model' => 'Accord',
                        'year' => '2003',
                        'bodyClass' => 'Coupe',
                        'engineInfo' => 'J30A4',
                        'engineSize' => '2.998832712',
                        'cylinders' => '6',
                        'transmission' => 'Automatic',
                        'fuelType' => 'Gasoline',
                        'vehicleType' => 'PASSENGER CAR',
                        'plantCountry' => 'UNITED STATES (USA)',
                        'manufacturer' => 'AMERICAN HONDA MOTOR CO., INC.',
                        '_metadata' => [
                            'sources' => ['Demo'],
                            'plan' => $plan,
                            'lastUpdated' => date('c')
                        ]
                    ];
                    
                    // Cache the VIN data for 24 hours
                    $stmt = $pdo->prepare("INSERT OR REPLACE INTO vin_data_cache (vin, data_source, cached_data, expires_at) VALUES (?, ?, ?, datetime('now', '+24 hours'))");
                    $stmt->execute([$vin, 'demo', json_encode($vinData)]);
                }
                
                // Store VIN request in database
                $requestId = 'R' . substr(time(), -6) . strtoupper(substr(bin2hex(random_bytes(2)), 0, 3));
                $stmt = $pdo->prepare("
                    INSERT INTO vin_requests (request_id, user_id, vin, plan, status, report_data, created_at) 
                    VALUES (?, ?, ?, ?, 'pending', ?, datetime('now'))
                ");
                $stmt->execute([$requestId, $user['id'], $vin, $plan, json_encode($vinData)]);
                
                // Get current user credits before deduction
                $stmt = $pdo->prepare("SELECT credits FROM users WHERE id = ?");
                $stmt->execute([$user['id']]);
                $currentUser = $stmt->fetch(PDO::FETCH_ASSOC);
                $balanceBefore = $currentUser['credits'];
                $balanceAfter = $balanceBefore - $creditsUsed;
                
                // Deduct credits
                $stmt = $pdo->prepare("UPDATE users SET credits = credits - ? WHERE id = ?");
                $stmt->execute([$creditsUsed, $user['id']]);
                
                // Log credit transaction
                $transactionId = 'TXN_' . time() . '_' . bin2hex(random_bytes(4));
                $stmt = $pdo->prepare("
                    INSERT INTO credit_transactions (
                        transaction_id, user_id, amount, transaction_type, reason, 
                        payment_method, admin_id, balance_before, balance_after
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ");
                $stmt->execute([
                    $transactionId, $user['id'], -$creditsUsed, 'deduction', 
                    "VIN check - {$plan} plan", 'system', null, $balanceBefore, $balanceAfter
                ]);
                
                // Get updated user credits
                $stmt = $pdo->prepare("SELECT credits FROM users WHERE id = ?");
                $stmt->execute([$user['id']]);
                $updatedUser = $stmt->fetch(PDO::FETCH_ASSOC);
                
                // Update session with new credits
                $_SESSION['user']['credits'] = $updatedUser['credits'];
                
                    jsonResponse([
                        'success' => true,
                        'message' => 'VIN request completed successfully',
                        'requestId' => $requestId,
                        'vin' => $vin,
                        'plan' => $plan,
                        'status' => 'pending',
                        'basicData' => $vinData,
                        'creditsUsed' => $creditsUsed,
                        'creditsRemaining' => $updatedUser['credits']
                    ]);
                } catch (Exception $e) {
                    jsonResponse(['error' => 'VIN check failed', 'message' => $e->getMessage()], 500);
                }
                break;
                
            case '/auth/logout':
                session_start();
                session_destroy();
                jsonResponse(['success' => true, 'message' => 'Logged out successfully']);
                break;
                
                
            case '/admin/requests/status':
                $user = getAuthUser();
                if (!$user || ($user['user_type'] !== 'admin' && $user['type'] !== 'admin')) {
                    jsonResponse(['error' => 'Admin access required'], 403);
                }
                
                $input = json_decode(file_get_contents('php://input'), true);
                $requestId = $input['request_id'] ?? null;
                $status = $input['status'] ?? null;
                
                if (!$requestId || !$status) {
                    jsonResponse(['error' => 'Missing required fields'], 400);
                }
                
                $stmt = $pdo->prepare("UPDATE vin_requests SET status = ? WHERE request_id = ?");
                $stmt->execute([$status, $requestId]);
                
                jsonResponse(['success' => true, 'message' => 'Request status updated']);
                break;
                
            case '/admin/upload-pdf':
                $user = getAuthUser();
                if (!$user || ($user['user_type'] !== 'admin' && $user['type'] !== 'admin')) {
                    jsonResponse(['error' => 'Admin access required'], 403);
                }
                
                $requestId = $_POST['request_id'] ?? null;
                $adminId = $_POST['admin_id'] ?? null;
                
                if (!$requestId || !$adminId) {
                    jsonResponse(['error' => 'Missing required fields'], 400);
                }
                
                if (!isset($_FILES['pdf_file']) || $_FILES['pdf_file']['error'] !== UPLOAD_ERR_OK) {
                    jsonResponse(['error' => 'No PDF file uploaded'], 400);
                }
                
                $file = $_FILES['pdf_file'];
                
                // Validate file type
                if ($file['type'] !== 'application/pdf') {
                    jsonResponse(['error' => 'File must be a PDF'], 400);
                }
                
                // Additional file type validation using file extension
                $fileExtension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
                if ($fileExtension !== 'pdf') {
                    jsonResponse(['error' => 'Invalid file extension'], 400);
                }
                
                // Validate file size (10MB limit)
                if ($file['size'] > 10 * 1024 * 1024) {
                    jsonResponse(['error' => 'File size must be less than 10MB'], 400);
                }
                
                // Validate file size (minimum 1KB)
                if ($file['size'] < 1024) {
                    jsonResponse(['error' => 'File too small'], 400);
                }
                
                // Validate filename
                if (preg_match('/[^a-zA-Z0-9._-]/', $file['name'])) {
                    jsonResponse(['error' => 'Invalid filename characters'], 400);
                }
                
                try {
                    // Create uploads directory if it doesn't exist
                    $uploadDir = __DIR__ . '/uploads/pdfs/';
                    if (!is_dir($uploadDir)) {
                        mkdir($uploadDir, 0755, true);
                    }
                    
                    // Generate unique filename
                    $filename = 'VINaris_Report_' . $requestId . '_' . time() . '.pdf';
                    $filepath = $uploadDir . $filename;
                    
                    // Move uploaded file
                    if (move_uploaded_file($file['tmp_name'], $filepath)) {
                        // Update request with PDF path
                        $stmt = $pdo->prepare("UPDATE vin_requests SET pdf_filename = ?, status = 'processed' WHERE request_id = ?");
                        $stmt->execute([$filename, $requestId]);
                        
                        jsonResponse(['success' => true, 'message' => 'PDF uploaded successfully', 'filename' => $filename]);
                    } else {
                        jsonResponse(['error' => 'Failed to save PDF file'], 500);
                    }
                } catch (Exception $e) {
                    error_log("PDF Upload Debug - Exception: " . $e->getMessage());
                    jsonResponse(['error' => 'Failed to upload PDF', 'message' => $e->getMessage()], 500);
                }
                break;
                
            case '/admin/send-pdf':
                $user = getAuthUser();
                if (!$user || ($user['user_type'] !== 'admin' && $user['type'] !== 'admin')) {
                    jsonResponse(['error' => 'Admin access required'], 403);
                }
                
                $input = json_decode(file_get_contents('php://input'), true);
                $requestId = $input['request_id'] ?? null;
                $adminId = $input['admin_id'] ?? null;
                
                if (!$requestId || !$adminId) {
                    jsonResponse(['error' => 'Missing required fields'], 400);
                }
                
                try {
                    // Get request details with user information
                    $stmt = $pdo->prepare("
                        SELECT vr.*, u.name as user_name, u.email as user_email 
                        FROM vin_requests vr 
                        JOIN users u ON vr.user_id = u.id 
                        WHERE vr.request_id = ?
                    ");
                    $stmt->execute([$requestId]);
                    $request = $stmt->fetch(PDO::FETCH_ASSOC);
                    
                    if (!$request) {
                        jsonResponse(['error' => 'Request not found'], 404);
                    }
                    
                    if (!$request['pdf_filename']) {
                        jsonResponse(['error' => 'No PDF available for this request'], 400);
                    }
                    
                    // Get admin details
                    $stmt = $pdo->prepare("SELECT name FROM users WHERE id = ?");
                    $stmt->execute([$adminId]);
                    $admin = $stmt->fetch(PDO::FETCH_ASSOC);
                    $adminName = $admin ? $admin['name'] : 'System Administrator';
                    
                    // Send email to user
                    $emailSent = sendPDFEmail($request, $adminName);
                    
                    if ($emailSent) {
                        // Update status to delivered
                        $stmt = $pdo->prepare("UPDATE vin_requests SET status = 'delivered', processed_by = ? WHERE request_id = ?");
                        $stmt->execute([$adminId, $requestId]);
                        
                        jsonResponse(['success' => true, 'message' => 'PDF sent to user successfully via email']);
                    } else {
                        jsonResponse(['error' => 'Failed to send email'], 500);
                    }
                } catch (Exception $e) {
                    jsonResponse(['error' => 'Failed to send PDF', 'message' => $e->getMessage()], 500);
                }
                break;
                
            case '/admin/users/credits':
                $user = getAuthUser();
                if (!$user || ($user['user_type'] !== 'admin' && $user['type'] !== 'admin')) {
                    jsonResponse(['error' => 'Admin access required'], 403);
                }
                
                $input = json_decode(file_get_contents('php://input'), true);
                $userId = $input['user_id'] ?? null;
                $credits = $input['credits'] ?? null;
                $reason = $input['reason'] ?? 'Admin credit adjustment';
                $adminId = $input['admin_id'] ?? $user['id'];
                
                if (!$userId || $credits === null) {
                    jsonResponse(['error' => 'Missing required fields'], 400);
                }
                
                try {
                    // Get current user credits
                    $stmt = $pdo->prepare("SELECT credits FROM users WHERE id = ?");
                    $stmt->execute([$userId]);
                    $currentUser = $stmt->fetch(PDO::FETCH_ASSOC);
                    
                    if (!$currentUser) {
                        jsonResponse(['error' => 'User not found'], 404);
                    }
                    
                    // Calculate new credits
                    $newCredits = $currentUser['credits'] + $credits;
                    if ($newCredits < 0) {
                        jsonResponse(['error' => 'Insufficient credits'], 400);
                    }
                    
                    // Update user credits
                    $stmt = $pdo->prepare("UPDATE users SET credits = ? WHERE id = ?");
                    $stmt->execute([$newCredits, $userId]);
                    
                    // Log transaction
                    $transactionId = 'TXN_' . time() . '_' . bin2hex(random_bytes(4));
                    $transactionType = $credits > 0 ? 'admin_adjustment' : 'deduction';
                    $stmt = $pdo->prepare("
                        INSERT INTO credit_transactions (
                            transaction_id, user_id, amount, transaction_type, reason, 
                            payment_method, admin_id, balance_before, balance_after
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ");
                    $stmt->execute([
                        $transactionId, $userId, $credits, $transactionType, $reason,
                        'admin', $adminId, $currentUser['credits'], $newCredits
                    ]);
                    
                    jsonResponse(['success' => true, 'message' => 'Credits updated successfully', 'new_credits' => $newCredits]);
                } catch (Exception $e) {
                    jsonResponse(['error' => 'Failed to update credits', 'message' => $e->getMessage()], 500);
                }
                break;
                
            case '/activities/log':
                $user = getAuthUser();
                if (!$user) {
                    jsonResponse(['error' => 'Authentication required'], 401);
                }
                
                $input = json_decode(file_get_contents('php://input'), true);
                $activityType = $input['activity_type'] ?? null;
                $description = $input['description'] ?? null;
                $metadata = $input['metadata'] ?? [];
                
                if (!$activityType || !$description) {
                    jsonResponse(['error' => 'Missing required fields'], 400);
                }
                
                try {
                    $stmt = $pdo->prepare("
                        INSERT INTO user_activities (user_id, activity_type, description, ip_address, user_agent, metadata) 
                        VALUES (?, ?, ?, ?, ?, ?)
                    ");
                    $stmt->execute([
                        $user['id'],
                        $activityType,
                        $description,
                        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                        $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                        json_encode($metadata)
                    ]);
                    
                    jsonResponse(['success' => true, 'message' => 'Activity logged successfully']);
                } catch (Exception $e) {
                    jsonResponse(['error' => 'Failed to log activity', 'message' => $e->getMessage()], 500);
                }
                break;
                
            default:
                jsonResponse(['error' => 'Endpoint not found'], 404);
        }
        break;
        
    default:
        jsonResponse(['error' => 'Method not allowed'], 405);
}
?>
