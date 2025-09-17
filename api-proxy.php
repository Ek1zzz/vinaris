<?php
/**
 * API Proxy for VINaris
 * Forwards requests from PHP/Apache to Node.js API to avoid CORS issues
 */

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, Accept');

// Handle preflight OPTIONS requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Get the API endpoint from the URL
$request_uri = $_SERVER['REQUEST_URI'];
$api_path = str_replace('/Vinaris/api-proxy.php', '', $request_uri);

// Node.js API base URL
$node_api_url = 'http://localhost:3001/api' . $api_path;

// Prepare the request
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $node_api_url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 30);

// Set request method
$method = $_SERVER['REQUEST_METHOD'];
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);

// Set headers
$headers = [];
foreach (getallheaders() as $name => $value) {
    if (strtolower($name) !== 'host') {
        $headers[] = $name . ': ' . $value;
    }
}
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

// Set request body for POST/PUT requests
if (in_array($method, ['POST', 'PUT', 'PATCH'])) {
    $input = file_get_contents('php://input');
    curl_setopt($ch, CURLOPT_POSTFIELDS, $input);
}

// Add query parameters
if (!empty($_GET)) {
    $query_string = http_build_query($_GET);
    $separator = strpos($node_api_url, '?') !== false ? '&' : '?';
    curl_setopt($ch, CURLOPT_URL, $node_api_url . $separator . $query_string);
}

// Execute the request
$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$error = curl_error($ch);
curl_close($ch);

// Handle errors
if ($error) {
    http_response_code(500);
    echo json_encode([
        'error' => 'Proxy Error',
        'message' => 'Failed to connect to Node.js API: ' . $error
    ]);
    exit();
}

// Set the HTTP status code
http_response_code($http_code);

// Return the response
echo $response;
?>
