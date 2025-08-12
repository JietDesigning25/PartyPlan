<?php
// Database configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'partyplan');
define('DB_USER', 'root');
define('DB_PASS', '');

// Website configuration
define('BASE_URL', 'http://localhost/PartyPlan');
define('SITE_NAME', 'PartyPlan');

// Security configuration
define('PEPPER', 'your-random-pepper-string-here'); // Change this to a random string
define('REQUIRE_EMAIL_VERIFICATION', false); // Set to true in production

// Session configuration
session_start([
    'name' => 'PartyPlanSession',
    'cookie_lifetime' => 86400, // 1 day
    'cookie_secure' => false, // Set to true in production with HTTPS
    'cookie_httponly' => true,
    'use_strict_mode' => true
]);

// Error reporting (disable in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Create database connection
try {
    $pdo = new PDO(
        "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
        DB_USER,
        DB_PASS,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]
    );
} catch (PDOException $e) {
    die("Database connection failed: " . $e->getMessage());
}

// Authentication functions
function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function requireLogin() {
    if (!isLoggedIn()) {
        $_SESSION['redirect_url'] = $_SERVER['REQUEST_URI'];
        header('Location: login.php');
        exit();
    }
}

function getCurrentUser() {
    if (!isLoggedIn()) return null;
    
    global $pdo;
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    return $stmt->fetch();
}

function hasRole($role) {
    if (!isLoggedIn()) return false;
    
    global $pdo;
    $stmt = $pdo->prepare("SELECT 1 FROM user_roles WHERE user_id = ? AND role = ?");
    $stmt->execute([$_SESSION['user_id'], $role]);
    return $stmt->fetch() !== false;
}

function generateToken($length = 32) {
    return bin2hex(random_bytes($length));
}

function hashPassword($password) {
    global $pepper;
    return password_hash($password . PEPPER, PASSWORD_BCRYPT, ['cost' => 12]);
}

function verifyPassword($password, $hash) {
    global $pepper;
    return password_verify($password . PEPPER, $hash);
}
?>