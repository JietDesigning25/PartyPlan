<?php
require_once '../config.php';

// Redirect if already logged in
if (isLoggedIn()) {
    header('Location: ' . ($_SESSION['redirect_url'] ?? 'index.php'));
    unset($_SESSION['redirect_url']);
    exit();
}

$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $remember = isset($_POST['remember']);
    
    if (empty($username) || empty($password)) {
        $errors[] = 'Please enter both username and password';
    } else {
        try {
            $stmt = $pdo->prepare("
                SELECT u.*, r.role 
                FROM users u
                LEFT JOIN user_roles r ON u.id = r.user_id
                WHERE u.username = ? OR u.email = ?
            ");
            $stmt->execute([$username, $username]);
            $user = $stmt->fetch();
            
            if ($user && verifyPassword($password, $user['password_hash'])) {
                if ($user['is_active']) {
                    // Regenerate session ID to prevent fixation
                    session_regenerate_id(true);
                    
                    // Set session variables
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    $_SESSION['roles'] = [$user['role']];
                    
                    // Remember me functionality
                    if ($remember) {
                        $token = generateToken();
                        $expires = time() + 60 * 60 * 24 * 30; // 30 days
                        
                        setcookie(
                            'remember_token',
                            $token,
                            $expires,
                            '/',
                            '',
                            false,
                            true // HttpOnly
                        );
                        
                        // Store token in database
                        $stmt = $pdo->prepare("UPDATE users SET remember_token = ?, remember_token_expires = ? WHERE id = ?");
                        $stmt->execute([$token, date('Y-m-d H:i:s', $expires), $user['id']]);
                    }
                    
                    // Redirect to intended page or home
                    header('Location: ' . ($_SESSION['redirect_url'] ?? 'index.php'));
                    unset($_SESSION['redirect_url']);
                    exit();
                } else {
                    $errors[] = 'Account is inactive. Please contact support.';
                }
            } else {
                $errors[] = 'Invalid username or password';
            }
        } catch (PDOException $e) {
            $errors[] = 'Login error. Please try again.';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - <?= SITE_NAME ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .form-container {
            max-width: 500px;
            margin: 2rem auto;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body>
    <?php include '../navbar.php'; ?>
    
    <div class="container py-5">
        <div class="form-container bg-white">
            <h2 class="text-center mb-4">Login to Your Account</h2>
            
            <?php if (!empty($errors)): ?>
                <div class="alert alert-danger">
                    <?php foreach ($errors as $error): ?>
                        <p class="mb-0"><?= htmlspecialchars($error) ?></p>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            
            <form method="post">
                <div class="mb-3">
                    <label for="username" class="form-label">Username or Email</label>
                    <input type="text" class="form-control" id="username" name="username" required>
                </div>
                
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" class="form-control" id="password" name="password" required>
                    <div class="text-end mt-1">
                        <a href="forgot_password.php">Forgot password?</a>
                    </div>
                </div>
                
                <div class="mb-3 form-check">
                    <input type="checkbox" class="form-check-input" id="remember" name="remember">
                    <label class="form-check-label" for="remember">Remember me</label>
                </div>
                
                <button type="submit" class="btn btn-primary w-100 py-2 mb-3">Login</button>
                
                <div class="text-center">
                    <p>Don't have an account? <a href="register.php">Register here</a></p>
                </div>
            </form>
        </div>
    </div>

    <?php include '../footer.php'; ?>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>