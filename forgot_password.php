<?php
require_once '../config.php';

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    
    if (empty($email)) {
        $message = 'Please enter your email address';
    } else {
        try {
            $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch();
            
            if ($user) {
                $token = generateToken();
                $expires = date('Y-m-d H:i:s', time() + 3600); // 1 hour expiration
                
                $stmt = $pdo->prepare("
                    UPDATE users 
                    SET reset_token = ?, reset_token_expires = ?
                    WHERE id = ?
                ");
                $stmt->execute([$token, $expires, $user['id']]);
                
                // In production: sendEmail($email, "Password Reset", "Click here to reset: $reset_url");
                $reset_url = BASE_URL . "/public/reset_password.php?token=$token";
                $message = 'If an account exists with that email, you will receive a password reset link.';
            } else {
                $message = 'If an account exists with that email, you will receive a password reset link.';
            }
        } catch (PDOException $e) {
            $message = 'An error occurred. Please try again.';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password - <?= SITE_NAME ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <?php include '../navbar.php'; ?>
    
    <div class="container py-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h3>Forgot Password</h3>
                    </div>
                    <div class="card-body">
                        <?php if ($message): ?>
                            <div class="alert alert-info"><?= htmlspecialchars($message) ?></div>
                        <?php endif; ?>
                        
                        <form method="post">
                            <div class="mb-3">
                                <label for="email" class="form-label">Email Address</label>
                                <input type="email" class="form-control" id="email" name="email" required>
                            </div>
                            <button type="submit" class="btn btn-primary">Send Reset Link</button>
                        </form>
                        
                        <div class="mt-3 text-center">
                            <a href="login.php">Back to Login</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <?php include '../footer.php'; ?>
</body>
</html>