<?php
require_once '../config.php';

$errors = [];
$success = false;
$token = $_GET['token'] ?? '';

// Validate token
if (!empty($token)) {
    try {
        $stmt = $pdo->prepare("
            SELECT id FROM users 
            WHERE reset_token = ? AND reset_token_expires > NOW()
        ");
        $stmt->execute([$token]);
        $user = $stmt->fetch();
        
        if (!$user) {
            $errors[] = 'Invalid or expired token';
        }
    } catch (PDOException $e) {
        $errors[] = 'An error occurred. Please try again.';
    }
} else {
    $errors[] = 'No token provided';
}

// Process password reset
if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($errors)) {
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    
    if (empty($password)) {
        $errors[] = 'Password is required';
    } elseif (strlen($password) < 8) {
        $errors[] = 'Password must be at least 8 characters';
    } elseif ($password !== $confirm_password) {
        $errors[] = 'Passwords do not match';
    }
    
    if (empty($errors)) {
        try {
            $pdo->beginTransaction();
            
            // Update password and clear reset token
            $stmt = $pdo->prepare("
                UPDATE users 
                SET password_hash = ?, reset_token = NULL, reset_token_expires = NULL
                WHERE reset_token = ?
            ");
            $stmt->execute([hashPassword($password), $token]);
            
            $pdo->commit();
            $success = true;
        } catch (PDOException $e) {
            $pdo->rollBack();
            $errors[] = 'Password reset failed. Please try again.';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password - <?= SITE_NAME ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <?php include '../navbar.php'; ?>
    
    <div class="container py-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h3>Reset Password</h3>
                    </div>
                    <div class="card-body">
                        <?php if ($success): ?>
                            <div class="alert alert-success">
                                <p>Your password has been reset successfully.</p>
                                <a href="login.php" class="btn btn-success">Login Now</a>
                            </div>
                        <?php elseif (!empty($errors)): ?>
                            <div class="alert alert-danger">
                                <?php foreach ($errors as $error): ?>
                                    <p class="mb-0"><?= htmlspecialchars($error) ?></p>
                                <?php endforeach; ?>
                            </div>
                        <?php else: ?>
                            <form method="post">
                                <div class="mb-3">
                                    <label for="password" class="form-label">New Password</label>
                                    <input type="password" class="form-control" id="password" name="password" required>
                                </div>
                                <div class="mb-3">
                                    <label for="confirm_password" class="form-label">Confirm New Password</label>
                                    <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                                </div>
                                <button type="submit" class="btn btn-primary">Reset Password</button>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <?php include '../footer.php'; ?>
</body>
</html>