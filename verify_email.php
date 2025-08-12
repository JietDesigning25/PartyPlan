<?php
require_once '../config.php';

$message = '';
$token = $_GET['token'] ?? '';

if (!empty($token)) {
    try {
        $stmt = $pdo->prepare("
            SELECT id FROM users 
            WHERE verification_token = ? AND is_active = FALSE
        ");
        $stmt->execute([$token]);
        $user = $stmt->fetch();
        
        if ($user) {
            $stmt = $pdo->prepare("
                UPDATE users 
                SET is_active = TRUE, verification_token = NULL
                WHERE id = ?
            ");
            $stmt->execute([$user['id']]);
            $message = 'Email verified successfully! You can now login.';
        } else {
            $message = 'Invalid or expired verification token';
        }
    } catch (PDOException $e) {
        $message = 'Verification failed. Please try again.';
    }
} else {
    $message = 'No verification token provided';
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification - <?= SITE_NAME ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <?php include '../navbar.php'; ?>
    
    <div class="container py-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h3>Email Verification</h3>
                    </div>
                    <div class="card-body text-center">
                        <p><?= htmlspecialchars($message) ?></p>
                        <a href="login.php" class="btn btn-primary">Go to Login</a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <?php include '../footer.php'; ?>
</body>
</html>