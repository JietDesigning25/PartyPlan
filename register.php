<?php
require_once '../config.php';

$errors = [];
$success = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitize inputs
    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    // Validate inputs
    if (empty($username)) {
        $errors['username'] = 'Username is required';
    } elseif (!preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username)) {
        $errors['username'] = 'Username must be 3-20 characters (letters, numbers, underscores)';
    }

    if (empty($email)) {
        $errors['email'] = 'Email is required';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors['email'] = 'Invalid email format';
    }

    if (empty($password)) {
        $errors['password'] = 'Password is required';
    } elseif (strlen($password) < 8) {
        $errors['password'] = 'Password must be at least 8 characters';
    } elseif ($password !== $confirm_password) {
        $errors['confirm_password'] = 'Passwords do not match';
    }

    // Check if username/email exists
    if (empty($errors)) {
        try {
            $stmt = $pdo->prepare("SELECT 1 FROM users WHERE username = ? OR email = ?");
            $stmt->execute([$username, $email]);
            
            if ($stmt->fetch()) {
                $errors['general'] = 'Username or email already exists';
            }
        } catch (PDOException $e) {
            $errors['general'] = 'Registration error. Please try again.';
        }
    }

    // Create user
    if (empty($errors)) {
        try {
            $pdo->beginTransaction();
            
            // Insert user
            $verification_token = REQUIRE_EMAIL_VERIFICATION ? generateToken() : null;
            $stmt = $pdo->prepare("
                INSERT INTO users (username, email, password_hash, verification_token)
                VALUES (?, ?, ?, ?)
            ");
            $stmt->execute([
                $username,
                $email,
                hashPassword($password),
                $verification_token
            ]);
            
            $user_id = $pdo->lastInsertId();
            
            // Assign user role
            $stmt = $pdo->prepare("INSERT INTO user_roles (user_id, role) VALUES (?, 'user')");
            $stmt->execute([$user_id]);
            
            $pdo->commit();
            
            // Send verification email if required
            if (REQUIRE_EMAIL_VERIFICATION && $verification_token) {
                $verification_url = BASE_URL . "/public/verify_email.php?token=$verification_token";
                // In production: sendEmail($email, "Verify your email", "Click here to verify: $verification_url");
            }
            
            $success = true;
        } catch (PDOException $e) {
            $pdo->rollBack();
            $errors['general'] = 'Registration failed. Please try again.';
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - <?= SITE_NAME ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .form-container {
            max-width: 500px;
            margin: 2rem auto;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }
        .password-strength {
            height: 5px;
            margin-top: 5px;
            background: #eee;
        }
        .password-strength span {
            display: block;
            height: 100%;
            transition: width 0.3s, background 0.3s;
        }
    </style>
</head>
<body>
    <?php include '../navbar.php'; ?>
    
    <div class="container py-5">
        <div class="form-container bg-white">
            <h2 class="text-center mb-4">Create an Account</h2>
            
            <?php if ($success): ?>
                <div class="alert alert-success">
                    <p>Registration successful! <?= REQUIRE_EMAIL_VERIFICATION ? 'Please check your email to verify your account.' : 'You can now login.' ?></p>
                    <a href="login.php" class="btn btn-success">Go to Login</a>
                </div>
            <?php else: ?>
                <?php if (!empty($errors['general'])): ?>
                    <div class="alert alert-danger"><?= htmlspecialchars($errors['general']) ?></div>
                <?php endif; ?>
                
                <form method="post" novalidate>
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <input type="text" class="form-control <?= isset($errors['username']) ? 'is-invalid' : '' ?>" 
                               id="username" name="username" value="<?= htmlspecialchars($username) ?>" required>
                        <?php if (isset($errors['username'])): ?>
                            <div class="invalid-feedback"><?= htmlspecialchars($errors['username']) ?></div>
                        <?php endif; ?>
                    </div>
                    
                    <div class="mb-3">
                        <label for="email" class="form-label">Email</label>
                        <input type="email" class="form-control <?= isset($errors['email']) ? 'is-invalid' : '' ?>" 
                               id="email" name="email" value="<?= htmlspecialchars($email) ?>" required>
                        <?php if (isset($errors['email'])): ?>
                            <div class="invalid-feedback"><?= htmlspecialchars($errors['email']) ?></div>
                        <?php endif; ?>
                    </div>
                    
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <input type="password" class="form-control <?= isset($errors['password']) ? 'is-invalid' : '' ?>" 
                               id="password" name="password" required>
                        <div class="password-strength mt-1">
                            <span id="password-strength-bar"></span>
                        </div>
                        <?php if (isset($errors['password'])): ?>
                            <div class="invalid-feedback"><?= htmlspecialchars($errors['password']) ?></div>
                        <?php else: ?>
                            <small class="text-muted">Minimum 8 characters</small>
                        <?php endif; ?>
                    </div>
                    
                    <div class="mb-4">
                        <label for="confirm_password" class="form-label">Confirm Password</label>
                        <input type="password" class="form-control <?= isset($errors['confirm_password']) ? 'is-invalid' : '' ?>" 
                               id="confirm_password" name="confirm_password" required>
                        <?php if (isset($errors['confirm_password'])): ?>
                            <div class="invalid-feedback"><?= htmlspecialchars($errors['confirm_password']) ?></div>
                        <?php endif; ?>
                    </div>
                    
                    <button type="submit" class="btn btn-primary w-100 py-2 mb-3">Register</button>
                    
                    <div class="text-center">
                        <p>Already have an account? <a href="login.php">Login here</a></p>
                    </div>
                </form>
            <?php endif; ?>
        </div>
    </div>

    <?php include '../footer.php'; ?>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Password strength indicator
        document.getElementById('password').addEventListener('input', function() {
            const password = this.value;
            const strengthBar = document.getElementById('password-strength-bar');
            let strength = 0;
            
            if (password.length >= 8) strength += 1;
            if (password.match(/[a-z]/)) strength += 1;
            if (password.match(/[A-Z]/)) strength += 1;
            if (password.match(/[0-9]/)) strength += 1;
            if (password.match(/[^a-zA-Z0-9]/)) strength += 1;
            
            const width = (strength / 5) * 100;
            let color;
            
            if (strength <= 1) color = '#dc3545';
            else if (strength <= 3) color = '#fd7e14';
            else color = '#28a745';
            
            strengthBar.style.width = width + '%';
            strengthBar.style.background = color;
        });
    </script>
</body>
</html>