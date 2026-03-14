<?php
// ============================================================
// auth.php - Session checker + Security
// ============================================================

if (session_status() === PHP_SESSION_NONE) {
    // Secure session settings
    ini_set('session.cookie_httponly', 1);    // JS cannot access session cookie
    ini_set('session.use_strict_mode', 1);    // Reject uninitialized session IDs
    ini_set('session.cookie_samesite', 'Strict');
    session_start();
}

// ============================================================
// SESSION TIMEOUT — log out after 8 hours of inactivity
// ============================================================
if (isset($_SESSION['last_activity'])) {
    if (time() - $_SESSION['last_activity'] > SESSION_LIFETIME) {
        session_unset();
        session_destroy();
        header('Location: ' . BASE_URL . 'index.php?timeout=1');
        exit();
    }
}
$_SESSION['last_activity'] = time();

// ============================================================
// Redirect to login if not logged in
// ============================================================
if (!isset($_SESSION['user_id'])) {
    header('Location: ' . BASE_URL . 'index.php');
    exit();
}

$current_user_id   = $_SESSION['user_id'];
$current_user_name = $_SESSION['full_name'];
$current_user_role = $_SESSION['role'];

// ============================================================
// SESSION FIXATION PROTECTION
// Regenerate session ID periodically (every 30 minutes)
// ============================================================
if (!isset($_SESSION['created_at'])) {
    $_SESSION['created_at'] = time();
} elseif (time() - $_SESSION['created_at'] > 1800) {
    session_regenerate_id(true);
    $_SESSION['created_at'] = time();
}

function is_admin() {
    return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
}

function require_admin() {
    if (!is_admin()) {
        header('Location: ' . BASE_URL . 'dashboard.php');
        exit();
    }
}
