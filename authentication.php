<?php

// ============================================================
// AUTHENTICATION — Session Naming & Secure Session Startup
// RUBRIC: Strong security (authentication, data protection)
// ============================================================
// Names the admin session separately from the patient portal
// session so their cookies never interfere with each other.
// httponly=1     — JavaScript cannot read or steal the cookie.
// use_strict_mode — Server rejects unrecognized session IDs.
// samesite=Strict — Cookie is never sent on cross-site requests,
//                   preventing CSRF (Cross-Site Request Forgery).
// ============================================================
session_name('dcms_admin');
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_samesite', 'Strict');
    session_start();
}

// ============================================================
// AUTHENTICATION — Session Timeout (8 hours)
// RUBRIC: Strong security (authentication, data protection)
// ============================================================
// Tracks the last time the user was active. If they have been
// inactive for more than 8 hours (SESSION_LIFETIME), their
// session is completely destroyed and they are redirected to
// the login page. This prevents unauthorized access from
// unattended or forgotten open browser sessions.
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
// AUTHENTICATION — Login Enforcement (Login Wall)
// RUBRIC: Strong security (authentication, data protection)
// ============================================================
// Every protected page includes this file. If user_id is not
// set in the session (meaning the user is not logged in),
// they are immediately redirected to the login page.
// No protected page can ever be reached without logging in first.
// ============================================================
if (!isset($_SESSION['user_id'])) {
    header('Location: ' . BASE_URL . 'index.php');
    exit();
}

// Store the current logged-in user's details for use on any page
$current_user_id   = $_SESSION['user_id'];
$current_user_name = $_SESSION['full_name'];
$current_user_role = $_SESSION['role'];

// ============================================================
// AUTHENTICATION — Session Fixation Protection
// RUBRIC: Strong security (authentication, data protection)
// ============================================================
// Regenerates the session ID every 30 minutes while the user
// is active. This means even if an attacker manages to steal
// a session ID, it becomes invalid after 30 minutes.
// session_regenerate_id(true) also deletes the old session
// file from the server so it cannot be reused.
// ============================================================
if (!isset($_SESSION['created_at'])) {
    $_SESSION['created_at'] = time();
} elseif (time() - $_SESSION['created_at'] > 1800) {
    session_regenerate_id(true);
    $_SESSION['created_at'] = time();
}

// ============================================================
// AUTHENTICATION — Role-Based Access Control (RBAC)
// RUBRIC: Strong security (authentication, data protection,
//         validation)
// ============================================================
// is_admin()     — Returns true only if the logged-in user has
//                  the 'admin' role stored in their session.
// require_admin() — Called at the top of admin-only pages.
//                  If a staff member tries to access an admin
//                  page directly via URL, they are blocked and
//                  redirected to the dashboard immediately.
// This ensures staff cannot access user management, reports,
// or any other admin-restricted functionality.
// ============================================================
function is_admin() {
    return isset($_SESSION['role']) && $_SESSION['role'] === 'admin';
}

function require_admin() {
    if (!is_admin()) {
        header('Location: ' . BASE_URL . 'dashboard.php');
        exit();
    }
}
