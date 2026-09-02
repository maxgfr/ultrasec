<?php
$page = $_GET['page'];
$allowed = ['home', 'about'];
// The input only selects among fixed includes; the path is never built from it.
if (in_array($page, $allowed, true)) {
    require_once __DIR__ . '/pages/home.php';
}
