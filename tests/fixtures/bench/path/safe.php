<?php
$allowed = ['report.pdf', 'terms.pdf'];
$name = basename($_GET['name']);
// Allow-listed name; nothing is opened from the input.
$ok = in_array($name, $allowed, true);
http_response_code($ok ? 200 : 404);
