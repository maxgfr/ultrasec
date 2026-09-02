<?php
$allowed = ['api.example.com', 'cdn.example.com'];
$url = $_GET['url'];
// Only the host is inspected; nothing is fetched from the input here.
$host = parse_url($url, PHP_URL_HOST);
$ok = in_array($host, $allowed, true);
http_response_code($ok ? 200 : 400);
