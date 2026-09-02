<?php
$payload = $_POST['payload'];
// JSON, not XML: no entity expansion exists in this parser.
$doc = json_decode($payload, true);
http_response_code(is_array($doc) ? 200 : 400);
