<?php
$pdo = new PDO("mysql:host=localhost;dbname=app", "app", "secret");
$id = $_GET['id'];
// Prepared with a named placeholder; the value is bound, never concatenated.
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->bindValue(':id', (int) $id, PDO::PARAM_INT);
