<?php
$dbFile = __DIR__ . '/vuln_db.sqlite';
if (file_exists($dbFile)) {
    unlink($dbFile);
}
$db = new PDO('sqlite:' . $dbFile);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Cria tabela users
$db->exec("CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)");

// Insere um utilizador de teste (senha em plain-text de propósito)
$insert = $db->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
$insert->execute(['admin', 'password123']);

echo "Base de dados criada em: $dbFile\nUtilizador: admin / password123\n";
