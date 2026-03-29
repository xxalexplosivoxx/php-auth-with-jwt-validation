<?php

declare(strict_types=1);

$host = getenv('DB_HOST') ?: 'db';
$db = getenv('DB_NAME') ?: 'escuela';
$user = getenv('DB_USER') ?: 'docker';
$pass = getenv('DB_PASS') ?: '';
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
];

function get_pdo_connection(): PDO
{
    static $pdo = null;
    global $dsn, $user, $pass, $options;

    if ($pdo === null) {
        $pdo = new PDO($dsn, $user, $pass, $options);
    }

    return $pdo;
}