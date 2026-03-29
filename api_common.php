<?php

declare(strict_types=1);

require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/msql-access.php';
require_once __DIR__ . '/token_utils.php';

function app_config(): array
{
    static $config = null;

    if ($config !== null) {
        return $config;
    }

    $originsRaw = getenv('APP_ALLOWED_ORIGINS') ?: 'http://localhost,http://127.0.0.1,http://localhost:8080';
    $origins = array_values(array_filter(array_map('trim', explode(',', $originsRaw))));

    $config = [
        'allowed_origins' => $origins,
        'jwt_ttl' => (int) (getenv('JWT_TTL') ?: 3600),
        'jwt_secret' => getenv('JWT_SECRET') ?: 'change-this-secret-in-production',
    ];

    return $config;
}

function apply_json_security_headers(): void
{
    header('Content-Type: application/json; charset=UTF-8');
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");
}

function apply_cors(): void
{
    $config = app_config();
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';

    if ($origin !== '' && in_array($origin, $config['allowed_origins'], true)) {
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Vary: Origin');
    }

    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Authorization, Content-Type');

    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'OPTIONS') {
        http_response_code(204);
        exit;
    }
}

function send_json(int $code, string $status, string $message, array $data = []): void
{
    http_response_code($code);
    echo json_encode([
        'status' => $status,
        'message' => $message,
        'data' => $data,
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

function request_payload(): array
{
    $contentType = $_SERVER['CONTENT_TYPE'] ?? '';

    if (stripos($contentType, 'application/json') !== false) {
        $raw = file_get_contents('php://input');
        $decoded = json_decode($raw ?: '{}', true);

        if (!is_array($decoded)) {
            send_json(400, 'error', 'JSON inválido');
        }

        return $decoded;
    }

    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
        return $_GET;
    }

    if (in_array($_SERVER['REQUEST_METHOD'] ?? 'GET', ['PUT', 'DELETE'], true)) {
        parse_str((string) file_get_contents('php://input'), $parsed);
        return is_array($parsed) ? $parsed : [];
    }

    return $_POST;
}

function require_methods(array $allowed): void
{
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

    if (!in_array($method, $allowed, true)) {
        send_json(405, 'error', 'Método no permitido');
    }
}

function bearer_token(): string
{
    $headers = getallheaders();
    $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? '';

    if ($authHeader === '') {
        send_json(401, 'access denied', 'cabecera Authorization no encontrada');
    }

    $parts = explode(' ', trim($authHeader), 2);

    if (count($parts) !== 2 || strcasecmp($parts[0], 'Bearer') !== 0 || trim($parts[1]) === '') {
        send_json(401, 'access denied', 'Formato de autorización inválido');
    }

    return trim($parts[1]);
}

function require_auth(array $allowedRoles = [])
{
    $token = bearer_token();

    try {
        $payload = decode_jwt($token);
    } catch (Throwable $e) {
        send_json(401, 'access denied', 'token de acceso inválido');
    }

    $role = $payload['data']['rol'] ?? null;

    if (!empty($allowedRoles) && !in_array($role, $allowedRoles, true)) {
        send_json(403, 'access denied', 'sin permisos suficientes');
    }

    return $payload;
}

function sanitize_text(string $input, int $maxLength = 255): string
{
    $value = trim($input);
    $value = preg_replace('/\s+/', ' ', $value) ?? '';

    if ($value === '' || mb_strlen($value) > $maxLength) {
        return '';
    }

    return $value;
}

function rate_limit(string $key, int $maxAttempts, int $windowSeconds): void
{
    $file = sys_get_temp_dir() . '/auth_rate_' . sha1($key) . '.json';
    $now = time();

    $fp = fopen($file, 'c+');
    if ($fp === false) {
        return;
    }

    flock($fp, LOCK_EX);

    $contents = stream_get_contents($fp);
    $timestamps = json_decode($contents ?: '[]', true);
    if (!is_array($timestamps)) {
        $timestamps = [];
    }

    $timestamps = array_values(array_filter($timestamps, static function ($ts) use ($now, $windowSeconds): bool {
        return is_int($ts) && $ts > ($now - $windowSeconds);
    }));

    if (count($timestamps) >= $maxAttempts) {
        flock($fp, LOCK_UN);
        fclose($fp);
        send_json(429, 'error', 'demasiados intentos, intenta más tarde');
    }

    $timestamps[] = $now;

    ftruncate($fp, 0);
    rewind($fp);
    fwrite($fp, json_encode($timestamps));

    flock($fp, LOCK_UN);
    fclose($fp);
}
