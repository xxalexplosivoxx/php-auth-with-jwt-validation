<?php

declare(strict_types=1);

require_once __DIR__ . '/api_common.php';

apply_json_security_headers();
apply_cors();
require_methods(['POST']);

use PragmaRX\Google2FA\Google2FA;

$google2fa = new Google2FA();

$payload = request_payload();
$secret = trim((string) ($payload['secret'] ?? ''));
$userInputCode = trim((string) ($payload['one-time-passwd'] ?? ''));

if ($secret === '' || $userInputCode === '') {
    send_json(400, 'access denied', 'faltan datos', ['token' => 'N/A']);
}

if (!preg_match('/^[0-9]{6}$/', $userInputCode)) {
    send_json(400, 'access denied', 'codigo OTP inválido', ['token' => 'N/A']);
}

$rateKey = ($_SERVER['REMOTE_ADDR'] ?? 'unknown') . '|' . $secret;
rate_limit($rateKey, 5, 600);

try {
    $pdo = get_pdo_connection();
    $stmt = $pdo->prepare('SELECT * FROM usuarios WHERE clave_acceso = :clave_acceso AND activo = 1 LIMIT 1');
    $stmt->execute(['clave_acceso' => $secret]);
    $userFound = $stmt->fetch();

    if (!$userFound) {
        send_json(401, 'access denied', 'clave o secreto incorrecto', ['token' => 'N/A']);
    }

    $valid = $google2fa->verifyKey($secret, $userInputCode);

    if (!$valid) {
        send_json(401, 'access denied', 'clave o secreto incorrecto', ['token' => 'N/A']);
    }

    $jwt = create_jwt($userFound);
    send_json(200, 'success', 'clave correcta', ['token' => $jwt]);
} catch (PDOException $e) {
    error_log('verify.php DB error: ' . $e->getMessage());
    send_json(500, 'error', 'error interno', ['token' => 'N/A']);
} catch (Throwable $e) {
    error_log('verify.php error: ' . $e->getMessage());
    send_json(500, 'error', 'error interno', ['token' => 'N/A']);
}
