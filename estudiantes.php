<?php

declare(strict_types=1);

require_once __DIR__ . '/api_common.php';

use PragmaRX\Google2FA\Google2FA;

apply_json_security_headers();
apply_cors();
require_methods(['POST']);

$auth = require_auth(['director', 'docente']);
$payload = request_payload();
$pdo = get_pdo_connection();

$nie = (int) ($payload['nie'] ?? 0);
$grado = sanitize_text((string) ($payload['grado'] ?? ''), 255);
$nombres = sanitize_text((string) ($payload['nombres'] ?? ''), 255);
$apellidos = sanitize_text((string) ($payload['apellidos'] ?? ''), 255);
$email = filter_var(trim((string) ($payload['email'] ?? '')), FILTER_VALIDATE_EMAIL);
$fechaNacimientoRaw = trim((string) ($payload['fecha_nacimiento'] ?? ''));
$fechaNacimiento = null;

if ($nie <= 0 || $grado === '' || $nombres === '' || $apellidos === '' || $email === false) {
    send_json(400, 'error', 'datos de estudiante inválidos');
}

if ($fechaNacimientoRaw !== '') {
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $fechaNacimientoRaw)) {
        send_json(400, 'error', 'fecha_nacimiento inválida, formato esperado YYYY-MM-DD');
    }
    $fechaNacimiento = $fechaNacimientoRaw;
}

try {
    $google2fa = new Google2FA();
    $secret = $google2fa->generateSecretKey();

    $pdo->beginTransaction();

    $createUser = $pdo->prepare(
        'INSERT INTO usuarios (rol, nombres, apellidos, email, fecha_nacimiento, clave_acceso, activo)
         VALUES (:rol, :nombres, :apellidos, :email, :fecha_nacimiento, :clave_acceso, 1)'
    );

    $createUser->execute([
        'rol' => 'estudiante',
        'nombres' => $nombres,
        'apellidos' => $apellidos,
        'email' => (string) $email,
        'fecha_nacimiento' => $fechaNacimiento,
        'clave_acceso' => $secret,
    ]);

    $usuarioId = (int) $pdo->lastInsertId();

    $createStudent = $pdo->prepare(
        'INSERT INTO estudiantes (nie, usuario_id, grado) VALUES (:nie, :usuario_id, :grado)'
    );
    $createStudent->execute([
        'nie' => $nie,
        'usuario_id' => $usuarioId,
        'grado' => $grado,
    ]);

    $pdo->commit();

    send_json(201, 'success', 'estudiante creado', [
        'nie' => $nie,
        'usuario_id' => $usuarioId,
        'clave_acceso' => $secret,
    ]);
} catch (PDOException $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log('estudiantes.php DB error: ' . $e->getMessage());

    if ($e->getCode() === '23000') {
        send_json(409, 'error', 'conflicto de datos: revisa nie, email o clave de acceso');
    }

    send_json(500, 'error', 'error interno');
}
