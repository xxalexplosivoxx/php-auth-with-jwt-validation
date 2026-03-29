<?php

declare(strict_types=1);

require_once __DIR__ . '/api_common.php';

use PragmaRX\Google2FA\Google2FA;

apply_json_security_headers();
apply_cors();
require_methods(['GET', 'POST', 'PUT', 'DELETE']);

$auth = require_auth(['director', 'docente']);
$role = $auth['data']['rol'] ?? '';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$payload = request_payload();
$pdo = get_pdo_connection();

try {
    if ($method === 'GET') {
        $nip = isset($_GET['nip']) ? (int) $_GET['nip'] : 0;

        if ($nip > 0) {
            $stmt = $pdo->prepare('SELECT nip, usuario_id, asignaturas FROM docentes WHERE nip = :nip AND deleted_at IS NULL');
            $stmt->execute(['nip' => $nip]);
            $row = $stmt->fetch();

            if (!$row) {
                send_json(404, 'error', 'docente no encontrado');
            }

            send_json(200, 'success', 'docente encontrado', ['docente' => $row]);
        }

        $stmt = $pdo->query('SELECT nip, usuario_id, asignaturas FROM docentes WHERE deleted_at IS NULL ORDER BY nip ASC');
        $rows = $stmt->fetchAll();
        send_json(200, 'success', 'listado de docentes', ['docentes' => $rows]);
    }

    if ($role !== 'director') {
        send_json(403, 'access denied', 'solo director puede modificar docentes');
    }

    if ($method === 'POST') {
        $nip = (int) ($payload['nip'] ?? 0);
        $usuarioId = (int) ($payload['usuario_id'] ?? 0);
        $asignaturas = sanitize_text((string) ($payload['asignaturas'] ?? ''), 255);

        $nombres = sanitize_text((string) ($payload['nombres'] ?? ''), 255);
        $apellidos = sanitize_text((string) ($payload['apellidos'] ?? ''), 255);
        $email = filter_var(trim((string) ($payload['email'] ?? '')), FILTER_VALIDATE_EMAIL);
        $fechaNacimientoRaw = trim((string) ($payload['fecha_nacimiento'] ?? ''));
        $fechaNacimiento = null;

        if ($nip <= 0 || $asignaturas === '') {
            send_json(400, 'error', 'datos de docente inválidos');
        }

        if ($fechaNacimientoRaw !== '') {
            if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $fechaNacimientoRaw)) {
                send_json(400, 'error', 'fecha_nacimiento inválida, formato esperado YYYY-MM-DD');
            }
            $fechaNacimiento = $fechaNacimientoRaw;
        }

        $generatedSecret = null;

        $pdo->beginTransaction();

        if ($usuarioId <= 0) {
            if ($nombres === '' || $apellidos === '' || $email === false) {
                $pdo->rollBack();
                send_json(400, 'error', 'para crear docente automático se requieren nombres, apellidos y email válidos');
            }

            $google2fa = new Google2FA();
            $generatedSecret = $google2fa->generateSecretKey();

            $createUser = $pdo->prepare(
                'INSERT INTO usuarios (rol, nombres, apellidos, email, fecha_nacimiento, clave_acceso, activo)
                 VALUES (:rol, :nombres, :apellidos, :email, :fecha_nacimiento, :clave_acceso, 1)'
            );
            $createUser->execute([
                'rol' => 'docente',
                'nombres' => $nombres,
                'apellidos' => $apellidos,
                'email' => (string) $email,
                'fecha_nacimiento' => $fechaNacimiento,
                'clave_acceso' => $generatedSecret,
            ]);

            $usuarioId = (int) $pdo->lastInsertId();
        }

        $exists = $pdo->prepare('SELECT id, rol FROM usuarios WHERE id = :id AND activo = 1');
        $exists->execute(['id' => $usuarioId]);
        $usuario = $exists->fetch();

        if (!$usuario || $usuario['rol'] !== 'docente') {
            $pdo->rollBack();
            send_json(400, 'error', 'usuario_id debe pertenecer a un docente activo');
        }

        $stmt = $pdo->prepare('INSERT INTO docentes (nip, usuario_id, asignaturas, deleted_at) VALUES (:nip, :usuario_id, :asignaturas, NULL)');
        $stmt->execute([
            'nip' => $nip,
            'usuario_id' => $usuarioId,
            'asignaturas' => $asignaturas,
        ]);

        $pdo->commit();

        $responseData = [
            'nip' => $nip,
            'usuario_id' => $usuarioId,
        ];

        if ($generatedSecret !== null) {
            $responseData['clave_acceso'] = $generatedSecret;
        }

        send_json(201, 'success', 'docente creado', $responseData);
    }

    if ($method === 'PUT') {
        $nip = (int) ($payload['nip'] ?? 0);
        if ($nip <= 0) {
            send_json(400, 'error', 'nip requerido');
        }

        $fields = [];
        $params = ['nip' => $nip];

        if (array_key_exists('usuario_id', $payload)) {
            $usuarioId = (int) $payload['usuario_id'];
            if ($usuarioId <= 0) {
                send_json(400, 'error', 'usuario_id inválido');
            }

            $exists = $pdo->prepare('SELECT id, rol FROM usuarios WHERE id = :id AND activo = 1');
            $exists->execute(['id' => $usuarioId]);
            $usuario = $exists->fetch();

            if (!$usuario || $usuario['rol'] !== 'docente') {
                send_json(400, 'error', 'usuario_id debe pertenecer a un docente activo');
            }

            $fields[] = 'usuario_id = :usuario_id';
            $params['usuario_id'] = $usuarioId;
        }

        if (array_key_exists('asignaturas', $payload)) {
            $asignaturas = sanitize_text((string) $payload['asignaturas'], 255);
            if ($asignaturas === '') {
                send_json(400, 'error', 'asignaturas inválidas');
            }

            $fields[] = 'asignaturas = :asignaturas';
            $params['asignaturas'] = $asignaturas;
        }

        if (empty($fields)) {
            send_json(400, 'error', 'no hay campos para actualizar');
        }

        $sql = 'UPDATE docentes SET ' . implode(', ', $fields) . ' WHERE nip = :nip AND deleted_at IS NULL';
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);

        if ($stmt->rowCount() === 0) {
            send_json(404, 'error', 'docente no encontrado o sin cambios');
        }

        send_json(200, 'success', 'docente actualizado');
    }

    if ($method === 'DELETE') {
        $nip = (int) ($payload['nip'] ?? ($_GET['nip'] ?? 0));
        if ($nip <= 0) {
            send_json(400, 'error', 'nip requerido');
        }

        $stmt = $pdo->prepare('UPDATE docentes SET deleted_at = CURRENT_TIMESTAMP WHERE nip = :nip AND deleted_at IS NULL');
        $stmt->execute(['nip' => $nip]);

        if ($stmt->rowCount() === 0) {
            send_json(404, 'error', 'docente no encontrado');
        }

        send_json(200, 'success', 'docente eliminado lógicamente');
    }

    send_json(405, 'error', 'método no permitido');
} catch (PDOException $e) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log('docentes.php DB error: ' . $e->getMessage());

    if ($e->getCode() === '23000') {
        send_json(409, 'error', 'conflicto de datos: revisa nip, email, usuario_id o clave de acceso');
    }

    send_json(500, 'error', 'error interno');
}
