<?php

declare(strict_types=1);

require_once __DIR__ . '/api_common.php';

apply_json_security_headers();
apply_cors();
require_methods(['GET', 'POST', 'PUT', 'DELETE']);

$auth = require_auth(['director', 'docente', 'estudiante']);
$role = $auth['data']['rol'] ?? '';
$userId = (int) ($auth['data']['user_id'] ?? 0);
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$payload = request_payload();
$pdo = get_pdo_connection();

function student_nie_for_user(PDO $pdo, int $userId): int
{
    $stmt = $pdo->prepare('SELECT nie FROM estudiantes WHERE usuario_id = :usuario_id');
    $stmt->execute(['usuario_id' => $userId]);
    $row = $stmt->fetch();

    return $row ? (int) $row['nie'] : 0;
}

try {
    if ($method === 'GET') {
        $id = isset($_GET['id']) ? (int) $_GET['id'] : 0;

        if ($id > 0) {
            $stmt = $pdo->prepare('SELECT id, estudiante_nie, descripcion, fecha_hora FROM demeritos WHERE id = :id AND deleted_at IS NULL');
            $stmt->execute(['id' => $id]);
            $row = $stmt->fetch();

            if (!$row) {
                send_json(404, 'error', 'demérito no encontrado');
            }

            if ($role === 'estudiante') {
                $myNie = student_nie_for_user($pdo, $userId);
                if ($myNie <= 0 || $myNie !== (int) $row['estudiante_nie']) {
                    send_json(403, 'access denied', 'solo puedes ver tus deméritos');
                }
            }

            send_json(200, 'success', 'demérito encontrado', ['demerito' => $row]);
        }

        if ($role === 'estudiante') {
            $myNie = student_nie_for_user($pdo, $userId);
            if ($myNie <= 0) {
                send_json(403, 'access denied', 'estudiante sin NIE asociado');
            }

            $stmt = $pdo->prepare('SELECT id, estudiante_nie, descripcion, fecha_hora FROM demeritos WHERE estudiante_nie = :nie AND deleted_at IS NULL ORDER BY fecha_hora DESC');
            $stmt->execute(['nie' => $myNie]);
            $rows = $stmt->fetchAll();
            send_json(200, 'success', 'tus deméritos', ['demeritos' => $rows]);
        }

        $params = [];
        $sql = 'SELECT id, estudiante_nie, descripcion, fecha_hora FROM demeritos WHERE deleted_at IS NULL';

        if (isset($_GET['estudiante_nie']) && $_GET['estudiante_nie'] !== '') {
            $sql .= ' AND estudiante_nie = :estudiante_nie';
            $params['estudiante_nie'] = (int) $_GET['estudiante_nie'];
        }

        $sql .= ' ORDER BY fecha_hora DESC';
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        $rows = $stmt->fetchAll();

        send_json(200, 'success', 'listado de deméritos', ['demeritos' => $rows]);
    }

    if ($method === 'POST') {
        if (!in_array($role, ['director', 'docente'], true)) {
            send_json(403, 'access denied', 'solo director o docente pueden agregar deméritos');
        }

        $estudianteNie = (int) ($payload['estudiante_nie'] ?? 0);
        $descripcion = sanitize_text((string) ($payload['descripcion'] ?? ''), 1000);

        if ($estudianteNie <= 0 || $descripcion === '') {
            send_json(400, 'error', 'datos de demérito inválidos');
        }

        $exists = $pdo->prepare('SELECT nie FROM estudiantes WHERE nie = :nie');
        $exists->execute(['nie' => $estudianteNie]);
        if (!$exists->fetch()) {
            send_json(400, 'error', 'el estudiante no existe');
        }

        $stmt = $pdo->prepare('INSERT INTO demeritos (estudiante_nie, descripcion, deleted_at) VALUES (:estudiante_nie, :descripcion, NULL)');
        $stmt->execute([
            'estudiante_nie' => $estudianteNie,
            'descripcion' => $descripcion,
        ]);

        send_json(201, 'success', 'demérito creado');
    }

    if ($method === 'PUT') {
        if ($role !== 'director') {
            send_json(403, 'access denied', 'solo director puede editar deméritos');
        }

        $id = (int) ($payload['id'] ?? 0);
        $descripcion = sanitize_text((string) ($payload['descripcion'] ?? ''), 1000);

        if ($id <= 0 || $descripcion === '') {
            send_json(400, 'error', 'id y descripcion son requeridos');
        }

        $stmt = $pdo->prepare('UPDATE demeritos SET descripcion = :descripcion WHERE id = :id AND deleted_at IS NULL');
        $stmt->execute([
            'descripcion' => $descripcion,
            'id' => $id,
        ]);

        if ($stmt->rowCount() === 0) {
            send_json(404, 'error', 'demérito no encontrado o sin cambios');
        }

        send_json(200, 'success', 'demérito actualizado');
    }

    if ($method === 'DELETE') {
        if ($role !== 'director') {
            send_json(403, 'access denied', 'solo director puede eliminar deméritos');
        }

        $id = (int) ($payload['id'] ?? ($_GET['id'] ?? 0));
        if ($id <= 0) {
            send_json(400, 'error', 'id requerido');
        }

        $stmt = $pdo->prepare('UPDATE demeritos SET deleted_at = CURRENT_TIMESTAMP WHERE id = :id AND deleted_at IS NULL');
        $stmt->execute(['id' => $id]);

        if ($stmt->rowCount() === 0) {
            send_json(404, 'error', 'demérito no encontrado');
        }

        send_json(200, 'success', 'demérito eliminado lógicamente');
    }

    send_json(405, 'error', 'método no permitido');
} catch (PDOException $e) {
    error_log('demeritos.php DB error: ' . $e->getMessage());
    send_json(500, 'error', 'error interno');
}
