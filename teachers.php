<?php

declare(strict_types=1);

require_once __DIR__ . '/api_common.php';

apply_json_security_headers();
apply_cors();
require_methods(['GET']);

$auth = require_auth(['director', 'docente']);

$response = [
    'status' => 'success',
    'message' => 'bienvenido',
    'data' => [
        'usuario' => $auth['data']['nombres'] ?? '',
        'rol' => $auth['data']['rol'] ?? '',
        'hora' => time(),
    ],
];

http_response_code(200);
echo json_encode($response, JSON_UNESCAPED_UNICODE);
