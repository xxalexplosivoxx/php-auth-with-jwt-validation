<?php

declare(strict_types=1);

require_once __DIR__ . '/api_common.php';

apply_json_security_headers();
apply_cors();
require_methods(['POST']);

use PragmaRX\Google2FA\Google2FA;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\Image\ImagickImageBackEnd;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;

$payload = request_payload();
$nombre = sanitize_text((string) ($payload['nombre'] ?? ''), 120);
$email = filter_var(trim((string) ($payload['email'] ?? '')), FILTER_VALIDATE_EMAIL);

if ($nombre !== '' && $email !== false) {
	$emailSanitized = (string) $email;

	$google2fa = new Google2FA();

	$secretKey = $google2fa->generateSecretKey();

	$qrCodeUrl = $google2fa->getQRCodeUrl(
	    $nombre,
	    $emailSanitized,
	    $secretKey
	);

	$renderer = new ImageRenderer(
	    new RendererStyle(300),
	    new ImagickImageBackEnd()
	);
	$writer = new Writer($renderer);

	$pngData = $writer->writeString($qrCodeUrl);
	$base64 = base64_encode($pngData);

	$response = [
	    "status" => "success",
	    "message" => "QR y clave de acceso generada",
	    "data" => [
	        "clave_acceso" => $secretKey,
	        "QR_base64" => $base64
	    ]
	];

	http_response_code(200);
	echo json_encode($response);
} else {
	$response = [
	    "status" => "error",
	    "message" => "faltan parametros",
	    "data" => [
	    ]
	];

	http_response_code(400);
	echo json_encode($response);
}
