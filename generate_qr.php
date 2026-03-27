<?php
require __DIR__ . '/vendor/autoload.php';
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");

use PragmaRX\Google2FA\Google2FA;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\Image\ImagickImageBackEnd;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;


if (isset($_GET['nombre']) and isset($_GET['email'])) {
	$nombre = addslashes($_GET['nombre']);
	$email = addslashes($_GET['email']);

	$google2fa = new Google2FA();

	$secretKey = $google2fa->generateSecretKey();

	$qrCodeUrl = $google2fa->getQRCodeUrl(
	    "$nombre",
	    "$email",
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
	        "clave_acceso" => "$secretKey",
	        "QR_base64" => "$base64"
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
?>
