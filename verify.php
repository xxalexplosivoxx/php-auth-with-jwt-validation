<?php
require __DIR__ . '/vendor/autoload.php';
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");

use PragmaRX\Google2FA\Google2FA;
use Firebase\JWT\JWT;

$host = 'db';
$db   = 'escuela';
$user = 'docker';
$pass = 'mititluloselollevoexpedition33';
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION, // Throw exceptions on error
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,       // Fetch as associative array
    PDO::ATTR_EMULATE_PREPARES   => false,                  // Use real prepared statements
];

$google2fa = new Google2FA();

if (isset($_POST['one-time-passwd']) and isset($_POST['secret'])) {
    $secret = $_POST['secret'];
    $userInputCode = $_POST['one-time-passwd'];
	
	try {
        $pdo = new PDO($dsn, $user, $pass, $options);
	    $stmt = $pdo->prepare("SELECT * FROM usuarios WHERE clave_acceso = :clave_acceso");

        $stmt->execute(['clave_acceso' => trim($secret)]);
	     
	    $user_finded = $stmt->fetch();
	     
	    if ($user_finded) {
	        $valid = $google2fa->verifyKey($secret, $userInputCode);
	         
	        if ($valid) {
	        	$payload = [
	         	    'iss'  => 'http://urldelserver', 	// Emisor
	         	    'aud'  => 'http://urldelserver', 	// Receptores autorizados
	         	    'iat'  => time(),                   // Emitido en
	         	    'nbf'  => time(),                   // No Antes de
	         	    'exp'  => time() + 3600,            // Expira (en 1 hora)
	         	    'data' => [                         // Data custom
	         	        'user_id' => $user_finded['id'],
	         	        'nombres' => $user_finded['nombres'],
	         	        'email'  => $user_finded['email'],
	         	    ]
	         	];
	         	$jwt = JWT::encode($payload, $secret, 'HS256');
	            $response = [
		            "status" => "success",
		            "message" => "clave correcta",
		            "data" => [
		                "token" => "$jwt"
		            ]
		        ];
	            http_response_code(200);
	            echo json_encode($response);
	         } else {
	         	$response = [
	         		"status" => "access denied",
	         		"message" => "clave o secreto incorrecto",
	         		"data" => [
	         			"token" => "N/A"
	         		]
	         	];
	         	http_response_code(401);
	         	echo json_encode($response);
	         }
	     } else {
			$response = [
				"status" => "access denied",
				"message" => "clave o secreto incorrecto",
				"data" => [
					"token" => "N/A"
				]
			];
			http_response_code(401);
			echo json_encode($response);
	     }
	} catch (PDOException $e) {
	     echo json_encode([
             "status" => "error",
             "debug_message" => $e->getMessage(),
             "target_host" => $host
         ]);
         exit;
	}	
} else {
	$response = [
		"status" => "access denied",
		"message" => "faltan datos",
		"data" => [
            "token" => "N/A",
        ]
	];
	http_response_code(400);
	echo json_encode($response);
}
?>
