<?php

declare(strict_types=1);

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

function jwt_secret(): string
{
    return getenv('JWT_SECRET') ?: 'change-this-secret-in-production';
}

function decode_jwt(string $jwt): array
{
    $decoded = JWT::decode($jwt, new Key(jwt_secret(), 'HS256'));
    return json_decode(json_encode($decoded), true) ?: [];
}

function create_jwt(array $user): string
{
    $ttl = (int) (getenv('JWT_TTL') ?: 3600);

    $payload = [
        'iss' => 'auth-api',
        'aud' => 'auth-client',
        'iat' => time(),
        'nbf' => time(),
        'exp' => time() + $ttl,
        'data' => [
            'user_id' => $user['id'],
            'rol' => $user['rol'],
            'nombres' => $user['nombres'],
            'email' => $user['email'],
        ],
    ];

    return JWT::encode($payload, jwt_secret(), 'HS256');
}
