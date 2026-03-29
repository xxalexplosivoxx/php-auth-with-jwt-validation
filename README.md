# php-auth-with-jwt-validation

API PHP con autenticación OTP + JWT, acceso seguro a MariaDB y CRUD para docentes y deméritos.

## Configuración segura

1. Crea un archivo `.env` tomando como base `.env.example`.
2. Define valores seguros para `DB_PASS`, `MYSQL_ROOT_PASSWORD` y `JWT_SECRET`.
3. Inicia el entorno:

```bash
docker compose up --build
```

## Variables de entorno

- `DB_HOST`
- `DB_NAME`
- `DB_USER`
- `DB_PASS`
- `JWT_SECRET`
- `JWT_TTL`
- `APP_ALLOWED_ORIGINS` (CSV, por defecto localhost)

## Endpoints

### 1) Generar QR para 2FA

- `POST /generate_qr.php`
- Body JSON:

```json
{
	"nombre": "Nombre Usuario",
	"email": "correo@dominio.com"
}
```

### 2) Verificar OTP y obtener JWT

- `POST /verify.php`
- Body JSON:

```json
{
	"secret": "CLAVE_ACCESO_2FA",
	"one-time-passwd": "123456"
}
```

### 3) Endpoint protegido de ejemplo

- `GET /teachers.php`
- Header: `Authorization: Bearer <token>`

### 4) CRUD Docentes

- `GET /docentes.php` (lista)
- `GET /docentes.php?nip=123` (detalle)
- `POST /docentes.php`
- `PUT /docentes.php`
- `DELETE /docentes.php?nip=123`

`POST /docentes.php` soporta 2 modos:
- Modo automático (crea usuario + docente en una sola transacción): enviar `nip`, `asignaturas`, `nombres`, `apellidos`, `email` y opcional `fecha_nacimiento`.
- Modo vinculación (docente existente): enviar `nip`, `asignaturas`, `usuario_id`.

En modo automático, la API devuelve `clave_acceso` para enrolar 2FA del docente.

Permisos:
- Lectura: `director`, `docente`
- Escritura: solo `director`

### 5) CRUD Deméritos

- `GET /demeritos.php` (lista)
- `GET /demeritos.php?id=1` (detalle)
- `POST /demeritos.php`
- `PUT /demeritos.php`
- `DELETE /demeritos.php?id=1`

Permisos:
- `director`: CRUD completo
- `docente`: crear y ver todos
- `estudiante`: solo ver sus propios deméritos

### 6) Alta de Estudiantes

- `POST /estudiantes.php`
- Body JSON:

```json
{
	"nie": 123456,
	"grado": "9A",
	"nombres": "Ana",
	"apellidos": "Pérez",
	"email": "ana@example.com",
	"fecha_nacimiento": "2012-04-03"
}
```

Permisos:
- `director` y `docente` pueden crear estudiantes.

La API crea el usuario (`rol=estudiante`) y el registro en `estudiantes` en una sola transacción, y devuelve `clave_acceso` para enrolar 2FA.

## Seguridad aplicada

- CORS restringido por lista de orígenes permitidos.
- Headers HTTP de seguridad en respuestas JSON.
- Consultas SQL con prepared statements.
- JWT firmado con secreto global del servidor.
- Rate limiting básico en verificación OTP.
- Borrado lógico para `docentes` y `demeritos` mediante `deleted_at`.