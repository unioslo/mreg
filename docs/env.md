# Environment Variables

## Keycloak authentication

See [Authentication](authentication.md) for the token contract, LDAP prerequisites,
and rollout instructions. The feature is disabled by default.

| Variable | Default | Purpose |
| --- | --- | --- |
| `MREG_OIDC_ENABLED` | `False` | Enable Keycloak bearer authentication alongside local tokens. |
| `MREG_OIDC_ISSUER` | Empty | Exact trusted HTTPS realm issuer. Required when enabled. |
| `MREG_OIDC_AUDIENCE` | Empty | Required access-token audience identifying mreg. |
| `MREG_OIDC_JWKS_URL` | Empty | Trusted HTTPS JWKS endpoint. Required when enabled. |
| `MREG_OIDC_USERNAME_CLAIM` | Empty | One authoritative LDAP username claim. Required when enabled. |
| `MREG_OIDC_ALLOWED_CLIENT_IDS` | Empty | Comma-separated permitted `azp` client IDs. Required when enabled. |
| `MREG_OIDC_ALGORITHMS` | `RS256` | Comma-separated asymmetric JWT signing algorithms. |
| `MREG_OIDC_JWKS_TIMEOUT` | `5` | Positive HTTPS fetch timeout, in seconds. |
| `MREG_OIDC_JWKS_CACHE_SECONDS` | `300` | Positive lifetime of each worker's JWKS cache. |
| `MREG_OIDC_JWKS_COOLDOWN_SECONDS` | `30` | Positive minimum interval between successful fetches and unknown-key refreshes. |
| `MREG_OIDC_LEEWAY_SECONDS` | `0` | Nonnegative clock tolerance for token time checks. |

Comma-separated values must not contain surrounding whitespace. In
`local_settings.py`, supply lists or tuples for client IDs and algorithms.
Issuer and JWKS URLs must not contain credentials, query strings, or fragments.

## `MREG_LOG_LEVEL`

Log level of the application. Default: `CRITICAL`

Must be one of the following:

- `DEBUG`
- `INFO`
- `WARNING`
- `ERROR`
- `CRITICAL`

## `MREG_LOG_FILE_SIZE`

Maximum file size of the log file in bytes. Default: `52428800` (50MB).

> [!IMPORTANT]  
> The actual disk space required is `MREG_LOG_FILE_SIZE` multiplied by `MREG_LOG_FILE_COUNT`.

## `MREG_LOG_FILE_COUNT`

Maximum number of log files to keep when rotating files as they reach their maximum size. Default: `10`

## `MREG_LOG_FILE_NAME`

Path to the log file. Default: `logs/app.log` (relative to the project's `BASE_DIR`).

## `MREG_MAP_GLOBAL_COMMUNITY_NAMES`

Boolean flag controlling whether global community names are mapped. Default: `False`.

If defined and not empty, this feature is enabled.

## `MREG_DB_NAME`

Name of the PostgreSQL database to connect to. Default: `mreg`.

## `MREG_DB_USER`

PostgreSQL username for database connection. Default: `mreg`.

## `MREG_DB_PASSWORD`

PostgreSQL password for database connection. Default: empty string (`""`).

## `MREG_DB_HOST`

Host address of the PostgreSQL server. Default: `localhost`.

## `MREG_DB_PORT`

Port number for the PostgreSQL server connection. Default: `5432`.
