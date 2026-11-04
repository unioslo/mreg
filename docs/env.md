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

## Directory refresh

These shared settings currently apply to OIDC requests. Local-token authentication
keeps its existing behavior. All values are seconds and can also be set in
`local_settings.py`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `MREG_LDAP_REFRESH_SECONDS` | `300` | Freshness interval for stored user attributes, groups, and eligibility. Zero refreshes on every request. |
| `MREG_LDAP_GRACE_SECONDS` | `3600` | Additional time after freshness expires during which temporary LDAP failures allow retained permissions. Zero disables grace. |
| `MREG_LDAP_RETRY_SECONDS` | `30` | Per-user delay between failed refresh attempts, shared across workers. Zero disables backoff. |
| `MREG_LDAP_TIMEOUT_SECONDS` | `5` | Positive timeout for LDAP connection and individual synchronous operations; not an overall request deadline. |

**Permission changes can take up to the refresh interval to propagate once visible
in LDAP. During unavailability, old permissions can remain usable for refresh plus
grace seconds after the last successful refresh, including write/admin access.**
Failed attempts and new JWTs never reset this clock. A known denial or local
account disabling cannot use grace. Unknown users require a successful LDAP
lookup. See [Authentication](authentication.md#ldap-eligibility-and-permissions)
for error classification, retries, and transaction requirements.

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
