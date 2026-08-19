# Environment Variables

## `MREG_LOG_LEVEL`

Log level of the application. Default: `CRITICAL`

Must be one of the following:

- `DEBUG`
- `INFO`
- `WARNING`
- `ERROR`
- `CRITICAL`

## `MREG_POLICY_PARITY_LOG_LEVEL`

Log level for the dedicated `mreg.policy.parity` logger. Default: `WARNING`

This controls parity discrepancy logs independently from `MREG_LOG_LEVEL`, so
legacy-vs-policy mismatches can be surfaced even when the general app logger is
more restrictive.

Must be one of the following:

- `DEBUG`
- `INFO`
- `WARNING`
- `ERROR`
- `CRITICAL`

## `MREG_POLICY_MODE`

Controls how MREG uses TreeTop. Default: `shadow`

- `off`: use legacy permissions and make no TreeTop calls.
- `shadow`: call TreeTop synchronously once per protected request, compare the
  complete endpoint decision, and return the legacy decision.
- `enforce`: make that same synchronous endpoint decision authoritative.

`enforce` requires a non-empty `MREG_POLICY_BASE_URL`; invalid values or a
missing enforcement URL stop Django during configuration rather than silently
falling back.

## `MREG_POLICY_PARITY_ENABLED`

Deprecated compatibility flag. Default: `True`

When `MREG_POLICY_MODE` is unset, true maps to `shadow` and false maps to `off`.
An explicit mode always takes precedence.

## `MREG_POLICY_BASE_URL`

Base URL for the TreeTop policy engine REST service. Default: empty (disabled)

If unset or empty, no policy requests are made in `off`/`shadow` operation. It
is a configuration error in `enforce` mode.

Example: `http://localhost:9999`

## `MREG_POLICY_NAMESPACE`

Namespace used when constructing policy principal/action IDs. Default: `MREG`

Use Cedar-style `::` separators (commas are also accepted).

Example: `MREG` or `org::MREG`

## `MREG_POLICY_PARITY_LOG_DETAILS`

Boolean flag controlling whether parity logs include principal names, groups,
resource IDs, and resource attributes. Default: `False`

Keep this disabled unless detailed parity investigation is necessary. These
fields may contain operationally sensitive data. Parity events use the normal
console and rotating `MREG_LOG_FILE_NAME` handlers.

## `MREG_POLICY_TIMEOUT_SECONDS`

Timeout in seconds for calls to TreeTop. Default: `5.0`

Both active modes wait for the result because authorization must finish before
request processing continues. `shadow` differs only in which decision is
returned. `enforce` always fails closed on timeout, invalid response, circuit
rejection, or other TreeTop failure; there is no legacy fallback.

## Synchronous circuit breaker

- `MREG_POLICY_CIRCUIT_FAILURES` (`5`): consecutive failures before the
  process-local worker circuit opens.
- `MREG_POLICY_CIRCUIT_RESET_SECONDS` (`30.0`): cooldown before one half-open
  probe is allowed.

The client timeout remains `MREG_POLICY_TIMEOUT_SECONDS` (`5.0`). Each
application process owns its client and thread-safe circuit state. An open
circuit returns the legacy decision in `shadow` and denies in `enforce`.

## TreeTop enforcement rollout gates

`manage.py check_policy_rollout` evaluates Prometheus telemetry before an
operator enables policy enforcement. Defaults can be tuned with:

- `MREG_POLICY_ROLLOUT_MIN_COMPARISONS` (`10000`)
- `MREG_POLICY_ROLLOUT_MAX_MISMATCH_RATE` (`0.001`)
- `MREG_POLICY_ROLLOUT_MAX_ERROR_RATE` (`0.001`)

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
