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

## `MREG_POLICY_PARITY_ENABLED`

Boolean flag controlling whether policy parity checks run. Default: `True`

Parity checks run only when both `MREG_POLICY_PARITY_ENABLED` is true and
`MREG_POLICY_BASE_URL` is set to a non-empty value.

## `MREG_POLICY_BASE_URL`

Base URL for the TreeTop policy engine REST service. Default: empty (disabled)

If unset or empty, the policy parity code is disabled and no requests are made
to the policy engine.

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

Timeout in seconds for calls from the background parity worker to TreeTop.
Default: `5.0`

## `MREG_POLICY_PARITY_BATCH_ENABLED`

Boolean flag controlling request-scoped batching of parity authorize checks.
Default: `True`

When enabled, parity checks are collected during request handling and persisted
to the PostgreSQL outbox as one batch. Requests never wait for TreeTop. When
disabled, each check is persisted as its own durable batch.

## Durable parity delivery

The following settings control the shared PostgreSQL outbox:

- `MREG_POLICY_PARITY_MAX_ATTEMPTS` (`8`): delivery attempts before a row is
  retained as a dead letter.
- `MREG_POLICY_PARITY_RETRY_BASE_SECONDS` (`2.0`): initial exponential-backoff
  delay.
- `MREG_POLICY_PARITY_RETRY_MAX_SECONDS` (`300.0`): retry delay cap.
- `MREG_POLICY_PARITY_LEASE_SECONDS` (`60.0`): time before an abandoned claim
  can be reclaimed by another worker.
- `MREG_POLICY_PARITY_POLL_SECONDS` (`1.0`): worker polling interval.
- `MREG_POLICY_PARITY_CIRCUIT_FAILURES` (`5`): consecutive delivery failures
  that open a worker's circuit breaker.
- `MREG_POLICY_PARITY_CIRCUIT_RESET_SECONDS` (`30.0`): circuit cooldown.

Successful rows are deleted. Exhausted rows remain in
`mreg_policyparityoutbox` with `failed_at` and `last_error` populated. The
outbox necessarily contains the principal, groups, resource identifier, and
resource attributes required for a later authorization call. Protect database
access accordingly and establish an operational dead-letter retention policy.

The container sets `PROMETHEUS_MULTIPROC_DIR` to an isolated directory so
metrics from every Gunicorn worker are aggregated. Custom Gunicorn deployments
must set this variable to a clean, writable directory before starting Python.

## TreeTop enforcement rollout gates

`manage.py check_policy_rollout` evaluates Prometheus telemetry before an
operator enables policy enforcement. Defaults can be tuned with:

- `MREG_POLICY_ROLLOUT_MIN_COMPARISONS` (`10000`)
- `MREG_POLICY_ROLLOUT_MAX_MISMATCH_RATE` (`0.001`)
- `MREG_POLICY_ROLLOUT_MAX_ERROR_RATE` (`0.001`)
- `MREG_POLICY_ROLLOUT_MAX_PERSIST_FAILURES` (`0`)
- `MREG_POLICY_ROLLOUT_MAX_DEAD_LETTERS` (`0`)
- `MREG_POLICY_ROLLOUT_MAX_BACKLOG_AGE_SECONDS` (`300.0`)

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
