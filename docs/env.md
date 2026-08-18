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
- `shadow`: keep legacy permissions authoritative and submit comparisons
  asynchronously through the durable PostgreSQL outbox.
- `enforce`: call TreeTop synchronously at each mapped authorization checkpoint
  and use its result. The shadow outbox and dispatcher are not used.

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

These calls run in the background in `shadow` and synchronously on the request
path in `enforce`.

## `MREG_POLICY_ENFORCEMENT_FAILURE_MODE`

Decision used when a synchronous authoritative TreeTop call cannot return a
valid result. Default: `deny`

- `deny`: fail closed. This is the production enforcement default.
- `legacy`: return the already-computed legacy decision. This is a transitional
  rollout fallback and is not fully authoritative.

Explicit TreeTop allow/deny responses are always authoritative in `enforce`;
this setting applies only to transport, serialization, configuration, or
invalid-result failures.

## `MREG_POLICY_PARITY_BATCH_ENABLED`

Boolean flag controlling request-scoped batching of parity authorize checks.
Default: `True`

When enabled, parity checks are collected during request handling and persisted
to the PostgreSQL outbox as one batch. Requests never wait for TreeTop. When
disabled, each check is persisted as its own durable batch. This setting applies
only to `shadow`; authoritative checks are necessarily synchronous and are not
queued.

## Durable parity delivery

The following settings control the shared PostgreSQL outbox in `shadow` mode:

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

Before switching from `shadow` to `enforce`, drain pending rows and resolve dead
letters. Enforcement does not start the dispatcher or consume old shadow rows;
re-evaluating them against a later bundle would not represent the decision that
was available when the original request ran.

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
- `MREG_POLICY_ROLLOUT_MAX_PENDING_BATCHES` (`0`)
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
