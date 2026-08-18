# Metrics Overview

MREG exposes Prometheus metrics at `/api/meta/metrics`. The endpoint itself is
not instrumented. Labels intentionally avoid usernames, raw URLs, query
parameters, remote addresses, SQL, and policy resource data.

## HTTP and dependency metrics

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `mreg_http_requests_total` | Counter | `method`, `path`, `status` | Requests by normalized route and status |
| `mreg_http_request_duration_seconds` | Histogram | `method`, `path`, `status` | End-to-end request latency |
| `mreg_http_inprogress_requests` | Gauge | `method`, `path` | Requests currently in flight |
| `mreg_http_request_size_bytes` | Histogram | `method`, `path` | Known request payload sizes |
| `mreg_http_response_size_bytes` | Histogram | `method`, `path`, `status` | Known non-streaming response sizes |
| `mreg_http_exceptions_total` | Counter | `method`, `path`, `exception` | Uncaught application exceptions |
| `mreg_http_unresolved_requests_total` | Counter | `method`, `status` | Requests whose route could not be normalized |
| `mreg_db_query_duration_seconds` | Histogram | `method`, `path` | Individual database query latency |
| `mreg_db_request_duration_seconds` | Histogram | `method`, `path`, `status` | Database time per request |
| `mreg_db_queries_per_request` | Histogram | `method`, `path`, `status` | Attempted queries per request |
| `mreg_db_queries_total` | Counter | `method`, `path` | Attempted database queries |
| `mreg_db_errors_total` | Counter | `method`, `path`, `exception` | Database errors |
| `mreg_ldap_call_duration_seconds` | Histogram | `operation` | LDAP health-check call latency |
| `mreg_ldap_call_failures_total` | Counter | `operation`, `exception` | LDAP health-check failures |

`path` is a resolved view name or route pattern, never a raw object URL. Timing
uses monotonic clocks.

## TreeTop metrics

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `mreg_policy_decisions_total` | Counter | `decision` | Composite TreeTop result: `allow`, `deny`, or `error` |
| `mreg_policy_legacy_decisions_total` | Counter | `decision` | Composite legacy result used for comparison |
| `mreg_policy_parity_results_total` | Counter | `result` | Endpoint comparison: `match`, `mismatch`, or `error` |
| `mreg_policy_authorize_calls_total` | Counter | `status` | Synchronous authorize calls: `success` or `exception` |
| `mreg_policy_authorize_duration_seconds` | Histogram | `status` | Synchronous authorize latency |
| `mreg_policy_failures_total` | Counter | `stage` | Integration failures, currently the `authorize` stage |
| `mreg_policy_enforcement_results_total` | Counter | `result` | Authoritative `allow`, `deny`, or fail-closed `error_deny` |
| `mreg_policy_mode_info` | Gauge | `mode` | Active `off`, `shadow`, or `enforce` mode |
| `mreg_policy_stack_size` | Histogram | none | Cedar leaves in the endpoint stack sent by one call |
| `mreg_policy_authorize_calls_per_request` | Histogram | none | TreeTop HTTP calls per MREG request; protected requests should be `1` |
| `mreg_policy_circuit_open` | Gauge | none | Whether a worker's synchronous circuit is open |

All protected endpoint checks are synchronous in both active modes. `shadow`
returns the legacy result after recording the comparison; `enforce` returns the
TreeTop composite and fails closed. There is no queue, retry worker, persistence
metric, and enforcement failures never return the legacy decision.

The two design-invariant metrics are:

- `mreg_policy_authorize_calls_per_request`: alert if observations exceed one.
- `mreg_policy_stack_size`: identify high-count endpoints whose semantic policy
  can be simplified even though transport is already consolidated.

## Rollout dashboard, alerts, and gate

- Dashboard: `monitoring/grafana/treetop-parity.json`
- Rules: `monitoring/treetop-alerts.yml`
- Gate: `python manage.py check_policy_rollout --prometheus-url URL`

The default gate requires at least 10,000 endpoint comparisons, no more than
0.1% mismatches, and no more than 0.1% errors over the selected window. The
alerts cover mismatch/error rates, any authoritative failure, an open circuit,
and violations of the one-call-per-request invariant.

Useful PromQL:

```promql
# Policy mismatch rate
sum(rate(mreg_policy_parity_results_total{result="mismatch"}[30m]))
/
clamp_min(sum(rate(mreg_policy_parity_results_total{result=~"match|mismatch"}[30m])), 1)

# p95 synchronous TreeTop latency
histogram_quantile(
  0.95,
  sum by (le) (rate(mreg_policy_authorize_duration_seconds_bucket[5m]))
)

# Average checks in each endpoint stack
rate(mreg_policy_stack_size_sum[5m])
/
clamp_min(rate(mreg_policy_stack_size_count[5m]), 1)
```

The container configures Prometheus multiprocess mode and clears its directory
before Gunicorn starts. Other process managers must provide a clean writable
`PROMETHEUS_MULTIPROC_DIR` and call
`prometheus_client.multiprocess.mark_process_dead` when a worker exits.
