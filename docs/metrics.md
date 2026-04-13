# Metrics Overview

This document describes the Prometheus metrics exposed by MREG, their purpose, labels, and units. Labels are chosen to keep cardinality low and operationally useful.

## Endpoint

Metrics are exposed at the following endpoint: `/api/meta/metrics`.

## HTTP Metrics

- Name: mreg_http_requests_total
  - Type: Counter
  - Labels: method, path, status
  - Unit: requests
  - Description: Total number of HTTP requests, partitioned by method, normalized path (view name/route), and status code.

- Name: mreg_http_request_duration_seconds
  - Type: Histogram
  - Labels: method, path, status
  - Unit: seconds
  - Description: Request latency from middleware entry to response.
  - Buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]

- Name: mreg_http_inprogress_requests
  - Type: Gauge
  - Labels: method, path
  - Unit: requests
  - Description: Number of requests in-flight.

- Name: mreg_http_request_size_bytes
  - Type: Histogram
  - Labels: method, path
  - Unit: bytes
  - Description: Size of HTTP request payload. Uses `CONTENT_LENGTH` when present; otherwise not observed to avoid loading bodies.
  - Buckets: [512, 1k, 2k, 4k, 8k, 16k, 64k, 256k, 1M, 4M]

- Name: mreg_http_response_size_bytes
  - Type: Histogram
  - Labels: method, path, status
  - Unit: bytes
  - Description: Size of HTTP response payload. Uses `Content-Length` when set; skips observation for streaming or unknown sizes.
  - Buckets: [512, 1k, 2k, 4k, 8k, 16k, 64k, 256k, 1M, 4M]

- Name: mreg_http_exceptions_total
  - Type: Counter
  - Labels: method, path, exception
  - Unit: exceptions
  - Description: Total number of uncaught application exceptions that resulted in 500 responses, partitioned by exception class name.

- Name: mreg_http_unresolved_requests_total
  - Type: Counter
  - Labels: method, status
  - Unit: requests
  - Description: Requests whose normalized path could not be resolved (e.g., 404s). Useful for monitoring spikes in unresolved routes.

## Database Metrics

- Name: mreg_db_query_duration_seconds
  - Type: Histogram
  - Labels: method, path
  - Unit: seconds
  - Description: Duration of each DB query executed during a request.

- Name: mreg_db_request_duration_seconds
  - Type: Histogram
  - Labels: method, path, status
  - Unit: seconds
  - Description: Total DB time aggregated per HTTP request.

- Name: mreg_db_queries_per_request
  - Type: Histogram
  - Labels: method, path, status
  - Unit: queries
  - Description: Number of DB queries attempted during a single HTTP request (includes attempted queries even if they error).
  - Buckets: [1, 2, 3, 5, 8, 13, 21, 34, 55]

- Name: mreg_db_queries_total
  - Type: Counter
  - Labels: method, path
  - Unit: queries
  - Description: Total number of DB queries attempted across all requests.

- Name: mreg_db_errors_total
  - Type: Counter
  - Labels: method, path, exception
  - Unit: errors
  - Description: Total number of DB errors, partitioned by exception class name.

## LDAP Metrics

- Name: mreg_ldap_call_duration_seconds
  - Type: Histogram
  - Labels: operation
  - Unit: seconds
  - Description: Duration of LDAP operations (initialize, bind, unbind) invoked by the health check.
  - Buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5]

- Name: mreg_ldap_call_failures_total
  - Type: Counter
  - Labels: operation, exception
  - Unit: failures
  - Description: LDAP operation failures by operation and exception class (e.g., bind LDAPError). Useful to see if LDAP is flapping or credential/ACL issues arise.

## Policy Engine Metrics

- Name: mreg_policy_decisions_total
  - Type: Counter
  - Labels: decision
  - Unit: decisions
  - Description: Policy-engine decisions recorded during parity checks.
  - Label values: `allow`, `deny`, `error`

- Name: mreg_policy_legacy_decisions_total
  - Type: Counter
  - Labels: decision
  - Unit: decisions
  - Description: Legacy permission decisions compared against policy parity.
  - Label values: `allow`, `deny`

- Name: mreg_policy_parity_results_total
  - Type: Counter
  - Labels: result
  - Unit: comparisons
  - Description: Outcome of legacy vs policy parity comparisons.
  - Label values: `match`, `mismatch`, `error`

- Name: mreg_policy_authorize_calls_total
  - Type: Counter
  - Labels: status
  - Unit: calls
  - Description: Calls made to the policy `authorize` endpoint.
  - Label values: `success`, `exception`

- Name: mreg_policy_authorize_duration_seconds
  - Type: Histogram
  - Labels: status
  - Unit: seconds
  - Description: Duration of policy `authorize` calls.
  - Buckets/ranges: `0-1ms`, `1-2.5ms`, `2.5-5ms`, `5-10ms`, `10-25ms`, `25-50ms`, `50-100ms`, `100-250ms`, `250-500ms`, `500ms-1s`, `1-2.5s`, `2.5-5s`, `5s+`
    - Prometheus boundaries: [0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, +Inf]

- Name: mreg_policy_requests_per_authorize
  - Type: Histogram
  - Labels: none
  - Unit: policy requests
  - Description: Number of policy requests included in each `authorize` call.
  - Buckets/ranges: `0`, `1`, `2`, `3`, `4-5`, `6-8`, `9+`
    - Prometheus boundaries: [0, 1, 2, 3, 5, 8, +Inf]

- Name: mreg_policy_queries_per_request
  - Type: Histogram
  - Labels: none
  - Unit: authorize queries
  - Description: Number of policy `authorize` queries made per HTTP request.
  - Buckets/ranges: `0`, `1`, `2`, `3`, `4-5`, `6-8`, `9+`
    - Prometheus boundaries: [0, 1, 2, 3, 5, 8, +Inf]

When request batching is enabled (default), `mreg_policy_queries_per_request` should usually be `0` (no parity checks queued) or `1` (one batched authorize call).

## Labeling Strategy

- path: normalized using Django URL resolution to view name (preferred) or route pattern. Falls back to "unresolved" to avoid cardinality explosion from raw paths with IDs.
- method: HTTP method (GET, POST, etc.).
- status: HTTP status code as string (e.g., "200", "404").
- exception: Python exception class name. We do not include messages or stack traces.

## Notes

- Timing uses monotonic clocks to avoid wall-clock skew.
- The metrics endpoint (/api/meta/metrics) is not instrumented and is tolerant to a trailing slash.
- Gauges are carefully paired to prevent underflow.
- For multi-process deployments, ensure Prometheus client multiprocess mode is configured or scrape per-worker and aggregate in Prometheus.
- Avoid building dashboards/alerts on high-cardinality labels; stick to method/path/status/exception.

## Alerting Examples

- N+1 query detection
  - Goal: Detect endpoints where average queries per request spike above a threshold.
  - PromQL:
    - Average queries per request per path/method over 5m:
      `sum by (method, path) (rate(mreg_db_queries_per_request_sum[5m])) / sum by (method, path) (rate(mreg_db_queries_per_request_count[5m]))`
    - Alert when `> 20` (tune to your baseline)

- Payload size anomalies (response size)
  - Goal: Detect endpoints returning unusually large payloads.
  - PromQL:
    - Average response size bytes per path/method over 5m:
      `sum by (method, path) (rate(mreg_http_response_size_bytes_sum[5m])) / sum by (method, path) (rate(mreg_http_response_size_bytes_count[5m]))`
    - Alert when `> 1048576` (1 MiB) or when deviates from a baseline (use recording rules or anomaly detection plugins)

- 5xx spikes by view/exception
  - Goal: Track and alert on failures grouped by normalized path and exception type.
  - PromQL:
    - 5xx rate per path/method over 5m:
      `sum by (method, path) (rate(mreg_http_requests_total{status=~"5.."}[5m]))`
    - Exceptions by type per path/method over 5m:
      `sum by (method, path, exception) (rate(mreg_http_exceptions_total[5m]))`
    - Alert on sustained spikes above baseline (e.g., `> 0.1 rps` for 10m)

## Sample Prometheus alert rules (starter set)

Tune thresholds to your baseline; these are illustrative.

```yaml
groups:
  - name: mreg-alerts
    rules:
      - alert: Mreg5xxSpike
        expr: sum by (method, path) (rate(mreg_http_requests_total{status=~"5.."}[5m])) > 0.1
        for: 10m
        labels:
          severity: page
        annotations:
          summary: "5xx spike on {{ $labels.method }} {{ $labels.path }}"

      - alert: MregLDAPFailures
        expr: sum by (operation, exception) (rate(mreg_ldap_call_failures_total[5m])) > 0
        for: 5m
        labels:
          severity: page
        annotations:
          summary: "LDAP failures {{ $labels.operation }} {{ $labels.exception }}"

      - alert: MregLDAPLatencyHigh
        expr: histogram_quantile(
                0.95,
                sum by (le) (rate(mreg_ldap_call_duration_seconds_bucket[5m]))
              ) > 1
        for: 5m
        labels:
          severity: ticket
        annotations:
          summary: "LDAP latency p95 > 1s"

      - alert: MregNPlusOneSuspect
        expr: (
                sum by (method, path) (rate(mreg_db_queries_per_request_sum[5m]))
              / sum by (method, path) (rate(mreg_db_queries_per_request_count[5m]))
              ) > 20
        for: 10m
        labels:
          severity: ticket
        annotations:
          summary: "High queries/request on {{ $labels.method }} {{ $labels.path }}"

      - alert: MregResponseSizeAnomaly
        expr: (
                sum by (method, path) (rate(mreg_http_response_size_bytes_sum[5m]))
              / sum by (method, path) (rate(mreg_http_response_size_bytes_count[5m]))
              ) > 1048576
        for: 10m
        labels:
          severity: ticket
        annotations:
          summary: "Large responses on {{ $labels.method }} {{ $labels.path }} (>1MiB avg over 5m)"
```

## What's intentionally not labeled

Almost all labels that could lead to high cardinality or sensitive data exposure are avoided, including but not limited to:

- User-specific labels (e.g., user ID) to prevent cardinality explosion and privacy concerns.
- Query parameters in paths to avoid high cardinality from unique URLs.
- Remote IP addresses for privacy and cardinality reasons.
- Detailed SQL query information to prevent high cardinality and sensitive data exposure.
