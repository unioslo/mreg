"""Prometheus metrics middleware for HTTP requests.

Adds HTTP request metrics (count, latency, in-progress) and DB timing
metrics (per-query and total DB time per request). Also records request/response
sizes, DB query counts per request, and DB/HTTP exception counters.
"""
from time import monotonic
from contextlib import ExitStack
from typing import Any, Callable

from django.db import connections
from django.http import HttpRequest, HttpResponse, StreamingHttpResponse
from django.conf import settings
from django.urls import resolve, Resolver404

from prometheus_client import Counter, Histogram, Gauge


REQUEST_COUNT = Counter(
    "mreg_http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)

REQUEST_LATENCY = Histogram(
    "mreg_http_request_duration_seconds",
    "HTTP request latency seconds",
    ["method", "path", "status"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
)

INPROGRESS = Gauge("mreg_http_inprogress_requests", "Inprogress requests", ["method", "path"])

# Request/response sizes (bytes)
REQUEST_SIZE = Histogram(
    "mreg_http_request_size_bytes",
    "HTTP request size in bytes",
    ["method", "path"],
    buckets=[512, 1024, 2048, 4096, 8192, 16384, 65536, 262144, 1048576, 4194304],
)

RESPONSE_SIZE = Histogram(
    "mreg_http_response_size_bytes",
    "HTTP response size in bytes",
    ["method", "path", "status"],
    buckets=[512, 1024, 2048, 4096, 8192, 16384, 65536, 262144, 1048576, 4194304],
)

# DB metrics
REQUEST_DB_QUERY = Histogram(
    "mreg_db_query_duration_seconds",
    "Duration of individual database queries",
    ["method", "path"],
    buckets=[0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5],
)

REQUEST_DB_REQUEST = Histogram(
    "mreg_db_request_duration_seconds",
    "Total DB time per HTTP request",
    ["method", "path", "status"],
    buckets=[0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5],
)

# DB queries per request
REQUEST_DB_QUERY_COUNT = Histogram(
    "mreg_db_queries_per_request",
    "Total number of DB queries executed during an HTTP request",
    ["method", "path", "status"],
    buckets=[1, 2, 3, 5, 8, 13, 21, 34, 55],
)

# Total DB queries counter (aggregate)
DB_QUERIES_TOTAL = Counter(
    "mreg_db_queries_total",
    "Total number of DB queries executed (aggregate)",
    ["method", "path"],
)

# DB errors by exception type
DB_ERRORS_TOTAL = Counter(
    "mreg_db_errors_total",
    "Total number of DB errors by exception type",
    ["method", "path", "exception"],
)

# HTTP exceptions by exception type
HTTP_EXCEPTIONS_TOTAL = Counter(
    "mreg_http_exceptions_total",
    "Total number of HTTP exceptions by type (500s)",
    ["method", "path", "exception"],
)

# Unresolved path requests (e.g., 404s) counter
UNRESOLVED_REQUESTS_TOTAL = Counter(
    "mreg_http_unresolved_requests_total",
    "Total number of requests with unresolved normalized path",
    ["method", "status"],
)


class PrometheusRequestMiddleware:
    """Middleware that records Prometheus metrics for incoming requests.

    Labels by `method` and by a normalized `path`. The middleware avoids
    instrumenting the metrics endpoint itself.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def _normalize_path(self, request: HttpRequest) -> str:
        # Resolve URL to get view name, avoiding cardinality explosion from object IDs
        try:
            match = resolve(request.path_info)
            # Prefer view_name for low cardinality (e.g., "api:hosts-detail")
            return match.view_name or match.route or "unresolved"
        except Resolver404:
            # Return marker instead of raw path to prevent cardinality explosion
            return "unresolved"  # pragma: no cover
        except Exception:  # pragma: no cover - defensive
            return "unresolved"

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Do not instrument the metrics endpoint itself (tolerant of trailing slashes)
        metrics_path = getattr(settings, "METRICS_PATH", "/api/meta/metrics")
        if request.path_info.rstrip("/") == metrics_path.rstrip("/"):
            return self.get_response(request)  # pragma: no cover - tested separately

        start = monotonic()
        path_label = self._normalize_path(request)

        # Prepare DB timing accumulation (use setattr to avoid pyright attribute warnings)
        setattr(request, "_db_time", 0.0)
        setattr(request, "_db_query_count", 0)

        def db_execute_wrapper(
            execute: Callable[..., Any],
            sql: str,
            params: Any,
            many: bool,
            context: Any,
        ) -> Any:
            t0 = monotonic()
            try:
                result = execute(sql, params, many, context)
            except Exception as e:  # pragma: no cover - rare path in tests
                try:
                    DB_ERRORS_TOTAL.labels(request.method, path_label, e.__class__.__name__).inc()
                except Exception:
                    pass
                raise
            else:
                return result
            finally:
                elapsed = monotonic() - t0
                try:
                    REQUEST_DB_QUERY.labels(request.method, path_label).observe(elapsed)
                except Exception:  # pragma: no cover - defensive
                    pass
                # accumulate per-request total using setattr/getattr to avoid pyright errors
                try:
                    total = getattr(request, "_db_time", 0.0) or 0.0
                    setattr(request, "_db_time", total + elapsed)
                except Exception:  # pragma: no cover - defensive
                    pass
                # increment per-request query count and global counter (attempted queries)
                try:
                    count = int(getattr(request, "_db_query_count", 0) or 0)
                    setattr(request, "_db_query_count", count + 1)
                    DB_QUERIES_TOTAL.labels(request.method, path_label).inc()
                except Exception:  # pragma: no cover - defensive
                    pass

        # Track in-progress requests - inc() before try to ensure dec() pairing
        inprogress_gauge = INPROGRESS.labels(request.method, path_label)
        inprogress_gauge.inc()
        
        try:
            # Install execute wrappers for all DB connections during this request.
            with ExitStack() as stack:
                for conn in connections.all():
                    stack.enter_context(conn.execute_wrapper(db_execute_wrapper))  # type: ignore[arg-type]

                response = self.get_response(request)

            status = str(getattr(response, "status_code", "0"))
            elapsed = monotonic() - start

            # Observe overall request metrics
            REQUEST_LATENCY.labels(request.method, path_label, status).observe(elapsed)
            REQUEST_COUNT.labels(request.method, path_label, status).inc()
            # Count unresolved path requests for ops visibility (typically 404s)
            try:
                if path_label == "unresolved":
                    UNRESOLVED_REQUESTS_TOTAL.labels(request.method, status).inc()
            except Exception:  # pragma: no cover - defensive
                pass

            # Record request/response sizes
            try:
                # Request size: only observe when CONTENT_LENGTH is present and numeric
                content_length = request.META.get("CONTENT_LENGTH")
                if content_length is not None and str(content_length).isdigit():
                    req_size = float(content_length)
                    REQUEST_SIZE.labels(request.method, path_label).observe(req_size)
            except Exception:  # pragma: no cover - defensive
                pass

            try:
                # Response size: prefer Content-Length; avoid forcing content rendering
                resp_len_header = response.get("Content-Length") if hasattr(response, "get") else None
                if resp_len_header is not None and str(resp_len_header).isdigit():
                    resp_size = float(resp_len_header)
                    RESPONSE_SIZE.labels(request.method, path_label, status).observe(resp_size)
                else:
                    # If streaming, skip. If non-streaming without header, skip to avoid materialization.
                    if isinstance(response, StreamingHttpResponse):
                        pass
                    # else: intentionally do not access response.content
            except Exception:  # pragma: no cover - defensive
                pass

            # Observe per-request aggregated DB time
            try:
                REQUEST_DB_REQUEST.labels(request.method, path_label, status).observe(getattr(request, "_db_time", 0.0))
            except Exception:  # pragma: no cover - defensive
                pass

            # Observe per-request DB query count
            try:
                REQUEST_DB_QUERY_COUNT.labels(request.method, path_label, status).observe(float(getattr(request, "_db_query_count", 0) or 0))
            except Exception:  # pragma: no cover - defensive
                pass

            return response
        except Exception as e:  # pragma: no cover - bubble up after counting as 500
            elapsed = monotonic() - start
            REQUEST_LATENCY.labels(request.method, path_label, "500").observe(elapsed)
            REQUEST_COUNT.labels(request.method, path_label, "500").inc()
            # Record DB time on exception too
            try:
                REQUEST_DB_REQUEST.labels(request.method, path_label, "500").observe(getattr(request, "_db_time", 0.0))
            except Exception:  # pragma: no cover - defensive
                pass
            # Record DB query count on exception too
            try:
                REQUEST_DB_QUERY_COUNT.labels(request.method, path_label, "500").observe(float(getattr(request, "_db_query_count", 0) or 0))
            except Exception:  # pragma: no cover - defensive
                pass
            # Record HTTP exception type
            try:
                HTTP_EXCEPTIONS_TOTAL.labels(request.method, path_label, e.__class__.__name__).inc()
            except Exception:  # pragma: no cover - defensive
                pass
            # Count unresolved path requests for exceptions too
            try:
                if path_label == "unresolved":
                    UNRESOLVED_REQUESTS_TOTAL.labels(request.method, "500").inc()
            except Exception:  # pragma: no cover - defensive
                pass
            raise
        finally:
            try:
                inprogress_gauge.dec()
            except Exception:  # pragma: no cover - defensive
                # Be defensive: metrics library shouldn't crash the app.
                pass
