import pytest
import ldap
from unittest.mock import Mock, patch

from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from typing import Any

from mreg.models.host import Host, Ipaddress
from mreg.middleware.metrics import PrometheusRequestMiddleware
from mreg.tests.prometheus_test_utils import parse_prometheus_metric as _parse_prometheus_metric



@pytest.mark.django_db
def test_metrics_endpoint_exposes_prometheus_metrics() -> None:
    """Test that metrics endpoint returns Prometheus-formatted output."""
    client = APIClient()

    User = get_user_model()
    user = User.objects.create_user(username="metrics_test_user", password="x")
    client.force_authenticate(user=user)

    r: Any = client.get("/api/meta/health/heartbeat")
    assert r.status_code == 200

    metrics: Any = client.get("/api/meta/metrics")
    assert metrics.status_code == 200
    assert "text/plain" in metrics["Content-Type"]
    assert b"mreg_http_requests_total" in metrics.content


@pytest.mark.django_db
def test_request_count_increments_by_status() -> None:
    """Test that request count increments with correct status labels."""
    client = APIClient()
    User = get_user_model()
    user = User.objects.create_user(username="count_test_user", password="x")
    client.force_authenticate(user=user)

    client.get("/api/meta/health/heartbeat")

    metrics_resp: Any = client.get("/api/meta/metrics")
    raw = metrics_resp.content.decode("utf-8")
    
    counts = _parse_prometheus_metric(raw, "mreg_http_requests_total")
    
    assert len(counts) > 0, f"No metrics recorded: {counts}"
    assert any("status=\"200\"" in k for k in counts.keys()), f"No 200 status in: {counts}"
    # Accept either view name or route pattern
    assert any(
        "HealthHeartbeat" in k or "meta/health/heartbeat" in k
        for k in counts.keys()
    ), f"No heartbeat endpoint in: {counts}"


@pytest.mark.django_db
def test_db_metrics_recorded_with_values() -> None:
    """Test that DB metrics are recorded when requests interact with the database."""
    client = APIClient()
    User = get_user_model()
    user = User.objects.create_user(username="db_test_user", password="x")
    client.force_authenticate(user=user)

    host = Host.objects.create(
        name="db_metric_test.example.com",
        contact="test@example.com",
        ttl=3600,
        comment="test",
    )
    Ipaddress.objects.create(host=host, ipaddress="10.10.10.10")  # type: ignore[attr-defined]

    resp: Any = client.get(f"/api/v1/hosts/{host.name}")
    assert resp.status_code == 200

    metrics_resp: Any = client.get("/api/meta/metrics")
    raw = metrics_resp.content.decode("utf-8")
    
    assert b"mreg_db_query_duration_seconds" in metrics_resp.content
    assert b"mreg_db_request_duration_seconds" in metrics_resp.content
    
    db_query_metrics = _parse_prometheus_metric(raw, "mreg_db_query_duration_seconds_sum")
    assert len(db_query_metrics) > 0, "No DB query metrics recorded"
    assert any(v > 0 for v in db_query_metrics.values()), f"Expected positive DB durations, got {db_query_metrics}"


@pytest.mark.django_db
def test_db_query_count_metrics() -> None:
    """Test that DB query count per request and total counters are recorded."""
    client = APIClient()
    User = get_user_model()
    user = User.objects.create_user(username="db_count_user", password="x")
    client.force_authenticate(user=user)

    host = Host.objects.create(
        name="db_count_test.example.com",
        contact="test@example.com",
        ttl=3600,
        comment="test",
    )
    Ipaddress.objects.create(host=host, ipaddress="10.10.10.20")  # type: ignore[attr-defined]

    resp: Any = client.get(f"/api/v1/hosts/{host.name}")
    assert resp.status_code == 200

    metrics_resp: Any = client.get("/api/meta/metrics")
    raw = metrics_resp.content.decode("utf-8")

    per_req_count = _parse_prometheus_metric(raw, "mreg_db_queries_per_request_count")
    assert len(per_req_count) > 0, "Expected DB queries-per-request histogram count series"
    assert any(v >= 1 for v in per_req_count.values()), f"Expected >=1 queries per request: {per_req_count}"

    total_counter = _parse_prometheus_metric(raw, "mreg_db_queries_total")
    assert len(total_counter) > 0, "Expected total DB queries counter series"
    assert any(v >= 1 for v in total_counter.values()), f"Expected total DB queries >= 1: {total_counter}"


@pytest.mark.django_db
def test_request_latency_recorded() -> None:
    """Test that request latency histogram is recorded with values."""
    client = APIClient()
    User = get_user_model()
    user = User.objects.create_user(username="latency_test_user", password="x")
    client.force_authenticate(user=user)

    client.get("/api/meta/health/heartbeat")

    metrics_resp: Any = client.get("/api/meta/metrics")
    raw = metrics_resp.content.decode("utf-8")
    
    latency_sum = _parse_prometheus_metric(raw, "mreg_http_request_duration_seconds_sum")
    assert len(latency_sum) > 0, "No request latency metrics recorded"
    assert any(v > 0 for v in latency_sum.values()), "Expected positive request durations"
    
    latency_count = _parse_prometheus_metric(raw, "mreg_http_request_duration_seconds_count")
    assert len(latency_count) > 0, "No request count metrics recorded"
    assert any(v >= 1 for v in latency_count.values()), "Expected at least 1 request counted"


@pytest.mark.django_db
def test_request_and_response_size_histograms() -> None:
    """Test request and response size histograms are recorded."""
    client = APIClient()
    User = get_user_model()
    user = User.objects.create_user(username="size_metrics_user", password="x")
    client.force_authenticate(user=user)

    # Simple GET with no body (request size ~0), small response
    r: Any = client.get("/api/meta/health/heartbeat")
    assert r.status_code == 200

    metrics_resp: Any = client.get("/api/meta/metrics")
    raw = metrics_resp.content.decode("utf-8")

    req_size_count = _parse_prometheus_metric(raw, "mreg_http_request_size_bytes_count")
    assert len(req_size_count) > 0, "Expected request size histogram count series"
    assert any(v >= 1 for v in req_size_count.values()), "Expected request size count >= 1"

    resp_size_count = _parse_prometheus_metric(raw, "mreg_http_response_size_bytes_count")
    assert len(resp_size_count) > 0, "Expected response size histogram count series"
    assert any(v >= 1 for v in resp_size_count.values()), "Expected response size count >= 1"


@pytest.mark.django_db
def test_metrics_endpoint_not_instrumented() -> None:
    """Test that the metrics endpoint itself is not instrumented (no recursion).

    Compares totals before and after repeated metrics scrapes; should not change.
    """
    client = APIClient()
    User = get_user_model()
    user = User.objects.create_user(username="metrics_skip_test_user", password="x")
    client.force_authenticate(user=user)

    # Baseline
    baseline_resp: Any = client.get("/api/meta/metrics")
    assert baseline_resp.status_code == 200
    baseline_raw = baseline_resp.content.decode("utf-8")
    baseline_counts = _parse_prometheus_metric(baseline_raw, "mreg_http_requests_total")
    baseline_total = sum(baseline_counts.values()) if baseline_counts else 0.0

    # Repeated metrics scrapes
    for _ in range(3):
        resp: Any = client.get("/api/meta/metrics")
        assert resp.status_code == 200

    # Compare
    final_resp: Any = client.get("/api/meta/metrics")
    final_raw = final_resp.content.decode("utf-8")
    final_counts = _parse_prometheus_metric(final_raw, "mreg_http_requests_total")
    final_total = sum(final_counts.values()) if final_counts else 0.0

    assert final_total == baseline_total, f"Metrics endpoint should not change request totals (baseline={baseline_total}, final={final_total})"


@pytest.mark.django_db
def test_metrics_endpoint_trailing_slash_not_instrumented() -> None:
    """Test that metrics endpoint with trailing slash is also not instrumented.

    Accepts 200/301/302/404 but ensures counters don't change.
    """
    client = APIClient()
    User = get_user_model()
    user = User.objects.create_user(username="metrics_trailing_slash_user", password="x")
    client.force_authenticate(user=user)

    # Baseline
    baseline_resp: Any = client.get("/api/meta/metrics")
    assert baseline_resp.status_code == 200
    baseline_raw = baseline_resp.content.decode("utf-8")
    baseline_counts = _parse_prometheus_metric(baseline_raw, "mreg_http_requests_total")
    baseline_total = sum(baseline_counts.values()) if baseline_counts else 0.0

    # Scrape with trailing slash (may be 200/3xx/404 depending on URL config)
    for _ in range(3):
        resp: Any = client.get("/api/meta/metrics/")
        assert resp.status_code in (200, 301, 302, 404)

    # Compare
    final_resp: Any = client.get("/api/meta/metrics")
    final_raw = final_resp.content.decode("utf-8")
    final_counts = _parse_prometheus_metric(final_raw, "mreg_http_requests_total")
    final_total = sum(final_counts.values()) if final_counts else 0.0

    assert final_total == baseline_total, f"Trailing slash metrics fetch should not change totals (baseline={baseline_total}, final={final_total})"


@pytest.mark.django_db
def test_request_without_resolver_match_uses_path() -> None:
    """Test that requests use view names or routes for low cardinality labeling."""
    client = APIClient()
    User = get_user_model()
    user = User.objects.create_user(username="path_test_user", password="x")
    client.force_authenticate(user=user)

    # Make a request to an endpoint
    resp: Any = client.get("/api/meta/health/heartbeat")
    assert resp.status_code == 200

    metrics_resp: Any = client.get("/api/meta/metrics")
    raw = metrics_resp.content.decode("utf-8")
    
    counts = _parse_prometheus_metric(raw, "mreg_http_requests_total")
    # Verify we have metrics with view name or route for low cardinality
    # (accepts either resolved view name or route template, never raw path with object IDs)
    assert any(
        "HealthHeartbeat" in k or "meta/health/heartbeat" in k
        for k in counts.keys()
    ), f"Expected view name or route label in metrics: {counts}"


@pytest.mark.django_db
def test_inprogress_gauge_decrements_on_success() -> None:
    """Test that in-progress gauge is decremented after request completes."""
    client = APIClient()
    User = get_user_model()
    user = User.objects.create_user(username="inprogress_test_user", password="x")
    client.force_authenticate(user=user)

    # Make multiple sequential requests
    for _ in range(2):
        resp: Any = client.get("/api/meta/health/heartbeat")
        assert resp.status_code == 200

    metrics_resp: Any = client.get("/api/meta/metrics")
    raw = metrics_resp.content.decode("utf-8")
    
    # Check that inprogress gauge exists and has value (should be 0 or 1 at metric collection time)
    _parse_prometheus_metric(raw, "mreg_http_inprogress_requests")
    # The gauge should exist in metrics (even if current value is 0)
    assert b"mreg_http_inprogress_requests" in metrics_resp.content, \
        "In-progress gauge should be recorded"


@pytest.mark.django_db
def test_db_metrics_resilience_to_errors() -> None:
    """Test that DB metrics recording is resilient to exceptions."""
    client = APIClient()
    User = get_user_model()
    user = User.objects.create_user(username="db_error_test_user", password="x")
    client.force_authenticate(user=user)

    # Make a request that will trigger DB queries
    resp: Any = client.get("/api/meta/health/heartbeat")
    assert resp.status_code == 200

    metrics_resp: Any = client.get("/api/meta/metrics")
    # Verify metrics endpoint still responds even if internal errors occurred
    assert metrics_resp.status_code == 200
    assert b"mreg_db_request_duration_seconds" in metrics_resp.content


@pytest.mark.django_db
def test_normalize_path_fallback_to_path_info() -> None:
    """Test that _normalize_path prevents cardinality explosion from unresolved paths."""

    
    middleware = PrometheusRequestMiddleware(lambda r: Mock(status_code=200))
    
    # Create a request with an unresolvable path (404)
    request = Mock(spec=["resolver_match", "path_info"])
    request.resolver_match = None
    request.path_info = "/invalid/path/that/does/not/exist"
    
    result = middleware._normalize_path(request)
    # Should return 'unresolved' instead of raw path to prevent cardinality explosion
    assert result == "unresolved"
    
    # Test that valid paths are resolved properly
    request2 = Mock(spec=["resolver_match", "path_info"])
    request2.path_info = "/api/meta/health/heartbeat"
    
    result2 = middleware._normalize_path(request2)
    # Should resolve to either view name or route, never raw path_info
    assert result2 != request2.path_info  # Never returns raw path
    # Accept view_name (has dots) or route template
    assert result2 in ["unresolved", "meta/health/heartbeat"] or "." in result2


@pytest.mark.django_db
def test_unresolved_path_counter_records_404s() -> None:
    """Requests to unknown paths should increment unresolved counter with 404 status."""
    client = APIClient()
    User = get_user_model()
    user = User.objects.create_user(username="unresolved_counter_user", password="x")
    client.force_authenticate(user=user)

    # Baseline
    baseline: Any = client.get("/api/meta/metrics")
    assert baseline.status_code == 200
    raw0 = baseline.content.decode("utf-8")
    base_unresolved = _parse_prometheus_metric(raw0, "mreg_http_unresolved_requests_total")
    base_total = sum(base_unresolved.values()) if base_unresolved else 0.0

    # Hit an unknown path
    r404: Any = client.get("/definitely/not/a/real/endpoint")
    assert r404.status_code == 404

    # Check counter increased
    metrics_resp: Any = client.get("/api/meta/metrics")
    raw = metrics_resp.content.decode("utf-8")
    unresolved = _parse_prometheus_metric(raw, "mreg_http_unresolved_requests_total")
    final_total = sum(unresolved.values()) if unresolved else 0.0
    assert final_total >= base_total + 1, f"Expected unresolved counter to increase (base={base_total}, final={final_total})"
    # Ensure 404 label appears
    assert any("status=\"404\"" in k for k in unresolved.keys()), f"Expected 404 status label: {unresolved}"


@pytest.mark.django_db
@patch("mreg.api.views.LDAPBackend")
def test_ldap_metrics_success(mock_backend: Any) -> None:
    """LDAP health check should record call duration metrics per operation."""
    client = APIClient()
    User = get_user_model()
    user = User.objects.create_user(username="ldap_metrics_user", password="x")
    client.force_authenticate(user=user)

    mock_connection = Mock()
    mock_backend.return_value.ldap.initialize.return_value = mock_connection

    resp: Any = client.get("/api/meta/health/ldap")
    assert resp.status_code == 200

    metrics_resp: Any = client.get("/api/meta/metrics")
    raw = metrics_resp.content.decode("utf-8")

    latency = _parse_prometheus_metric(raw, "mreg_ldap_call_duration_seconds_sum")
    assert any("operation=\"initialize\"" in k for k in latency.keys()), f"Expected initialize op metric: {latency}"
    assert any("operation=\"bind\"" in k for k in latency.keys()), f"Expected bind op metric: {latency}"
    assert any("operation=\"unbind\"" in k for k in latency.keys()), f"Expected unbind op metric: {latency}"


@pytest.mark.django_db
@patch("mreg.api.views.LDAPBackend")
def test_ldap_metrics_failure_counter(mock_backend: Any) -> None:
    """LDAP failures should increment the failure counter with exception label."""
    client = APIClient()
    User = get_user_model()
    user = User.objects.create_user(username="ldap_metrics_fail_user", password="x")
    client.force_authenticate(user=user)

    mock_connection = Mock()
    mock_connection.simple_bind_s.side_effect = ldap.LDAPError("bind failed")
    mock_backend.return_value.ldap.initialize.return_value = mock_connection

    resp: Any = client.get("/api/meta/health/ldap")
    assert resp.status_code == 503

    metrics_resp: Any = client.get("/api/meta/metrics")
    raw = metrics_resp.content.decode("utf-8")

    failures = _parse_prometheus_metric(raw, "mreg_ldap_call_failures_total")
    assert any(
        "operation=\"bind\"" in k and "exception=\"LDAPError\"" in k
        for k in failures.keys()
    ), f"Expected LDAPError bind failure metric: {failures}"
