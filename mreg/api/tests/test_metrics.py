import re
from typing import Any
from unittest.mock import Mock, patch

import ldap
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from rest_framework.test import APIRequestFactory, APITestCase

from mreg.models.host import Host, Ipaddress
from mreg.middleware.metrics import PrometheusRequestMiddleware


def _parse_prometheus_metric(content: str, metric_name: str) -> dict[str, float]:
    """Parse Prometheus text format and extract metrics by name."""
    result = {}
    pattern = rf"^{re.escape(metric_name)}(\{{[^}}]*\}})?\s+([0-9.e+-]+)$"
    for line in content.split("\n"):
        if line.startswith("#"):
            continue
        match = re.match(pattern, line)
        if match:
            labels = match.group(1) or ""
            value = float(match.group(2))
            result[labels] = value
    return result


class MetricsTestCase(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(username="metrics_test_user")

    def setUp(self):
        self.client.force_authenticate(user=self.user)

    def test_metrics_endpoint_exposes_prometheus_metrics(self) -> None:
        """Test that metrics endpoint returns Prometheus-formatted output."""
        r: Any = self.client.get("/api/meta/health/heartbeat")
        self.assertEqual(r.status_code, 200)

        metrics: Any = self.client.get("/api/meta/metrics")
        self.assertEqual(metrics.status_code, 200)
        self.assertIn("text/plain", metrics["Content-Type"])
        self.assertIn(b"mreg_http_requests_total", metrics.content)

    def test_request_count_increments_by_status(self) -> None:
        """Test that request count increments with correct status labels."""
        self.client.get("/api/meta/health/heartbeat")

        metrics_resp: Any = self.client.get("/api/meta/metrics")
        raw = metrics_resp.content.decode("utf-8")

        counts = _parse_prometheus_metric(raw, "mreg_http_requests_total")

        self.assertGreater(len(counts), 0, f"No metrics recorded: {counts}")
        self.assertTrue(any('status="200"' in k for k in counts.keys()), f"No 200 status in: {counts}")
        # Accept either view name or route pattern
        self.assertTrue(
            any("HealthHeartbeat" in k or "meta/health/heartbeat" in k for k in counts.keys()), f"No heartbeat endpoint in: {counts}"
        )

    def test_db_metrics_recorded_with_values(self) -> None:
        """Test that DB metrics are recorded when requests interact with the database."""
        host = Host.objects.create(
            name="db_metric_test.example.com",
            ttl=3600,
            comment="test",
        )
        host.add_contacts(["test@example.com"])
        Ipaddress.objects.create(host=host, ipaddress="10.10.10.10")

        resp: Any = self.client.get(f"/api/v1/hosts/{host.name}")
        self.assertEqual(resp.status_code, 200)

        metrics_resp: Any = self.client.get("/api/meta/metrics")
        raw = metrics_resp.content.decode("utf-8")

        self.assertIn(b"mreg_db_query_duration_seconds", metrics_resp.content)
        self.assertIn(b"mreg_db_request_duration_seconds", metrics_resp.content)

        db_query_metrics = _parse_prometheus_metric(raw, "mreg_db_query_duration_seconds_sum")
        self.assertGreater(len(db_query_metrics), 0, "No DB query metrics recorded")
        self.assertTrue(any(v > 0 for v in db_query_metrics.values()), f"Expected positive DB durations, got {db_query_metrics}")

    def test_db_query_count_metrics(self) -> None:
        """Test that DB query count per request and total counters are recorded."""
        host = Host.objects.create(
            name="db_count_test.example.com",
            ttl=3600,
            comment="test",
        )
        host.add_contacts(["test@example.com"])
        Ipaddress.objects.create(host=host, ipaddress="10.10.10.20")

        resp: Any = self.client.get(f"/api/v1/hosts/{host.name}")
        self.assertEqual(resp.status_code, 200)

        metrics_resp: Any = self.client.get("/api/meta/metrics")
        raw = metrics_resp.content.decode("utf-8")

        per_req_count = _parse_prometheus_metric(raw, "mreg_db_queries_per_request_count")
        self.assertGreater(len(per_req_count), 0, "Expected DB queries-per-request histogram count series")
        self.assertTrue(any(v >= 1 for v in per_req_count.values()), f"Expected >=1 queries per request: {per_req_count}")

        total_counter = _parse_prometheus_metric(raw, "mreg_db_queries_total")
        self.assertGreater(len(total_counter), 0, "Expected total DB queries counter series")
        self.assertTrue(any(v >= 1 for v in total_counter.values()), f"Expected total DB queries >= 1: {total_counter}")

    def test_request_latency_recorded(self) -> None:
        """Test that request latency histogram is recorded with values."""
        self.client.get("/api/meta/health/heartbeat")

        metrics_resp: Any = self.client.get("/api/meta/metrics")
        raw = metrics_resp.content.decode("utf-8")

        latency_sum = _parse_prometheus_metric(raw, "mreg_http_request_duration_seconds_sum")
        self.assertGreater(len(latency_sum), 0, "No request latency metrics recorded")
        self.assertTrue(any(v > 0 for v in latency_sum.values()), "Expected positive request durations")

        latency_count = _parse_prometheus_metric(raw, "mreg_http_request_duration_seconds_count")
        self.assertGreater(len(latency_count), 0, "No request count metrics recorded")
        self.assertTrue(any(v >= 1 for v in latency_count.values()), "Expected at least 1 request counted")

    def test_request_and_response_size_histograms(self) -> None:
        """Test request and response size histograms are recorded."""
        baseline = self.client.get("/api/meta/metrics").content.decode("utf-8")

        # The middleware records sizes only when Content-Length is available.
        request = APIRequestFactory().post("/api/meta/health/heartbeat", "request", content_type="text/plain")
        response = HttpResponse("response", headers={"Content-Length": "8"})
        middleware = PrometheusRequestMiddleware(lambda request: response)
        self.assertIs(middleware(request), response)

        metrics_resp: Any = self.client.get("/api/meta/metrics")
        raw = metrics_resp.content.decode("utf-8")

        expected_increments = {
            "mreg_http_request_size_bytes_count": 1,
            "mreg_http_request_size_bytes_sum": 7,
            "mreg_http_response_size_bytes_count": 1,
            "mreg_http_response_size_bytes_sum": 8,
        }
        for metric_name, increment in expected_increments.items():
            with self.subTest(metric=metric_name):
                before = sum(_parse_prometheus_metric(baseline, metric_name).values())
                after = sum(_parse_prometheus_metric(raw, metric_name).values())
                self.assertEqual(after - before, increment)

    def test_metrics_endpoint_not_instrumented(self) -> None:
        """Test that the metrics endpoint itself is not instrumented (no recursion).

        Compares totals before and after repeated metrics scrapes; should not change.
        """
        # Baseline
        baseline_resp: Any = self.client.get("/api/meta/metrics")
        self.assertEqual(baseline_resp.status_code, 200)
        baseline_raw = baseline_resp.content.decode("utf-8")
        baseline_counts = _parse_prometheus_metric(baseline_raw, "mreg_http_requests_total")
        baseline_total = sum(baseline_counts.values()) if baseline_counts else 0.0

        # Repeated metrics scrapes
        for _ in range(3):
            resp: Any = self.client.get("/api/meta/metrics")
            self.assertEqual(resp.status_code, 200)

        # Compare
        final_resp: Any = self.client.get("/api/meta/metrics")
        final_raw = final_resp.content.decode("utf-8")
        final_counts = _parse_prometheus_metric(final_raw, "mreg_http_requests_total")
        final_total = sum(final_counts.values()) if final_counts else 0.0

        self.assertEqual(
            final_total,
            baseline_total,
            f"Metrics endpoint should not change request totals (baseline={baseline_total}, final={final_total})",
        )

    def test_metrics_endpoint_trailing_slash_not_instrumented(self) -> None:
        """Test that metrics endpoint with trailing slash is also not instrumented.

        Accepts 200/301/302/404 but ensures counters don't change.
        """
        # Baseline
        baseline_resp: Any = self.client.get("/api/meta/metrics")
        self.assertEqual(baseline_resp.status_code, 200)
        baseline_raw = baseline_resp.content.decode("utf-8")
        baseline_counts = _parse_prometheus_metric(baseline_raw, "mreg_http_requests_total")
        baseline_total = sum(baseline_counts.values()) if baseline_counts else 0.0

        # Scrape with trailing slash (may be 200/3xx/404 depending on URL config)
        for _ in range(3):
            resp: Any = self.client.get("/api/meta/metrics/")
            self.assertIn(resp.status_code, (200, 301, 302, 404))

        # Compare
        final_resp: Any = self.client.get("/api/meta/metrics")
        final_raw = final_resp.content.decode("utf-8")
        final_counts = _parse_prometheus_metric(final_raw, "mreg_http_requests_total")
        final_total = sum(final_counts.values()) if final_counts else 0.0

        self.assertEqual(
            final_total,
            baseline_total,
            f"Trailing slash metrics fetch should not change totals (baseline={baseline_total}, final={final_total})",
        )

    def test_request_without_resolver_match_uses_path(self) -> None:
        """Test that requests use view names or routes for low cardinality labeling."""
        # Make a request to an endpoint
        resp: Any = self.client.get("/api/meta/health/heartbeat")
        self.assertEqual(resp.status_code, 200)

        metrics_resp: Any = self.client.get("/api/meta/metrics")
        raw = metrics_resp.content.decode("utf-8")

        counts = _parse_prometheus_metric(raw, "mreg_http_requests_total")
        # Verify we have metrics with view name or route for low cardinality
        # (accepts either resolved view name or route template, never raw path with object IDs)
        self.assertTrue(
            any("HealthHeartbeat" in k or "meta/health/heartbeat" in k for k in counts.keys()),
            f"Expected view name or route label in metrics: {counts}",
        )

    def test_inprogress_gauge_decrements_on_success(self) -> None:
        """Test that in-progress gauge is decremented after request completes."""
        # Make multiple sequential requests
        for _ in range(2):
            resp: Any = self.client.get("/api/meta/health/heartbeat")
            self.assertEqual(resp.status_code, 200)

        metrics_resp: Any = self.client.get("/api/meta/metrics")
        raw = metrics_resp.content.decode("utf-8")

        inprogress = _parse_prometheus_metric(raw, "mreg_http_inprogress_requests")
        self.assertTrue(inprogress, "In-progress gauge should be recorded")
        self.assertTrue(all(value == 0 for value in inprogress.values()), inprogress)

    def test_db_metrics_resilience_to_errors(self) -> None:
        """Test that DB metrics recording is resilient to exceptions."""
        with patch("mreg.middleware.metrics.REQUEST_DB_REQUEST.labels") as mock_labels:
            mock_labels.return_value.observe.side_effect = ValueError("metrics unavailable")
            resp: Any = self.client.get("/api/meta/health/heartbeat")
            mock_labels.return_value.observe.assert_called_once()
        self.assertEqual(resp.status_code, 200)

        metrics_resp: Any = self.client.get("/api/meta/metrics")
        # Verify metrics endpoint still responds even if internal errors occurred
        self.assertEqual(metrics_resp.status_code, 200)
        self.assertIn(b"mreg_db_request_duration_seconds", metrics_resp.content)

    def test_normalize_path_fallback_to_path_info(self) -> None:
        """Test that _normalize_path prevents cardinality explosion from unresolved paths."""

        middleware = PrometheusRequestMiddleware(lambda r: Mock(status_code=200))

        # Create a request with an unresolvable path (404)
        request = Mock(spec=["resolver_match", "path_info"])
        request.resolver_match = None
        request.path_info = "/invalid/path/that/does/not/exist"

        result = middleware._normalize_path(request)
        # Should return 'unresolved' instead of raw path to prevent cardinality explosion
        self.assertEqual(result, "unresolved")

        # Test that valid paths are resolved properly
        request2 = Mock(spec=["resolver_match", "path_info"])
        request2.path_info = "/api/meta/health/heartbeat"

        result2 = middleware._normalize_path(request2)
        # Should resolve to either view name or route, never raw path_info
        self.assertNotEqual(result2, request2.path_info)
        # Accept view_name (has dots) or route template
        self.assertEqual(result2, "mreg.api.views.HealthHeartbeat")

    def test_unresolved_path_counter_records_404s(self) -> None:
        """Requests to unknown paths should increment unresolved counter with 404 status."""
        # Baseline
        baseline: Any = self.client.get("/api/meta/metrics")
        self.assertEqual(baseline.status_code, 200)
        raw0 = baseline.content.decode("utf-8")
        base_unresolved = _parse_prometheus_metric(raw0, "mreg_http_unresolved_requests_total")
        base_total = sum(base_unresolved.values()) if base_unresolved else 0.0

        # Hit an unknown path
        r404: Any = self.client.get("/definitely/not/a/real/endpoint")
        self.assertEqual(r404.status_code, 404)

        # Check counter increased
        metrics_resp: Any = self.client.get("/api/meta/metrics")
        raw = metrics_resp.content.decode("utf-8")
        unresolved = _parse_prometheus_metric(raw, "mreg_http_unresolved_requests_total")
        final_total = sum(unresolved.values()) if unresolved else 0.0
        self.assertGreaterEqual(
            final_total, base_total + 1, f"Expected unresolved counter to increase (base={base_total}, final={final_total})"
        )
        # Ensure 404 label appears
        self.assertTrue(any('status="404"' in k for k in unresolved.keys()), f"Expected 404 status label: {unresolved}")

    @patch("mreg.api.views.LDAPBackend")
    def test_ldap_metrics_success(self, mock_backend: Any) -> None:
        """LDAP health check should record call duration metrics per operation."""
        mock_connection = Mock()
        mock_backend.return_value.ldap.initialize.return_value = mock_connection

        resp: Any = self.client.get("/api/meta/health/ldap")
        self.assertEqual(resp.status_code, 200)

        metrics_resp: Any = self.client.get("/api/meta/metrics")
        raw = metrics_resp.content.decode("utf-8")

        latency = _parse_prometheus_metric(raw, "mreg_ldap_call_duration_seconds_sum")
        self.assertTrue(any('operation="initialize"' in k for k in latency.keys()), f"Expected initialize op metric: {latency}")
        self.assertTrue(any('operation="bind"' in k for k in latency.keys()), f"Expected bind op metric: {latency}")
        self.assertTrue(any('operation="unbind"' in k for k in latency.keys()), f"Expected unbind op metric: {latency}")

    @patch("mreg.api.views.LDAPBackend")
    def test_ldap_metrics_failure_counter(self, mock_backend: Any) -> None:
        """LDAP failures should increment the failure counter with exception label."""
        mock_connection = Mock()
        mock_connection.simple_bind_s.side_effect = ldap.LDAPError("bind failed")
        mock_backend.return_value.ldap.initialize.return_value = mock_connection

        resp: Any = self.client.get("/api/meta/health/ldap")
        self.assertEqual(resp.status_code, 503)

        metrics_resp: Any = self.client.get("/api/meta/metrics")
        raw = metrics_resp.content.decode("utf-8")

        failures = _parse_prometheus_metric(raw, "mreg_ldap_call_failures_total")
        self.assertTrue(
            any('operation="bind"' in k and 'exception="LDAPError"' in k for k in failures.keys()),
            f"Expected LDAPError bind failure metric: {failures}",
        )
