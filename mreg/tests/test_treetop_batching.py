from types import SimpleNamespace
from unittest.mock import mock_open, patch

from django.http import HttpRequest, HttpResponse
from django.test import SimpleTestCase

from mreg.api.treetop import (
    _initialize_policy_parity_log_file,
    _thread_local,
    batch_policy_parity,
    policy_parity,
)
from mreg.middleware.logging_http import LoggingMiddleware
from mreg.tests.prometheus_test_utils import (
    metric_by_label as _metric_by_label,
    metric_total as _metric_total,
    prometheus_registry_text,
)


class _DummyAuthorizeResult:
    def __init__(self, allowed: bool) -> None:
        self._allowed = allowed
        self.status = "success"
        self.error = None

    def is_success(self) -> bool:
        return True

    def is_allowed(self) -> bool:
        return self._allowed


class _DummyAuthorizeResponse:
    def __init__(self, decisions: list[bool]) -> None:
        self.results = [_DummyAuthorizeResult(decision) for decision in decisions]


class TreeTopParityBatchingTests(SimpleTestCase):
    def tearDown(self) -> None:
        _thread_local.batch_queue = []
        _thread_local.batch_depth = 0
        super().tearDown()

    @staticmethod
    def _request() -> HttpRequest:
        request = HttpRequest()
        request.method = "GET"
        request.path = "/api/v1/hosts/"
        request.META["HTTP_X_CORRELATION_ID"] = "test-correlation-id"
        request.user = SimpleNamespace(is_authenticated=True)
        return request

    def test_initialize_policy_log_file_truncates_only_once(self) -> None:
        """Main process should truncate once and then mark initialization."""
        mocked_open = mock_open()
        with (
            patch("mreg.api.treetop.POLICY_TRUNCATE_LOG_FILE", True),
            patch("mreg.api.treetop.POLICY_EXTRA_LOG_FILE_NAME", "policy_parity.log"),
            patch(
                "mreg.api.treetop.multiprocessing.current_process",
                return_value=SimpleNamespace(name="MainProcess"),
            ),
            patch("mreg.api.treetop.open", mocked_open),
            patch.dict("mreg.api.treetop.os.environ", {}, clear=True),
        ):
            _initialize_policy_parity_log_file()
            _initialize_policy_parity_log_file()

        mocked_open.assert_called_once_with("policy_parity.log", "w")

    def test_initialize_policy_log_file_skips_parallel_worker(self) -> None:
        """Parallel workers must not truncate the shared parity log file."""
        mocked_open = mock_open()
        with (
            patch("mreg.api.treetop.POLICY_TRUNCATE_LOG_FILE", True),
            patch(
                "mreg.api.treetop.multiprocessing.current_process",
                return_value=SimpleNamespace(name="ForkPoolWorker-1"),
            ),
            patch("mreg.api.treetop.open", mocked_open),
            patch.dict("mreg.api.treetop.os.environ", {}, clear=True),
        ):
            _initialize_policy_parity_log_file()

        mocked_open.assert_not_called()

    @patch("mreg.api.treetop.MregUser.from_request")
    @patch("mreg.api.treetop.log_policy_parity")
    def test_batch_policy_parity_uses_single_authorize_call(
        self,
        mock_log_policy_parity,
        mock_from_request,
    ) -> None:
        mock_from_request.return_value = SimpleNamespace(username="tester", group_list=[])

        calls: list[tuple[int, str | None]] = []

        def fake_authorize(requests, correlation_id=None):  # type: ignore[no-untyped-def]
            request_list = requests if isinstance(requests, list) else [requests]
            calls.append((len(request_list), correlation_id))
            # Keep policy results aligned with legacy decisions in this test.
            decisions = [True, False][: len(request_list)]
            return _DummyAuthorizeResponse(decisions)

        request = self._request()
        with (
            patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            patch("mreg.api.treetop.POLICY_PARITY_BATCH_ENABLED", True),
            patch("mreg.api.treetop.treetopclient.authorize", side_effect=fake_authorize),
            batch_policy_parity(),
        ):
            self.assertTrue(
                policy_parity(
                    True,
                    request=request,
                    action="host_read",
                    resource_kind="Host",
                    resource_id="host1.example.org",
                    resource_attrs={"kind": "host", "hostname": "host1.example.org"},
                )
            )
            self.assertFalse(
                policy_parity(
                    False,
                    request=request,
                    action="host_read",
                    resource_kind="Host",
                    resource_id="host2.example.org",
                    resource_attrs={"kind": "host", "hostname": "host2.example.org"},
                )
            )

        self.assertEqual(calls, [(2, "test-correlation-id")])
        self.assertEqual(mock_log_policy_parity.call_count, 2)

    @patch("mreg.api.treetop.MregUser.from_request")
    @patch("mreg.api.treetop.log_policy_parity")
    def test_policy_parity_without_batch_context_calls_authorize_per_check(
        self,
        mock_log_policy_parity,
        mock_from_request,
    ) -> None:
        mock_from_request.return_value = SimpleNamespace(username="tester", group_list=[])

        calls: list[int] = []

        def fake_authorize(requests, correlation_id=None):  # type: ignore[no-untyped-def]
            request_list = requests if isinstance(requests, list) else [requests]
            calls.append(len(request_list))
            return _DummyAuthorizeResponse([True] * len(request_list))

        request = self._request()
        with (
            patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            patch("mreg.api.treetop.POLICY_PARITY_BATCH_ENABLED", True),
            patch("mreg.api.treetop.treetopclient.authorize", side_effect=fake_authorize),
        ):
            policy_parity(
                True,
                request=request,
                action="host_read",
                resource_kind="Host",
                resource_id="host1.example.org",
                resource_attrs={"kind": "host", "hostname": "host1.example.org"},
            )
            policy_parity(
                True,
                request=request,
                action="host_read",
                resource_kind="Host",
                resource_id="host2.example.org",
                resource_attrs={"kind": "host", "hostname": "host2.example.org"},
            )

        self.assertEqual(calls, [1, 1])
        self.assertEqual(mock_log_policy_parity.call_count, 2)

    @patch("mreg.api.treetop.MregUser.from_request")
    @patch("mreg.api.treetop.log_policy_parity")
    def test_single_http_request_flushes_one_authorize_batch(
        self,
        mock_log_policy_parity,
        mock_from_request,
    ) -> None:
        """Verify one policy-engine query for one request with multiple parity checks."""
        mock_from_request.return_value = SimpleNamespace(username="tester", group_list=[])

        calls: list[tuple[int, str | None]] = []

        def fake_authorize(requests, correlation_id=None):  # type: ignore[no-untyped-def]
            request_list = requests if isinstance(requests, list) else [requests]
            calls.append((len(request_list), correlation_id))
            return _DummyAuthorizeResponse([True] * len(request_list))

        request = self._request()
        request.path_info = request.path
        request._body = b""
        request.user = SimpleNamespace(username="tester")

        def mock_get_response(http_request: HttpRequest) -> HttpResponse:
            policy_parity(
                True,
                request=http_request,
                action="host_read",
                resource_kind="Host",
                resource_id="host1.example.org",
                resource_attrs={"kind": "host", "hostname": "host1.example.org"},
            )
            policy_parity(
                True,
                request=http_request,
                action="host_read",
                resource_kind="Host",
                resource_id="host2.example.org",
                resource_attrs={"kind": "host", "hostname": "host2.example.org"},
            )
            return HttpResponse(status=200)

        middleware = LoggingMiddleware(mock_get_response)

        with (
            patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            patch("mreg.api.treetop.POLICY_PARITY_BATCH_ENABLED", True),
            patch("mreg.api.treetop.treetopclient.authorize", side_effect=fake_authorize),
        ):
            middleware(request)

        self.assertEqual(calls, [(2, "test-correlation-id")])
        self.assertEqual(mock_log_policy_parity.call_count, 2)

    @patch("mreg.api.treetop.MregUser.from_request")
    @patch("mreg.api.treetop.log_policy_parity")
    @patch("mreg.api.treetop.logger.warning")
    def test_policy_metrics_are_recorded_for_batched_request(
        self,
        _mock_warning,
        mock_log_policy_parity,
        mock_from_request,
    ) -> None:
        mock_from_request.return_value = SimpleNamespace(username="tester", group_list=[])

        base_calls_success = _metric_by_label("mreg_policy_authorize_calls_total", 'status="success"')
        base_policy_allow = _metric_by_label("mreg_policy_decisions_total", 'decision="allow"')
        base_policy_deny = _metric_by_label("mreg_policy_decisions_total", 'decision="deny"')
        base_legacy_allow = _metric_by_label("mreg_policy_legacy_decisions_total", 'decision="allow"')
        base_legacy_deny = _metric_by_label("mreg_policy_legacy_decisions_total", 'decision="deny"')
        base_parity_match = _metric_by_label("mreg_policy_parity_results_total", 'result="match"')
        base_parity_mismatch = _metric_by_label("mreg_policy_parity_results_total", 'result="mismatch"')
        base_parity_error = _metric_by_label("mreg_policy_parity_results_total", 'result="error"')
        base_queries_count = _metric_total("mreg_policy_queries_per_request_count")
        base_queries_sum = _metric_total("mreg_policy_queries_per_request_sum")
        base_req_per_auth_count = _metric_total("mreg_policy_requests_per_authorize_count")
        base_req_per_auth_sum = _metric_total("mreg_policy_requests_per_authorize_sum")

        def fake_authorize(requests, correlation_id=None):  # type: ignore[no-untyped-def]
            request_list = requests if isinstance(requests, list) else [requests]
            decisions = [True, False, True][: len(request_list)]
            return _DummyAuthorizeResponse(decisions)

        request = self._request()
        request.path_info = request.path
        request._body = b""
        request.user = SimpleNamespace(username="tester")

        def mock_get_response(http_request: HttpRequest) -> HttpResponse:
            policy_parity(
                True,
                request=http_request,
                action="host_read",
                resource_kind="Host",
                resource_id="host1.example.org",
                resource_attrs={"kind": "host", "hostname": "host1.example.org"},
            )
            policy_parity(
                True,
                request=http_request,
                action="host_read",
                resource_kind="Host",
                resource_id="host2.example.org",
                resource_attrs={"kind": "host", "hostname": "host2.example.org"},
            )
            policy_parity(
                False,
                request=http_request,
                action="host_read",
                resource_kind="Host",
                resource_id="host3.example.org",
                resource_attrs={"kind": "host", "hostname": "host3.example.org"},
            )
            return HttpResponse(status=200)

        middleware = LoggingMiddleware(mock_get_response)

        with (
            patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            patch("mreg.api.treetop.POLICY_PARITY_BATCH_ENABLED", True),
            patch("mreg.api.treetop.treetopclient.authorize", side_effect=fake_authorize),
        ):
            middleware(request)

        self.assertEqual(
            _metric_by_label("mreg_policy_authorize_calls_total", 'status="success"') - base_calls_success,
            1.0,
        )
        self.assertEqual(
            _metric_by_label("mreg_policy_decisions_total", 'decision="allow"') - base_policy_allow,
            2.0,
        )
        self.assertEqual(
            _metric_by_label("mreg_policy_decisions_total", 'decision="deny"') - base_policy_deny,
            1.0,
        )
        self.assertEqual(
            _metric_by_label("mreg_policy_legacy_decisions_total", 'decision="allow"') - base_legacy_allow,
            2.0,
        )
        self.assertEqual(
            _metric_by_label("mreg_policy_legacy_decisions_total", 'decision="deny"') - base_legacy_deny,
            1.0,
        )
        self.assertEqual(
            _metric_by_label("mreg_policy_parity_results_total", 'result="match"') - base_parity_match,
            1.0,
        )
        self.assertEqual(
            _metric_by_label("mreg_policy_parity_results_total", 'result="mismatch"') - base_parity_mismatch,
            2.0,
        )
        self.assertEqual(
            _metric_by_label("mreg_policy_parity_results_total", 'result="error"') - base_parity_error,
            0.0,
        )
        self.assertEqual(_metric_total("mreg_policy_queries_per_request_count") - base_queries_count, 1.0)
        self.assertEqual(_metric_total("mreg_policy_queries_per_request_sum") - base_queries_sum, 1.0)
        self.assertEqual(_metric_total("mreg_policy_requests_per_authorize_count") - base_req_per_auth_count, 1.0)
        self.assertEqual(_metric_total("mreg_policy_requests_per_authorize_sum") - base_req_per_auth_sum, 3.0)

        raw = prometheus_registry_text()
        # Prometheus boundaries for buckets: 0,1,2,3,5,8,+Inf (ranges: 0,1,2,3,4-5,6-8,9+)
        self.assertIn('mreg_policy_queries_per_request_bucket{le="0.0"}', raw)
        self.assertIn('mreg_policy_queries_per_request_bucket{le="1.0"}', raw)
        self.assertIn('mreg_policy_queries_per_request_bucket{le="2.0"}', raw)
        self.assertIn('mreg_policy_queries_per_request_bucket{le="3.0"}', raw)
        self.assertIn('mreg_policy_queries_per_request_bucket{le="5.0"}', raw)
        self.assertIn('mreg_policy_queries_per_request_bucket{le="8.0"}', raw)
        self.assertIn('mreg_policy_requests_per_authorize_bucket{le="0.0"}', raw)
        self.assertIn('mreg_policy_requests_per_authorize_bucket{le="1.0"}', raw)
        self.assertIn('mreg_policy_requests_per_authorize_bucket{le="2.0"}', raw)
        self.assertIn('mreg_policy_requests_per_authorize_bucket{le="3.0"}', raw)
        self.assertIn('mreg_policy_requests_per_authorize_bucket{le="5.0"}', raw)
        self.assertIn('mreg_policy_requests_per_authorize_bucket{le="8.0"}', raw)
