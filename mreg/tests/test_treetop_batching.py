from types import SimpleNamespace
from unittest.mock import patch

from django.http import HttpRequest, HttpResponse
from django.test import SimpleTestCase

from mreg.api.treetop import _thread_local, batch_policy_parity, policy_parity
from mreg.middleware.logging_http import LoggingMiddleware


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
            return _DummyAuthorizeResponse([True] * len(request_list))

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
