from __future__ import annotations

from copy import deepcopy
import logging
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.http import HttpRequest, HttpResponse
from django.test import TestCase

from mreg.api.treetop import (
    PolicyCheck,
    PolicyResource,
    _CircuitBreaker,
    _ParityBatchItem,
    _ParityDispatcher,
    _build_policy_request,
    _build_resource_attrs,
    _compute_parity_payload,
    _deserialize_policy_batch,
    _fully_qualified_action,
    _get_treetop_client,
    _is_parity_enabled,
    _process_policy_parity_batch,
    _qualified_resource_kind,
    _request_state,
    _result_to_decision_and_error,
    _safe_log,
    _serialize_policy_batch,
    _close_treetop_client,
    batch_policy_parity,
    disable_policy_parity,
    flush_policy_parity_batch,
    policy_parity,
    start_policy_parity_dispatcher,
    stop_policy_parity_dispatcher,
)
from mreg.middleware.logging_http import LoggingMiddleware


class _DummyAuthorizeResult:
    def __init__(
        self,
        allowed: bool = False,
        *,
        status: str = "success",
        error: str | None = None,
    ) -> None:
        self._allowed = allowed
        self.status = status
        self.error = error

    def is_success(self) -> bool:
        return self.status == "success"

    def is_allowed(self) -> bool:
        return self._allowed


class _DummyAuthorizeResponse:
    def __init__(self, decisions: list[bool]) -> None:
        self.results = [_DummyAuthorizeResult(decision) for decision in decisions]


class TreeTopParityBatchingTests(TestCase):
    @staticmethod
    def _request() -> HttpRequest:
        request = HttpRequest()
        request.method = "GET"
        request.path = "/api/v1/hosts/"
        request.META["HTTP_X_CORRELATION_ID"] = "test-correlation-id"
        request.user = SimpleNamespace(is_authenticated=True)
        return request

    @staticmethod
    def _middleware_request() -> HttpRequest:
        request = TreeTopParityBatchingTests._request()
        request.path_info = request.path
        request._body = b""
        request.user = SimpleNamespace(username="tester")
        return request

    @staticmethod
    def _check(hostname: str = "host.example.org") -> PolicyCheck:
        return PolicyCheck(
            action="host_read",
            resource=PolicyResource(
                kind="Host",
                id=hostname,
                attrs={"kind": "host", "hostname": hostname},
            ),
        )

    def _run_parity_check(
        self,
        request: HttpRequest,
        *,
        decision: bool,
        hostname: str,
    ) -> bool:
        return policy_parity(
            decision,
            request=request,
            check=self._check(hostname),
        )

    def test_policy_contract_rejects_empty_values(self) -> None:
        with self.assertRaisesRegex(ValueError, "kind"):
            PolicyResource(kind="", id="id", attrs={"kind": "host"})
        with self.assertRaisesRegex(ValueError, "ID"):
            PolicyResource(kind="Host", id="", attrs={"kind": "host"})
        with self.assertRaisesRegex(ValueError, "attributes"):
            PolicyResource(kind="Host", id="id", attrs={})
        with self.assertRaisesRegex(ValueError, "action"):
            PolicyCheck(action="", resource=self._check().resource)

    def test_is_parity_enabled_requires_configuration_and_context(self) -> None:
        with patch("mreg.api.treetop.POLICY_PARITY_ENABLED", False):
            self.assertFalse(_is_parity_enabled())
        with (
            patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            patch("mreg.api.treetop.POLICY_BASE_URL", ""),
        ):
            self.assertFalse(_is_parity_enabled())
        with (
            patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
            disable_policy_parity(),
        ):
            self.assertFalse(_is_parity_enabled())

    def test_disable_policy_parity_supports_nesting(self) -> None:
        with (
            patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
        ):
            self.assertTrue(_is_parity_enabled())
            with disable_policy_parity():
                with disable_policy_parity():
                    self.assertFalse(_is_parity_enabled())
                self.assertFalse(_is_parity_enabled())
            self.assertTrue(_is_parity_enabled())

    def test_build_resource_attrs_detects_ip_values(self) -> None:
        attrs = _build_resource_attrs({"ip": "192.0.2.1", "name": "host"})
        self.assertEqual(attrs["ip"].type.value, "Ip")
        self.assertEqual(attrs["name"].type.value, "String")

    def test_build_policy_request_uses_namespaced_resource_and_groups(self) -> None:
        muser = SimpleNamespace(username="tester", group_list=["admins"])
        with patch("mreg.api.treetop.POLICY_NAMESPACE", ["UiO", "MREG"]):
            payload = _build_policy_request(muser, self._check()).to_api()

        self.assertEqual(payload["resource"]["kind"], "UiO::MREG::Host")
        self.assertEqual(payload["action"]["namespace"], ["UiO", "MREG"])
        self.assertEqual(
            payload["principal"]["User"]["groups"][0],
            {"id": "admins", "namespace": ["UiO", "MREG"]},
        )

    def test_qualified_names_without_namespace(self) -> None:
        action = SimpleNamespace(__str__=lambda _self: "host_read")
        self.assertEqual(_fully_qualified_action(action), str(action))
        with patch("mreg.api.treetop.POLICY_NAMESPACE", []):
            self.assertEqual(_qualified_resource_kind("Host"), "Host")

    def test_result_parsing_covers_missing_failed_and_success(self) -> None:
        allowed, error = _result_to_decision_and_error([], 0)
        self.assertIsNone(allowed)
        self.assertEqual(error, "Missing policy result at index 0")

        failed = _DummyAuthorizeResult(status="failed")
        allowed, error = _result_to_decision_and_error([failed], 0)  # type: ignore[arg-type]
        self.assertIsNone(allowed)
        self.assertEqual(error, "Authorization failed with status=failed")

        failed_with_error = _DummyAuthorizeResult(status="failed", error="bad request")
        allowed, error = _result_to_decision_and_error([failed_with_error], 0)  # type: ignore[arg-type]
        self.assertIsNone(allowed)
        self.assertEqual(error, "bad request")

        allowed, error = _result_to_decision_and_error([_DummyAuthorizeResult(True)], 0)  # type: ignore[arg-type]
        self.assertTrue(allowed)
        self.assertIsNone(error)

    def test_compute_payload_distinguishes_match_mismatch_and_error(self) -> None:
        matching = _compute_parity_payload(
            decision=True,
            policy_allowed=True,
            error=None,
            context={},
        )
        mismatch = _compute_parity_payload(
            decision=False,
            policy_allowed=True,
            error=None,
            context={},
        )
        unavailable = _compute_parity_payload(
            decision=True,
            policy_allowed=None,
            error="offline",
            context={},
        )
        self.assertTrue(matching["parity"])
        self.assertFalse(mismatch["parity"])
        self.assertFalse(unavailable["parity"])

    @patch("mreg.api.treetop.logger")
    def test_safe_log_preserves_structured_context(self, logger: Mock) -> None:
        _safe_log(logging.WARNING, "policy_event", result="mismatch")

        logger.log.assert_called_once_with(
            logging.WARNING,
            "policy_event",
            result="mismatch",
        )

    @patch("mreg.api.treetop.MregUser.from_request")
    def test_request_batch_is_submitted_after_response_without_authorize_io(
        self,
        mock_from_request: Mock,
    ) -> None:
        mock_from_request.return_value = SimpleNamespace(username="tester", group_list=[])
        submitted: list[list[_ParityBatchItem]] = []

        def capture(items):  # type: ignore[no-untyped-def]
            submitted.append(list(items))
            return True

        request = self._request()
        with (
            patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
            patch("mreg.api.treetop.POLICY_PARITY_BATCH_ENABLED", True),
            patch("mreg.api.treetop._submit_policy_batch", side_effect=capture),
            patch("mreg.api.treetop._get_treetop_client") as get_client,
            batch_policy_parity(),
        ):
            self.assertTrue(self._run_parity_check(request, decision=True, hostname="one.example"))
            self.assertFalse(self._run_parity_check(request, decision=False, hostname="two.example"))
            self.assertEqual(submitted, [])

        get_client.assert_not_called()
        self.assertEqual(len(submitted), 1)
        self.assertEqual(len(submitted[0]), 2)
        self.assertIsNone(_request_state.get())

    @patch("mreg.api.treetop.MregUser.from_request")
    def test_batching_disabled_submits_each_check(self, mock_from_request: Mock) -> None:
        mock_from_request.return_value = SimpleNamespace(username="tester", group_list=[])
        submissions: list[int] = []

        def capture(items):  # type: ignore[no-untyped-def]
            submissions.append(len(items))
            return True

        with (
            patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
            patch("mreg.api.treetop.POLICY_PARITY_BATCH_ENABLED", False),
            patch("mreg.api.treetop._submit_policy_batch", side_effect=capture),
            batch_policy_parity(),
        ):
            self._run_parity_check(self._request(), decision=True, hostname="one.example")
            self._run_parity_check(self._request(), decision=True, hostname="two.example")

        self.assertEqual(submissions, [1, 1])

    @patch("mreg.api.treetop.MregUser.from_request")
    def test_flush_submits_and_clears_active_batch(self, mock_from_request: Mock) -> None:
        mock_from_request.return_value = SimpleNamespace(username="tester", group_list=[])
        with (
            patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
            patch("mreg.api.treetop.POLICY_PARITY_BATCH_ENABLED", True),
            patch("mreg.api.treetop._submit_policy_batch", return_value=True) as submit,
            batch_policy_parity(),
        ):
            self._run_parity_check(self._request(), decision=True, hostname="one.example")
            self.assertTrue(flush_policy_parity_batch())
            self.assertFalse(flush_policy_parity_batch())

        submit.assert_called_once()

    @patch("mreg.api.treetop.MregUser.from_request", side_effect=RuntimeError("broken user"))
    @patch("mreg.api.treetop._record_instrumentation_failure")
    def test_policy_parity_is_fail_open_for_build_errors(
        self,
        record_failure: Mock,
        _from_request: Mock,
    ) -> None:
        with (
            patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
        ):
            self.assertTrue(policy_parity(True, request=self._request(), check=self._check()))
        record_failure.assert_called_once()

    @patch("mreg.api.treetop.MregUser.from_request")
    def test_sensitive_log_details_are_disabled_by_default(self, mock_from_request: Mock) -> None:
        mock_from_request.return_value = SimpleNamespace(
            username="tester",
            group_list=["secret-group"],
        )
        captured: list[_ParityBatchItem] = []

        def capture(items):  # type: ignore[no-untyped-def]
            captured.extend(items)
            return True

        with (
            patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
            patch("mreg.api.treetop.POLICY_PARITY_LOG_DETAILS", False),
            patch("mreg.api.treetop._submit_policy_batch", side_effect=capture),
        ):
            self._run_parity_check(self._request(), decision=True, hostname="secret.example")

        self.assertNotIn("principal", captured[0].context)
        self.assertNotIn("groups", captured[0].context)
        self.assertNotIn("resource_attrs", captured[0].context)

    @patch("mreg.api.treetop.MregUser.from_request")
    def test_sensitive_log_details_can_be_enabled(self, mock_from_request: Mock) -> None:
        mock_from_request.return_value = SimpleNamespace(username="tester", group_list=["admins"])
        captured: list[_ParityBatchItem] = []

        def capture(items):  # type: ignore[no-untyped-def]
            captured.extend(items)
            return True

        with (
            patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
            patch("mreg.api.treetop.POLICY_PARITY_LOG_DETAILS", True),
            patch("mreg.api.treetop._submit_policy_batch", side_effect=capture),
        ):
            self._run_parity_check(self._request(), decision=True, hostname="host.example")

        self.assertEqual(captured[0].context["principal"], "tester")
        self.assertEqual(captured[0].context["groups"], ["admins"])

    @patch("mreg.api.treetop._log_parity_payload")
    @patch("mreg.api.treetop._get_treetop_client")
    def test_worker_processes_a_batch_in_one_authorize_call(
        self,
        get_client: Mock,
        log_payload: Mock,
    ) -> None:
        client = get_client.return_value
        client.authorize.return_value = _DummyAuthorizeResponse([True, False])
        items = [
            _ParityBatchItem(True, {"request": "one"}, {"correlation_id": "cid", "path": "/one"}),
            _ParityBatchItem(False, {"request": "two"}, {"correlation_id": "cid", "path": "/one"}),
        ]

        _process_policy_parity_batch(items)

        client.authorize.assert_called_once_with(
            [{"request": "one"}, {"request": "two"}],
            correlation_id="cid",
        )
        self.assertEqual(log_payload.call_count, 2)
        self.assertTrue(log_payload.call_args_list[0].args[0]["parity"])
        self.assertTrue(log_payload.call_args_list[1].args[0]["parity"])

    @patch("mreg.api.treetop._log_parity_payload")
    @patch("mreg.api.treetop._get_treetop_client")
    def test_worker_records_authorize_exceptions_for_every_item(
        self,
        get_client: Mock,
        log_payload: Mock,
    ) -> None:
        get_client.return_value.authorize.side_effect = RuntimeError("offline")
        items = [
            _ParityBatchItem(True, {"request": "one"}, {}),
            _ParityBatchItem(False, {"request": "two"}, {}),
        ]

        with self.assertRaisesRegex(RuntimeError, "offline"):
            _process_policy_parity_batch(items)

        log_payload.assert_not_called()

    def test_dispatcher_persists_batches_in_the_shared_outbox(self) -> None:
        dispatcher = _ParityDispatcher()
        request = _build_policy_request(
            SimpleNamespace(username="tester", group_list=[]),
            self._check(),
        )
        item = _ParityBatchItem(True, request, {"path": "/one"})
        with patch.object(dispatcher, "_ensure_started"):
            self.assertTrue(dispatcher.submit([item]))

        from mreg.models.policy import PolicyParityOutbox

        row = PolicyParityOutbox.objects.get()
        self.assertEqual(row.payload["version"], 1)
        self.assertEqual(row.payload["items"][0]["context"]["path"], "/one")

    def test_durable_batch_round_trip_preserves_typed_requests(self) -> None:
        request = _build_policy_request(
            SimpleNamespace(username="tester", group_list=["admins"]),
            self._check(),
        )
        items = [_ParityBatchItem(False, request, {"correlation_id": "cid"})]

        restored = _deserialize_policy_batch(_serialize_policy_batch(items))

        self.assertEqual(len(restored), 1)
        self.assertFalse(restored[0].decision)
        self.assertEqual(restored[0].context, {"correlation_id": "cid"})
        self.assertEqual(restored[0].policy_request.to_api(), request.to_api())

    def test_durable_batch_rejects_malformed_payloads(self) -> None:
        request = _build_policy_request(
            SimpleNamespace(username="tester", group_list=[]),
            self._check(),
        ).to_api()

        def batch(policy_request):  # type: ignore[no-untyped-def]
            return {
                "version": 1,
                "items": [{"decision": True, "policy_request": policy_request, "context": {}}],
            }

        invalid_payloads: list[dict[str, object]] = [
            {"version": 2, "items": []},
            {"version": 1, "items": {}},
            {"version": 1, "items": ["invalid"]},
            {"version": 1, "items": [{"policy_request": request, "context": []}]},
            batch({"principal": []}),
            batch({"principal": {"User": []}}),
        ]

        invalid_action = deepcopy(request)
        invalid_action["action"] = []
        invalid_payloads.append(batch(invalid_action))
        invalid_attrs = deepcopy(request)
        invalid_attrs["resource"]["attrs"] = []
        invalid_payloads.append(batch(invalid_attrs))
        invalid_attribute = deepcopy(request)
        invalid_attribute["resource"]["attrs"]["kind"] = []
        invalid_payloads.append(batch(invalid_attribute))

        for payload in invalid_payloads:
            with self.subTest(payload=payload), self.assertRaises((ValueError, KeyError)):
                _deserialize_policy_batch(payload)

    def test_treetop_client_is_process_local_and_closed_safely(self) -> None:
        old_client = Mock()
        new_client = Mock()
        with (
            patch("mreg.api.treetop._client", old_client),
            patch("mreg.api.treetop._client_pid", -1),
            patch("mreg.api.treetop.os.getpid", return_value=42),
            patch("mreg.api.treetop.TreeTopClient", return_value=new_client) as client_class,
        ):
            self.assertIs(_get_treetop_client(), new_client)

        old_client.close.assert_called_once_with()
        client_class.assert_called_once()

        with (
            patch("mreg.api.treetop._client", new_client),
            patch("mreg.api.treetop._client_pid", 42),
            patch("mreg.api.treetop.asyncio.run") as async_run,
        ):
            _close_treetop_client()
        async_run.assert_called_once_with(new_client.aclose.return_value)

        fallback_client = Mock()
        with (
            patch("mreg.api.treetop._client", fallback_client),
            patch("mreg.api.treetop._client_pid", 42),
            patch("mreg.api.treetop.asyncio.run", side_effect=RuntimeError("no event loop")),
        ):
            _close_treetop_client()
        fallback_client.close.assert_called_once_with()

    def test_dispatcher_lifecycle_respects_configuration_and_process(self) -> None:
        dispatcher = Mock()
        with (
            patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
            patch("mreg.api.treetop._get_dispatcher", return_value=dispatcher),
        ):
            start_policy_parity_dispatcher()
        dispatcher._ensure_started.assert_called_once_with()

        with (
            patch("mreg.api.treetop._dispatcher", dispatcher),
            patch("mreg.api.treetop._dispatcher_pid", 42),
            patch("mreg.api.treetop.os.getpid", return_value=42),
        ):
            stop_policy_parity_dispatcher()
        dispatcher.shutdown.assert_called_once_with()

    def test_dispatcher_claims_and_completes_a_durable_batch(self) -> None:
        from mreg.models.policy import PolicyParityOutbox

        request = _build_policy_request(
            SimpleNamespace(username="tester", group_list=[]),
            self._check(),
        )
        row = PolicyParityOutbox.objects.create(
            payload=_serialize_policy_batch([_ParityBatchItem(True, request, {})]),
        )
        dispatcher = _ParityDispatcher()

        claimed = dispatcher._claim()

        self.assertIsNotNone(claimed)
        assert claimed is not None
        self.assertEqual(claimed.id, row.id)
        self.assertEqual(claimed.attempts, 1)
        dispatcher._complete(claimed)
        self.assertFalse(PolicyParityOutbox.objects.filter(id=row.id).exists())

    def test_dispatcher_retries_then_retains_a_dead_letter(self) -> None:
        from mreg.models.policy import PolicyParityOutbox

        request = _build_policy_request(
            SimpleNamespace(username="tester", group_list=[]),
            self._check(),
        )
        item = _ParityBatchItem(True, request, {})
        row = PolicyParityOutbox.objects.create(payload=_serialize_policy_batch([item]))
        dispatcher = _ParityDispatcher()
        claimed = dispatcher._claim()
        assert claimed is not None

        with patch("mreg.api.treetop.POLICY_PARITY_MAX_ATTEMPTS", 2):
            dispatcher._fail(claimed, RuntimeError("offline"), [item])
            row.refresh_from_db()
            self.assertIsNone(row.failed_at)
            self.assertIsNone(row.locked_at)

            row.available_at = row.created_at
            row.save(update_fields=("available_at",))
            claimed = dispatcher._claim()
            assert claimed is not None
            dispatcher._fail(claimed, RuntimeError("still offline"), [item])

        row.refresh_from_db()
        self.assertIsNotNone(row.failed_at)
        self.assertIn("still offline", row.last_error)

    def test_circuit_breaker_opens_and_recovers(self) -> None:
        circuit = _CircuitBreaker(failure_threshold=2, reset_seconds=30)
        circuit.failure()
        self.assertEqual(circuit.wait_seconds(), 0)
        circuit.failure()
        self.assertGreater(circuit.wait_seconds(), 0)
        circuit.success()
        self.assertEqual(circuit.wait_seconds(), 0)

    @patch("mreg.api.treetop.MregUser.from_request")
    def test_logging_middleware_only_enqueues_policy_work(self, mock_from_request: Mock) -> None:
        mock_from_request.return_value = SimpleNamespace(username="tester", group_list=[])

        def get_response(request: HttpRequest) -> HttpResponse:
            self._run_parity_check(request, decision=True, hostname="one.example")
            self._run_parity_check(request, decision=True, hostname="two.example")
            return HttpResponse(status=200)

        middleware = LoggingMiddleware(get_response)
        with (
            patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
            patch("mreg.api.treetop.POLICY_PARITY_BATCH_ENABLED", True),
            patch("mreg.api.treetop._submit_policy_batch", return_value=True) as submit,
            patch("mreg.api.treetop._get_treetop_client") as get_client,
        ):
            response = middleware(self._middleware_request())

        self.assertEqual(response.status_code, 200)
        get_client.assert_not_called()
        self.assertEqual(len(submit.call_args.args[0]), 2)
