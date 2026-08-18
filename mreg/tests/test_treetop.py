"""Tests for synchronous endpoint policy stacks."""

from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import SimpleTestCase
from rest_framework.test import APIRequestFactory

from mreg.api.treetop import (
    PolicyAll,
    PolicyAny,
    PolicyCheck,
    PolicyLeaf,
    PolicyResource,
    _SynchronousCircuitBreaker,
    _build_resource_attrs,
    authorize_policy_stack,
    close_policy_client,
    disable_policy_parity,
    policy_all,
    policy_any,
    policy_leaf,
    policy_request_scope,
    policy_shadow_enabled,
)
from mreg.policy.config import PolicyMode


class SynchronousPolicyStackTests(SimpleTestCase):
    def setUp(self) -> None:
        self.factory = APIRequestFactory()
        self.user = SimpleNamespace(username="alice", group_list=("users",))

    def _request(self):
        return self.factory.get(
            "/api/v1/hosts/",
            HTTP_X_CORRELATION_ID="test-correlation",
        )

    @staticmethod
    def _leaf(name: str = "host.example.org") -> PolicyLeaf:
        return policy_leaf(
            action="host_read",
            resource_kind="Host",
            resource_id=name,
            resource_attrs={"kind": "host", "name": name},
        )

    @staticmethod
    def _result(allowed: bool, index: int):
        result = Mock()
        result.index = index
        result.id = f"mreg-{index}"
        result.is_success.return_value = True
        result.is_allowed.return_value = allowed
        return result

    def _client(self, *decisions: bool):
        client = Mock()
        client.authorize.return_value = SimpleNamespace(results=[self._result(decision, index) for index, decision in enumerate(decisions)])
        return client

    def test_policy_contracts_reject_empty_values(self) -> None:
        with self.assertRaisesRegex(ValueError, "kind"):
            PolicyResource("", "id", {"kind": "host"})
        with self.assertRaisesRegex(ValueError, "ID"):
            PolicyResource("Host", "", {"kind": "host"})
        with self.assertRaisesRegex(ValueError, "attributes"):
            PolicyResource("Host", "id", {})
        with self.assertRaisesRegex(ValueError, "action"):
            PolicyCheck("", PolicyResource("Host", "id", {"kind": "host"}))
        with self.assertRaisesRegex(ValueError, "at least one"):
            PolicyAll(())
        with self.assertRaisesRegex(ValueError, "at least one"):
            PolicyAny(())

    def test_resource_attributes_detect_bool_ip_and_string(self) -> None:
        attrs = _build_resource_attrs({"restricted": "true", "ip": "192.0.2.1", "name": "host"})
        self.assertEqual(attrs["restricted"].type.value, "Bool")
        self.assertEqual(attrs["ip"].type.value, "Ip")
        self.assertEqual(attrs["name"].type.value, "String")

    @patch("mreg.api.treetop.MregUser.from_request")
    @patch("mreg.api.treetop._get_treetop_client")
    def test_nested_stack_uses_one_batched_authorize_call(self, get_client, from_request) -> None:
        from_request.return_value = self.user
        client = self._client(True, False, True)
        get_client.return_value = client
        root = policy_all(
            policy_any(self._leaf("one.example.org"), self._leaf("two.example.org")),
            self._leaf("three.example.org"),
        )

        with (
            patch("mreg.api.treetop.POLICY_MODE", PolicyMode.ENFORCE),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
            policy_request_scope(),
        ):
            self.assertTrue(authorize_policy_stack(False, request=self._request(), root=root))

        client.authorize.assert_called_once()
        requests = client.authorize.call_args.args[0]
        self.assertEqual(len(requests), 3)
        self.assertEqual([request.id for request in requests], ["mreg-0", "mreg-1", "mreg-2"])

    @patch("mreg.api.treetop.MregUser.from_request")
    @patch("mreg.api.treetop._get_treetop_client")
    def test_identical_stack_is_cached_inside_request(self, get_client, from_request) -> None:
        from_request.return_value = self.user
        client = self._client(True)
        get_client.return_value = client
        root = self._leaf()
        with (
            patch("mreg.api.treetop.POLICY_MODE", PolicyMode.ENFORCE),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
            policy_request_scope(),
        ):
            self.assertTrue(authorize_policy_stack(False, request=self._request(), root=root))
            self.assertTrue(authorize_policy_stack(False, request=self._request(), root=root))
        client.authorize.assert_called_once()

    @patch("mreg.api.treetop.MregUser.from_request")
    @patch("mreg.api.treetop._get_treetop_client")
    def test_second_different_stack_denies_without_second_call(self, get_client, from_request) -> None:
        from_request.return_value = self.user
        client = self._client(True)
        get_client.return_value = client
        with (
            patch("mreg.api.treetop.POLICY_MODE", PolicyMode.ENFORCE),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
            policy_request_scope(),
        ):
            self.assertTrue(authorize_policy_stack(False, request=self._request(), root=self._leaf("one")))
            self.assertFalse(authorize_policy_stack(True, request=self._request(), root=self._leaf("two")))
        client.authorize.assert_called_once()

    @patch("mreg.api.treetop._get_treetop_client")
    def test_off_and_unconfigured_shadow_do_not_call_treetop(self, get_client) -> None:
        for mode in (PolicyMode.OFF, PolicyMode.SHADOW):
            with (
                patch("mreg.api.treetop.POLICY_MODE", mode),
                patch("mreg.api.treetop.POLICY_BASE_URL", ""),
            ):
                self.assertTrue(authorize_policy_stack(True, request=self._request(), root=self._leaf()))
        get_client.assert_not_called()

    def test_shadow_enabled_reflects_configuration_and_disable_scope(self) -> None:
        with (
            patch("mreg.api.treetop.POLICY_MODE", PolicyMode.SHADOW),
            patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
        ):
            self.assertTrue(policy_shadow_enabled())
            with disable_policy_parity():
                self.assertFalse(policy_shadow_enabled())

        with patch("mreg.api.treetop.POLICY_MODE", PolicyMode.ENFORCE):
            self.assertFalse(policy_shadow_enabled())

    @patch("mreg.api.treetop.MregUser.from_request")
    @patch("mreg.api.treetop._get_treetop_client")
    def test_shadow_calls_synchronously_but_returns_legacy(self, get_client, from_request) -> None:
        from_request.return_value = self.user
        get_client.return_value = self._client(True)
        with (
            patch("mreg.api.treetop.POLICY_MODE", PolicyMode.SHADOW),
            patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
            policy_request_scope(),
        ):
            self.assertFalse(authorize_policy_stack(False, request=self._request(), root=self._leaf()))
        get_client.return_value.authorize.assert_called_once()

    @patch("mreg.api.treetop.MregUser.from_request")
    @patch("mreg.api.treetop._get_treetop_client")
    def test_enforce_returns_allow_and_deny(self, get_client, from_request) -> None:
        from_request.return_value = self.user
        with (
            patch("mreg.api.treetop.POLICY_MODE", PolicyMode.ENFORCE),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
        ):
            get_client.return_value = self._client(True)
            self.assertTrue(authorize_policy_stack(False, request=self._request(), root=self._leaf()))
            get_client.return_value = self._client(False)
            self.assertFalse(authorize_policy_stack(True, request=self._request(), root=self._leaf()))

    @patch("mreg.api.treetop.MregUser.from_request")
    @patch("mreg.api.treetop._get_treetop_client")
    def test_results_are_composed_by_response_index(self, get_client, from_request) -> None:
        from_request.return_value = self.user
        client = self._client(True, False)
        client.authorize.return_value.results.reverse()
        get_client.return_value = client
        with (
            patch("mreg.api.treetop.POLICY_MODE", PolicyMode.ENFORCE),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
        ):
            self.assertFalse(
                authorize_policy_stack(
                    True,
                    request=self._request(),
                    root=policy_all(self._leaf("one"), self._leaf("two")),
                )
            )

    @patch("mreg.api.treetop.MregUser.from_request")
    @patch("mreg.api.treetop._get_treetop_client")
    def test_invalid_result_is_a_circuit_failure(self, get_client, from_request) -> None:
        from_request.return_value = self.user
        client = self._client(True)
        client.authorize.return_value.results[0].id = "wrong"
        get_client.return_value = client
        circuit = _SynchronousCircuitBreaker(2, 30)
        with (
            patch("mreg.api.treetop.POLICY_MODE", PolicyMode.ENFORCE),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
            patch("mreg.api.treetop._circuit", circuit),
        ):
            self.assertFalse(authorize_policy_stack(True, request=self._request(), root=self._leaf()))
        self.assertEqual(circuit._failures, 1)

    @patch("mreg.api.treetop.MregUser.from_request")
    @patch("mreg.api.treetop._get_treetop_client")
    def test_enforce_errors_deny_and_shadow_errors_use_legacy(self, get_client, from_request) -> None:
        from_request.return_value = self.user
        get_client.return_value.authorize.side_effect = RuntimeError("offline")
        with (
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
            patch("mreg.api.treetop._circuit", _SynchronousCircuitBreaker(5, 30)),
        ):
            with patch("mreg.api.treetop.POLICY_MODE", PolicyMode.ENFORCE):
                self.assertFalse(authorize_policy_stack(True, request=self._request(), root=self._leaf()))
            with (
                patch("mreg.api.treetop.POLICY_MODE", PolicyMode.SHADOW),
                patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            ):
                self.assertTrue(authorize_policy_stack(True, request=self._request(), root=self._leaf()))

    @patch("mreg.api.treetop._get_treetop_client")
    def test_disable_helper_only_disables_shadow(self, get_client) -> None:
        with (
            patch("mreg.api.treetop.POLICY_MODE", PolicyMode.SHADOW),
            patch("mreg.api.treetop.POLICY_PARITY_ENABLED", True),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
            disable_policy_parity(),
        ):
            self.assertTrue(authorize_policy_stack(True, request=self._request(), root=self._leaf()))
        get_client.assert_not_called()

    @patch("mreg.api.treetop.MregUser.from_request")
    @patch("mreg.api.treetop._get_treetop_client")
    def test_disable_helper_cannot_bypass_enforcement(self, get_client, from_request) -> None:
        from_request.return_value = self.user
        get_client.return_value = self._client(False)
        with (
            patch("mreg.api.treetop.POLICY_MODE", PolicyMode.ENFORCE),
            patch("mreg.api.treetop.POLICY_BASE_URL", "http://policy"),
            disable_policy_parity(),
        ):
            self.assertFalse(authorize_policy_stack(True, request=self._request(), root=self._leaf()))
        get_client.return_value.authorize.assert_called_once()

    def test_circuit_opens_and_allows_one_half_open_probe(self) -> None:
        circuit = _SynchronousCircuitBreaker(2, 30)
        self.assertTrue(circuit.allow_call())
        circuit.failure()
        self.assertTrue(circuit.allow_call())
        circuit.failure()
        self.assertFalse(circuit.allow_call())

        circuit._open_until = 0.1
        with patch("mreg.api.treetop.monotonic", return_value=1.0):
            self.assertTrue(circuit.allow_call())
            self.assertFalse(circuit.allow_call())
        circuit.success()
        self.assertTrue(circuit.allow_call())

    @patch("mreg.api.treetop._client_lock")
    def test_close_policy_client_is_safe_without_client(self, client_lock) -> None:
        client_lock.__enter__ = Mock()
        client_lock.__exit__ = Mock(return_value=False)
        with patch("mreg.api.treetop._client", None):
            close_policy_client()
