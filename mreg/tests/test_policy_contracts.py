from unittest import mock

from django.test import SimpleTestCase

from mreg.api.permissions import ParityMixin
from mreg.api.treetop import PolicyCheck, PolicyResource


class _ExampleModel:
    pass


class _ModelSerializer:
    class Meta:
        model = _ExampleModel


class _ModelView:
    kwargs = {"pk": 42}

    @staticmethod
    def get_serializer_class():
        return _ModelSerializer


class PolicyContractTests(SimpleTestCase):
    def setUp(self):
        self.mixin = ParityMixin()

    def test_resource_kind_uses_serializer_model(self):
        self.assertEqual(
            self.mixin._resource_kind_from_view(view=_ModelView()),
            "_ExampleModel",
        )

    def test_resource_kind_supports_explicit_non_model_contract(self):
        view = mock.Mock(policy_resource_kind="HealthCheck")
        view.get_serializer_class.side_effect = AttributeError

        self.assertEqual(
            self.mixin._resource_kind_from_view(view=view),
            "HealthCheck",
        )

    def test_resource_kind_does_not_guess_from_view_name(self):
        class ReportList:
            @staticmethod
            def get_serializer_class():
                return object

        with self.assertRaisesRegex(ValueError, "Meta.model"):
            self.mixin._resource_kind_from_view(view=ReportList())

    def test_resource_id_has_stable_precedence(self):
        obj = mock.Mock(pk=7)

        self.assertEqual(
            self.mixin._resource_id_from_view(
                view=_ModelView(),
                obj=obj,
                data={"id": 8},
            ),
            "7",
        )
        self.assertEqual(
            self.mixin._resource_id_from_view(
                view=_ModelView(),
                data={"id": 8},
            ),
            "8",
        )
        self.assertEqual(
            self.mixin._resource_id_from_view(view=_ModelView()),
            "42",
        )

    def test_unsupported_http_method_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "TRACE"):
            self.mixin._crud_operation_from_method("TRACE")

    def test_non_crud_action_is_an_explicit_view_contract(self):
        view = mock.Mock(policy_actions={"read": "host_contacts_read"})

        self.assertEqual(
            self.mixin._policy_action_from_view(
                view=view,
                resource_kind="Host",
                operation="read",
            ),
            "host_contacts_read",
        )

    def test_resource_attrs_cannot_override_canonical_kind(self):
        attrs = self.mixin._normalize_resource_attrs(
            resource_kind="BACnetID",
            attrs={"kind": "spoofed", "value": 1},
        )

        self.assertEqual(attrs, {"kind": "bacnet_id", "value": "1"})

    @mock.patch("mreg.api.permissions.policy_parity")
    def test_pp_builds_typed_policy_contract(self, policy_parity):
        policy_parity.return_value = True
        request = mock.Mock()
        view = _ModelView()

        result = self.mixin.pp(
            decision=True,
            action="host_read",
            request=request,
            view=view,
            resource_kind="Host",
            resource_id="host.example.org",
            resource_attrs={"hostname": "host.example.org"},
        )

        self.assertTrue(result)
        check = policy_parity.call_args.kwargs["check"]
        self.assertIsInstance(check, PolicyCheck)
        self.assertEqual(
            check,
            PolicyCheck(
                action="host_read",
                resource=PolicyResource(
                    kind="Host",
                    id="host.example.org",
                    attrs={"hostname": "host.example.org"},
                ),
            ),
        )
