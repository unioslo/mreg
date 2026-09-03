from django.test import SimpleTestCase

from mreg.policy.config import (
    PolicyMode,
    resolve_policy_mode,
    validate_policy_configuration,
)


class PolicyConfigurationTests(SimpleTestCase):
    def test_explicit_policy_mode_takes_precedence(self) -> None:
        self.assertEqual(
            resolve_policy_mode(" enforce ", legacy_parity_enabled=False),
            PolicyMode.ENFORCE,
        )

    def test_deprecated_parity_boolean_maps_to_shadow_or_off(self) -> None:
        self.assertEqual(
            resolve_policy_mode("", legacy_parity_enabled=True),
            PolicyMode.SHADOW,
        )
        self.assertEqual(
            resolve_policy_mode(None, legacy_parity_enabled=False),
            PolicyMode.OFF,
        )

    def test_invalid_policy_mode_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "off, shadow, enforce"):
            resolve_policy_mode("invalid", legacy_parity_enabled=True)

    def test_enforcement_requires_a_base_url(self) -> None:
        with self.assertRaisesRegex(ValueError, "MREG_POLICY_BASE_URL"):
            validate_policy_configuration(PolicyMode.ENFORCE, "")
        validate_policy_configuration(PolicyMode.ENFORCE, "http://policy")
        validate_policy_configuration(PolicyMode.SHADOW, "")
