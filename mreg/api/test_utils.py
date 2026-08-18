"""Django test utilities for permission scenarios."""

from mreg.api.treetop import disable_policy_parity


class PermissionModifyingTestCase:
    """Mixin for test classes that modify permissions during tests.

    This mixin automatically disables parity checking for all tests in the class
    since modifying permissions mid-test would cause the legacy and policy
    systems to be out of sync.

    Usage:
        class TestSomePermissions(PermissionModifyingTestCase, TestCase):
            def test_something(self):
                # This test can safely modify permissions
                user.groups.add(some_group)
                # Parity checking will be skipped
    """

    def setUp(self) -> None:
        """Set up test with parity checking disabled."""
        self._parity_context = disable_policy_parity()
        self._parity_context.__enter__()
        super().setUp()  # type: ignore[misc]

    def tearDown(self) -> None:
        """Clean up parity checking context."""
        self._parity_context.__exit__(None, None, None)
        super().tearDown()  # type: ignore[misc]
