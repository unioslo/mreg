"""Test utilities for parity checking and permission management."""

import pytest
from mreg.api.treetop import disable_policy_parity


# Pytest marker for tests that modify permissions
def pytest_configure(config):
    """Register custom pytest markers."""
    config.addinivalue_line(
        "markers",
        "modifies_permissions: mark test as modifying permissions (will skip parity checking)"
    )


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
        if hasattr(super(), "setUp"):
            super().setUp()  # type: ignore[misc]
    
    def tearDown(self) -> None:
        """Clean up parity checking context."""
        self._parity_context.__exit__(None, None, None)
        if hasattr(super(), "tearDown"):
            super().tearDown()  # type: ignore[misc]


@pytest.fixture
def no_parity_check():
    """Pytest fixture to disable parity checking for a test.
    
    Usage:
        def test_modify_permissions(no_parity_check):
            # Parity checking is disabled in this test
            user.groups.add(some_group)
            # Make API calls
    """
    with disable_policy_parity():
        yield
