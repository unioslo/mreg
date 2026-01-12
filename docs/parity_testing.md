# Disabling Parity Checking in Tests

## Problem

Tests that modify permissions or group memberships mid-test cause the legacy permission system and the TreeTop policy engine to be out of sync. Since TreeTop's policy content is immutable, these tests cannot maintain parity between the two systems.

## Solutions

### Option 1: Context Manager (Recommended for individual test sections)

Use the `disable_policy_parity()` context manager to temporarily disable parity checking:

```python
from mreg.api.treetop import disable_policy_parity

class TestPermissions(MregAPITestCase):
    def test_permission_change(self):
        # Normal parity checking is active here
        self.client.get('/api/v1/hosts/')
        
        # Disable parity checking for permission modifications
        with disable_policy_parity():
            # Add user to a group
            user.groups.add(some_group)
            
            # Make API calls - parity checking is skipped
            response = self.client.post('/api/v1/hosts/', data)
            self.assertEqual(response.status_code, 201)
        
        # Parity checking resumes after the context exits
```

### Option 2: Test Class Mixin (Recommended for entire test classes)

Use the `PermissionModifyingTestCase` mixin for test classes that modify permissions throughout:

```python
from mreg.api.test_utils import PermissionModifyingTestCase

class TestGroupPermissions(PermissionModifyingTestCase, MregAPITestCase):
    """All tests in this class have parity checking disabled."""
    
    def test_add_group(self):
        # Parity checking is disabled for all tests in this class
        user.groups.add(admin_group)
        response = self.client.post('/api/v1/hosts/', data)
        self.assertEqual(response.status_code, 201)
    
    def test_remove_group(self):
        # Still disabled here
        user.groups.remove(admin_group)
        response = self.client.post('/api/v1/hosts/', data)
        self.assertEqual(response.status_code, 403)
```

### Option 3: Pytest Fixture (For pytest-style tests)

Use the `no_parity_check` fixture:

```python
def test_permission_modifications(no_parity_check):
    """This test has parity checking disabled."""
    user.groups.add(some_group)
    # Make API calls without parity checking
```

### Option 4: Pytest Marker (Documentation only)

Mark tests that modify permissions for documentation purposes:

```python
@pytest.mark.modifies_permissions
def test_permission_changes():
    """This marker documents that this test modifies permissions."""
    with disable_policy_parity():
        user.groups.add(some_group)
        # Test code
```

## When to Use

Disable parity checking when your test:

- Adds or removes users from groups
- Changes NetGroupRegexPermission entries
- Modifies any permission-related database state
- Tests permission escalation/de-escalation scenarios

## When NOT to Use

Do NOT disable parity checking for:

- Tests that only read data
- Tests that modify non-permission data (hosts, networks, etc.)
- Tests where both legacy and policy systems should agree

## Implementation Details

The `disable_policy_parity()` context manager uses thread-local storage to safely disable parity checking for the current thread only, ensuring test isolation in parallel test execution.
