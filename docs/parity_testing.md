# Disabling Parity Checking in Tests

Related documentation:

- Policy actions and resource/action contracts: [`policies.md`](./policies.md)

## Problem

Tests that modify permissions or group memberships mid-test cause the legacy permission system and the TreeTop policy engine to be out of sync. Since TreeTop's policy content is immutable (in this context), these tests cannot maintain parity between the two systems.

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

## Scope Rules (Enforcement Guidance)

Keep parity disable scope as narrow as possible:

- Prefer wrapping only the exact mutation and requests that depend on that mutation.
- Do not wrap an entire test module unless the whole module genuinely mutates permission state.
- Do not wrap whole suites by default; this hides real policy regressions.
- Re-enable parity immediately after the mutation scenario has been asserted.

## Implementation Details

The `disable_policy_parity()` context manager uses `ContextVar` state. Nested
contexts and concurrently handled requests are isolated from one another.

Parity HTTP calls run on a bounded process-local background worker. Client,
serialization, queue, logging, and TreeTop failures are fail-open: they are
recorded, but never replace the legacy permission decision.

## Parity Runbook

Use this sequence when validating parity changes:

1. Run full tests with coverage and parity logging enabled.

```bash
source .env; .venv/bin/tox -e coverage
```

2. Query the mismatch metric in Prometheus.

```promql
mreg_policy_parity_results_total{result="mismatch"}
```

3. List mismatch events in the configured application log.

```bash
rg -n '"event": "policy_parity_mismatch"' logs/app.log
```

4. Optional: inspect actions seen in mismatch events.

```bash
jq -r 'select(.event == "policy_parity_mismatch") | .context.action // empty' logs/app.log \
  | sort | uniq -c | sort -nr
```

Set `MREG_POLICY_PARITY_LOG_DETAILS=True` temporarily in a suitably protected
environment only when principal, group, resource ID, or attribute details are
required for triage.

## Mismatch Triage Guide

Use `legacy_decision`, `policy_decision`, and `context.action`. Detailed resource
attributes are available only when `MREG_POLICY_PARITY_LOG_DETAILS` is enabled.

- `legacy_decision=true`, `policy_decision=false`:
  - Missing/too-narrow Cedar allow rule.
  - Action name mismatch (for example wrong CRUD token).
  - Missing required attributes for Cedar conditions.
- `legacy_decision=false`, `policy_decision=true`:
  - Cedar rule is broader than legacy behavior.
  - Resource kind fallback produced a more permissive policy path than intended.
- `error` present:
  - Policy client/server failure. Resolve connectivity/config first before triaging semantics.
- Unexpected `context.resource_kind`:
  - Fix serializer `Meta.model` or declare `policy_resource_kind` explicitly on
    the non-model view. View-name inference is intentionally unsupported.

When fixing mismatches, update code and Cedar together, then rerun the tests until mismatch count is zero.
