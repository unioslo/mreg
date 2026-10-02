# Testing Guide

## Selected API benchmarks

CI benchmarks a small, named set of GET requests from
[`ci/query-benchmarks.json`](../ci/query-benchmarks.json), using the single
`ci/query_bench` tool. It does not profile the whole test suite. Each case names
an existing Django test fixture class and a request; application endpoints and
functional tests need no benchmark instrumentation.

The PR head supplies the same runner and manifest for head, parent, and (for a
stacked PR) master. Each checkout supplies its own application, dependencies,
and fixture code. The benchmark runner invokes that fixture's normal Django
setup/teardown, without executing its test methods or their assertions.
The selected request gets three discarded warm-ups, one separate SQL-count
run, and fifteen timed runs. Timing capture does not enable SQL logging or
query-count wrappers. Fixture setup, parameter lookups, response validation,
and teardown are outside the measured interval.

```bash
# Run the selected suite.
uv run python ci/query_bench sample \
    --suite ci/query-benchmarks.json --output /tmp/head.json

# Select a subset by label; --case can be repeated.
uv run python ci/query_bench sample \
    --suite ci/query-benchmarks.json --case 'hosts/*' --output /tmp/hosts.json

# Run the shared suite against a baseline with its own dependencies.
uv run --project /path/to/parent python /path/to/head/ci/query_bench sample \
    --suite /path/to/head/ci/query-benchmarks.json \
    --checkout /path/to/parent --output /tmp/parent.json

python ci/query_bench compare \
    --head /tmp/head.json --baseline parent=/tmp/parent.json \
    --baseline master=/tmp/master.json \
    --summary /tmp/summary.md --json /tmp/comparison.json
```

Omit the `master` baseline for PRs targeting master. Timings are observations
from an in-process Django test client, not production latency promises. CI
revisions currently run on separate runners, so timing deltas are informational;
only comparable query-count increases fail the check. The report shows median,
p95 (nearest rank), timed run count, and discarded warm-up count. Every duration,
min/max, sample standard deviation, and SQL attribution is retained in JSON.

### Opting a request in

Add a manifest entry with a stable, descriptive label of your choice:

```json
{
  "label": "hosts/detail/full",
  "fixture": "mreg.api.v1.tests.test_host_query_profile.HostQueryProfileTestCase",
  "path": "/api/v1/hosts/{first_host_name}"
}
```

Path placeholders use attributes created by the fixture. Dynamic identifiers
can also come from a preliminary GET, outside the measured interval:

```json
{
  "label": "communities/hosts/50",
  "fixture": "mreg.api.v1.tests.test_host_query_profile.HostQueryProfileTestCase",
  "path": "/api/v1/networks/10.0.0.0/24/communities/{community_id}/hosts/",
  "parameters": {
    "community_id": {
      "path": "/api/v1/networks/10.0.0.0/24/communities/",
      "json": ["results", 0, "id"]
    }
  }
}
```

The manifest also defines shared Django settings, warm-ups, and run count.
Existing fixtures provide authentication and representative data. If no suitable
fixture exists, it must be added explicitly; the runner does not invent one.
Only synchronous, non-streaming GET requests are supported. Repeated calls
share one fixture and warm database/application caches; choose read-only,
repeatable endpoints. Normal tests still check endpoint correctness and query
scaling independently.

### Baseline compatibility and reporting

A baseline does not need this tool or the manifest. Missing fixture modules,
fixture classes, or URL routes are reported per label as **missing from that
baseline**, without numbers or deltas. New fixtures are not copied into old
checkouts. Missing dependencies, broken fixture setup, lookup failures, or a
non-200 response from an existing route are **errors**, not missing benchmarks.

Definitions, shared settings, and local fixture/inherited-class source modules
are fingerprinted. A changed fixture, request/response workload, or measurement
setting is **incomparable**: raw observations remain visible, but no delta is
calculated and no query regression is inferred. The source check is conservative
and includes the whole fixture module; it does not prove external service or
fixture equivalence. Every selected label remains visible even when neither
revision can run it. Missing measurements are never zero, and improvements
cannot offset another benchmark's regression.

The same compact report appears in the job summary and one updated bot comment
on the PR, with links to the run and artifacts. A separate `workflow_run`
reporter supports fork PRs: only default-branch code receives comment permission,
and artifact JSON is read without extraction or execution. GitHub API metadata
identifies the PR; outdated commits/runs cannot overwrite newer comments.
Automatic comments begin once the reporter reaches the default branch, as
required by [GitHub's workflow_run event](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run).

This follows [rust-pr-bench](https://github.com/terjekv/rust-pr-bench)'s selected
cases, shared measurement identities, isolated revisions, and explicit missing
results. It has no Rust runtime dependency.

## Running Tests

### Basic Test Execution

```bash
# Run all tests
uv run manage.py test

# Run specific test module
uv run manage.py test mreg.api.v1.tests

# Run specific test class
uv run manage.py test mreg.api.v1.tests.tests.MregAPITestCase

# Run specific test method
uv run manage.py test mreg.api.v1.tests.tests.MregAPITestCase.test_specific_method
```

### Parallel Test Execution

For significantly faster test execution, use the `--parallel` flag:

```bash
# Auto-detect number of CPUs
uv run manage.py test --parallel

# Specify number of parallel processes
uv run manage.py test --parallel=4

# Combine with other options
uv run manage.py test --parallel --failfast
```

**Performance Impact**: Parallel testing typically reduces test execution time from 10-12 minutes to 2-4 minutes.

### How Parallel Testing Works

1. **Database Isolation**: Django creates separate test databases for each worker process (e.g., `test_mreg_1`, `test_mreg_2`, etc.)
2. **Transaction Rollback**: Each test still runs in a transaction that's rolled back after completion
3. **Process Safety**: Tests are distributed across worker processes, ensuring no shared state between parallel tests

### Advanced Options

```bash
# Preserve databases between runs (faster subsequent runs)
uv run manage.py test --parallel --keepdb

# Control verbosity
uv run manage.py test --parallel --verbosity=2

# Run with coverage
coverage run manage.py test --parallel
coverage report -m
```

## Test Isolation and Best Practices

### What Makes Tests Safe for Parallel Execution

All tests in this project inherit from `APITestCase` (or `TestCase`), which provides:

- **Automatic transaction rollback**: Each test runs in a transaction that's rolled back after the test completes
- **Database isolation**: When running in parallel, each process has its own test database
- **Clean state**: Each test starts with a fresh database state

### Potential Issues and Solutions

#### 1. Tests That Use `TransactionTestCase`

`TransactionTestCase` truncates tables instead of using transaction rollback. These tests are **not safe for parallel execution** and will cause failures.

**Solution**: Use `TestCase` or `APITestCase` instead. If you absolutely need to test transactions, mark the test class:

```python
class MyTransactionTest(TransactionTestCase):
    # This will force serial execution of this test class
    serialized_rollback = True
```

#### 2. Tests That Depend on Execution Order

Tests should never depend on the execution order or state from other tests.

**Solution**: Ensure each test sets up its own required state in `setUp()` or within the test method.

#### 3. Shared File System Resources

Tests that write to specific file paths may conflict if run in parallel.

**Solution**: Use temporary directories or include the test/process ID in filenames:

```python
from django.test import TestCase
import tempfile

class MyFileTest(TestCase):
    def test_something(self):
        with tempfile.NamedTemporaryFile() as f:
            # Use f.name
            pass
```

#### 4. External Service Dependencies

Tests that connect to external services (like LDAP) may have connection limits.

**Solution**: Mock external services in tests:

```python
from unittest import mock

class MyLDAPTest(TestCase):
    @mock.patch('django_auth_ldap.backend.LDAPBackend.authenticate')
    def test_ldap_auth(self, mock_auth):
        mock_auth.return_value = self.user
        # Test code
```

## Coverage with Parallel Tests

Coverage.py requires special configuration to work with Django's parallel testing. This is already configured in `pyproject.toml`:

```toml
[tool.coverage.run]
concurrency = ["multiprocessing"]
parallel = true
sigterm = true
```

**Running tests with coverage:**

```bash
# Run tests with coverage (multiprocessing support)
coverage run --concurrency=multiprocessing manage.py test --parallel

# Combine coverage data from all parallel processes
coverage combine

# Generate report
coverage report -m

# Generate HTML report
coverage html
```

**Important**: Always run `coverage combine` after parallel test execution to merge the coverage data files from all worker processes. Without this, you'll only see coverage from one process.

The `tox.ini` configuration handles this automatically:

```ini
commands =
    coverage run --concurrency=multiprocessing manage.py test --parallel
    coverage combine
    coverage report -m
```

## Debugging Parallel Test Failures

If a test fails only when run in parallel:

1. **Run the test serially first**:

   ```bash
   uv run manage.py test path.to.failing.test
   ```

2. **Check for shared state**: Look for class-level variables or module-level state that might be shared

3. **Run with fewer processes**:

   ```bash
   uv run manage.py test --parallel=2 path.to.tests
   ```

4. **Check database state assumptions**: Ensure the test doesn't depend on data from other tests

## CI/CD Integration

The parallel flag is already enabled in `tox.ini` for all test environments:

```ini
[testenv]
commands =
    coverage run manage.py test --parallel
```

This ensures faster CI/CD pipelines while maintaining test reliability.
