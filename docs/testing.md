# Testing Guide

## Comparing API query counts

The `API query profiles` workflow runs the existing API tests on the PR head
and the PR's target commit. For a PR targeting a branch other than `master`,
it also samples `unioslo/mreg`'s current `master`. The report records the exact
commits used. Each revision uses its own tests, dependencies, and test database.

An external wrapper intercepts synchronous Django `Client` and DRF `APIClient`
requests. No endpoint-specific profiling code, decorator, application setting,
or changes to existing functional tests are needed. Every request made inside
a selected test method is sampled; fixture setup and teardown are excluded.
Requests execute once, including POST/PATCH/DELETE. SQL execute calls are counted
across the configured database connections in the request's thread.

Run the wrapper from the repository root:

```bash
uv run python ci/profile_tests.py --output /tmp/head-queries.json -- mreg.api hostpolicy.api

# Restrict sampling using normal Django test labels.
uv run python ci/profile_tests.py --output /tmp/hosts.json -- mreg.api.v1.tests.test_host_query_profile

# The output path can also come from the environment.
MREG_QUERY_PROFILE_OUT=/tmp/head-queries.json uv run python ci/profile_tests.py -- mreg.api
```

The wrapper forces serial test execution to preserve request ordering. It
captures the HTTP method, resolved route, query parameters, request occurrence,
test ID, response status/result count, SQL count and attribution, and elapsed
time. Dynamic path IDs do not create different endpoint identities. Request
bodies, response bodies, and SQL parameters are not stored.

Use the same wrapper to sample an older checkout; it does not need to contain
the profiling tool:

```bash
uv run --project /path/to/parent python /path/to/head/ci/profile_tests.py \
    --checkout /path/to/parent --output /tmp/parent-queries.json -- mreg.api hostpolicy.api

python ci/compare_query_profiles.py \
    --head /tmp/head-queries.json \
    --baseline parent=/tmp/parent-queries.json \
    --baseline master=/tmp/master-queries.json \
    --summary /tmp/query-summary.md --json /tmp/query-comparison.json
```

Omit the `master` argument for a PR targeting `master`. Keep the test selection
the same for all revisions. Baseline sampling must use baseline dependencies;
do not copy new tests or application code into a baseline checkout.

### What the report means

- Matching request identities are compared individually. An increased query
  count fails CI; improvements elsewhere cannot cancel out a regression.
- A request seen only on one revision is **missing** on the other. Missing
  measurements are never counted as zero or reported as improvements. New
  endpoints gain measurements as soon as existing functional tests exercise them.
- Changed local test/fixture modules or different response statuses/result
  counts are marked **incomparable**. The source check includes the test class's
  module and local inherited test-class modules. This is deliberately conservative:
  adding a test to a module also marks that module's other samples incomparable.
  It does not prove equivalence of external fixtures or services; review fixture
  changes when interpreting a report.
- Installation, database, and test failures are **errors**, not missing baselines.
  A head run with no samples also fails the comparison.
- The endpoint table sums only paired, comparable requests. Detailed JSON retains
  all observations, source fingerprints, missing cases, and SQL attribution.
- Timings are informational observations with profiling overhead, not a latency
  threshold or a replacement for repeated controlled benchmarks.

Only exercised endpoints are measured. `RequestFactory`, async clients, live
HTTP clients, worker-thread queries, and streaming response bodies are outside
the current capture boundary; streaming responses are marked incomparable.
There are no hard-coded endpoint query budgets. The populated host/community
tests additionally check that increasing page size or community membership does
not increase query counts.

This design follows [rust-pr-bench](https://github.com/terjekv/rust-pr-bench):
isolated revision runs, comparisons over matching measurement identities, and
explicit missing results. The request profiler is specific to Django and does
not depend on the Rust action.

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
