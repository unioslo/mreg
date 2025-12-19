# Testing Guide

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

Coverage works with parallel testing using the `--parallel` flag:

```bash
# Run tests with coverage
coverage run manage.py test --parallel

# Generate report
coverage report -m

# Generate HTML report
coverage html
```

Coverage automatically combines data from all parallel processes.

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
