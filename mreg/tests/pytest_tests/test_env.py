"""Tests for environment configuration.

Each test boots Django in a subprocess via one of the entry points in
BOOT_COMMANDS, with `MREG_DOTENV_PATH` pointed at a test .env file, and
asserts on the LOG_LEVEL setting the subprocess ends up with.

NOTE: these tests use pytest as their test runner - NOT Django's unittest test runner.
"""

import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest
from inline_snapshot import snapshot

REPO_ROOT = Path(__file__).resolve().parents[3]

# Printed inside the booted Django process; the tests assert on this exact output format.
_PRINT_LOG_LEVEL = "from django.conf import settings; print(f'{settings.LOG_LEVEL=}')"

# Both ways of booting Django must load the .env file on their own.
BOOT_COMMANDS = [
    pytest.param([sys.executable, "manage.py", "shell", "-c", _PRINT_LOG_LEVEL], id="manage.py"),
    pytest.param([sys.executable, "-c", f"import mregsite.wsgi; {_PRINT_LOG_LEVEL}"], id="wsgi"),
]


_PROTECTED_ENV_VARS = {"MREG_LOG_LEVEL", "MREG_DOTENV_PATH", "MREG_DOTENV_OVERRIDE"}

@pytest.fixture(name="env_file")
def _env_file(tmp_path: Path) -> Path:
    """Return the path to a fresh .env file for the current test."""
    return tmp_path / ".env"


def boot_and_read_log_level(boot_command: list[str], env_file: Path | None, extra_env: Mapping[str, str] | None = None) -> str:
    """Boot Django in a subprocess and return the printed LOG_LEVEL line.

    MREG_LOG_LEVEL is dropped from the inherited environment so its value can only come
    from the .env file, unless the test sets it via `extra_env`.

    Args:
        boot_command: The argv that boots Django in the subprocess.
        env_file: The .env file the subprocess loads via MREG_DOTENV_PATH.
        extra_env: Extra environment variables to set in the subprocess.

    Returns:
        The last line of the subprocess stdout, e.g. `settings.LOG_LEVEL='DEBUG'`.
    """
    child_env = {k: v for k, v in os.environ.items() if k not in _PROTECTED_ENV_VARS}
    if env_file is not None:
        child_env["MREG_DOTENV_PATH"] = str(env_file)

    child_env.update(extra_env or {})
    result = subprocess.run(boot_command, env=child_env, cwd=REPO_ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    return result.stdout.splitlines()[-1]


@pytest.mark.parametrize("boot_command", BOOT_COMMANDS)
class TestDotenvLogLevel:
    """Tests for overriding MREG_LOG_LEVEL via .env and the real environment.

    Parametrized over different boot commands (manage.py & mregsite/wsgi.py).
    """

    def test_dotenv_value_overrides_default(self, env_file: Path, boot_command: list[str]) -> None:
        """A value in the .env file overrides the default setting."""
        env_file.write_text("MREG_LOG_LEVEL=DEBUG\n")
        assert boot_and_read_log_level(boot_command, env_file) == snapshot("settings.LOG_LEVEL='DEBUG'")

    def test_env_overrides_dotenv(self, env_file: Path, boot_command: list[str]) -> None:
        """The real environment variable overrides the .env file setting."""
        env_file.write_text("MREG_LOG_LEVEL=DEBUG\n")
        # python-dotenv default (override=False): the real env wins over the .env contents.
        assert boot_and_read_log_level(boot_command, env_file, {"MREG_LOG_LEVEL": "ERROR"}) == snapshot("settings.LOG_LEVEL='ERROR'")

    def test_dotenv_value_with_override(self, env_file: Path, boot_command: list[str]) -> None:
        """A value in the .env file overrides the environment when override is enabled."""
        env_file.write_text("MREG_LOG_LEVEL=DEBUG\n")
        # The env file wins over the real environment when MREG_DOTENV_OVERRIDE is True.
        extra_env = {"MREG_LOG_LEVEL": "ERROR", "MREG_DOTENV_OVERRIDE": "True"}
        assert boot_and_read_log_level(boot_command, env_file, extra_env) == snapshot("settings.LOG_LEVEL='DEBUG'")

    def test_dotenv_is_reloaded_in_each_subprocess(self, env_file: Path, boot_command: list[str]) -> None:
        """The .env file is reloaded in each subprocess."""
        env_file.write_text("MREG_LOG_LEVEL=DEBUG\n")
        assert boot_and_read_log_level(boot_command, env_file) == snapshot("settings.LOG_LEVEL='DEBUG'")

        # Change the .env file to see if it is reloaded in the next subprocess.
        env_file.write_text("MREG_LOG_LEVEL=ERROR\n")
        assert boot_and_read_log_level(boot_command, env_file) == snapshot("settings.LOG_LEVEL='ERROR'")

    def test_env_file_does_not_exist_no_path_specified(self, env_file: Path, boot_command: list[str]) -> None:
        """Behavior when the .env file does not exist and no path is specified."""
        env_file.unlink(missing_ok=True)
        level = boot_and_read_log_level(boot_command, None)
        assert level == snapshot("settings.LOG_LEVEL='CRITICAL'")
    
    def test_env_file_does_not_exist_explicit_path(self, env_file: Path, boot_command: list[str]) -> None:
        """Behavior when the .env file does not exist and is explicitly specified as env var."""
        env_file.unlink(missing_ok=True)
        level = boot_and_read_log_level(boot_command, None, extra_env={"MREG_DOTENV_PATH": str(env_file)})
        assert level == snapshot("settings.LOG_LEVEL='CRITICAL'")
