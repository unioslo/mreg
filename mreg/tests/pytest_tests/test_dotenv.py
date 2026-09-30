"""Tests for dotenv functionality.

NOTE: these tests use pytest as their test runner - NOT Django's unittest test runner.
"""

import os
import subprocess
import sys
from pathlib import Path
import pytest


from inline_snapshot import snapshot

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(name="env_file", scope="function")
def _env_file(tmp_path: Path) -> Path:
    env_file = tmp_path / ".env"
    return env_file


class TestDotenvLogLevel:
    """dotenv test case that tests overriding MREG_LOG_LEVEL via .env and real environment."""

    def _boot_and_read_log_level(self, env_file: Path, extra_env: dict[str, str]) -> str:
        """Boot Django in a subprocess and return the loaded LOG_LEVEL setting."""
        # Drop MREG_LOG_LEVEL from the inherited env so the value can only come
        # from the .env file (unless a test explicitly sets it via extra_env).
        child_env = {k: v for k, v in os.environ.items() if k != "MREG_LOG_LEVEL"}
        child_env["MREG_DOTENV_PATH"] = str(env_file)
        child_env.update(extra_env)
        result = subprocess.run(
            [
                sys.executable,
                "manage.py",
                "shell",
                "-c",
                # Print log level as a debug string we can compare against
                "from django.conf import settings; print(f'{settings.LOG_LEVEL=}')",
            ],
            env=child_env,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr

        # Django prints some debug info to stdout before the actual log level line
        # Only return the last line, which should be the actual log level output.
        return result.stdout.splitlines()[-1]

    def test_dotenv_value_overrides_default(self, env_file: Path):
        """Test that a value in the .env file overrides the default setting."""
        env_file.write_text("MREG_LOG_LEVEL=DEBUG\n")
        loglevel = self._boot_and_read_log_level(env_file, {})
        assert loglevel == snapshot("settings.LOG_LEVEL='DEBUG'")

    def test_env_overrides_dotenv(self, env_file: Path):
        """Test that the real environment variable overrides the .env file setting."""
        env_file.write_text("MREG_LOG_LEVEL=DEBUG\n")
        # python-dotenv default (override=False): real env wins over .env contents)
        loglevel = self._boot_and_read_log_level(env_file, {"MREG_LOG_LEVEL": "ERROR"})
        assert loglevel == snapshot("settings.LOG_LEVEL='ERROR'")

    def test_dotenv_value_with_override(self, env_file: Path):
        """Test that a value in the .env file overrides the environment when override is enabled."""
        env_file.write_text("MREG_LOG_LEVEL=DEBUG\n")

        # Env file wins over the real environment when MREG_DOTENV_OVERRIDE is True.
        loglevel = self._boot_and_read_log_level(
            env_file,
            {"MREG_LOG_LEVEL": "ERROR", "MREG_DOTENV_OVERRIDE": "True"},
        )
        
        assert loglevel == snapshot("settings.LOG_LEVEL='DEBUG'")
