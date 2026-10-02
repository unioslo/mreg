import os
from typing import TypeVar
from pathlib import Path
from dotenv import load_dotenv

DefaultT = TypeVar("DefaultT", str, int, float, bool)

_TRUE = {"1", "true", "t", "yes", "y", "on"}
_FALSE = {"0", "false", "f", "no", "n", "off"}


def envvar(var: str, default: DefaultT) -> DefaultT:
    """Get the value of an environment variable as a specific type.

    The type of the default value specifies the return type.
    Boolean defaults are parsed from common true/false strings.
    """
    raw = os.environ.get(var)
    if raw is None:
        return default

    if isinstance(default, bool):
        s = raw.strip().lower()
        if s in _TRUE:
            return True
        if s in _FALSE:
            return False
        return default

    try:
        return type(default)(raw)
    except ValueError, TypeError:
        return default


def parse_protected_policy_attrs(raw: str) -> list[dict[str, str]]:
    """Parse a comma-separated list of protected policy attributes key-value pairs.

    Each attribute should be in the form 'key=value', where value is the
    description of the policy attribute. If the value is omitted, a default
    description is be used.
    """
    out: list[dict[str, str]] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue

        key, value = (part.split("=", 1) + [""])[:2]
        key = key.strip()
        value = value.strip()

        if not key:
            # Either skip silently or raise; skipping is safer for prod.
            continue

        desc = value if value else f"Protected attribute {key}."
        out.append({"name": key, "description": desc})
    return out


_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_DOTENV_PATH = _PROJECT_ROOT / ".env"


def configure_environment() -> None:
    load_dotenv(
        os.getenv("MREG_DOTENV_PATH", _DEFAULT_DOTENV_PATH),
        override=envvar("MREG_DOTENV_OVERRIDE", False),
    )
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mregsite.settings")
