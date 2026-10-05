import os
from pathlib import Path
from typing import TYPE_CHECKING, Literal
from typing import TypeVar

from dotenv import load_dotenv

if TYPE_CHECKING:  # pragma: no cover
    from django_auth_ldap.config import LDAPGroupType, LDAPSearch

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


def envvar_list(var: str, default: list[str]) -> list[str]:
    """Get a comma-separated list of strings from an environment variable.

    Args:
        var: The name of the environment variable.
        default: The value to return if the variable is unset.

    Returns:
        The variable's value split on commas, with each item stripped and
        empty items dropped, or a copy of the default if the variable is unset.
    """
    raw = os.environ.get(var)
    if raw is None:
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def envvar_pairs(var: str, default: dict[str, str]) -> dict[str, str]:
    """Get a comma-separated set of key=value pairs from an environment variable.

    Args:
        var: The name of the environment variable.
        default: The value to return if the variable is unset.

    Returns:
        The variable's value parsed as key=value pairs, or a copy of the
        default if the variable is unset.
    """
    raw = os.environ.get(var)
    if raw is None:
        return dict(default)
    return parse_kv_pairs(raw)


def parse_kv_pairs(raw: str) -> dict[str, str]:
    """Parse comma-separated key=value pairs into a dict.

    Malformed entries (missing key or value) are skipped, matching the
    lenient behavior of parse_protected_policy_attrs.

    Args:
        raw: The raw string to parse, e.g. "first_name=givenName,last_name=sn".

    Returns:
        A dict mapping keys to values.
    """
    out: dict[str, str] = {}
    for part in raw.split(","):
        key, _, value = part.partition("=")
        key = key.strip()
        value = value.strip()
        if key and value:
            out[key] = value
    return out


def parse_txt_auto_records(raw: str) -> dict[str, tuple[str, ...]]:
    """Parse automatic TXT records from a string.

    Zones are separated by ';' and each zone is on the form
    'zone=record1,record2', e.g. "uio.no=v=spf1 -all;example.org=a,b".

    Args:
        raw: The raw string to parse.

    Returns:
        A dict mapping zone names to tuples of TXT record strings.
    """
    out: dict[str, tuple[str, ...]] = {}
    for zone_entry in raw.split(";"):
        zone, _, records = zone_entry.partition("=")
        zone = zone.strip()
        if not zone:
            continue
        out[zone] = tuple(record.strip() for record in records.split(",") if record.strip())
    return out


def parse_header_pair(raw: str) -> tuple[str, str]:
    """Parse a (header, value) pair from a comma-separated string.

    Args:
        raw: The raw string to parse, e.g. "HTTP_X_FORWARDED_PROTO,https".

    Returns:
        A (header, value) tuple.

    Raises:
        ValueError: If the string is not exactly two non-empty, comma-separated parts.
    """
    header, sep, value = raw.partition(",")
    header = header.strip()
    value = value.strip()
    if not sep or not header or not value or "," in value:
        raise ValueError(f"Expected 'header,value' with exactly two parts, got: {raw!r}")
    return header, value


def parse_ldap_options(raw: str) -> dict[int, int]:
    """Parse LDAP library options from comma-separated OPTION=VALUE pairs.

    Each option name must be the name of a constant from the :mod:`ldap`
    module, e.g. 'OPT_X_TLS_REQUIRE_CERT'. The value is either the name of
    a constant from the same module (e.g. 'OPT_X_TLS_NEVER') or a plain integer.

    Args:
        raw: The raw string to parse,
            e.g. "OPT_X_TLS_REQUIRE_CERT=OPT_X_TLS_NEVER".

    Returns:
        A dict mapping LDAP option constants to integer values.

    Raises:
        ValueError: If an option or value name is not an integer constant
            in the ldap module.
    """
    import ldap

    out: dict[int, int] = {}
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        name, _, value = part.partition("=")
        name = name.strip()
        option = getattr(ldap, name, None)
        if not isinstance(option, int):
            raise ValueError(f"Unknown LDAP option: {name!r}")
        value = value.strip()
        if value.lstrip("-").isdigit():
            resolved: int = int(value)
        else:
            resolved = getattr(ldap, value, None)
            if not isinstance(resolved, int):
                raise ValueError(f"Unknown LDAP option value: {value!r}")
        out[option] = resolved
    return out


def make_ldap_group_type(name: str) -> "LDAPGroupType":
    """Create a django-auth-ldap group type instance from a class name.

    The name must be a class from django_auth_ldap.config that subclasses
    LDAPGroupType and that can be constructed without required arguments,
    e.g. 'NestedActiveDirectoryGroupType'.

    Args:
        name: The name of the group type class.

    Returns:
        A new group type instance.

    Raises:
        ValueError: If the name is not a supported group type class, or the
            class cannot be constructed without arguments.
    """
    import django_auth_ldap.config as ldap_config

    cls = getattr(ldap_config, name, None)
    if not isinstance(cls, type) or not issubclass(cls, ldap_config.LDAPGroupType):
        raise ValueError(f"Unsupported AUTH_LDAP_GROUP_TYPE: {name!r}")
    try:
        return cls()
    except TypeError as exc:
        raise ValueError(f"Group type {name!r} cannot be constructed without arguments: {exc}") from exc


def make_ldap_search(base_dn: str, scope: str, filterstr: str = "(objectClass=*)") -> "LDAPSearch":
    """Create a django-auth-ldap LDAPSearch object.

    Args:
        base_dn: The base DN to search from,
            e.g. "OU=filegroups,DC=example,DC=com".
        scope: The LDAP search scope: "SUBTREE", "ONELEVEL" or "BASE".
        filterstr: The LDAP search filter, e.g. "(objectClass=group)".

    Returns:
        A configured LDAPSearch object.

    Raises:
        ValueError: If the scope is not one of "SUBTREE", "ONELEVEL" or "BASE".
    """
    import ldap
    from django_auth_ldap.config import LDAPSearch

    scopes: dict[str, int] = {
        "SUBTREE": ldap.SCOPE_SUBTREE,
        "ONELEVEL": ldap.SCOPE_ONELEVEL,
        "BASE": ldap.SCOPE_BASE,
    }
    resolved = scopes.get(scope.strip().upper())
    if resolved is None:
        raise ValueError(f"Unsupported LDAP search scope: {scope!r}")
    return LDAPSearch(base_dn, resolved, filterstr)


_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_DOTENV_PATH = _PROJECT_ROOT / ".env"


def configure_environment() -> None:
    load_dotenv(
        os.getenv("MREG_DOTENV_PATH", _DEFAULT_DOTENV_PATH),
        override=envvar("MREG_DOTENV_OVERRIDE", False),
    )
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mregsite.settings")
