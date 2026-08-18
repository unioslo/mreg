"""Configuration contracts for TreeTop shadow and enforcement modes."""

from __future__ import annotations

from enum import StrEnum


class PolicyMode(StrEnum):
    """How MREG uses TreeTop decisions."""

    OFF = "off"
    SHADOW = "shadow"
    ENFORCE = "enforce"


def resolve_policy_mode(raw: str | None, *, legacy_parity_enabled: bool) -> PolicyMode:
    """Resolve the explicit mode, falling back to the deprecated boolean."""
    candidate = (raw or "").strip().lower()
    if not candidate:
        candidate = PolicyMode.SHADOW if legacy_parity_enabled else PolicyMode.OFF
    try:
        return PolicyMode(candidate)
    except ValueError as exc:
        raise ValueError("MREG_POLICY_MODE must be one of: off, shadow, enforce") from exc


def validate_policy_configuration(mode: PolicyMode, base_url: str) -> None:
    """Reject configurations that cannot provide authoritative decisions."""
    if mode == PolicyMode.ENFORCE and not base_url.strip():
        raise ValueError("MREG_POLICY_BASE_URL is required when MREG_POLICY_MODE=enforce")
