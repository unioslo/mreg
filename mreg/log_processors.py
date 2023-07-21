"""Logging processors for mreg."""

from typing import Any

from structlog import get_logger
from structlog.typing import EventDict

logger = get_logger("hubuum.manual")


def _replace_token(token: str) -> str:
    """Replace a token with a shortened and safe version of it."""
    if len(token) > 10:
        return token[:3] + "..." + token[-3:]

    return "..."


def filter_sensitive_data(_: Any, __: Any, event_dict: EventDict) -> EventDict:
    """Filter sensitive data from a structlogs event_dict."""
    if "model" in event_dict and (
        event_dict["model"] == "ExpiringToken" or event_dict["model"] == "Session"
    ):
        clean_token = _replace_token(event_dict["_str"])
        event_dict["_str"] = clean_token
        event_dict["id"] = clean_token

    return event_dict
