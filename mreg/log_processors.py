"""Logging processors for mreg."""

from collections import defaultdict
from typing import Any
import re

from rich.console import Console
from rich.text import Text
from structlog.typing import EventDict


def _replace_token(token: str) -> str:
    """Replace a token with a shortened and safe version of it."""
    if len(token) > 10:
        return token[:3] + "..." + token[-3:]

    return "..."


def filter_sensitive_data(_: Any, __: Any, event_dict: EventDict) -> EventDict:
    """Filter sensitive data from a structlogs event_dict.

    :param _: Unused parameter
    :param __: Unused parameter
    :param event_dict: Dictionary containing event data.

    :returns: Event dictionary with sensitive data filtered.
    """
    LOGIN_PATH = "/api/token-auth/"

    if "model" in event_dict and event_dict["model"] in ["ExpiringToken", "Session"]:
        clean_token = _replace_token(event_dict["_str"])
        event_dict["_str"] = clean_token
        event_dict["id"] = clean_token

    is_login_event = (
        "path" in event_dict
        and event_dict["path"] == LOGIN_PATH
        and "method" in event_dict
        and event_dict["method"] == "POST"
    )

    if is_login_event:
        content: str = event_dict.get("content", "")
        event: str = event_dict.get("event", "")

        if event == "request" and "password" in content:
            if isinstance(event_dict["content"],dict):
                event_dict["content"]["password"] = '...'
            elif isinstance(event_dict["content"],str):
                event_dict["content"] = re.sub(r'"password"\s*:\s*".*?"', '"password":"..."', event_dict["content"])
        elif event == "response" and "token" in content:
            token = content.split('"token":"')[1].split('"')[0]
            event_dict["content"] = content.replace(token, _replace_token(token))

    return event_dict


def collapse_request_id_processor(_: Any, __: Any, event_dict: EventDict) -> EventDict:
    """Collapse request_id into a shorter form."""
    if "request_id" in event_dict:
        event_dict["request_id"] = _replace_token(event_dict["request_id"])
    return event_dict


def reorder_keys_processor(_: Any, __: Any, event_dict: EventDict) -> EventDict:
    """Reorder keys in a structlogs event_dict, ensuring that request_id always comes first."""
    event_dict = {
        k: event_dict[k]
        for k in sorted(event_dict.keys(), key=lambda k: k != "request_id")
    }
    return event_dict


class RequestColorTracker:
    """Add an easy to track colored bubble based on an events request_id.

    :ivar COLORS: A list of color names to use for the bubbles.
    :ivar request_to_color: A dictionary mapping request_ids to colors.
    """

    COLORS = ["red", "white", "green", "yellow", "blue", "magenta", "cyan"]

    def __init__(self):
        """Initialize a new RequestColorizer.

        Sets the initial mapping of request_ids to colors to be an empty defaultdict.
        """
        self.console = Console()
        self.request_to_color = defaultdict(self._color_generator().__next__)

    def _colorize(self, color: str, s: str) -> str:
        """Colorize a string using Rich.

        :param color: The name of the color to use.
        :param s: The string to colorize.
        :return: The colorized string.
        """
        text = Text(s, style=f"bold {color}")

        with self.console.capture() as capture:
            self.console.print(text)

        output = capture.get()

        return output.rstrip()  # remove trailing newline

    def _color_generator(self):
        """Create a generator that cycles through the colors.

        :yield: A color from the COLORS list.
        """
        i = 0
        while True:
            yield self.COLORS[i % len(self.COLORS)]
            i += 1

    def __call__(self, _: Any, __: Any, event_dict: EventDict) -> EventDict:
        """Add a colored bubble to the event message.

        :param _: The logger instance. This argument is ignored.
        :param __: The log level. This argument is ignored.
        :param event_dict: The event dictionary of the log entry.
        :return: The modified event dictionary.
        """
        request_id = event_dict.get("request_id")

        color = "black"
        if request_id:
            color = self.request_to_color[request_id]

        colored_bubble = self._colorize(color, " • ")
        event_dict["event"] = colored_bubble + event_dict.get("event", "")

        return event_dict
