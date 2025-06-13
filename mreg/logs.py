"""Utility functions for logging."""

from django.conf import settings
from django.http import HttpRequest


def get_request_header(request: HttpRequest, header_key: str, meta_key: str) -> str:
    """Get the value of a header from the request, either via headers or META."""
    if hasattr(request, "headers"):  # pragma: no cover
        return request.headers.get(header_key)
    return request.META.get(meta_key)


def get_request_body(request: HttpRequest) -> str:
    """Get the request body as a string, or '<Binary Data>' if it's binary.

    We currently do not support multipart/form-data requests.
    """
    if request.POST:
        return request.POST.dict()

    try:
        body = request.body.decode("utf-8")
    except UnicodeDecodeError:
        return "<Binary Data>"

    # Try to remove the content-type line and leading line breaks
    body = body.split("\n", 1)[-1]  # Removes the first line
    body = body.lstrip()  # Removes leading line breaks

    # Limit the size of the body logged
    return body[: settings.LOGGING_MAX_BODY_LENGTH]


def get_request_username(request: HttpRequest, default: str = "AnonymousUser") -> str:
    """Get the username of the user making the request, or a default value ('AnonymousUser')."""
    return getattr(request.user, "username", default) if hasattr(request, "user") else default


def get_request_user_agent(request: HttpRequest, default: str = "Unknown") -> str:
    try:
        return get_request_header(request, "user-agent", "HTTP_USER_AGENT")
    except Exception:
        return default


def get_request_method(request: HttpRequest, default: str = "UNKNOWN") -> str:
    """Get the HTTP method of the request, or a default value ('UNKNOWN')."""
    return request.method if request.method else default
