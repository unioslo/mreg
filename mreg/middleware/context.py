"""Middleware for setting context variables."""
import uuid
from contextvars import ContextVar
from typing import Callable

from django.http import HttpRequest, HttpResponse

request_id_var = ContextVar("request_id", default=None)


def get_request_id() -> str:
    """Return the current request ID, or generate a new one if not available."""
    request_id = request_id_var.get()
    if request_id is None:
        request_id = str(uuid.uuid4())
        request_id_var.set(request_id)
    return request_id


class ContextMiddleware:
    """Set context variables for the request.

    Sets the following context variables:
    - request_id: A UUID for the request.
    - user: The user making the request.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        """Initialize the middleware."""
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Process the request."""
        response = self.get_response(request)

        # Set the request ID into the response headers.
        response["X-Request-ID"] = get_request_id()

        # Clean up the request ID from ContextVar.
        request_id_var.set(None)

        return response
