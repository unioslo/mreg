"""
Custom exception handler for Django REST Framework (DRF).

This module provides a custom exception handler that logs all exceptions
with additional context for improved observability and debugging.
"""

import traceback

import structlog
from drf_standardized_errors.handler import ExceptionHandler
from rest_framework import exceptions
from rest_framework.request import Request
from rest_framework.response import Response

from mreg.logs import get_request_method, get_request_user_agent, get_request_username

mreg_logger = structlog.getLogger("mreg.http")


class MregExceptionHandler(ExceptionHandler):
    """Custom DRF exception handler that logs all exceptions with additional context.

    This handler extends the default DRF exception handler to log _all_ exceptions,
    not just those that are handled by drf-standardized-errors (5xx errors).

    Furthermore, it redacts sensitive information from `PermissionDenied` exceptions
    to avoid leaking this information to users.

    See: <https://drf-standardized-errors.readthedocs.io/en/latest/customization.html#handle-a-non-drf-exception>
    """

    def report_exception(self, exc: exceptions.APIException, response: Response) -> None:
        try:
            drf_request: Request | None = self.context["request"]
            request = drf_request._request  # pyright: ignore[reportOptionalMemberAccess, reportPrivateUsage]
        except AttributeError:
            # If the request is not available, we cannot log request-specific information
            # NOTE: perform some sort of fallback logging here if needed
            return super().report_exception(exc, response)

        # Extract useful request information
        request_username = get_request_username(request)
        request_user_agent = get_request_user_agent(request)
        request_method = get_request_method(request)
        response_status = response.status_code

        # Get the stack trace from the original exception
        stack_trace = traceback.format_tb(self.exc.__traceback__) if self.exc.__traceback__ else []

        mreg_logger.bind(
            username=request_username,
            user_agent=request_user_agent,
            method=request_method,
            path=getattr(request, "path", ""),
            status_code=response_status,
            exception_type=type(self.exc).__name__,
            exception_message=str(self.exc),
            drf_exception_type=type(exc).__name__,
            drf_exception_message=str(exc),
            # detail=exc.detail, # pyright: ignore[reportUnknownMemberType]
        ).error(
            "DRF exception: %s (%s) on %s %s -> %s",
            type(self.exc).__name__,
            str(self.exc),
            request_method,
            getattr(request, "path", ""),
            response_status,
            stack_trace=stack_trace,
        )

        return super().report_exception(exc, response)

    def convert_known_exceptions(self, exc: Exception) -> Exception:
        """
        By default, Django's built-in `Http404` and `PermissionDenied` are converted
        to their DRF equivalent. This method also converts DRF `PermissionDenied`
        exceptions to a generic `PermissionDenied` without details to avoid leaking
        sensitive information about _why_ the permission was denied.

        The original exception is logged with the details intact, but the
        `PermissionDenied` exception returned to the user will not contain
        any details about the permission check that failed.
        """
        if isinstance(exc, exceptions.PermissionDenied):
            return exceptions.PermissionDenied()
        else:
            return super().convert_known_exceptions(exc)
