"""Middleware to handle logging of HTTP requests and responses."""
import http
import logging
import time
import uuid
from typing import Callable, cast

import structlog
import sentry_sdk
import traceback
from django.conf import settings
from django.http import HttpRequest, HttpResponse

mreg_logger = structlog.getLogger("mreg.http")

LOGMAP = {
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}

def get_request_header(
    request: HttpRequest, header_key: str, meta_key: str
) -> str:
    """Get the value of a header from the request, either via headers or META."""
    if hasattr(request, "headers"): # pragma: no cover
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
    """Get the username of the user making the request, or 'AnonymousUser'."""
    return getattr(request.user, "username", default) if hasattr(request, 'user') else default


def get_request_user_agent(request: HttpRequest, default: str = "Unknown") -> str:
    try:
        return get_request_header(request, "user-agent", "HTTP_USER_AGENT")
    except Exception:
        return default


class LoggingMiddleware:
    """Middleware to log HTTP requests and responses.

    This middleware checks the status code of the response and logs a message
    based on the response code range (success, redirection, client error, or server error).
    The time it took to process the response is also logged.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        """Initialize the middleware.

        :param get_response: A reference to the next middleware or view in the chain.
        """
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Process the request and log the response.

        :param request: The incoming request.
        :return: A response object
        """
        start_time = int(time.time())

        self.log_request(request)
 
        try:
            response = self.get_response(request)
        except Exception as e: # pragma: no cover (this is somewhat tricky to properly test)
            self.log_exception(request, e, start_time)
            raise

        self.log_response(request, response, start_time)
        return response

    def log_request(self, request: HttpRequest) -> None:
        """Log the request."""
        request_id = get_request_header(
            request, "x-request-id", "HTTP_X_REQUEST_ID"
        ) or str(uuid.uuid4())
        correlation_id = get_request_header(
            request, "x-correlation-id", "HTTP_X_CORRELATION_ID"
        )
        structlog.contextvars.bind_contextvars(request_id=request_id)
        if correlation_id:
            structlog.contextvars.bind_contextvars(correlation_id=correlation_id)

        remote_ip = request.META.get("REMOTE_ADDR")

        # Check for a proxy address
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            proxy_ip = x_forwarded_for.split(",")[0]
        else:
            proxy_ip = ""

        user_agent = get_request_header(request, "user-agent", "HTTP_USER_AGENT")

        # Size of request
        request_size = len(request.body)

        mreg_logger.bind(
            method=request.method,
            remote_ip=remote_ip,
            proxy_ip=proxy_ip,
            user_agent=user_agent,
            path=request.path_info,
            query_string=request.META.get("QUERY_STRING"),
            request_size=request_size,
            content=get_request_body(request),
        ).info("request")

    def log_response(
        self, request: HttpRequest, response: HttpResponse, start_time: int
    ) -> HttpResponse:
        """Log the response."""
        end_time = time.time()
        status_code = response.status_code
        run_time_ms = (end_time - start_time) * 1000

        status_label = cast(str, http.client.responses[status_code])

        if status_code in range(200, 399):
            log_level = logging.INFO
        elif status_code in range(400, 499):
            log_level = logging.WARNING
        else:
            log_level = logging.ERROR

        extra_data = {}

        if run_time_ms >= settings.REQUESTS_THRESHOLD_VERY_SLOW:
            extra_data["original_log_level"] = log_level
            extra_data["very_slow_response"] = True
            log_level = LOGMAP[settings.REQUESTS_LOG_LEVEL_VERY_SLOW.upper()]
        elif run_time_ms >= settings.REQUESTS_THRESHOLD_SLOW:
            extra_data["original_log_level"] = log_level
            extra_data["slow_response"] = True
            log_level = LOGMAP[settings.REQUESTS_LOG_LEVEL_SLOW.upper()]

        content = ""
        if "application/json" in response.headers.get("Content-Type", ""):
            content = response.content.decode("utf-8")

        username = get_request_username(request)
        user_agent = get_request_user_agent(request)

        mreg_logger.bind(
            user=username,
            method=request.method,
            user_agent=user_agent,
            status_code=status_code,
            status_label=status_label,
            path=request.path_info,
            query_string=request.META.get("QUERY_STRING"),  
            content=content,
            **extra_data,
            run_time_ms=round(run_time_ms, 2),
        ).log(log_level, "response")

        contextvars = structlog.contextvars.get_contextvars()
        response["X-Request-ID"] = contextvars["request_id"]
        if "correlation_id" in contextvars:
            response["X-Correlation-ID"] = contextvars["correlation_id"]

        structlog.contextvars.clear_contextvars()

        return response

    def log_exception(self, request: HttpRequest, exception: Exception, start_time: float) -> None: # pragma: no cover
        """Log an exception that occurred during request processing."""
        end_time = time.time()
        run_time_ms = (end_time - start_time) * 1000

        stack_trace = traceback.format_exc()

        username = get_request_username(request)
        user_agent = get_request_user_agent(request)

        # Log the exception with stack trace
        mreg_logger.bind(
            user=username,
            method=request.method,
            user_agent=user_agent,
            path=request.path_info,
            query_string=request.META.get("QUERY_STRING"),
            run_time_ms=round(run_time_ms, 2),
        ).error(
            "Unhandled exception occurred",
            exception_string=str(exception),
            exception_type=type(exception).__name__,
            stack_trace=stack_trace,
        )

        # Capture the exception with Sentry and add context
        with sentry_sdk.push_scope() as scope:
            scope.set_user({"username": username})
            scope.set_extra("method", request.method)
            scope.set_extra("user_agent", user_agent)
            scope.set_extra("path", request.path_info)
            scope.set_extra("query_string", request.META.get("QUERY_STRING"))
            scope.set_extra("run_time_ms", round(run_time_ms, 2))
            scope.set_extra("exception_string", str(exception))
            scope.set_extra("stack_trace", stack_trace)

            scope.set_extra("request_body", get_request_body(request))

            # Capture the exception
            sentry_sdk.capture_exception(exception)