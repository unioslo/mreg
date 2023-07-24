"""Middleware to handle logging of HTTP requests and responses."""
import http
import logging
import time
from typing import Callable, cast

import structlog
from django.conf import settings
from django.http import HttpRequest, HttpResponse

from mreg.middleware.context import get_request_id

mreg_logger = structlog.getLogger("mreg.http")

LOGMAP = {
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
    "DEBUG": logging.DEBUG,
}


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
        start_time = time.time()

        request.id = get_request_id()
        self.log_request(request)
        response = self.get_response(request)
        self.log_response(request, response, start_time)
        return response

    def _get_body(self, request: HttpRequest) -> str:
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

    def log_request(self, request: HttpRequest) -> None:
        """Log the request."""
        remote_ip = request.META.get("REMOTE_ADDR")

        # Check for a proxy address
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            proxy_ip = x_forwarded_for.split(",")[0]
        else:
            proxy_ip = ""

        # Size of request
        request_size = len(request.body)

        mreg_logger.bind(
            method=request.method,
            remote_ip=remote_ip,
            proxy_ip=proxy_ip,
            path=request.path_info,
            request_size=request_size,
            content=self._get_body(request),
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

        content = "[]"
        if "application/json" in response.headers.get("Content-Type", ""):
            content = response.content.decode("utf-8")

        username = request.user.username

        mreg_logger.bind(
            user=username,
            method=request.method,
            status_code=status_code,
            status_label=status_label,
            path=request.path_info,
            content=content,
            **extra_data,
            run_time_ms=round(run_time_ms, 2),
        ).log(log_level, "response")

        return response
