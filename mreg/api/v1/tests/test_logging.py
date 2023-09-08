"""Test logging middleware and logging output."""


import io
import logging
from typing import List
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.http import HttpRequest, HttpResponse
from structlog import get_logger
from structlog.testing import capture_logs

from mreg.api.v1.tests.tests import MregAPITestCase
from mreg.log_processors import (
    RequestColorTracker,
    collapse_request_id_processor,
    filter_sensitive_data,
    reorder_keys_processor,
)
from mreg.middleware.logging_http import LoggingMiddleware
from mreg.models.base import ExpiringToken


class CustomLogHandler(logging.Handler):
    """Custom log handler to capture logs for testing."""

    def __init__(self) -> None:
        super().__init__()
        self.logs: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        """Capture a log record.

        :param record: The log record to capture.
        """
        self.logs.append(self.format(record))


class TestLoggingInternals(MregAPITestCase):
    """Test internals in the logging framework."""

    def test_reorder_keys_processor(self) -> None:
        """Test that the keys are reordered properly."""
        # Simulate a logging event
        event = {
            "event": "Event 1",
            "request_id": "request_id",
            "another_key": "value",
        }

        # Process the event
        processed_event = reorder_keys_processor(None, None, event)

        # Check that request_id is the first key
        first_key = next(iter(processed_event.keys()))
        self.assertEqual(first_key, "request_id")

    def test_collapse_request_id_processor(self):
        """Test that the request ID is collapsed properly."""
        testcases = [
            ("", "..."),  # length 0
            ("12345", "..."),  # length 5
            ("1234567890", "..."),  # length 10
            ("12345678901", "123...901"),  # length 11
            ("12345678901234567890", "123...890"),  # length 20
        ]

        for original_request_id, expected_request_id in testcases:
            # Simulate a logging event
            event = {"event": "Event 1", "request_id": original_request_id}

            # Process the event
            processed_event = collapse_request_id_processor(None, None, event)

            # Check that the request ID has been replaced and properly formatted
            self.assertEqual(processed_event["request_id"], expected_request_id)

    def test_filtering_of_sensitive_data(self):
        """Test that sensitive data is filtered correctly."""
        source_dicts = [
            {
                "model": "ExpiringToken",
                "_str": "1234567890123456789012345678901234567890",
                "id": "1234567890123456789012345678901234567890",
            },
            {
                "model": "ExpiringToken",
                "_str": "123456789",
                "id": "123456789",
            },
            {
                "model": "Session",
                "_str": "123456789012345678901234567890123456789a",
                "id": "123456789012345678901234567890123456789a",
            },
        ]

        expected_dicts = [
            {
                "model": "ExpiringToken",
                "_str": "123...890",
                "id": "123...890",
            },
            {
                "model": "ExpiringToken",
                "_str": "...",
                "id": "...",
            },
            {
                "model": "Session",
                "_str": "123...89a",
                "id": "123...89a",
            },
        ]

        for source_dict, expected_dict in zip(source_dicts, expected_dicts):
            self.assertEqual(
                filter_sensitive_data(None, None, source_dict), expected_dict
            )

    def test_binary_request_body(self) -> None:
        """Test logging of a request with a binary body."""
        middleware = LoggingMiddleware(MagicMock())

        def mock_get_response(_):
            return HttpResponse(status=200)

        middleware.get_response = mock_get_response

        with capture_logs() as cap_logs:
            get_logger().bind()
            request = HttpRequest()
            request._read_started = False
            request.user = get_user_model().objects.get(username="superuser")

            # Mock a binary request body
            binary_body = b"\x80abc\x01\x02\x03\x04\x05"
            request._stream = io.BytesIO(binary_body)

            middleware(request)

            # Check that the body was logged as '<Binary Data>'
            self.assertEqual(cap_logs[0]["content"], "<Binary Data>")


class TestLoggingMiddleware(MregAPITestCase):
    """Test logging middleware."""

    def test_run_time_ms_escalation(self):
        """Test run_time_ms escalation for logging levels."""
        middleware = LoggingMiddleware(MagicMock())

        # mock the get_response method to return a response with a specified status code and delay
        def mock_get_response(_):
            return HttpResponse(status=200)

        middleware.get_response = mock_get_response

        # test the behavior of the logging system with different delays
        delay_responses = [
            (0.1, "info"),
            (0.5, "info"),
            (1.0, "warning"),
            (2.0, "warning"),
            (5.0, "critical"),
            (5.5, "critical"),
        ]

        for delay, expected_level in delay_responses:
            with patch("time.time", side_effect=[0, delay]):
                with capture_logs() as cap_logs:
                    get_logger().bind()
                    request = HttpRequest()
                    request._body = b"Some request body"
                    request.user = get_user_model().objects.get(username="superuser")
                    middleware(request)
                    # cap_logs[0] is the request, cap_logs[1] is the response
                    self.assertEqual(cap_logs[1]["log_level"], expected_level)

    def test_return_500_error(self) -> None:
        """Test middleware returning 500 error."""
        middleware = LoggingMiddleware(MagicMock())

        def mock_get_response(_):
            return HttpResponse(status=500)

        middleware.get_response = mock_get_response

        with capture_logs() as cap_logs:
            get_logger().bind()
            request = HttpRequest()
            request._read_started = False
            request._stream = io.BytesIO(b"request body")  # mock the _stream attribute
            request.user = get_user_model().objects.get(username="superuser")
            middleware(request)
            self.assertEqual(cap_logs[1]["status_code"], 500)

    def test_proxy_ip_in_logs(self) -> None:
        """Check that a proxy IP is logged."""
        middleware = LoggingMiddleware(MagicMock())

        def mock_get_response(_):
            return HttpResponse(status=500)

        middleware.get_response = mock_get_response

        with capture_logs() as cap_logs:
            get_logger().bind()
            request = HttpRequest()
            request._read_started = False
            request._stream = io.BytesIO(b"request body")
            request.user = get_user_model().objects.get(username="superuser")
            request.META["HTTP_X_FORWARDED_FOR"] = "192.0.2.0"  # set a proxy IP
            middleware(request)
            self.assertEqual(cap_logs[0]["proxy_ip"], "192.0.2.0")

    def test_request_color_tracker(self) -> None:
        """Test that the request color tracker works as expected."""
        color_tracker = RequestColorTracker()

        events = [
            {"request_id": "abc123", "event": "Event 1"},
            {"request_id": "def456", "event": "Event 2"},
            {"request_id": "abc123", "event": "Event 3"},
            {"request_id": "abc123", "event": "Event 3"},
            {"request_id": "ghi789", "event": "Event 3"},
        ]

        expected_colors = [
            color_tracker.COLORS[0],
            color_tracker.COLORS[1],
            color_tracker.COLORS[0],
            color_tracker.COLORS[0],
            color_tracker.COLORS[2],
        ]

        for i, event in enumerate(events):
            expected_color = expected_colors[i]
            colored_bubble = color_tracker._colorize(expected_color, " • ")
            expected_event = colored_bubble + event["event"]
            colored_event = color_tracker(None, None, event)

            self.assertEqual(colored_event["event"], expected_event)

    # We can't use capture_logs() as we need processors to run, so we use
    # a custom handler instead.
    def test_auth_secrets_not_in_log(self) -> None:
        """Test to ensure that sensitive authentication secrets are not logged."""

        handler = CustomLogHandler()
        logger = get_logger("mreg.http")
        logger.setLevel(logging.DEBUG)  # Make sure we capture all logs
        handler.setLevel(logging.DEBUG)  # Ditto for the handler
        logger.addHandler(handler)

        try:
            logger.bind()
            the_password = "test"  # because we can't easily extract it from self.user

            self.assert_post_and_200(
                "/api/token-auth/",
                {"username": self.user.username, "password": the_password},
            )

            the_token = ExpiringToken.objects.get(user=self.user).key

            req = handler.logs[0]
            res = handler.logs[1]

            self.assertNotIn(the_password, req)
            self.assertNotIn(the_token, res)
            self.assertIn("'password': '...'", req)
            self.assertIn("...", res)

        finally:
            logger.removeHandler(handler)
