import json
import ssl
from itertools import combinations
from unittest import mock

from django.test import TestCase, override_settings
from mreg.mqsender import MQSender
from pika import SSLOptions
from pika.exceptions import (
    AMQPConnectionError,
    ConnectionClosedByBroker,
    StreamLostError,
)


class MQSenderTest(TestCase):
    """Test the MQSender class."""

    def setUp(self):
        """Set up the MQSender tests."""
        self.override_settings = override_settings(
            MQ_CONFIG={
                "username": "test",
                "password": "test",
                "host": "localhost",
                "ssl": False,
                "virtual_host": "/",
                "exchange": "test_exchange",
            }
        )
        self.override_settings.enable()
        self.mock_blocking_connection = mock.patch("pika.BlockingConnection")

    def tearDown(self):
        """Tear down the MQSender tests."""
        self.override_settings.disable()

    def create_mq_sender_and_send_event(self, connection_side_effect=None):
        """Create a MQSender and send an event, set side effects if requested."""
        with mock.patch("pika.BlockingConnection") as mock_blocking_connection:
            if connection_side_effect is not None:
                mock_blocking_connection.side_effect = connection_side_effect
            mq_sender = MQSender()
            mq_sender.send_event({"test": "test"}, "test_route")
        return mq_sender

    def assert_channel_is_gone(self, mq_sender):
        """Validate the channel is gone."""
        self.assertIsNone(mq_sender.mq_channel)

    def assert_event_published_correctly(self, mq_sender):
        """Validate the event published has correct data."""
        assert mq_sender.mq_channel.basic_publish.called
        _, kwargs = mq_sender.mq_channel.basic_publish.call_args
        body = kwargs["body"]
        body_dict = json.loads(body)
        self.assertIn("test", body_dict)
        self.assertIn("id", body_dict)
        self.assertIn("timestamp", body_dict)
        self.assertEqual(body_dict["test"], "test")

    def test_send_event_default(self):
        """Test that the event is published correctly."""
        mq_sender = self.create_mq_sender_and_send_event()
        self.assert_event_published_correctly(mq_sender)

    def test_send_event_exception(self):
        """Test that the event is published if the connection fails but retries work."""
        connection_side_effects = [AMQPConnectionError] * 3 + [mock.MagicMock()]
        mq_sender = self.create_mq_sender_and_send_event(connection_side_effects)
        self.assert_event_published_correctly(mq_sender)

    def test_send_event_failure_exception_ten_times(self):
        """Test that the event is not published if the connection fails more than 10 times."""
        connection_side_effects = [AMQPConnectionError] * 11
        mq_sender = self.create_mq_sender_and_send_event(connection_side_effects)
        self.assert_channel_is_gone(mq_sender)

    def test_singleton(self):
        """Test that the MQSender class is a proper singleton."""
        instance1 = MQSender()
        instance2 = MQSender()
        self.assertEqual(instance1, instance2)

    def test_initialization(self):
        """Test that the MQSender class is properly initialized."""
        mq_sender = MQSender()
        self.assertIsNone(mq_sender.mq_channel)
        self.assertIsInstance(mq_sender.mq_id, int)

    @mock.patch("pika.BlockingConnection")
    def test_send_event_config(self, mock_blocking_connection):
        """Test that we handle different configuration options."""
        keys = ["host", "username", "password", "exchange"]
        full_config = {
            "host": "localhost",
            "username": "test",
            "password": "test",
            "exchange": "test_exchange",
        }

        # Test with MQ_CONFIG=None
        with self.settings(MQ_CONFIG=None):
            mq_sender = MQSender()
            mq_sender.send_event({"test": "test"}, "test")
            mock_blocking_connection.basic_publish.assert_not_called()

        # Test with MQ_CONFIG not a dictionary
        with self.settings(MQ_CONFIG=[]):
            with self.assertRaises(ValueError):
                mq_sender = MQSender()

        # Test all combinations of missing keys
        for r in range(1, len(keys) + 1):
            for combination in combinations(keys, r):
                test_config = full_config.copy()
                for key in combination:
                    del test_config[key]
                with self.settings(MQ_CONFIG=test_config):
                    with self.assertRaises(ValueError):
                        mq_sender = MQSender()

    @mock.patch("ssl.SSLContext.load_cert_chain")
    @mock.patch("pika.BlockingConnection")
    def test_send_event_with_ssl_and_declare(
        self, mock_blocking_connection, mock_load_cert_chain
    ):
        """Test that SSL and declare options are handled correctly."""
        mock_connection = mock.MagicMock()
        mock_channel = mock.MagicMock()
        mock_connection.channel.return_value = mock_channel
        mock_blocking_connection.return_value = mock_connection

        ssl_context = ssl.create_default_context()
        ssl_options = SSLOptions(ssl_context, "localhost")

        with override_settings(
            MQ_CONFIG={
                "username": "test",
                "password": "test",
                "host": "localhost",
                "ssl": ssl_options,
                "declare": True,
                "virtual_host": "/",
                "exchange": "test_exchange",
            }
        ):
            mq_sender = MQSender()
            mq_sender.send_event({"test": "test"}, "test_route")

        # Assert that exchange_declare was called if 'declare' option is set to True
        mock_channel.exchange_declare.assert_called_once_with(
            exchange="test_exchange", exchange_type="topic"
        )

    def _run_basic_publish_test(self, side_effects, expect_published):
        with mock.patch("pika.BlockingConnection") as mock_blocking_connection:
            mock_connection = mock.MagicMock()
            mock_channel = mock.MagicMock()
            mock_channel.basic_publish.side_effect = side_effects
            mock_connection.channel.return_value = mock_channel
            mock_blocking_connection.return_value = mock_connection

            mq_sender = MQSender()
            mq_sender.send_event({"test": "test"}, "test_route")

            if expect_published:
                self.assert_event_published_correctly(mq_sender)
            else:
                self.assertIsNone(mq_sender.mq_channel)

    def test_send_event_basic_publish_raises_exceptions(self):
        """Test that exceptions in basic_publish are handled correctly.

        We specifically handle ConnectionClosedByBroker and StreamLostError."""

        # Test when exceptions are raised and no event is published
        self._run_basic_publish_test(
            [
                ConnectionClosedByBroker(reply_code=123, reply_text="test"),
                StreamLostError,
            ]
            * 6,
            expect_published=False,
        )

        # Test when exceptions are raised, but eventually an event is published
        self._run_basic_publish_test(
            [
                ConnectionClosedByBroker(reply_code=123, reply_text="test"),
                StreamLostError,
                mock.MagicMock(),
            ],
            expect_published=True,
        )
