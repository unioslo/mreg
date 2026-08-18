"""Tests for worker-scoped Gunicorn lifecycle hooks."""

import os
from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from mregsite import gunicorn_conf


class GunicornLifecycleHookTests(SimpleTestCase):
    """Ensure parity dispatchers follow each Gunicorn worker lifecycle."""

    @patch("mreg.api.treetop.start_policy_parity_dispatcher")
    def test_post_fork_starts_dispatcher(self, start_dispatcher):
        gunicorn_conf.post_fork(None, None)

        start_dispatcher.assert_called_once_with()

    @patch("mreg.api.treetop.stop_policy_parity_dispatcher")
    def test_worker_exit_stops_dispatcher(self, stop_dispatcher):
        gunicorn_conf.worker_exit(None, None)

        stop_dispatcher.assert_called_once_with()

    @patch("prometheus_client.multiprocess.mark_process_dead")
    @patch("mreg.api.treetop.stop_policy_parity_dispatcher")
    def test_worker_exit_marks_prometheus_process_dead(self, stop_dispatcher, mark_process_dead):
        with patch.dict(os.environ, {"PROMETHEUS_MULTIPROC_DIR": "/tmp/prometheus"}):
            gunicorn_conf.worker_exit(None, SimpleNamespace(pid=42))

        stop_dispatcher.assert_called_once_with()
        mark_process_dead.assert_called_once_with(42)
