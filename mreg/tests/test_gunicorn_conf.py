"""Tests for worker-scoped Gunicorn lifecycle hooks."""

import os
from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from mregsite import gunicorn_conf


class GunicornLifecycleHookTests(SimpleTestCase):
    """Ensure worker-local policy clients follow Gunicorn lifecycle."""

    @patch("mreg.api.treetop.close_policy_client")
    def test_worker_exit_closes_policy_client(self, close_client):
        gunicorn_conf.worker_exit(None, None)

        close_client.assert_called_once_with()

    @patch("mreg.api.treetop.close_policy_client")
    @patch("django.apps.apps")
    def test_worker_exit_is_safe_before_django_setup(self, apps, close_client):
        apps.ready = False

        gunicorn_conf.worker_exit(None, SimpleNamespace(pid=42))

        close_client.assert_not_called()

    @patch("prometheus_client.multiprocess.mark_process_dead")
    @patch("mreg.api.treetop.close_policy_client")
    def test_worker_exit_marks_prometheus_process_dead(self, close_client, mark_process_dead):
        with patch.dict(os.environ, {"PROMETHEUS_MULTIPROC_DIR": "/tmp/prometheus"}):
            gunicorn_conf.worker_exit(None, SimpleNamespace(pid=42))

        close_client.assert_called_once_with()
        mark_process_dead.assert_called_once_with(42)
