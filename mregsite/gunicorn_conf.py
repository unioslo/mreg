"""Gunicorn lifecycle hooks for process-local runtime resources."""

import os


def worker_exit(server, worker):  # noqa: ARG001
    """Close worker-local clients and mark its multiprocess metrics dead."""
    from django.apps import apps

    if not apps.ready:
        return

    from mreg.api.treetop import close_policy_client

    close_policy_client()

    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        from prometheus_client import multiprocess

        multiprocess.mark_process_dead(worker.pid)
