"""Gunicorn lifecycle hooks for process-local runtime resources."""

import os


def _setup_django() -> None:
    """Initialize Django before Gunicorn loads worker-scoped integrations."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mregsite.settings")

    import django
    from django.apps import apps

    if not apps.ready:
        django.setup()


def post_fork(server, worker):  # noqa: ARG001
    """Start the shadow-mode outbox consumer only after worker fork."""
    _setup_django()

    from mreg.api.treetop import start_policy_parity_dispatcher

    start_policy_parity_dispatcher()


def worker_exit(server, worker):  # noqa: ARG001
    """Stop the worker thread; unprocessed rows remain durable in PostgreSQL."""
    from django.apps import apps

    if not apps.ready:
        return

    from mreg.api.treetop import stop_policy_parity_dispatcher

    stop_policy_parity_dispatcher()

    if os.environ.get("PROMETHEUS_MULTIPROC_DIR"):
        from prometheus_client import multiprocess

        multiprocess.mark_process_dead(worker.pid)
