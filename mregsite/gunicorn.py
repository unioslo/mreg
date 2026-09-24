"""Worker deadlines for the synchronous snapshot endpoint."""

import os

from django.conf import settings

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mregsite.settings")

# Leave time for the final database operation, cleanup, and response handling
# after the snapshot's generation deadline. Use effective Django settings so
# local_settings.py overrides and environment configuration both take effect.
timeout = max(30, settings.MREG_SNAPSHOT_MAX_DURATION_SECONDS + 60)
graceful_timeout = timeout
