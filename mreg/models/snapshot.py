"""Operational state for portable snapshots, excluded from snapshot exports."""

from django.conf import settings
from django.db import models


class SnapshotThrottleState(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, primary_key=True)
    history = models.JSONField(default=list)
