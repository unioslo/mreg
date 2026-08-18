"""Durable policy parity delivery models."""

from django.db import models
from django.utils import timezone


class PolicyParityOutbox(models.Model):
    """One durable, shared TreeTop parity batch.

    Successful rows are deleted.  Rows that exhaust their retries remain as
    dead letters so operators can inspect and explicitly resolve them.
    """

    payload = models.JSONField()
    attempts = models.PositiveIntegerField(default=0)
    available_at = models.DateTimeField(default=timezone.now, db_index=True)
    locked_at = models.DateTimeField(null=True, blank=True, db_index=True)
    failed_at = models.DateTimeField(null=True, blank=True, db_index=True)
    last_error = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=("failed_at", "available_at", "id"), name="policy_outbox_ready_idx"),
        ]
        verbose_name_plural = "policy parity outbox entries"
