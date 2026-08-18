"""Fail unless TreeTop parity telemetry is ready for enforcement."""

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser

from mreg.policy.rollout import RolloutThresholds, evaluate_rollout, fetch_rollout_snapshot


class Command(BaseCommand):
    help = "Check Prometheus parity signals against the TreeTop enforcement rollout gates"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--prometheus-url", required=True)
        parser.add_argument("--window", default="24h")
        parser.add_argument("--timeout", type=float, default=10.0)

    def handle(self, *args, **options):  # type: ignore[no-untyped-def]
        thresholds = RolloutThresholds(
            min_comparisons=settings.POLICY_ROLLOUT_MIN_COMPARISONS,
            max_mismatch_rate=settings.POLICY_ROLLOUT_MAX_MISMATCH_RATE,
            max_error_rate=settings.POLICY_ROLLOUT_MAX_ERROR_RATE,
            max_persist_failures=settings.POLICY_ROLLOUT_MAX_PERSIST_FAILURES,
            max_dead_letters=settings.POLICY_ROLLOUT_MAX_DEAD_LETTERS,
            max_backlog_age_seconds=settings.POLICY_ROLLOUT_MAX_BACKLOG_AGE_SECONDS,
        )
        try:
            snapshot = fetch_rollout_snapshot(
                options["prometheus_url"],
                window=options["window"],
                timeout=options["timeout"],
            )
        except Exception as exc:
            raise CommandError(f"Unable to query Prometheus: {exc}") from exc
        evaluation = evaluate_rollout(snapshot, thresholds)
        summary = (
            f"comparisons={snapshot.comparisons:g} "
            f"mismatch_rate={snapshot.mismatch_rate:.6f} "
            f"error_rate={snapshot.error_rate:.6f} "
            f"persist_failures={snapshot.persist_failures:g} "
            f"dead_letters={snapshot.dead_letters:g} "
            f"backlog_age_seconds={snapshot.backlog_age_seconds:g}"
        )
        if not evaluation.ready:
            raise CommandError(f"TreeTop rollout gate failed: {'; '.join(evaluation.reasons)} ({summary})")
        self.stdout.write(self.style.SUCCESS(f"TreeTop rollout gate passed: {summary}"))
