from django.test import SimpleTestCase

from mreg.policy.rollout import RolloutSnapshot, RolloutThresholds, evaluate_rollout


class PolicyRolloutTests(SimpleTestCase):
    def test_ready_snapshot_passes_every_gate(self) -> None:
        result = evaluate_rollout(
            RolloutSnapshot(
                comparisons=20_000,
                mismatches=1,
                errors=1,
                persist_failures=0,
                dead_letters=0,
                backlog_age_seconds=10,
            ),
            RolloutThresholds(),
        )

        self.assertTrue(result.ready)
        self.assertEqual(result.reasons, ())

    def test_failed_snapshot_reports_every_broken_gate(self) -> None:
        result = evaluate_rollout(
            RolloutSnapshot(
                comparisons=100,
                mismatches=5,
                errors=5,
                persist_failures=2,
                dead_letters=3,
                backlog_age_seconds=600,
            ),
            RolloutThresholds(),
        )

        self.assertFalse(result.ready)
        self.assertEqual(len(result.reasons), 6)
        self.assertIn("comparisons", result.reasons[0])
