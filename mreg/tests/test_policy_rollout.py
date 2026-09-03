from io import BytesIO
from unittest.mock import patch

from django.test import SimpleTestCase

from mreg.policy.rollout import (
    RolloutSnapshot,
    RolloutThresholds,
    _prometheus_value,
    evaluate_rollout,
    fetch_rollout_snapshot,
)


class PolicyRolloutTests(SimpleTestCase):
    def test_prometheus_value_handles_value_empty_and_error_responses(self) -> None:
        with patch(
            "mreg.policy.rollout.urlopen",
            return_value=BytesIO(b'{"status":"success","data":{"result":[{"value":[1,"42.5"]}]}}'),
        ):
            self.assertEqual(_prometheus_value("http://prometheus/", "up == 1", 2), 42.5)

        with patch(
            "mreg.policy.rollout.urlopen",
            return_value=BytesIO(b'{"status":"success","data":{"result":[]}}'),
        ):
            self.assertEqual(_prometheus_value("http://prometheus", "absent(up)", 2), 0)

        with (
            patch(
                "mreg.policy.rollout.urlopen",
                return_value=BytesIO(b'{"status":"error","error":"bad query"}'),
            ),
            self.assertRaisesRegex(RuntimeError, "Prometheus query failed"),
        ):
            _prometheus_value("http://prometheus", "invalid", 2)

    @patch("mreg.policy.rollout._prometheus_value", side_effect=[100, 1, 2])
    def test_fetch_rollout_snapshot_queries_every_gate(self, prometheus_value) -> None:
        snapshot = fetch_rollout_snapshot("http://prometheus", window="6h", timeout=4)

        self.assertEqual(snapshot, RolloutSnapshot(100, 1, 2))
        self.assertEqual(prometheus_value.call_count, 3)
        self.assertTrue(all(call.args[0] == "http://prometheus" for call in prometheus_value.call_args_list))
        self.assertTrue(all(call.args[2] == 4 for call in prometheus_value.call_args_list))
        self.assertIn("[6h]", prometheus_value.call_args_list[0].args[1])

    def test_ready_snapshot_passes_every_gate(self) -> None:
        result = evaluate_rollout(
            RolloutSnapshot(
                comparisons=20_000,
                mismatches=1,
                errors=1,
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
            ),
            RolloutThresholds(),
        )

        self.assertFalse(result.ready)
        self.assertEqual(len(result.reasons), 3)
        self.assertIn("comparisons", result.reasons[0])
