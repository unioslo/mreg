"""Prometheus-backed TreeTop rollout readiness evaluation."""

from __future__ import annotations

from dataclasses import dataclass
import json
from urllib.parse import urlencode
from urllib.request import urlopen


@dataclass(frozen=True, slots=True)
class RolloutThresholds:
    min_comparisons: int = 10_000
    max_mismatch_rate: float = 0.001
    max_error_rate: float = 0.001
    max_persist_failures: int = 0
    max_dead_letters: int = 0
    max_backlog_age_seconds: float = 300.0


@dataclass(frozen=True, slots=True)
class RolloutSnapshot:
    comparisons: float
    mismatches: float
    errors: float
    persist_failures: float
    dead_letters: float
    backlog_age_seconds: float

    @property
    def mismatch_rate(self) -> float:
        return self.mismatches / self.comparisons if self.comparisons else 0.0

    @property
    def error_rate(self) -> float:
        total = self.comparisons + self.errors
        return self.errors / total if total else 0.0


@dataclass(frozen=True, slots=True)
class RolloutEvaluation:
    ready: bool
    reasons: tuple[str, ...]


def evaluate_rollout(snapshot: RolloutSnapshot, thresholds: RolloutThresholds) -> RolloutEvaluation:
    """Evaluate every rollout gate and return all failures at once."""
    reasons: list[str] = []
    if snapshot.comparisons < thresholds.min_comparisons:
        reasons.append(f"comparisons {snapshot.comparisons:g} < {thresholds.min_comparisons}")
    if snapshot.mismatch_rate > thresholds.max_mismatch_rate:
        reasons.append(f"mismatch rate {snapshot.mismatch_rate:.6f} > {thresholds.max_mismatch_rate:.6f}")
    if snapshot.error_rate > thresholds.max_error_rate:
        reasons.append(f"error rate {snapshot.error_rate:.6f} > {thresholds.max_error_rate:.6f}")
    if snapshot.persist_failures > thresholds.max_persist_failures:
        reasons.append(f"persist failures {snapshot.persist_failures:g} > {thresholds.max_persist_failures}")
    if snapshot.dead_letters > thresholds.max_dead_letters:
        reasons.append(f"dead letters {snapshot.dead_letters:g} > {thresholds.max_dead_letters}")
    if snapshot.backlog_age_seconds > thresholds.max_backlog_age_seconds:
        reasons.append(
            f"oldest backlog age {snapshot.backlog_age_seconds:g}s > {thresholds.max_backlog_age_seconds:g}s"
        )
    return RolloutEvaluation(ready=not reasons, reasons=tuple(reasons))


def _prometheus_value(base_url: str, query: str, timeout: float) -> float:
    endpoint = f"{base_url.rstrip('/')}/api/v1/query?{urlencode({'query': query})}"
    with urlopen(endpoint, timeout=timeout) as response:  # noqa: S310 - operator-provided Prometheus URL
        payload = json.load(response)
    if payload.get("status") != "success":
        raise RuntimeError(f"Prometheus query failed: {payload}")
    results = payload.get("data", {}).get("result", [])
    if not results:
        return 0.0
    return float(results[0]["value"][1])


def fetch_rollout_snapshot(
    prometheus_url: str,
    *,
    window: str = "24h",
    timeout: float = 10.0,
) -> RolloutSnapshot:
    """Read the six low-cardinality signals required by the rollout gate."""
    queries = {
        "comparisons": f'sum(increase(mreg_policy_parity_results_total{{result=~"match|mismatch"}}[{window}]))',
        "mismatches": f'sum(increase(mreg_policy_parity_results_total{{result="mismatch"}}[{window}]))',
        "errors": f'sum(increase(mreg_policy_parity_results_total{{result="error"}}[{window}]))',
        "persist_failures": f'sum(increase(mreg_policy_parity_batches_total{{status="persist_failed"}}[{window}]))',
        "dead_letters": 'max(mreg_policy_parity_outbox_entries{status="dead_letter"})',
        "backlog_age_seconds": "max(mreg_policy_parity_outbox_oldest_seconds)",
    }
    values = {
        name: _prometheus_value(prometheus_url, query, timeout)
        for name, query in queries.items()
    }
    return RolloutSnapshot(**values)
