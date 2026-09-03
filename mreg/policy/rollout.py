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


@dataclass(frozen=True, slots=True)
class RolloutSnapshot:
    comparisons: float
    mismatches: float
    errors: float

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
    """Read the composite parity signals required by the rollout gate."""
    queries = {
        "comparisons": f'sum(increase(mreg_policy_parity_results_total{{result=~"match|mismatch"}}[{window}]))',
        "mismatches": f'sum(increase(mreg_policy_parity_results_total{{result="mismatch"}}[{window}]))',
        "errors": f'sum(increase(mreg_policy_parity_results_total{{result="error"}}[{window}]))',
    }
    values = {
        name: _prometheus_value(prometheus_url, query, timeout)
        for name, query in queries.items()
    }
    return RolloutSnapshot(**values)
