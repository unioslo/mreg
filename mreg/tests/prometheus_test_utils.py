from __future__ import annotations

import re

from prometheus_client import generate_latest


def parse_prometheus_metric(content: str, metric_name: str) -> dict[str, float]:
    """Parse Prometheus text exposition and return samples for one metric name."""
    result: dict[str, float] = {}
    pattern = rf"^{re.escape(metric_name)}(\{{[^}}]*\}})?\s+([0-9.e+-]+)$"
    for line in content.split("\n"):
        if line.startswith("#"):
            continue
        match = re.match(pattern, line)
        if match:
            labels = match.group(1) or ""
            result[labels] = float(match.group(2))
    return result


def prometheus_registry_text() -> str:
    """Return the current default Prometheus registry text format."""
    return generate_latest().decode("utf-8")


def metric_by_label(metric_name: str, label_filter: str, *, content: str | None = None) -> float:
    """Return metric value for the first sample whose label set contains label_filter."""
    raw = content if content is not None else prometheus_registry_text()
    values = parse_prometheus_metric(raw, metric_name)
    for labels, value in values.items():
        if label_filter in labels:
            return value
    return 0.0


def metric_total(metric_name: str, *, content: str | None = None) -> float:
    """Return sum of all samples for a metric from Prometheus text content."""
    raw = content if content is not None else prometheus_registry_text()
    values = parse_prometheus_metric(raw, metric_name)
    return sum(values.values()) if values else 0.0
