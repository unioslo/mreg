"""Automatic request sampling and revision comparisons for Django tests."""

import hashlib
import inspect
import json
import math
import re
import time
import unittest
from collections import Counter
from contextlib import ExitStack, contextmanager
from pathlib import Path
from statistics import median
from unittest.mock import patch
from urllib.parse import parse_qsl


SCHEMA_VERSION = 1
_TABLE = re.compile(r'\b(?:FROM|JOIN|UPDATE|INTO)\s+"?([\w]+)', re.IGNORECASE)


def scenario_hash(test, checkout):
    """Conservatively fingerprint local test and inherited fixture modules."""
    sources = {}
    for cls in type(test).__mro__:
        try:
            source = Path(inspect.getfile(cls)).resolve()
            relative = source.relative_to(checkout)
        except (TypeError, ValueError):
            continue
        sources[str(relative)] = hashlib.sha256(source.read_bytes()).hexdigest()
    return hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest()


def response_shape(response):
    """Workload hints, without retaining response bodies or volatile IDs."""
    shape = {"status": response.status_code, "streaming": response.streaming}
    data = getattr(response, "data", None)
    if data is None and not response.streaming and response.get("Content-Type", "").startswith("application/json"):
        try:
            data = json.loads(response.content)
        except (ValueError, UnicodeDecodeError):
            pass
    if isinstance(data, dict) and isinstance(data.get("results"), list):
        shape.update(count=data.get("count"), results=len(data["results"]))
    elif isinstance(data, list):
        shape["results"] = len(data)
    return shape


class RequestProfiler:
    def __init__(self, checkout):
        self.checkout = Path(checkout).resolve()
        self.samples = []
        self.current_test = None
        self.occurrences = Counter()

    @contextmanager
    def installed(self):
        # Import only after the wrapper has selected the target checkout and
        # configured Django. No profiling code is needed in that revision.
        from django.db import connections
        from django.test import Client
        from django.urls import Resolver404, resolve

        original_method = unittest.TestCase._callTestMethod
        original_request = Client.request

        def test_method(test, method):
            previous = self.current_test, self.occurrences
            self.current_test = (test.id(), scenario_hash(test, self.checkout))
            self.occurrences = Counter()
            try:
                return original_method(test, method)
            finally:
                self.current_test, self.occurrences = previous

        def request(client, **kwargs):
            if self.current_test is None:
                return original_request(client, **kwargs)
            environ = client._base_environ(**kwargs)
            path = environ.get("PATH_INFO", "/")
            try:
                match = resolve(path)
                route = match.route or "/"
            except Resolver404:
                route = "<unresolved> " + path
            identity = {
                "test": self.current_test[0],
                "method": environ.get("REQUEST_METHOD", "GET"),
                "route": route,
                "query": sorted(parse_qsl(environ.get("QUERY_STRING", ""), keep_blank_values=True)),
            }
            key = json.dumps(identity, sort_keys=True)
            self.occurrences[key] += 1
            identity["occurrence"] = self.occurrences[key]
            counts = Counter()

            def count_query(execute, sql, params, many, context):
                sql_text = str(sql)
                table = _TABLE.search(sql_text)
                operation = sql_text.lstrip().split(None, 1)[0].upper() if sql_text.strip() else "unknown"
                counts[f"{context['connection'].alias}:{operation}:{table.group(1) if table else 'other'}"] += 1
                return execute(sql, params, many, context)

            start = time.perf_counter()
            with ExitStack() as stack:
                for connection in connections.all():
                    stack.enter_context(connection.execute_wrapper(count_query))
                response = original_request(client, **kwargs)
            elapsed = time.perf_counter() - start
            self.samples.append({
                **identity,
                "scenario_hash": self.current_test[1],
                "shape": response_shape(response),
                "query_count": sum(counts.values()),
                "seconds": elapsed,
                "queries": dict(counts),
            })
            return response

        with patch.object(unittest.TestCase, "_callTestMethod", test_method), patch.object(Client, "request", request):
            yield self


def sample_key(sample):
    return json.dumps({key: sample[key] for key in ("test", "method", "route", "query", "occurrence")}, sort_keys=True)


def index_samples(report):
    if not isinstance(report, dict):
        raise ValueError("A query-profile report must be an object")
    if report.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported or missing query-profile schema version")
    if report.get("status") not in {"ok", "error", "missing"}:
        raise ValueError("Invalid query-profile run status")
    if not isinstance(report.get("samples"), list):
        raise ValueError("Missing request samples")
    if report["status"] == "ok" and not report["samples"]:
        raise ValueError("A successful sampling run must contain requests")
    indexed = {}
    for sample in report["samples"]:
        key = sample_key(sample)
        if key in indexed:
            raise ValueError(f"Duplicate request sample: {key}")
        if type(sample["query_count"]) is not int or sample["query_count"] < 0:
            raise ValueError(f"Invalid query count: {key}")
        for field in ("test", "method", "route", "scenario_hash"):
            if not isinstance(sample[field], str) or not sample[field]:
                raise ValueError(f"Invalid {field}: {key}")
        if not isinstance(sample["shape"], dict) or not isinstance(sample["shape"].get("streaming"), bool):
            raise ValueError(f"Invalid response shape: {key}")
        if not isinstance(sample["shape"].get("status"), int):
            raise ValueError(f"Invalid response status: {key}")
        if not isinstance(sample["seconds"], (float, int)) or not math.isfinite(sample["seconds"]) or sample["seconds"] < 0:
            raise ValueError(f"Invalid request timing: {key}")
        indexed[key] = sample
    return indexed


def compare(head, baseline):
    """Compare the union of identities; unknown measurements are never zero."""
    head_samples, base_samples = index_samples(head), index_samples(baseline)
    rows = []
    for key in sorted(head_samples.keys() | base_samples.keys()):
        current, previous = head_samples.get(key), base_samples.get(key)
        sample = current or previous
        row = {
            "test": sample["test"], "method": sample["method"], "route": sample["route"],
            "query": sample["query"], "occurrence": sample["occurrence"],
            "head": current, "baseline": previous, "delta": None,
        }
        if head["status"] == "error" or baseline["status"] == "error":
            row["status"] = "sampling error"
        elif current is None:
            row["status"] = "missing from head"
        elif previous is None:
            row["status"] = "missing from baseline"
        elif current["scenario_hash"] != previous["scenario_hash"]:
            row["status"] = "test/fixture source changed"
        elif current["shape"] != previous["shape"] or current["shape"]["streaming"]:
            row["status"] = "response workload changed or streaming"
        else:
            row["delta"] = current["query_count"] - previous["query_count"]
            row["status"] = "regression" if row["delta"] > 0 else "improved" if row["delta"] < 0 else "unchanged"
        rows.append(row)
    return rows


def markdown_report(head, baselines):
    lines = ["# API query comparison", "", f"PR head: `{head['revision']}` ({head['status']})", ""]
    failed = head["status"] != "ok"
    for name, baseline in baselines.items():
        rows = compare(head, baseline)
        statuses = Counter(row["status"] for row in rows)
        failed |= baseline["status"] == "error" or bool(statuses["regression"])
        lines.extend([
            f"## Against {name}", "", f"Revision: `{baseline['revision']}` ({baseline['status']})", "",
            ", ".join(f"{count} {status}" for status, count in sorted(statuses.items())) or "No request samples.", "",
        ])
        if baseline.get("reason"):
            lines.extend([baseline["reason"], ""])
        # Group by endpoint, but derive totals only from paired comparable samples.
        endpoints = {}
        for row in rows:
            endpoint = f"{row['method']} {row['route']}"
            group = endpoints.setdefault(endpoint, {
                "head": 0, "base": 0, "paired": 0, "unknown": 0, "regressions": 0, "head_times": [], "base_times": [],
            })
            if row["delta"] is None:
                group["unknown"] += 1
            else:
                group["paired"] += 1
                group["head"] += row["head"]["query_count"]
                group["base"] += row["baseline"]["query_count"]
                group["regressions"] += row["status"] == "regression"
                group["head_times"].append(row["head"]["seconds"])
                group["base_times"].append(row["baseline"]["seconds"])
        lines.extend([
            "Query totals and median timings use only matched, comparable requests.", "",
            "| Endpoint | Matched | Base queries | Head queries | Base ms | Head ms | Uncompared | Regressions |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ])
        for endpoint, group in sorted(endpoints.items()):
            endpoint = endpoint.replace("|", "\\|").replace("\n", " ")
            base = group["base"] if group["paired"] else "—"
            current = group["head"] if group["paired"] else "—"
            base_ms = f"{median(group['base_times']) * 1000:.1f}" if group["paired"] else "—"
            head_ms = f"{median(group['head_times']) * 1000:.1f}" if group["paired"] else "—"
            lines.append(
                f"| `{endpoint}` | {group['paired']} | {base} | {current} | {base_ms} | {head_ms} | "
                f"{group['unknown']} | {group['regressions']} |"
            )
        lines.extend(["", "<details><summary>Changed or incomparable request samples</summary>", ""])
        changed = sorted((row for row in rows if row["status"] != "unchanged"), key=lambda row: row["status"] != "regression")
        for row in changed[:100]:
            label = f"{row['test']} :: {row['method']} {row['route']} :: {row['query']} #{row['occurrence']}"
            label = label.replace("`", "'").replace("\n", " ")
            delta = f" ({row['delta']:+d} queries)" if row["delta"] is not None else ""
            lines.append(f"- `{label}`: {row['status']}{delta}")
        if len(changed) > 100:
            lines.extend(["", f"Showing 100 of {len(changed)} changed/incomparable requests; all are in the JSON artifact."])
        lines.extend(["", "</details>", ""])
    lines.append("Timing is informational. Raw request timings, SQL attribution, and comparison rows are in the JSON artifacts.")
    if head.get("reason"):
        lines.extend(["", head["reason"]])
    return "\n".join(lines) + "\n", failed
