#!/usr/bin/env python3
"""Benchmark selected GET requests using each revision's existing Django fixtures."""

import argparse
import fnmatch
import hashlib
import importlib
import inspect
import json
import math
import os
import re
import subprocess
import sys
import time
import traceback
import unittest
from collections import Counter
from contextlib import ExitStack
from pathlib import Path
from statistics import median, stdev
from urllib.parse import parse_qsl, urlsplit

from ci.query_bench.reporting import SCHEMA_VERSION
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



class MissingBenchmark(Exception):
    """The requested fixture or route does not exist in this revision."""


def load_suite(path, patterns=()):
    suite = json.loads(Path(path).read_text())
    if type(suite["warmups"]) is not int or suite["warmups"] < 1:
        raise ValueError("warmups must be a positive integer")
    if type(suite["runs"]) is not int or suite["runs"] < 2:
        raise ValueError("runs must be an integer of at least two")
    cases = suite["benchmarks"]
    labels = [case["label"] for case in cases]
    if not all(isinstance(label, str) and label for label in labels) or len(labels) != len(set(labels)):
        raise ValueError("Benchmark labels must be nonempty and unique")
    for case in cases:
        if not isinstance(case["fixture"], str) or not case["path"].startswith("/"):
            raise ValueError("Each benchmark needs a fixture class and an absolute GET path")
    for pattern in patterns:
        if not any(fnmatch.fnmatchcase(label, pattern) for label in labels):
            raise ValueError(f"No benchmark matches {pattern!r}")
    suite["benchmarks"] = [case for case in cases if not patterns or any(fnmatch.fnmatchcase(case["label"], p) for p in patterns)]
    if not suite["benchmarks"]:
        raise ValueError("Select at least one benchmark")
    return suite


def load_fixture(label):
    module_name, _, class_name = label.rpartition(".")
    try:
        module = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if module_name == exc.name or module_name.startswith(exc.name + "."):
            raise MissingBenchmark(f"Fixture module {module_name} is absent") from exc
        raise  # A missing dependency is a setup error, not an absent benchmark.
    try:
        return getattr(module, class_name)
    except AttributeError as exc:
        raise MissingBenchmark(f"Fixture class {label} is absent") from exc


def timing_stats(durations, warmups):
    ordered = sorted(durations)
    return {
        "warmups": warmups, "runs": len(durations), "samples_seconds": durations,
        "median_seconds": median(durations), "p95_seconds": ordered[math.ceil(len(ordered) * 0.95) - 1],
        "min_seconds": ordered[0], "max_seconds": ordered[-1], "stdev_seconds": stdev(durations),
    }


def measure(case, definition, suite, checkout):
    from django.db import connections
    from django.test import Client
    from django.urls import Resolver404, resolve

    if not isinstance(case.client, Client):
        raise TypeError("Benchmarks require a synchronous Django/DRF test client")

    def route_for(path):
        try:
            return resolve(urlsplit(path).path).route or "/"
        except Resolver404 as exc:
            raise MissingBenchmark(f"No route for {urlsplit(path).path}") from exc

    values = vars(case).copy()
    for name, lookup in definition.get("parameters", {}).items():
        lookup_path = lookup["path"].format_map(values)
        route_for(lookup_path)
        response = case.client.get(lookup_path)
        case.assertEqual(response.status_code, 200, "Benchmark parameter lookup failed")
        value = response.json()
        for key in lookup["json"]:
            value = value[key]
        values[name] = value
    path = definition["path"].format_map(values)
    url = urlsplit(path)
    route = route_for(path)

    expected_shape = None

    def get():
        nonlocal expected_shape
        start = time.perf_counter()
        response = case.client.get(path)
        duration = time.perf_counter() - start
        case.assertEqual(response.status_code, 200, f"Benchmark GET {path} failed")
        shape = response_shape(response)
        case.assertFalse(shape["streaming"], "Streaming requests are not supported")
        if expected_shape is None:
            expected_shape = shape
        case.assertEqual(shape, expected_shape, "Response workload changed between benchmark runs")
        return duration

    for _ in range(suite["warmups"]):
        get()
    counts = Counter()

    def count(execute, sql, params, many, context):
        statement = str(sql)
        table = _TABLE.search(statement)
        operation = statement.lstrip().split(None, 1)[0].upper() if statement.strip() else "unknown"
        counts[f"{context['connection'].alias}:{operation}:{table.group(1) if table else 'other'}"] += 1
        return execute(sql, params, many, context)

    with ExitStack() as stack:
        for connection in connections.all():
            stack.enter_context(connection.execute_wrapper(count))
        get()  # Separate query-count run, excluded from the timing distribution.
    durations = [get() for _ in range(suite["runs"])]
    timing = timing_stats(durations, suite["warmups"])
    # The shared definition/settings and the target revision's fixture source
    # both contribute. Changed fixtures remain visible but aren't auto-compared.
    fingerprint = {"definition": definition, "settings": suite.get("settings", {}), "source": scenario_hash(case, checkout)}
    return {
        "label": definition["label"], "method": "GET", "route": route,
        "query": sorted(parse_qsl(url.query, keep_blank_values=True)),
        "scenario_hash": hashlib.sha256(json.dumps(fingerprint, sort_keys=True).encode()).hexdigest(),
        "shape": expected_shape, "query_count": sum(counts.values()), "queries": dict(counts),
        "timing": timing,
    }


def build_cases(suite, checkout, report):
    cases = []
    for definition in suite["benchmarks"]:
        record = {"label": definition["label"], "status": "error", "reason": "Fixture setup or sampling did not complete"}
        report["benchmarks"].append(record)
        try:
            fixture = load_fixture(definition["fixture"])
        except MissingBenchmark as exc:
            record.update(status="missing", reason=str(exc))
            continue

        def benchmark(case, definition=definition, record=record):
            try:
                sample = measure(case, definition, suite, checkout)
            except MissingBenchmark as exc:
                record.update(status="missing", reason=str(exc))
                case.skipTest(str(exc))
            report["samples"].append(sample)
            record.update(status="ok")
            record.pop("reason", None)

        benchmark.__doc__ = definition["label"]
        # Inherit only fixture lifecycle; never invoke the old test method or
        # its count assertions, timing loops, or request-capture instrumentation.
        benchmark_class = type("RequestBenchmark", (fixture,), {"runTest": benchmark, "__module__": fixture.__module__})
        cases.append(benchmark_class("runTest"))
    return cases


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, default=Path.cwd())
    parser.add_argument("--suite", required=True, type=Path)
    parser.add_argument("--case", action="append", default=[], help="Select labels with a shell-style glob; repeatable")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    checkout, output = args.checkout.resolve(), args.output.resolve()
    suite = load_suite(args.suite, args.case)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip()
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=checkout, text=True).strip():
        revision += " (working tree changes)"
    report = {"schema_version": SCHEMA_VERSION, "revision": revision, "status": "error", "samples": [], "benchmarks": []}
    result = 1
    try:
        if not (checkout / "manage.py").is_file():
            report.update(status="missing", reason="This revision has no Django test entrypoint (manage.py).")
            report["benchmarks"] = [{"label": case["label"], "status": "missing", "reason": report["reason"]}
                                    for case in suite["benchmarks"]]
            return 0
        os.chdir(checkout)
        sys.path.insert(0, str(checkout))
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mregsite.settings")
        sys.argv = [str(checkout / "manage.py"), "test"]
        import django
        django.setup()
        from django.test import override_settings
        from django.test.runner import DiscoverRunner

        with override_settings(**suite.get("settings", {})):
            cases = build_cases(suite, checkout, report)

            class BenchmarkRunner(DiscoverRunner):
                def build_suite(self, *args, **kwargs):
                    return unittest.TestSuite(cases)

            result = int(bool(BenchmarkRunner(verbosity=2, interactive=False, parallel=1).run_tests([]))) if cases else 0
        result = int(bool(result or any(case["status"] == "error" for case in report["benchmarks"])))
        report["status"] = "error" if result else "ok" if report["samples"] else "missing"
    except Exception:
        traceback.print_exc()
        report["reason"] = "Benchmark setup or execution failed; see the test log."
    finally:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
    return result
