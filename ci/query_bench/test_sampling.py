import json
import io
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from unittest.mock import patch

from django.db import connection
from django.http import JsonResponse
from django.test import TestCase, override_settings
from django.urls import path

from ci.query_bench.reporting import compare, index_samples, load_report, main as compare_main, render_report
from ci.query_bench.sampling import MissingBenchmark, build_cases, load_fixture, load_suite, measure
from ci.query_bench.test_github import report

CAPTURED = []


def query_view(request):
    CAPTURED.append(len(connection.execute_wrappers))
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
        cursor.execute("SELECT 2")
    return JsonResponse({"results": [1], "count": 1})


urlpatterns = [path("objects/", query_view)]


class SelectionAndComparisonTests(unittest.TestCase):
    def test_selection_is_shared_and_unknown_patterns_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "suite.json"
            path.write_text(json.dumps({"warmups": 3, "runs": 15, "benchmarks": [
                {"label": label, "fixture": "tests.Fixture", "path": "/objects/"}
                for label in ("hosts/list", "hosts/detail", "networks/list")
            ]}))
            self.assertEqual([case["label"] for case in load_suite(path, ["hosts/*"])["benchmarks"]], ["hosts/list", "hosts/detail"])
            with self.assertRaises(ValueError):
                load_suite(path, ["missing/*"])

    def test_missing_fixture_is_distinct_from_broken_dependency(self):
        with self.assertRaises(MissingBenchmark):
            load_fixture("ci.no_such_fixture.TestCase")
        with self.assertRaises(MissingBenchmark):
            load_fixture("ci.query_bench.sampling.AbsentClass")
        with patch("ci.query_bench.sampling.importlib.import_module", side_effect=ModuleNotFoundError(name="missing_dependency")):
            with self.assertRaises(ModuleNotFoundError):
                load_fixture("tests.Fixture")

    def test_missing_fixtures_record_each_selected_label(self):
        output = {"samples": [], "benchmarks": []}
        suite = {"benchmarks": [{"label": "new/request", "fixture": "ci.absent.Fixture", "path": "/new/"}]}
        self.assertEqual(build_cases(suite, Path.cwd(), output), [])
        self.assertEqual(output["benchmarks"][0]["status"], "missing")

    def test_count_regressions_gate_but_timing_does_not(self):
        head, parent = report(4), report(3)
        self.assertTrue(render_report(head, {"parent": parent})[1])
        head = report(2)
        head["samples"][0]["timing"].update(samples_seconds=[10, 30], median_seconds=20, p95_seconds=30)
        self.assertFalse(render_report(head, {"parent": parent})[1])
        self.assertEqual(compare(head, parent)[0]["delta"], -1)

    def test_improvements_cannot_offset_regression(self):
        head, parent = report(1), report(20)
        for output, count in ((head, 5), (parent, 4)):
            extra = report(count, label="another/request")
            output["samples"] += extra["samples"]
            output["benchmarks"] += extra["benchmarks"]
        self.assertTrue(render_report(head, {"parent": parent})[1])

    def test_changed_workloads_and_run_settings_are_incomparable(self):
        for field in ("scenario_hash", "shape", "route", "timing"):
            head = report()
            if field == "timing":
                head["samples"][0][field]["warmups"] = 4
            else:
                head["samples"][0][field] = {"results": 2} if field == "shape" else "changed"
            self.assertIsNone(compare(head, report())[0]["delta"])

    def test_invalid_timing_and_duplicate_labels_are_rejected(self):
        for invalid in (float("nan"), -1, True):
            head = report()
            head["samples"][0]["timing"]["samples_seconds"][0] = invalid
            with self.assertRaises(ValueError):
                index_samples(head)
        head = report()
        head["benchmarks"] *= 2
        with self.assertRaises(ValueError):
            index_samples(head)

    def test_missing_measurements_are_not_zero_or_errors(self):
        absent = {**report(), "status": "missing", "samples": [],
                  "benchmarks": [{"label": "hosts/list/100", "status": "missing"}]}
        row = compare(report(), absent)[0]
        self.assertEqual(row["status"], "missing from baseline")
        self.assertIsNone(row["delta"])
        self.assertFalse(render_report(report(), {"parent": absent})[1])
        self.assertEqual(compare(absent, absent)[0]["status"], "missing from both")
        self.assertTrue(render_report(absent, {"parent": report()})[1])
        self.assertEqual(compare(report(0), report(0))[0]["delta"], 0)

    def test_compare_cli_writes_reports_and_preserves_failure_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            head, parent = root / "head.json", root / "parent.json"
            summary, comparison = root / "summary.md", root / "comparison.json"
            parent.write_text(json.dumps(report(3)))
            args = ["--head", str(head), "--baseline", f"parent={parent}",
                    "--summary", str(summary), "--json", str(comparison)]
            for count, expected in ((2, 0), (4, 1)):
                head.write_text(json.dumps(report(count)))
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(compare_main(args), expected)
                self.assertEqual(json.loads(comparison.read_text())["parent"][0]["delta"], count - 3)
                self.assertIn("Median ms", summary.read_text())
            head.write_text("[]")
            self.assertEqual(load_report(head)["status"], "error")
            self.assertEqual(load_report(root / "absent.json")["status"], "error")


@override_settings(ROOT_URLCONF=__name__)
class MeasurementTests(TestCase):
    def test_warmups_and_query_capture_are_excluded_from_timing_samples(self):
        CAPTURED.clear()
        definition = {"label": "objects/list", "fixture": __name__ + ".MeasurementTests", "path": "/objects/"}
        clock = [0, 9, 10, 19, 20, 39, 40, 41, 50, 52, 60, 63, 70, 74, 80, 85]
        with patch("ci.query_bench.sampling.time.perf_counter", side_effect=clock):
            result = measure(self, definition, {"warmups": 2, "runs": 5}, Path(__file__).resolve().parents[2])
        self.assertEqual(result["query_count"], 2)
        baseline = CAPTURED[0]
        self.assertEqual(CAPTURED, [baseline, baseline, baseline + 1, baseline, baseline, baseline, baseline, baseline])
        self.assertEqual(result["timing"]["samples_seconds"], [1, 2, 3, 4, 5])
        self.assertEqual(result["timing"]["median_seconds"], 3)
        self.assertEqual(result["timing"]["p95_seconds"], 5)
        self.assertEqual(result["timing"]["runs"], 5)
        self.assertEqual(result["timing"]["warmups"], 2)

    def test_absent_route_is_missing_but_bad_lookup_is_error(self):
        suite = {"warmups": 1, "runs": 2}
        definition = {"label": "missing", "fixture": __name__ + ".MeasurementTests", "path": "/absent/"}
        with self.assertRaises(MissingBenchmark):
            measure(self, definition, suite, Path.cwd())
        definition.update(path="/objects/{id}", parameters={"id": {"path": "/absent/", "json": ["id"]}})
        with self.assertRaises(AssertionError):
            measure(self, definition, suite, Path.cwd())
