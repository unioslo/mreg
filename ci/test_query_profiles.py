import json
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from ci.compare_query_profiles import load_report, main as compare_main
from ci.query_profiles import RequestProfiler, compare, index_samples, markdown_report, scenario_hash
from django.db import connection
from django.http import JsonResponse
from django.test import Client, TestCase, override_settings
from django.urls import path


def query_view(request, pk):
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
        cursor.execute("SELECT 2")
    return JsonResponse({"count": 1, "results": [{"id": pk}]})


urlpatterns = [path("objects/<int:pk>/", query_view)]


def report(count=3, **changes):
    sample = {
        "test": "tests.Example.test_list", "method": "GET", "route": "objects/<int:pk>/",
        "query": [], "occurrence": 1, "scenario_hash": "fixture-v1",
        "shape": {"status": 200, "streaming": False, "count": 1, "results": 1},
        "query_count": count, "seconds": 0.01,
    }
    sample.update(changes)
    return {"schema_version": 1, "revision": "abc123", "status": "ok", "samples": [sample]}


class ComparisonTests(unittest.TestCase):
    def test_regression_and_improvement_are_independent_of_time(self):
        self.assertEqual(compare(report(4, seconds=0.001), report(3))[0]["status"], "regression")
        self.assertEqual(compare(report(2, seconds=10), report(3))[0]["status"], "improved")
        self.assertEqual(compare(report(3), report(3))[0]["delta"], 0)

    def test_missing_samples_have_no_delta(self):
        empty = {**report(), "status": "missing", "samples": []}
        row = compare(report(), empty)[0]
        self.assertEqual(row["status"], "missing from baseline")
        self.assertIsNone(row["delta"])
        self.assertEqual(compare(empty, report())[0]["status"], "missing from head")
        summary, failed = markdown_report(report(), {"parent": empty, "master": report()})
        self.assertFalse(failed)
        self.assertIn("missing from baseline", summary)
        self.assertIn("—", summary)

    def test_error_is_not_missing(self):
        broken = {**report(), "status": "error", "samples": []}
        self.assertEqual(compare(report(), broken)[0]["status"], "sampling error")
        self.assertTrue(markdown_report(report(), {"parent": broken})[1])

    def test_changed_sources_or_workloads_are_not_compared(self):
        for changed in (report(scenario_hash="new"), report(shape={"status": 404, "streaming": False})):
            self.assertIsNone(compare(changed, report())[0]["delta"])

    def test_different_queries_and_occurrences_do_not_match(self):
        for changed in (report(query=[["page_size", "100"]]), report(occurrence=2)):
            self.assertEqual(len(compare(changed, report())), 2)
            self.assertTrue(all(row["delta"] is None for row in compare(changed, report())))

    def test_improvements_cannot_hide_a_regression(self):
        head, base = report(1), report(20)
        head["samples"].append(report(5, occurrence=2)["samples"][0])
        base["samples"].append(report(4, occurrence=2)["samples"][0])
        self.assertTrue(markdown_report(head, {"parent": base})[1])

    def test_rejects_duplicate_and_invalid_counts(self):
        duplicate = report()
        duplicate["samples"] *= 2
        for invalid in (duplicate, report(-1), report(True)):
            with self.assertRaises(ValueError):
                index_samples(invalid)

    def test_invalid_or_absent_file_is_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            self.assertEqual(load_report(path)["status"], "error")
            path.write_text("not JSON")
            self.assertEqual(load_report(path)["status"], "error")
            path.write_text("[]")
            self.assertEqual(load_report(path)["status"], "error")
            path.write_text(json.dumps(report()))
            self.assertEqual(load_report(path)["status"], "ok")

    def test_no_head_samples_fails(self):
        empty = {**report(), "status": "missing", "samples": []}
        self.assertTrue(markdown_report(empty, {"parent": report()})[1])

    def test_matched_zero_queries_are_valid(self):
        self.assertEqual(compare(report(0), report(0))[0]["delta"], 0)

    def test_cli_writes_reports_and_returns_regression_status(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            head, parent = root / "head.json", root / "parent.json"
            summary, comparison = root / "summary.md", root / "comparison.json"
            parent.write_text(json.dumps(report(3)))
            args = ["--head", str(head), "--baseline", f"parent={parent}",
                    "--summary", str(summary), "--json", str(comparison)]
            for count, expected_exit in ((2, 0), (4, 1)):
                with self.subTest(count=count), redirect_stdout(io.StringIO()):
                    head.write_text(json.dumps(report(count)))
                    self.assertEqual(compare_main(args), expected_exit)
                    self.assertEqual(json.loads(comparison.read_text())["parent"][0]["delta"], count - 3)
                    self.assertIn("Against parent", summary.read_text())


@override_settings(ROOT_URLCONF=__name__)
class InstrumentationTests(TestCase):
    def test_existing_django_client_calls_are_captured_without_fixture_queries(self):
        profiler = RequestProfiler(Path(__file__).resolve().parents[1])
        client = Client()

        class ExistingTest(unittest.TestCase):
            def setUp(self):
                # Fixture requests and SQL must not become measured requests.
                client.get("/objects/99/")
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 3")

            def test_requests(self):
                client.get("/objects/1/?page_size=1")
                client.get("/objects/2/?page_size=1")

        with profiler.installed():
            result = unittest.TestResult()
            ExistingTest("test_requests").run(result)
        self.assertTrue(result.wasSuccessful(), result.errors)
        self.assertEqual(len(profiler.samples), 2)
        first, second = profiler.samples
        self.assertEqual(first["query_count"], 2)
        self.assertEqual(first["route"], "objects/<int:pk>/")
        self.assertEqual(first["query"], [("page_size", "1")])
        self.assertEqual([first["occurrence"], second["occurrence"]], [1, 2])
        self.assertEqual(first["shape"]["results"], 1)
        client.get("/objects/3/")
        self.assertEqual(len(profiler.samples), 2)

    def test_drf_client_is_captured_and_post_is_not_replayed(self):
        from rest_framework.test import APIClient

        profiler = RequestProfiler(Path(__file__).resolve().parents[1])

        class ExistingTest(unittest.TestCase):
            def test_post(self):
                self.assertEqual(APIClient().post("/objects/4/").status_code, 200)

        with profiler.installed():
            result = unittest.TestResult()
            ExistingTest("test_post").run(result)
        self.assertTrue(result.wasSuccessful(), result.errors)
        self.assertEqual(len(profiler.samples), 1)
        self.assertEqual(profiler.samples[0]["method"], "POST")

    def test_hash_tracks_source_changes_across_checkouts(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory) / "first", Path(directory) / "second"
            hashes = []
            for root in (first, second):
                root.mkdir()
                source = root / "test_example.py"
                source.write_text("fixture = 1\n")
                with patch("ci.query_profiles.inspect.getfile", return_value=str(source)):
                    hashes.append(scenario_hash(self, root))
            self.assertEqual(*hashes)
            source.write_text("fixture = 2\n")
            with patch("ci.query_profiles.inspect.getfile", return_value=str(source)):
                self.assertNotEqual(hashes[0], scenario_hash(self, second))
