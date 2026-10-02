import copy
import io
import json
import unittest
import zipfile
from contextlib import redirect_stdout
from unittest.mock import patch

from ci.query_bench.github import api, publish
from ci.query_bench.reporting import MARKER, archive_report, render_comment


HEAD = "a" * 40
BASE = "b" * 40


def report(count=3, revision=HEAD, **changes):
    label = changes.pop("label", "hosts/list/100")
    sample = {
        "label": label, "method": "GET", "route": "hosts/<name>", "query": [],
        "scenario_hash": "fixture-v1", "shape": {"status": 200, "streaming": False, "results": 100},
        "query_count": count,
        "timing": {"warmups": 3, "runs": 2, "samples_seconds": [0.01, 0.03], "median_seconds": 0.02, "p95_seconds": 0.03},
    }
    sample.update(changes)
    return {"schema_version": 2, "revision": revision, "status": "ok", "samples": [sample],
            "benchmarks": [{"label": label, "status": "ok"}]}


def archive_bytes(reports):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in reports.items():
            archive.writestr(f"query-profile-{name}/profile.json", json.dumps(data))
        # Unexpected files must never be extracted or executed.
        archive.writestr("../../reporter.py", "raise RuntimeError('untrusted code')")
    return buffer.getvalue()


def render(head, baselines, **kwargs):
    return render_comment(head, baselines, sha=HEAD, run_url="https://github.com/org/repo/actions/runs/42",
                          run_id=42, attempt=1, conclusion=kwargs.get("conclusion", "success"))


class CommentRenderingTests(unittest.TestCase):
    def test_reports_timings_run_counts_and_missing_baseline(self):
        parent = {**report(revision=BASE), "status": "missing", "samples": [],
                  "benchmarks": [{"label": "hosts/list/100", "status": "missing", "reason": "Fixture absent"}]}
        body = render(report(), {"parent": parent})
        self.assertIn("missing from baseline", body)
        self.assertIn("— → 20.00", body)
        self.assertIn("— → 30.00", body)
        self.assertIn("— → 2 (3)", body)
        self.assertIn("Fixture absent", body)

    def test_changed_fixtures_show_measurements_without_deltas(self):
        body = render(report(2), {"parent": report(20, scenario_hash="changed")})
        self.assertIn("20 → 2", body)
        self.assertIn("fixture or definition changed", body)
        self.assertNotIn("(-18)", body)
        self.assertIn("No comparable benchmarks", body)

    def test_markup_mentions_and_long_labels_are_bounded(self):
        head = report(label="<details>|@everyone[link](https://example.org)")
        body = render(head, {"parent": head})
        self.assertNotIn("@everyone", body)
        self.assertIn("&#124;&#64;everyone", body)
        head = report(label="a" * 10000)
        body = render(head, {"parent": head})
        self.assertLess(len(body), 5000)

    def test_archive_missing_invalid_or_oversized_is_error(self):
        with zipfile.ZipFile(io.BytesIO(archive_bytes({"head": report(), "parent": []}))) as archive:
            self.assertEqual(archive_report(archive, "head")["status"], "ok")
            self.assertEqual(archive_report(archive, "parent")["status"], "error")
            self.assertEqual(archive_report(archive, "master")["status"], "error")
            with patch("ci.query_bench.reporting.MAX_REPORT_BYTES", 5):
                self.assertEqual(archive_report(archive, "head")["status"], "error")


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.run = {
            "id": 42, "run_attempt": 1, "event": "pull_request", "status": "completed", "conclusion": "success",
            "repository": {"full_name": "org/repo"}, "path": ".github/workflows/query-profiles.yml",
            "head_sha": HEAD, "head_branch": "feature", "pull_requests": [],
            "head_repository": {"full_name": "contributor/repo", "owner": {"login": "contributor"}},
        }
        self.pr = {
            "number": 7, "state": "open",
            "head": {"sha": HEAD, "ref": "feature", "repo": {"full_name": "contributor/repo"}},
            "base": {"sha": BASE, "ref": "stacked", "repo": {"full_name": "org/repo"}},
        }
        self.comments = []
        self.reports = {"head": report(), "parent": report(revision=BASE), "master": report(revision=BASE)}
        self.artifacts = [{"id": 9, "name": "query-profile-comparison", "expired": False, "size_in_bytes": 1024}]
        self.fresh_pr = None
        self.writes = []

    def fake_api(self, path, **kwargs):
        if "body" in kwargs:
            self.writes.append((path, kwargs))
            return {}
        if path.endswith("/actions/runs/42"):
            return self.run
        if "/pulls?" in path:
            return [[self.pr]]
        if path.endswith("/artifacts?per_page=100"):
            return [{"artifacts": self.artifacts}]
        if path.endswith("/artifacts/9/zip"):
            return archive_bytes(self.reports)
        if path.endswith("/comments?per_page=100"):
            return [self.comments]
        if path.endswith("/pulls/7"):
            return self.fresh_pr or self.pr
        self.fail(f"Unexpected API call: {path}")

    def publish(self, event=None):
        with patch("ci.query_bench.github.api", side_effect=self.fake_api), redirect_stdout(io.StringIO()):
            publish(event or {"workflow_run": self.run}, "org/repo")

    def bot_comment(self, run_id=41, attempt=1):
        return {"id": 123, "body": f"{MARKER}\n<!-- query-profile-run:{run_id}:{attempt} -->\nold report",
                "user": {"login": "github-actions[bot]", "type": "Bot"}}

    def test_fork_without_pr_array_resolves_by_github_metadata_and_posts(self):
        self.publish()
        self.assertEqual(len(self.writes), 1)
        path, request = self.writes[0]
        self.assertEqual(path, "repos/org/repo/issues/7/comments")
        self.assertEqual(request["method"], "POST")
        self.assertIn("<code>master</code>", request["body"]["body"])

    def test_master_target_only_reports_parent(self):
        self.pr["base"]["ref"] = "master"
        self.publish()
        self.assertNotIn("<code>master</code>", self.writes[0][1]["body"]["body"])

    def test_updates_only_its_bot_comment_and_keeps_newer_results(self):
        human = self.bot_comment()
        human["user"] = {"login": "contributor", "type": "User"}
        self.comments = [human, self.bot_comment()]
        self.publish()
        self.assertEqual(self.writes[0][0], "repos/org/repo/issues/comments/123")
        self.assertEqual(self.writes[0][1]["method"], "PATCH")
        for comment in (self.bot_comment(43), self.bot_comment(42, 2)):
            self.writes.clear()
            self.comments = [comment]
            self.publish()
            self.assertFalse(self.writes)

    def test_human_marker_is_not_overwritten(self):
        human = self.bot_comment()
        human["user"] = {"login": "contributor", "type": "User"}
        self.comments = [human]
        self.publish()
        self.assertEqual(self.writes[0][1]["method"], "POST")

    def test_stale_sha_closed_pr_or_different_fork_cannot_receive_comment(self):
        original = copy.deepcopy(self.pr)
        for kind in ("sha", "fork", "closed"):
            self.pr = copy.deepcopy(original)
            if kind == "sha":
                self.pr["head"]["sha"] = "new"
            elif kind == "fork":
                self.pr["head"]["repo"]["full_name"] = "other/repo"
            else:
                self.pr["state"] = "closed"
            self.publish()
            self.assertFalse(self.writes)

    def test_recheck_rejects_push_or_retarget_during_reporting(self):
        for kind in ("head", "base"):
            self.fresh_pr = copy.deepcopy(self.pr)
            self.fresh_pr[kind]["sha"] = "new"
            self.publish()
            self.assertFalse(self.writes)

    def test_mismatched_report_revisions_are_not_published(self):
        for name in ("head", "parent"):
            with patch.dict(self.reports, {name: report(revision="wrong")}):
                self.publish()
                self.assertFalse(self.writes)

    def test_missing_artifact_is_failure_not_missing_baseline(self):
        self.artifacts = []
        self.publish()
        body = self.writes[0][1]["body"]["body"]
        self.assertIn("reporting failure", body)
        self.assertIn("/runs/42/attempts/1", body)

    def test_wrong_workflow_and_superseded_attempts_are_ignored(self):
        event = {"workflow_run": copy.deepcopy(self.run)}
        event["workflow_run"]["path"] = ".github/workflows/other.yml"
        self.publish(event)
        event["workflow_run"] = copy.deepcopy(self.run)
        self.run["run_attempt"] = 2
        self.publish(event)
        self.assertFalse(self.writes)

    def test_api_passes_comment_as_json_without_a_shell(self):
        body = {"body": "literal $(command) `text`\nnext line"}
        with patch("ci.query_bench.github.subprocess.run") as command:
            command.return_value.stdout = b"{}"
            self.assertEqual(api("repos/org/repo/issues/7/comments", method="POST", body=body), {})
        self.assertEqual(json.loads(command.call_args.kwargs["input"]), body)
        self.assertNotIn("shell", command.call_args.kwargs)
