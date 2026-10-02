#!/usr/bin/env python3
"""Publish query results using only trusted code from the default branch."""

import io
import json
import re
import subprocess
import zipfile
from urllib.parse import urlencode

from ci.query_bench.reporting import MARKER, archive_report, render_comment


def api(path, *, body=None, method="GET", paginate=False, binary=False):
    args = ["gh", "api", path, "--method", method]
    if paginate:
        args.extend(["--paginate", "--slurp"])
    if body is not None:
        args.extend(["--input", "-"])
    result = subprocess.run(
        args, input=json.dumps(body).encode() if body is not None else None, capture_output=True, check=True,
    ).stdout
    return result if binary else json.loads(result)


def matches_pr(pr, run, repository):
    return (
        pr["state"] == "open" and pr["base"]["repo"]["full_name"] == repository
        and pr["head"]["sha"] == run["head_sha"] and pr["head"]["ref"] == run["head_branch"]
        and pr["head"].get("repo") is not None
        and pr["head"]["repo"]["full_name"] == run["head_repository"]["full_name"]
    )


def existing_comment(comments):
    return next((comment for comment in comments if (
        comment["user"]["login"] == "github-actions[bot]" and comment["user"]["type"] == "Bot"
        and (comment.get("body") or "").startswith(MARKER)
    )), None)


def newer_comment(comment, run):
    version = re.search(r"<!-- query-profile-run:(\d+):(\d+) -->", comment["body"])
    return version is not None and tuple(map(int, version.groups())) > (run["id"], run["run_attempt"])


def publish(event, repository):
    run = event["workflow_run"]
    if (run["event"] != "pull_request" or run["repository"]["full_name"] != repository
            or run["path"] != ".github/workflows/query-profiles.yml"):
        print("Skipping an unrelated workflow run.")
        return
    root = f"repos/{repository}"
    current = api(f"{root}/actions/runs/{run['id']}")
    if current["status"] != "completed" or current["run_attempt"] != run["run_attempt"]:
        print("Skipping a superseded run attempt.")
        return
    # Fork workflow_run payloads can have an empty pull_requests array. Resolve
    # the PR through GitHub's API, never through a number supplied in an artifact.
    owner = run["head_repository"]["owner"]["login"]
    query = urlencode({"state": "open", "head": f"{owner}:{run['head_branch']}", "per_page": 100})
    prs = [pr for page in api(f"{root}/pulls?{query}", paginate=True) for pr in page if matches_pr(pr, run, repository)]
    if not prs:
        print("No open PR still matches this run's repository, branch and commit.")
        return
    artifacts = [artifact for page in api(f"{root}/actions/runs/{run['id']}/artifacts?per_page=100", paginate=True)
                 for artifact in page["artifacts"] if artifact["name"] == "query-profile-comparison" and not artifact["expired"]]
    archive = None
    if len(artifacts) == 1 and artifacts[0]["size_in_bytes"] <= 32 * 1024 * 1024:
        data = api(f"{root}/actions/artifacts/{artifacts[0]['id']}/zip", binary=True)
        try:
            archive = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            pass
    for pr in prs:
        run_url = f"https://github.com/{repository}/actions/runs/{run['id']}/attempts/{run['run_attempt']}"
        if archive is None:
            body = (f"{MARKER}\n<!-- query-profile-run:{run['id']}:{run['run_attempt']} -->\n"
                    f"## API benchmark comparison\n\n⚠️ The comparison report is unavailable for `{run['head_sha'][:7]}`. "
                    f"This is a reporting failure, not a missing baseline. [Inspect the CI run]({run_url}).\n")
        else:
            head = archive_report(archive, "head")
            baselines = {name: archive_report(archive, name)
                         for name in (["parent"] if pr["base"]["ref"] == "master" else ["parent", "master"])}
            if head["revision"] not in {run["head_sha"], "unknown"}:
                print("Skipping a report for a different head commit.")
                continue
            if baselines["parent"]["revision"] not in {pr["base"]["sha"], "unknown"}:
                print("Skipping a report whose target branch has moved or changed.")
                continue
            body = render_comment(head, baselines, sha=run["head_sha"], run_url=run_url,
                                  run_id=run["id"], attempt=run["run_attempt"], conclusion=run["conclusion"])
        comments = [comment for page in api(f"{root}/issues/{pr['number']}/comments?per_page=100", paginate=True) for comment in page]
        previous = existing_comment(comments)
        if previous and newer_comment(previous, run):
            print("Keeping the newer comment.")
            continue
        # Recheck after downloading reports; the contributor may have pushed.
        fresh = api(f"{root}/pulls/{pr['number']}")
        if (not matches_pr(fresh, run, repository)
                or any(fresh["base"][key] != pr["base"][key] for key in ("ref", "sha"))):
            print("The PR changed while preparing the report.")
            continue
        if previous:
            api(f"{root}/issues/comments/{previous['id']}", method="PATCH", body={"body": body})
        else:
            api(f"{root}/issues/{pr['number']}/comments", method="POST", body={"body": body})
        print(f"Updated query comparison for PR #{pr['number']}.")
