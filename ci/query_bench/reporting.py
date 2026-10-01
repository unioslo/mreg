"""Compare selected benchmarks and render the same report in CI and on PRs."""

import argparse
import html
import json
import math
import zipfile
from collections import Counter
from pathlib import Path

SCHEMA_VERSION = 2
MARKER = "<!-- mreg-query-profiles -->"
MAX_REPORT_BYTES = 8 * 1024 * 1024


def error_report():
    return {"schema_version": SCHEMA_VERSION, "revision": "unknown", "status": "error", "samples": [], "benchmarks": []}


def index_samples(report):
    if not isinstance(report, dict) or report.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("Unsupported or missing benchmark schema")
    if report.get("status") not in {"ok", "error", "missing"} or not isinstance(report.get("revision"), str):
        raise ValueError("Invalid benchmark run metadata")
    if not isinstance(report.get("samples"), list) or not isinstance(report.get("benchmarks"), list):
        raise ValueError("Missing benchmark samples or selection")
    if report["status"] == "ok" and not report["samples"]:
        raise ValueError("A successful run must contain measurements")
    selected = set()
    for case in report["benchmarks"]:
        if not isinstance(case["label"], str) or not case["label"] or case["label"] in selected:
            raise ValueError("Invalid or duplicate benchmark label")
        if case["status"] not in {"ok", "error", "missing"}:
            raise ValueError("Invalid benchmark status")
        selected.add(case["label"])
    indexed = {}
    for sample in report["samples"]:
        label = sample["label"]
        if label in indexed or label not in selected:
            raise ValueError("Duplicate or unselected benchmark sample")
        if type(sample["query_count"]) is not int or not 0 <= sample["query_count"] <= 1_000_000_000:
            raise ValueError("Invalid query count")
        for key in ("method", "route", "scenario_hash"):
            if not isinstance(sample[key], str) or not sample[key]:
                raise ValueError(f"Invalid sample {key}")
        if not isinstance(sample["shape"], dict) or not isinstance(sample["query"], list):
            raise ValueError("Invalid request workload")
        timing = sample["timing"]
        if type(timing["warmups"]) is not int or timing["warmups"] < 1:
            raise ValueError("Invalid warm-up count")
        if type(timing["runs"]) is not int or timing["runs"] < 2 or timing["runs"] != len(timing["samples_seconds"]):
            raise ValueError("Invalid timing sample count")
        for value in [*timing["samples_seconds"], timing["median_seconds"], timing["p95_seconds"]]:
            if type(value) not in (float, int) or not math.isfinite(value) or not 0 <= value <= 86400:
                raise ValueError("Invalid timing")
        indexed[label] = sample
    return indexed


def read_report(read):
    try:
        report = json.loads(read())
        index_samples(report)
        return report
    except (KeyError, TypeError, ValueError, OSError, OverflowError, zipfile.BadZipFile):
        return error_report()


def load_report(path):
    return read_report(lambda: Path(path).read_text())


def archive_report(archive, name):
    def read():
        member = archive.getinfo(f"query-profile-{name}/profile.json")
        if member.file_size > MAX_REPORT_BYTES:
            raise ValueError("Profile exceeds the report size limit")
        return archive.read(member)
    return read_report(read)


def compare(head, baseline):
    current, previous = index_samples(head), index_samples(baseline)
    selected = {case["label"] for report in (head, baseline) for case in report["benchmarks"]}
    rows = []
    for label in sorted(selected):
        new, old = current.get(label), previous.get(label)
        delta = None
        if head["status"] == "error" or baseline["status"] == "error":
            status = "sampling error"
        elif new is None and old is None:
            status = "missing from both"
        elif new is None:
            status = "missing from head"
        elif old is None:
            status = "missing from baseline"
        elif new["scenario_hash"] != old["scenario_hash"]:
            status = "fixture or definition changed"
        elif any(new[key] != old[key] for key in ("method", "route", "query", "shape")):
            status = "request or response workload changed"
        elif any(new["timing"][key] != old["timing"][key] for key in ("warmups", "runs")):
            status = "measurement settings changed"
        else:
            delta = new["query_count"] - old["query_count"]
            status = "regression" if delta > 0 else "improved" if delta < 0 else "unchanged"
        rows.append({"label": label, "status": status, "head": new, "baseline": old, "delta": delta})
    return rows


def code(value, limit=180):
    text = " ".join(str(value).split())
    if len(text) > limit:
        text = text[:limit - 1] + "…"
    return "<code>" + html.escape(text).replace("|", "&#124;").replace("@", "&#64;") + "</code>"


def failed_comparison(head, baselines, comparisons):
    return (head["status"] != "ok" or any(base["status"] == "error" for base in baselines.values())
            or any(row["status"] == "regression" for rows in comparisons.values() for row in rows))


def render_report(head, baselines):
    comparisons = {name: compare(head, baseline) for name, baseline in baselines.items()}
    counts = {name: Counter(row["status"] for row in rows) for name, rows in comparisons.items()}
    errors = head["status"] != "ok" or any(base["status"] == "error" for base in baselines.values())
    regressions = sum(count["regression"] for count in counts.values())
    matched = sum(count[status] for count in counts.values() for status in ("regression", "improved", "unchanged"))
    outcome = "⚪ No comparable benchmarks."
    if errors:
        outcome = "⚠️ Sampling or comparison failed — results are incomplete."
    elif regressions:
        outcome = "🔴 Query-count regressions detected."
    elif matched:
        outcome = "✅ No query-count regressions in comparable benchmarks."
    lines = ["## API benchmark comparison", "", f"**{outcome}**", "", f"Head: {code(head['revision'])}", "",
             "| Baseline | Compared | Regressions | Improved | Unchanged | Missing | Incomparable |",
             "|---|---:|---:|---:|---:|---:|---:|"]
    for name, baseline in baselines.items():
        count = counts[name]
        paired = sum(count[status] for status in ("regression", "improved", "unchanged"))
        missing = sum(value for status, value in count.items() if status.startswith("missing"))
        unknown = sum(value for status, value in count.items() if "changed" in status)
        label = f"{code(name)} {code(baseline['revision'][:7])}"
        if head["status"] == "error" or baseline["status"] == "error":
            lines.append(f"| {label} | Sampling error | — | — | — | — | — |")
        else:
            lines.append(f"| {label} | {paired} | {count['regression']} | {count['improved']} | "
                         f"{count['unchanged']} | {missing} | {unknown} |")
    lines.extend(["", "Only selected GET requests are benchmarked. Warm-ups and the separate SQL-count run are excluded from timings."])
    for name, rows in comparisons.items():
        lines.extend(["", f"### Against {code(name)}", "",
                      "| Benchmark | Queries: base → head | Median ms: base → head | p95 ms: base → head | "
                      "Runs (warm-ups): base → head | Result |",
                      "|---|---:|---:|---:|---:|---|"])
        for row in sorted(rows, key=lambda row: (row["status"] != "regression", row["label"]))[:20]:
            before, after = row["baseline"], row["head"]

            def value(sample, metric):
                if sample is None:
                    return "—"
                if metric == "queries":
                    return str(sample["query_count"])
                timing = sample["timing"]
                if metric == "runs":
                    return f"{timing['runs']} ({timing['warmups']})"
                return f"{timing[metric] * 1000:.2f}"

            queries = f"{value(before, 'queries')} → {value(after, 'queries')}"
            median = f"{value(before, 'median_seconds')} → {value(after, 'median_seconds')}"
            if row["delta"] is not None:
                queries += f" ({row['delta']:+d})"
                if before["timing"]["median_seconds"]:
                    percent = 100 * (after["timing"]["median_seconds"] / before["timing"]["median_seconds"] - 1)
                    median += f" ({percent:+.1f}%)"
            p95 = f"{value(before, 'p95_seconds')} → {value(after, 'p95_seconds')}"
            runs = f"{value(before, 'runs')} → {value(after, 'runs')}"
            lines.append(f"| {code(row['label'], 120)} | {queries} | {median} | {p95} | {runs} | {row['status']} |")
        if len(rows) > 20:
            lines.extend(["", f"Showing 20 of {len(rows)} benchmarks, regressions first; see the full JSON artifact."])
    reasons = [(name, case) for name, report in {"head": head, **baselines}.items()
               for case in report["benchmarks"] if case.get("reason")]
    if reasons:
        lines.extend(["", "<details><summary>Missing benchmarks and setup details</summary>", ""])
        for name, case in reasons[:10]:
            lines.append(f"- {code(name)} / {code(case['label'], 80)}: {code(case['reason'], 100)}")
        if len(reasons) > 10:
            lines.append("- Further setup details are in the JSON artifact.")
        lines.extend(["", "</details>"])
    lines.extend([
        "", "Missing measurements are not zero. Changed fixtures, definitions, workloads, or run settings are shown "
        "without calculated deltas. Query regressions fail CI; timing changes are informational.", "",
        "The **query-profile-comparison** artifact contains every timing sample, min/max, standard deviation, "
        "SQL attribution, and all comparison rows.",
    ])
    return "\n".join(lines) + "\n", failed_comparison(head, baselines, comparisons)


def render_comment(head, baselines, *, sha, run_url, run_id, attempt, conclusion):
    report, failed = render_report(head, baselines)
    if conclusion != "success" and not failed:
        report = "⚠️ The CI run did not succeed; inspect its logs before interpreting these measurements.\n\n" + report
    return (f"{MARKER}\n<!-- query-profile-run:{run_id}:{attempt} -->\n"
            f"[CI run and full reports]({run_url}) · Commit {code(sha[:7])}\n\n{report}\n"
            "This comment is updated in place for each completed run.\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--head", required=True, type=Path)
    parser.add_argument("--baseline", required=True, action="append", metavar="NAME=PATH")
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--json", required=True, type=Path)
    args = parser.parse_args(argv)
    head, baselines = load_report(args.head), {}
    for spec in args.baseline:
        name, separator, path = spec.partition("=")
        if not separator or not name or not path or name in baselines:
            parser.error("Baselines must have unique names and use NAME=PATH")
        baselines[name] = load_report(path)
    summary, failed = render_report(head, baselines)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(summary)
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps({name: compare(head, baseline) for name, baseline in baselines.items()}, indent=2) + "\n")
    print(summary)
    return int(failed)
