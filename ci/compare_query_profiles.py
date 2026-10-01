#!/usr/bin/env python3
"""Render request-query comparisons and fail on regressions or sampling errors."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ci.query_profiles import SCHEMA_VERSION, compare, index_samples, markdown_report  # noqa: E402


def load_report(path):
    try:
        report = json.loads(Path(path).read_text())
        index_samples(report)
        if not isinstance(report["revision"], str):
            raise ValueError("Invalid revision")
        return report
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {
            "schema_version": SCHEMA_VERSION, "revision": "unknown", "status": "error", "samples": [],
            "reason": f"Missing or invalid report {path}: {exc}",
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--head", required=True, type=Path)
    parser.add_argument("--baseline", required=True, action="append", metavar="NAME=PATH")
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--json", required=True, type=Path)
    args = parser.parse_args(argv)
    head = load_report(args.head)
    baselines = {}
    for spec in args.baseline:
        name, separator, path = spec.partition("=")
        if not separator or not name or not path or name in baselines:
            parser.error("Baselines must have unique names and use NAME=PATH")
        baselines[name] = load_report(path)
    summary, failed = markdown_report(head, baselines)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(summary)
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps({name: compare(head, baseline) for name, baseline in baselines.items()}, indent=2) + "\n")
    print(summary)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
