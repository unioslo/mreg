#!/usr/bin/env python3
"""Run a checkout's existing Django tests with automatic request profiling."""

import argparse
import json
import os
import subprocess
import sys
import traceback
from pathlib import Path

# Resolve tooling from this checkout, then application imports from the target.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ci.query_profiles import RequestProfiler, SCHEMA_VERSION  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, default=os.environ.get("MREG_QUERY_PROFILE_OUT"))
    parser.add_argument("tests", nargs=argparse.REMAINDER, help="Arguments after -- are passed to manage.py test")
    args = parser.parse_args(argv)
    if args.output is None:
        parser.error("--output or MREG_QUERY_PROFILE_OUT is required")
    checkout, output = args.checkout.resolve(), args.output.resolve()
    test_args = args.tests[1:] if args.tests[:1] == ["--"] else args.tests
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip()
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=checkout, text=True).strip():
        revision += " (working tree changes)"
    report = {"schema_version": SCHEMA_VERSION, "revision": revision, "status": "error", "samples": [], "tests": test_args}
    profiler = RequestProfiler(checkout)
    result = 1
    try:
        if not (checkout / "manage.py").is_file():
            report.update(status="missing", reason="This revision has no Django test entrypoint (manage.py).")
            return 0
        os.chdir(checkout)
        sys.path.insert(0, str(checkout))
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "mregsite.settings")
        # Preserve MREG's TESTING detection and keep request order deterministic.
        sys.argv = [str(checkout / "manage.py"), "test", *test_args, "--parallel=1", "--noinput"]
        from django.core.management import execute_from_command_line

        with profiler.installed():
            execute_from_command_line(sys.argv)
        result = 0
        report["status"] = "ok" if profiler.samples else "missing"
        if not profiler.samples:
            report["reason"] = "The selected tests produced no synchronous Django test-client requests."
    except SystemExit as exc:
        result = exc.code if isinstance(exc.code, int) else 1
        report["reason"] = f"The test runner exited with status {result}; this is not a missing baseline."
    except Exception:
        traceback.print_exc()
        report["reason"] = "Sampling failed; see the test log."
    finally:
        report["samples"] = profiler.samples
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2) + "\n")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
