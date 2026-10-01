"""One entry point for sampling, comparison, and PR comments."""

import json
import os
import sys
from pathlib import Path

# Also support `python /path/to/driver/ci/query_bench sample --checkout ...`
# and isolated Python mode in the trusted comment workflow.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in {"sample", "compare", "comment"}:
        raise SystemExit("Usage: python ci/query_bench {sample|compare|comment} [options]")
    command, args = sys.argv[1], sys.argv[2:]
    if command == "sample":
        from ci.query_bench.sampling import main as sample
        return sample(args)
    if command == "compare":
        from ci.query_bench.reporting import main as compare
        return compare(args)
    from ci.query_bench.github import publish
    publish(json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text()), os.environ["GITHUB_REPOSITORY"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
