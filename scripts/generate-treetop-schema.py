#!/usr/bin/env python3
"""Generate or verify the Cedar schema from MREG's policy contracts."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mreg.policy.contracts import render_cedar_schema


SCHEMA_PATH = Path("treetop/data/mreg.cedarschema")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if the committed schema is stale")
    args = parser.parse_args()
    rendered = render_cedar_schema()
    if args.check:
        if not SCHEMA_PATH.exists() or SCHEMA_PATH.read_text() != rendered:
            print(f"{SCHEMA_PATH} is stale; run {sys.argv[0]}", file=sys.stderr)
            return 1
        print(f"{SCHEMA_PATH} matches the Python policy contracts")
        return 0
    SCHEMA_PATH.write_text(rendered)
    print(f"wrote {SCHEMA_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
