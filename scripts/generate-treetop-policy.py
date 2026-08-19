#!/usr/bin/env python3
"""Generate TreeTop policy data from existing MREG API endpoints."""

from pathlib import Path
from runpy import run_path


ROOT = Path(__file__).resolve().parents[1]
main = run_path(str(ROOT / "mreg/policy/treetop_generator.py"))["main"]


if __name__ == "__main__":
    raise SystemExit(main())
