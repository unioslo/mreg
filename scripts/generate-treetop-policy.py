#!/usr/bin/env python3
"""Generate TreeTop policy data from deterministic mreg-cli table output."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mreg.policy.treetop_generator import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
