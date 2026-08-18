#!/usr/bin/env python3
"""Generate or verify the Cedar schema from MREG's policy contracts."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = Path("treetop/data/mreg.cedarschema")
CONTRACTS_PATH = ROOT / "mreg/policy/contracts.py"


def _render_cedar_schema() -> str:
    """Load the dependency-free contracts without importing the MREG package."""
    spec = importlib.util.spec_from_file_location("_mreg_policy_contracts", CONTRACTS_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load policy contracts from {CONTRACTS_PATH}")
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves annotations through the defining module while the
    # class decorators execute, so the standalone module must be registered.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.render_cedar_schema()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if the committed schema is stale")
    args = parser.parse_args()
    rendered = _render_cedar_schema()
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
