from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from unittest import TestCase


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/generate-treetop-policy.py"
SPEC = importlib.util.spec_from_file_location("_generate_treetop_policy", SCRIPT)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError(f"Unable to load {SCRIPT}")
generator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = generator
SPEC.loader.exec_module(generator)


class TreeTopPolicyGeneratorTests(TestCase):
    permission_table = """\
Range             Group       Regex                     Labels
10.0.0.0/24       group two   ^web [0-9]+\\.example$        Shared, Unused
10.0.0.1/32       group two   ^web [0-9]+\\.example$        Shared
2001:db8::1/128   ipv6        .*\\.example$
"""
    role_table = """\
Name       Description with spaces       Labels
role1      A delegated role              Shared
role2      A role without permission     Missing
"""

    def test_parser_preserves_spaces_and_normalizes_values(self) -> None:
        permissions = generator.parse_permissions(self.permission_table)
        self.assertEqual(permissions[0].group, "group two")
        self.assertEqual(permissions[0].regex, r"^web [0-9]+\.example$")
        self.assertEqual(permissions[0].labels, ("Shared", "Unused"))
        self.assertEqual(permissions[-1].network, "2001:db8::1/128")

        roles = generator.parse_roles(self.role_table)
        self.assertEqual(roles[0].name, "role1")
        self.assertEqual(roles[0].labels, ("Shared",))

    def test_generation_uses_derived_labels_and_exact_roles(self) -> None:
        permissions = generator.parse_permissions(self.permission_table)
        roles = generator.parse_roles(self.role_table)
        result = generator.generate_policy(permissions, roles)
        report = json.loads(result.report)

        derived_label = report["derived_labels"][r"^web [0-9]+\.example$"]
        self.assertIn(f'resource.nameLabels.contains("{derived_label}")', result.cedar)
        self.assertIn('resource == MREG::HostPolicyRole::"role1"', result.cedar)
        self.assertNotIn("Shared", result.cedar)
        self.assertNotIn("Unused", result.labels)
        self.assertEqual(report["generated_role_rules"], 1)
        self.assertEqual(report["unused_permission_labels"], ["Unused"])
        self.assertEqual(report["unmatched_role_labels"], ["Missing"])

    def test_duplicate_rows_are_deduplicated_and_output_is_stable(self) -> None:
        permissions = generator.parse_permissions(self.permission_table + self.permission_table.splitlines()[1] + "\n")
        roles = generator.parse_roles(self.role_table)
        first = generator.generate_policy(permissions, roles)
        second = generator.generate_policy(tuple(reversed(permissions)), tuple(reversed(roles)))
        self.assertEqual(first, second)

    def test_rejects_malformed_input(self) -> None:
        with self.assertRaises(generator.ConversionError):
            generator.parse_permissions("Range Group Regex Labels\n10.0.0.0/24 g .* x\n")
        with self.assertRaises(generator.ConversionError):
            generator.parse_permissions(
                "Range          Group   Regex   Labels\n10.0.0.1/24   g       .*      \n"
            )

    def test_cli_check_detects_stale_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)
            self.assertEqual(
                generator.main(
                    [
                        "--permissions",
                        str(ROOT / "treetop/fixtures/network-permissions.txt"),
                        "--roles",
                        str(ROOT / "treetop/fixtures/hostpolicy-roles.txt"),
                        "--output-dir",
                        str(output_dir),
                    ]
                ),
                0,
            )
            self.assertEqual(
                generator.main(
                    [
                        "--permissions",
                        str(ROOT / "treetop/fixtures/network-permissions.txt"),
                        "--roles",
                        str(ROOT / "treetop/fixtures/hostpolicy-roles.txt"),
                        "--output-dir",
                        str(output_dir),
                        "--check",
                    ]
                ),
                0,
            )
