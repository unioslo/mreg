from __future__ import annotations

import json
from pathlib import Path
import tempfile
from unittest import TestCase
from unittest.mock import patch

from mreg.policy import treetop_generator as generator


class JsonResponse:
    def __init__(self, url: str, payload: object) -> None:
        self.url = url
        self.payload = payload

    def __enter__(self) -> JsonResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def geturl(self) -> str:
        return self.url

    def read(self) -> bytes:
        return json.dumps(self.payload).encode()


class RawResponse(JsonResponse):
    def read(self) -> bytes:
        assert isinstance(self.payload, bytes)
        return self.payload


class TreeTopPolicyGeneratorTests(TestCase):
    snapshot_payload = {
        "schema_version": generator.SNAPSHOT_SCHEMA_VERSION,
        "permissions": [
            {
                "range": "10.0.0.0/24",
                "group": "group two",
                "regex": r"^web [0-9]+\.example$",
                "labels": ["Shared", "Unused"],
            },
            {
                "range": "10.0.0.1/32",
                "group": "group two",
                "regex": r"^web [0-9]+\.example$",
                "labels": ["Shared"],
            },
            {
                "range": "2001:db8::1/128",
                "group": "ipv6",
                "regex": r".*\.example$",
                "labels": [],
            },
        ],
        "roles": [
            {"name": "role1", "labels": ["Shared"]},
            {"name": "role2", "labels": ["Missing"]},
        ],
    }

    def snapshot(self, payload: object | None = None) -> str:
        return json.dumps(self.snapshot_payload if payload is None else payload)

    def test_snapshot_parser_preserves_spaces_and_normalizes_values(self) -> None:
        permissions, roles = generator.parse_snapshot(self.snapshot())

        self.assertEqual(permissions[0].group, "group two")
        self.assertEqual(permissions[0].regex, r"^web [0-9]+\.example$")
        self.assertEqual(permissions[0].labels, ("Shared", "Unused"))
        self.assertEqual(permissions[-1].network, "2001:db8::1/128")
        self.assertEqual(roles[0].name, "role1")
        self.assertEqual(roles[0].labels, ("Shared",))

    def test_generation_uses_derived_labels_and_exact_roles(self) -> None:
        permissions, roles = generator.parse_snapshot(self.snapshot())
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

    def test_duplicate_permission_rows_are_deduplicated_and_output_is_stable(self) -> None:
        payload = json.loads(self.snapshot())
        payload["permissions"].append(dict(payload["permissions"][0]))
        permissions, roles = generator.parse_snapshot(self.snapshot(payload))

        self.assertEqual(len(permissions), 3)
        first = generator.generate_policy(permissions, roles)
        second = generator.generate_policy(tuple(reversed(permissions)), tuple(reversed(roles)))
        self.assertEqual(first, second)

    def test_rejects_malformed_snapshot(self) -> None:
        with self.assertRaisesRegex(generator.ConversionError, "valid JSON"):
            generator.parse_snapshot("{")

        payload = json.loads(self.snapshot())
        payload["schema_version"] = 99
        with self.assertRaisesRegex(generator.ConversionError, "schema_version"):
            generator.parse_snapshot(self.snapshot(payload))

        payload = json.loads(self.snapshot())
        payload["permissions"][0]["range"] = "10.0.0.1/24"
        with self.assertRaisesRegex(generator.ConversionError, "Invalid permission range"):
            generator.parse_snapshot(self.snapshot(payload))

        payload = json.loads(self.snapshot())
        payload["roles"].append(dict(payload["roles"][0]))
        with self.assertRaisesRegex(generator.ConversionError, "Duplicate host-policy role"):
            generator.parse_snapshot(self.snapshot(payload))

        invalid_payloads = [
            ([], "snapshot must be a JSON object"),
            ({"schema_version": 1, "permissions": None, "roles": []}, "permissions must be a JSON array"),
            (
                {
                    "schema_version": 1,
                    "permissions": [{"range": "10.0.0.0/24", "regex": ".*", "labels": []}],
                    "roles": [{"name": "role1", "labels": []}],
                },
                "group must be a non-empty string",
            ),
            (
                {
                    "schema_version": 1,
                    "permissions": [{"range": "10.0.0.0/24", "group": "group", "regex": "[", "labels": []}],
                    "roles": [{"name": "role1", "labels": []}],
                },
                "Invalid permission regex",
            ),
            (
                {
                    "schema_version": 1,
                    "permissions": [{"range": "10.0.0.0/24", "group": "group", "regex": ".*", "labels": [1]}],
                    "roles": [{"name": "role1", "labels": []}],
                },
                "must contain only non-empty strings",
            ),
            ({"schema_version": 1, "permissions": [], "roles": []}, "permissions contains no data rows"),
            (
                {
                    "schema_version": 1,
                    "permissions": [{"range": "10.0.0.0/24", "group": "group", "regex": ".*", "labels": []}],
                    "roles": [],
                },
                "roles contains no data rows",
            ),
        ]
        for invalid_payload, error in invalid_payloads:
            with self.subTest(error=error), self.assertRaisesRegex(generator.ConversionError, error):
                generator.parse_snapshot(self.snapshot(invalid_payload))

    def test_endpoint_rows_resolve_label_ids_to_names(self) -> None:
        snapshot = generator.snapshot_from_endpoint_rows(
            permission_rows=[
                {
                    "range": "10.0.0.0/24",
                    "group": "group two",
                    "regex": r".*\.example$",
                    "labels": [2, 1],
                }
            ],
            role_rows=[{"name": "role1", "labels": [1]}],
            label_rows=[{"id": 1, "name": "Shared"}, {"id": 2, "name": "Unused"}],
        )

        permissions, roles = generator.parse_snapshot(snapshot)
        self.assertEqual(permissions[0].labels, ("Shared", "Unused"))
        self.assertEqual(roles[0].labels, ("Shared",))

        with self.assertRaisesRegex(generator.ConversionError, "unknown label id 3"):
            generator.snapshot_from_endpoint_rows(
                permission_rows=[
                    {
                        "range": "10.0.0.0/24",
                        "group": "group two",
                        "regex": ".*",
                        "labels": [3],
                    }
                ],
                role_rows=[{"name": "role1", "labels": []}],
                label_rows=[{"id": 1, "name": "Shared"}],
            )

        label_errors = [
            ([{"id": True, "name": "Shared"}], "id must be an integer"),
            ([{"id": 1, "name": "Shared"}, {"id": 1, "name": "Other"}], "Duplicate label id"),
            ([{"id": 1, "name": "Shared"}, {"id": 2, "name": "Shared"}], "Duplicate label name"),
        ]
        for labels, error in label_errors:
            with self.subTest(error=error), self.assertRaisesRegex(generator.ConversionError, error):
                generator.snapshot_from_endpoint_rows([], [], labels)

        with self.assertRaisesRegex(generator.ConversionError, "integer label ids"):
            generator.snapshot_from_endpoint_rows(
                permission_rows=[
                    {"range": "10.0.0.0/24", "group": "group", "regex": ".*", "labels": ["Shared"]}
                ],
                role_rows=[],
                label_rows=[{"id": 1, "name": "Shared"}],
            )

    def test_fetches_all_endpoint_pages_with_token_authentication(self) -> None:
        calls: list[tuple[str, str | None, float]] = []

        def fake_urlopen(request, timeout: float) -> JsonResponse:
            calls.append((request.full_url, request.get_header("Authorization"), timeout))
            if "/labels/" in request.full_url and "page=2" not in request.full_url:
                return JsonResponse(
                    request.full_url,
                    {
                        "next": "/api/v1/labels/?ordering=name&page=2&page_size=1000",
                        "results": [{"id": 1, "name": "Shared"}],
                    },
                )
            if "/labels/" in request.full_url:
                return JsonResponse(
                    request.full_url,
                    {"next": None, "results": [{"id": 2, "name": "Unused"}]},
                )
            if "/permissions/netgroupregex/" in request.full_url:
                return JsonResponse(
                    request.full_url,
                    {
                        "next": None,
                        "results": [
                            {
                                "range": "10.0.0.0/24",
                                "group": "group two",
                                "regex": r".*\.example$",
                                "labels": [2, 1],
                            }
                        ],
                    },
                )
            return JsonResponse(
                request.full_url,
                {"next": None, "results": [{"name": "role1", "labels": [1]}]},
            )

        with patch.object(generator, "urlopen", side_effect=fake_urlopen):
            snapshot = generator.fetch_policy_snapshot("https://mreg.example/", "secret", 3.5)

        permissions, roles = generator.parse_snapshot(snapshot)
        self.assertEqual(permissions[0].labels, ("Shared", "Unused"))
        self.assertEqual(roles[0].labels, ("Shared",))
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(auth == "Token secret" for _url, auth, _timeout in calls))
        self.assertTrue(all(timeout == 3.5 for _url, _auth, timeout in calls))
        self.assertTrue(all(url.startswith("https://mreg.example/") for url, _auth, _timeout in calls))
        self.assertIn("page_size=1000", calls[0][0])

    def test_rejects_invalid_endpoint_configuration_and_responses(self) -> None:
        invalid_configurations = [
            (("mreg.example", "secret", 1), "absolute HTTP"),
            (("https://user:password@mreg.example", "secret", 1), "must not contain credentials"),
            (("https://mreg.example", "", 1), "must be a non-empty HTTP header"),
            (("https://mreg.example", "value\nInjected: header", 1), "must be a non-empty HTTP header"),
            (("https://mreg.example", "secret", 0), "greater than zero"),
            (("https://mreg.example", "secret", float("nan")), "finite number"),
        ]
        for arguments, error in invalid_configurations:
            with self.subTest(error=error), self.assertRaisesRegex(generator.ConversionError, error):
                generator.fetch_policy_snapshot(*arguments)

        def fetch_one(response: object) -> None:
            with patch.object(generator, "urlopen", return_value=response):
                generator._fetch_paginated_rows(
                    base_url="https://mreg.example",
                    path="/api/v1/labels/",
                    token="secret",
                    timeout=1,
                    ordering="name",
                )

        invalid_responses = [
            (JsonResponse("https://other.example/api/v1/labels/", {"next": None, "results": []}), "response changed origin"),
            (RawResponse("https://mreg.example/api/v1/labels/", b"not json"), "returned invalid JSON"),
            (JsonResponse("https://mreg.example/api/v1/labels/", []), "must be a JSON object"),
            (JsonResponse("https://mreg.example/api/v1/labels/", {"next": None, "results": {}}), "results must be a JSON array"),
            (JsonResponse("https://mreg.example/api/v1/labels/", {"next": None, "results": [1]}), "must be a JSON object"),
            (JsonResponse("https://mreg.example/api/v1/labels/", {"next": 1, "results": []}), "next must be a URL or null"),
        ]
        for response, error in invalid_responses:
            with self.subTest(error=error), self.assertRaisesRegex(generator.ConversionError, error):
                fetch_one(response)

        initial_url = "https://mreg.example/api/v1/labels/?ordering=name&page_size=1000"
        pagination_errors = [
            ({"next": initial_url, "results": []}, "pagination loop"),
            ({"next": "https://other.example/api/v1/labels/", "results": []}, "pagination URL changed origin"),
        ]
        for payload, error in pagination_errors:
            with self.subTest(error=error), self.assertRaisesRegex(generator.ConversionError, error):
                fetch_one(JsonResponse(initial_url, payload))

        http_error = generator.HTTPError(initial_url, 401, "Unauthorized", {}, None)
        transport_errors = [
            (http_error, "returned HTTP 401"),
            (generator.URLError("connection refused"), "Unable to reach MREG API"),
        ]
        for error_response, error in transport_errors:
            with self.subTest(error=error), patch.object(generator, "urlopen", side_effect=error_response):
                with self.assertRaisesRegex(generator.ConversionError, error):
                    generator._fetch_paginated_rows(
                        base_url="https://mreg.example",
                        path="/api/v1/labels/",
                        token="secret",
                        timeout=1,
                        ordering="name",
                    )

    def test_cli_fetches_and_persists_current_api_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp_dir = Path(directory)
            snapshot_path = temp_dir / "fixtures" / "policy-source.json"
            output_dir = temp_dir / "output"
            snapshot = generator.serialize_snapshot(*generator.parse_snapshot(self.snapshot()))
            arguments = [
                "--api-base-url",
                "https://mreg.example",
                "--snapshot",
                str(snapshot_path),
                "--output-dir",
                str(output_dir),
            ]

            with (
                patch.dict(generator.os.environ, {"MREG_API_TOKEN": "secret"}),
                patch.object(generator, "fetch_policy_snapshot", return_value=snapshot) as fetch,
            ):
                self.assertEqual(generator.main(arguments), 0)
                self.assertEqual(generator.main([*arguments, "--check"]), 0)

            fetch.assert_called_with("https://mreg.example", "secret", 20.0)
            self.assertEqual(snapshot_path.read_text(), snapshot)

            snapshot_path.write_text("stale\n")
            with (
                patch.dict(generator.os.environ, {"MREG_API_TOKEN": "secret"}),
                patch.object(generator, "fetch_policy_snapshot", return_value=snapshot),
            ):
                self.assertEqual(generator.main([*arguments, "--check"]), 1)

            with patch.dict(generator.os.environ, {}, clear=True):
                self.assertEqual(generator.main(arguments), 2)

    def test_cli_check_detects_stale_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp_dir = Path(directory)
            snapshot_path = temp_dir / "policy-source.json"
            output_dir = temp_dir / "output"
            snapshot_path.write_text(self.snapshot())
            arguments = [
                "--api-base-url",
                "",
                "--snapshot",
                str(snapshot_path),
                "--output-dir",
                str(output_dir),
            ]

            self.assertEqual(generator.main(arguments), 0)
            self.assertEqual(generator.main([*arguments, "--check"]), 0)

            (output_dir / "netgroup.cedar").write_text("stale\n")
            self.assertEqual(generator.main([*arguments, "--check"]), 1)
