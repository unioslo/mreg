import gzip
import hashlib
import io
import json
import tarfile
import tempfile
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth.models import Group
from django.db import DatabaseError
from django.test import SimpleTestCase, TestCase, override_settings
from rest_framework.request import Request
from rest_framework.test import APIRequestFactory, force_authenticate
from unittest_parametrize import ParametrizedTestCase, param, parametrize

from mreg.api.v1.snapshot import (
    ARCHIVE_FORMAT,
    JSON_FORMAT,
    NetworkIndex,
    SnapshotArtifact,
    SnapshotData,
    SnapshotDataFile,
    SnapshotError,
    SnapshotFileResponse,
    SnapshotNotAcceptable,
    SnapshotRequestError,
    SnapshotUnavailable,
    SnapshotView,
    _attachment_items,
    _header_allows,
    _host_dns_record_items,
    _host_group_items,
    _ip_items,
    _normalized_mac,
    _parse_loc,
    _parse_request,
    _split_dns_character_strings,
    _validate_wildcard_hosts,
    _write_snapshot_data,
    create_snapshot_artifact,
    iter_deferred_record_items,
    iter_import_items,
    iter_permission_items,
)
from hostpolicy.models import HostPolicyAtom, HostPolicyRole
from mreg.models.base import Label, NameServer
from mreg.models.host import BACnetID, Host, HostContact, HostGroup, Ipaddress, PtrOverride
from mreg.models.network import NetGroupRegexPermission, Network, NetworkExcludedRange
from mreg.models.network_policy import (
    Community,
    HostCommunityMapping,
    NetworkPolicy,
    NetworkPolicyAttribute,
    NetworkPolicyAttributeValue,
)
from mreg.models.resource_records import Cname, Hinfo, Loc, Mx, Naptr, Srv, Sshfp, Txt
from mreg.models.zone import ForwardZone, ForwardZoneDelegation, ReverseZone, ReverseZoneDelegation


ITEMS = [
    {
        "ref": "nameserver:1",
        "kind": "nameserver",
        "operation": "create",
        "attributes": {"name": "ns1.example.org"},
    },
    {
        "ref": "forward_zone:1",
        "kind": "forward_zone",
        "operation": "create",
        "attributes": {
            "name": "example.org",
            "primary_ns": "ns1.example.org",
            "nameservers": ["nameserver:1"],
            "email": "hostmaster@example.org",
        },
    },
]

PERMISSIONS = [
    {
        "ref": "netgroup_regex_permission:7",
        "kind": "netgroup_regex_permission",
        "operation": "create",
        "attributes": {
            "group": "dns-admins",
            "range": "192.0.2.0/24",
            "regex": r".*\.example\.org",
            "labels": ["production"],
        },
    }
]

DEFERRED_RECORDS = [
    {
        "ref": "record_hinfo:9",
        "kind": "record",
        "operation": "create",
        "attributes": {
            "type_name": "HINFO",
            "owner_name": "*.example.org",
            "data": {"cpu": "x86_64", "os": "Linux"},
        },
        "deferred": {
            "reason": "wildcard_owner_not_supported_by_import_contract",
            "requires_manual_handling": True,
        },
    }
]


def write_values(path, values):
    digest = hashlib.sha256()
    with path.open("wb") as output:
        for value in values:
            line = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
            output.write(line)
            digest.update(line)
    return SnapshotDataFile(path=path, count=len(values), sha256=digest.hexdigest())


def fake_write_snapshot_data(directory, chunk_size, *, include_permissions):
    items = write_values(directory / "items.ndjson", ITEMS)
    deferred_records = write_values(
        directory / "deferred-records.ndjson",
        DEFERRED_RECORDS,
    )
    permissions = write_values(directory / "permissions.ndjson", PERMISSIONS) if include_permissions else None
    return SnapshotData(
        items=items,
        deferred_records=deferred_records,
        permissions=permissions,
        database_timestamp=datetime(2026, 7, 12, 10, 14, 58, tzinfo=timezone.utc),
    )


@override_settings(MREG_SNAPSHOT_TMPDIR=None, MREG_SNAPSHOT_CHUNK_SIZE=10)
class SnapshotArtifactTests(ParametrizedTestCase, SimpleTestCase):
    @mock.patch("mreg.api.v1.snapshot._write_snapshot_data", side_effect=fake_write_snapshot_data)
    def test_archive_contract(self, _write_snapshot_data):
        artifact = create_snapshot_artifact(ARCHIVE_FORMAT, "snapshotter", "mreg.example.org")
        try:
            compressed = artifact.path.read_bytes()
            self.assertEqual(hashlib.sha256(compressed).hexdigest(), artifact.digest_hex)
            with tarfile.open(fileobj=io.BytesIO(compressed), mode="r:gz") as archive:
                self.assertEqual(
                    archive.getnames(),
                    ["manifest.json", "items.ndjson", "deferred-records.ndjson"],
                )
                manifest = json.load(archive.extractfile("manifest.json"))
                item_bytes = archive.extractfile("items.ndjson").read()
                deferred_bytes = archive.extractfile("deferred-records.ndjson").read()
            self.assertEqual(manifest["format"], "no.uio.mreg.snapshot")
            self.assertEqual(manifest["format_version"], 1)
            self.assertTrue(manifest["snapshot"]["consistent"])
            self.assertEqual(manifest["items"]["count"], 2)
            self.assertEqual(manifest["items"]["sha256"], hashlib.sha256(item_bytes).hexdigest())
            self.assertFalse(manifest["semantics"]["fully_importable"])
            self.assertEqual(manifest["deferred_records"]["count"], 1)
            self.assertEqual(
                manifest["deferred_records"]["sha256"],
                hashlib.sha256(deferred_bytes).hexdigest(),
            )
            self.assertEqual([json.loads(line) for line in item_bytes.splitlines()], ITEMS)
            self.assertEqual(
                [json.loads(line) for line in deferred_bytes.splitlines()],
                DEFERRED_RECORDS,
            )
        finally:
            artifact.cleanup()

    @mock.patch("mreg.api.v1.snapshot._write_snapshot_data", side_effect=fake_write_snapshot_data)
    def test_json_import_contract(self, _write_snapshot_data):
        artifact = create_snapshot_artifact(JSON_FORMAT, "snapshotter", "mreg.example.org")
        try:
            with gzip.open(artifact.path, "rt", encoding="utf-8") as source:
                document = json.load(source)
            self.assertEqual(
                document,
                {
                    "requested_by": "snapshotter",
                    "items": ITEMS,
                    "deferred_records": DEFERRED_RECORDS,
                },
            )
        finally:
            artifact.cleanup()

    @mock.patch("mreg.api.v1.snapshot._write_snapshot_data", side_effect=fake_write_snapshot_data)
    def test_archive_can_include_permissions(self, _write_snapshot_data):
        artifact = create_snapshot_artifact(
            ARCHIVE_FORMAT,
            "snapshotter",
            "mreg.example.org",
            include_permissions=True,
        )
        try:
            with tarfile.open(artifact.path, mode="r:gz") as archive:
                self.assertEqual(
                    archive.getnames(),
                    [
                        "manifest.json",
                        "items.ndjson",
                        "deferred-records.ndjson",
                        "permissions.ndjson",
                    ],
                )
                manifest = json.load(archive.extractfile("manifest.json"))
                permission_bytes = archive.extractfile("permissions.ndjson").read()
            self.assertTrue(manifest["semantics"]["permissions_included"])
            self.assertEqual(manifest["permissions"]["count"], 1)
            self.assertEqual(
                manifest["permissions"]["sha256"],
                hashlib.sha256(permission_bytes).hexdigest(),
            )
            self.assertEqual(
                [json.loads(line) for line in permission_bytes.splitlines()],
                PERMISSIONS,
            )
        finally:
            artifact.cleanup()

    @parametrize(
        ("snapshot_format", "include_permissions"),
        [
            param("unsupported", False, id="unsupported_format"),
            param(JSON_FORMAT, True, id="json_with_permissions"),
        ],
    )
    def test_rejects_invalid_direct_options(self, snapshot_format, include_permissions):
        with self.assertRaises(SnapshotRequestError):
            create_snapshot_artifact(
                snapshot_format,
                "snapshotter",
                "mreg.example.org",
                include_permissions=include_permissions,
            )

    @mock.patch("mreg.api.v1.snapshot._write_snapshot_data")
    def test_rejects_empty_snapshot_data(self, write_snapshot_data):
        empty_file = SnapshotDataFile(path=Path("items.ndjson"), count=0, sha256=hashlib.sha256().hexdigest())
        write_snapshot_data.return_value = SnapshotData(
            items=empty_file,
            deferred_records=empty_file,
            permissions=None,
            database_timestamp=datetime(2026, 7, 12, 10, 14, 58, tzinfo=timezone.utc),
        )

        with self.assertRaisesMessage(SnapshotError, "contains no snapshot items"):
            create_snapshot_artifact(ARCHIVE_FORMAT, "snapshotter", "mreg.example.org")

    def test_file_response_cleans_up_if_initialization_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact_path = Path(directory) / "snapshot.tar.gz"
            artifact_path.write_bytes(b"snapshot")
            artifact = mock.Mock(spec=SnapshotArtifact)
            artifact.path = artifact_path
            artifact.filename = artifact_path.name
            artifact.content_type = "application/octet-stream"

            with (
                mock.patch("mreg.api.v1.snapshot.FileResponse.__init__", side_effect=RuntimeError("response failed")),
                self.assertRaisesMessage(RuntimeError, "response failed"),
            ):
                SnapshotFileResponse(artifact)

            artifact.cleanup.assert_called_once_with()

    def test_loc_conversion(self):
        value = _parse_loc("42 21 54 N 71 06 18 W -24m 30m", pk=1)
        self.assertAlmostEqual(value["latitude"], 42.365)
        self.assertAlmostEqual(value["longitude"], -71.105)
        self.assertEqual(value["altitude_m"], -24)
        self.assertEqual(value["size_m"], 30)

    def test_loc_conversion_rejects_incomplete_values(self):
        with self.assertRaisesMessage(SnapshotError, "LOC value cannot be translated"):
            _parse_loc("42 N 71 W", pk=7)

    def test_mac_normalization_handles_empty_and_invalid_values(self):
        self.assertIsNone(_normalized_mac(""))
        with self.assertRaisesMessage(SnapshotError, "Invalid MAC address"):
            _normalized_mac("not-a-mac")

    def test_txt_values_are_split_by_encoded_octets(self):
        chunks = _split_dns_character_strings("a" * 510 + "ø" * 128)
        self.assertEqual("".join(chunks), "a" * 510 + "ø" * 128)
        self.assertTrue(all(len(chunk.encode("utf-8")) <= 255 for chunk in chunks))


class SnapshotDataWritingTests(SimpleTestCase):
    def fake_connection(self, *, vendor="postgresql", execute_error=None):
        cursor = mock.MagicMock()
        cursor.fetchone.return_value = (datetime(2026, 7, 12, 10, 14, 58, tzinfo=timezone.utc),)
        if execute_error is not None:
            cursor.execute.side_effect = execute_error
        cursor_manager = mock.MagicMock()
        cursor_manager.__enter__.return_value = cursor
        connection = SimpleNamespace(vendor=vendor, cursor=mock.Mock(return_value=cursor_manager))
        return connection, cursor

    def test_writes_snapshot_data_and_metadata(self):
        connection, cursor = self.fake_connection()
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch("mreg.api.v1.snapshot.connection", connection),
            mock.patch("mreg.api.v1.snapshot.transaction.atomic", return_value=nullcontext()),
            mock.patch("mreg.api.v1.snapshot.iter_import_items", return_value=ITEMS),
            mock.patch("mreg.api.v1.snapshot.iter_deferred_record_items", return_value=DEFERRED_RECORDS),
            mock.patch("mreg.api.v1.snapshot.iter_permission_items", return_value=PERMISSIONS),
        ):
            data = _write_snapshot_data(Path(directory), 10, include_permissions=True)

        self.assertEqual(data.items.count, len(ITEMS))
        self.assertEqual(data.deferred_records.count, len(DEFERRED_RECORDS))
        self.assertEqual(data.permissions.count, len(PERMISSIONS))
        self.assertEqual(
            [call.args[0] for call in cursor.execute.call_args_list],
            [
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
                "SELECT transaction_timestamp()",
            ],
        )

    def test_rejects_non_postgresql_connections(self):
        connection, _cursor = self.fake_connection(vendor="sqlite")
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch("mreg.api.v1.snapshot.connection", connection),
            mock.patch("mreg.api.v1.snapshot.transaction.atomic", return_value=nullcontext()),
            self.assertRaisesMessage(SnapshotUnavailable, "consistent PostgreSQL snapshot"),
        ):
            _write_snapshot_data(Path(directory), 10, include_permissions=False)

    def test_translates_database_errors(self):
        connection, _cursor = self.fake_connection(execute_error=DatabaseError("database unavailable"))
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch("mreg.api.v1.snapshot.connection", connection),
            mock.patch("mreg.api.v1.snapshot.transaction.atomic", return_value=nullcontext()),
            self.assertRaisesMessage(SnapshotUnavailable, "consistent database snapshot could not be read"),
        ):
            _write_snapshot_data(Path(directory), 10, include_permissions=False)


class SnapshotTranslationValidationTests(ParametrizedTestCase, SimpleTestCase):
    def ip_row(self, *, pk=1, host_id=1, ipaddress="192.0.2.10", macaddress=None):
        return SimpleNamespace(
            pk=pk,
            host_id=host_id,
            ipaddress=ipaddress,
            macaddress=macaddress,
        )

    def test_wildcard_ip_assignment_rejects_mac_address(self):
        row = self.ip_row(macaddress="aa:bb:cc:dd:ee:ff")
        with (
            mock.patch("mreg.api.v1.snapshot._ip_rows", return_value=[row]),
            self.assertRaisesMessage(SnapshotError, "Wildcard IP assignment has a MAC address"),
        ):
            list(_attachment_items(mock.Mock(), {row.host_id}, 10))

    def test_attachment_requires_a_matching_network(self):
        row = self.ip_row()
        index = mock.Mock()
        index.match.return_value = None
        with (
            mock.patch("mreg.api.v1.snapshot._ip_rows", return_value=[row]),
            self.assertRaisesMessage(SnapshotError, "IP address is not contained in a network"),
        ):
            list(_attachment_items(index, set(), 10))

    def test_duplicate_attachment_is_emitted_once(self):
        rows = [
            self.ip_row(pk=1, ipaddress="192.0.2.10"),
            self.ip_row(pk=2, ipaddress="192.0.2.11"),
        ]
        index = mock.Mock()
        index.match.return_value = (7, "192.0.2.0/24")
        with mock.patch("mreg.api.v1.snapshot._ip_rows", return_value=rows):
            attachments = list(_attachment_items(index, set(), 10))

        self.assertEqual(len(attachments), 1)

    def ipaddress_model(self, *, duplicate=None, exists=False):
        manager = mock.MagicMock()
        duplicate_query = manager.values.return_value.annotate.return_value.filter.return_value.order_by.return_value
        duplicate_query.first.return_value = duplicate
        manager.filter.return_value.exists.return_value = exists
        return SimpleNamespace(objects=manager)

    def test_duplicate_ip_address_is_rejected(self):
        ipaddress_model = self.ipaddress_model(duplicate={"ipaddress": "192.0.2.10"})
        with (
            mock.patch("mreg.api.v1.snapshot.Ipaddress", ipaddress_model),
            self.assertRaisesMessage(SnapshotError, "assigned more than once"),
        ):
            list(_ip_items(mock.Mock(), set(), 10))

    def test_ip_address_requires_a_matching_network(self):
        row = self.ip_row()
        index = mock.Mock()
        index.match.return_value = None
        with (
            mock.patch("mreg.api.v1.snapshot.Ipaddress", self.ipaddress_model()),
            mock.patch("mreg.api.v1.snapshot._ip_rows", return_value=[row]),
            self.assertRaisesMessage(SnapshotError, "IP address is not contained in a network"),
        ):
            list(_ip_items(index, set(), 10))

    def model_with_manager(self, *, hosts=(), exists=False):
        manager = mock.MagicMock()
        manager.filter.return_value.exists.return_value = exists
        manager.filter.return_value.order_by.return_value.iterator.return_value = hosts
        return SimpleNamespace(objects=manager)

    def wildcard_host(self, *, comment=""):
        relation = mock.Mock()
        relation.exists.return_value = False
        return SimpleNamespace(
            pk=1,
            comment=comment,
            contacts=relation,
            hostgroups=relation,
            hostpolicyroles=relation,
        )

    def test_wildcard_host_requires_dns_data(self):
        host_model = self.model_with_manager(hosts=[self.wildcard_host()])
        empty_model = self.model_with_manager()
        specifications = ((empty_model, "TEST", mock.Mock(), mock.Mock()),)
        with (
            mock.patch("mreg.api.v1.snapshot.Host", host_model),
            mock.patch("mreg.api.v1.snapshot.Ipaddress", empty_model),
            mock.patch("mreg.api.v1.snapshot._HOST_RECORD_SPECIFICATIONS", specifications),
            self.assertRaisesMessage(SnapshotError, "has no translatable DNS data"),
        ):
            _validate_wildcard_hosts({1}, 10)

    @parametrize(
        ("comment", "has_bacnet_id"),
        [
            param("documented", False, id="comment"),
            param("", True, id="bacnet_id"),
        ],
    )
    def test_wildcard_host_rejects_non_dns_relationships(self, comment, has_bacnet_id):
        host = self.wildcard_host(comment=comment)
        with (
            mock.patch("mreg.api.v1.snapshot.Host", self.model_with_manager(hosts=[host])),
            mock.patch("mreg.api.v1.snapshot.Ipaddress", self.model_with_manager(exists=True)),
            mock.patch("mreg.api.v1.snapshot.BACnetID", self.model_with_manager(exists=has_bacnet_id)),
            mock.patch("mreg.api.v1.snapshot.HostCommunityMapping", self.model_with_manager()),
            self.assertRaisesMessage(SnapshotError, "has non-DNS relationships"),
        ):
            _validate_wildcard_hosts({1}, 10)

    def test_host_group_cycles_are_rejected(self):
        group = mock.Mock(pk=1)
        group.parent.all.return_value = [group]
        manager = mock.MagicMock()
        manager.prefetch_related.return_value.order_by.return_value = [group]
        with (
            mock.patch("mreg.api.v1.snapshot.HostGroup", SimpleNamespace(objects=manager)),
            self.assertRaisesMessage(SnapshotError, "contain a cycle"),
        ):
            list(_host_group_items(set()))


class SnapshotRequestTests(ParametrizedTestCase, SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    def request(self, path, **headers):
        return Request(self.factory.get(path, **headers))

    def test_defaults_to_archive(self):
        options = _parse_request(self.request("/api/v1/snapshot"))
        self.assertEqual(options.snapshot_format, ARCHIVE_FORMAT)
        self.assertFalse(options.include_permissions)

    def test_accepts_json_import(self):
        request = self.request(
            "/api/v1/snapshot?format=mreg-import-json-v1",
            HTTP_ACCEPT="application/json",
            HTTP_ACCEPT_ENCODING="gzip",
        )
        options = _parse_request(request)
        self.assertEqual(options.snapshot_format, JSON_FORMAT)
        self.assertFalse(options.include_permissions)

    def test_accepts_permissions_for_archive(self):
        options = _parse_request(self.request("/api/v1/snapshot?include_permissions=true"))
        self.assertTrue(options.include_permissions)

    def test_rejects_non_default_options(self):
        with self.assertRaises(SnapshotRequestError):
            _parse_request(self.request("/api/v1/snapshot?include_audit=true"))

    @parametrize(
        "header",
        [
            param("br, gzip;q=0", id="explicit_gzip"),
            param("gzip;q=0, *;q=1", id="gzip_overrides_wildcard"),
        ],
    )
    def test_rejects_explicitly_disabled_gzip(self, header):
        with self.assertRaises(SnapshotRequestError):
            _parse_request(self.request("/api/v1/snapshot", HTTP_ACCEPT_ENCODING=header))

    def test_rejects_explicitly_disabled_media_type(self):
        with self.assertRaises(SnapshotRequestError):
            _parse_request(
                self.request(
                    "/api/v1/snapshot",
                    HTTP_ACCEPT="application/vnd.uio.mreg-snapshot+tar;q=0, */*;q=1",
                )
            )

    def test_rejects_permissions_for_json_import(self):
        with self.assertRaises(SnapshotRequestError):
            _parse_request(self.request("/api/v1/snapshot?format=mreg-import-json-v1&include_permissions=true"))

    def test_rejects_invalid_permissions_value(self):
        with self.assertRaisesMessage(SnapshotRequestError, "must be 'true' or 'false'"):
            _parse_request(self.request("/api/v1/snapshot?include_permissions=yes"))

    @parametrize(
        "path",
        [
            param(
                "/api/v1/snapshot?format=mreg-snapshot-v1&format=mreg-import-json-v1",
                id="duplicate",
            ),
            param("/api/v1/snapshot?surprise=true", id="unknown"),
        ],
    )
    def test_rejects_duplicate_and_unknown_parameters(self, path):
        with self.assertRaises(SnapshotRequestError):
            _parse_request(self.request(path))

    def test_header_matching_handles_ranges_and_invalid_values(self):
        self.assertTrue(_header_allows("application/*", "application/json"))
        self.assertFalse(_header_allows("gzip;q=invalid", "gzip"))
        self.assertFalse(_header_allows("gzip;q=2", "gzip"))
        self.assertFalse(_header_allows("br", "gzip"))


@override_settings(MREG_SNAPSHOT_TMPDIR=None, MREG_SNAPSHOT_CHUNK_SIZE=10)
class SnapshotViewTests(ParametrizedTestCase, SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    def request(self, *, allowed, admin=False, path="/api/v1/snapshot", **headers):
        request = self.factory.get(path, **headers)
        user = SimpleNamespace(
            is_authenticated=True,
            is_mreg_snapshotter=allowed,
            is_mreg_superuser_or_admin=admin,
            username="snapshotter",
        )
        force_authenticate(request, user=user)
        return request

    def test_dedicated_permission_is_required(self):
        response = SnapshotView.as_view()(self.request(allowed=False))
        response.render()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertEqual(response.data["error"], "snapshot_forbidden")

    @mock.patch("mreg.api.v1.snapshot._write_snapshot_data", side_effect=fake_write_snapshot_data)
    def test_mreg_admin_can_create_snapshot(self, _write_snapshot_data):
        response = SnapshotView.as_view()(
            self.request(
                allowed=False,
                admin=True,
                HTTP_ACCEPT="application/vnd.uio.mreg-snapshot+tar",
                HTTP_ACCEPT_ENCODING="gzip",
            )
        )
        self.assertEqual(response.status_code, 200)
        response.close()

    @mock.patch("mreg.api.v1.snapshot._write_snapshot_data", side_effect=fake_write_snapshot_data)
    def test_response_headers_and_cleanup(self, _write_snapshot_data):
        response = SnapshotView.as_view()(
            self.request(
                allowed=True,
                HTTP_ACCEPT="application/vnd.uio.mreg-snapshot+tar",
                HTTP_ACCEPT_ENCODING="gzip",
            )
        )
        artifact_path = response.artifact.path
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Encoding"], "gzip")
        self.assertTrue(response["Content-Digest"].startswith("sha-256=:"))
        self.assertNotIn("Digest", response)
        self.assertTrue(response["ETag"].startswith('"snapshot-'))
        self.assertEqual(response["Cache-Control"], "private, no-store")
        self.assertTrue(artifact_path.exists())
        b"".join(response.streaming_content)
        response.close()
        self.assertFalse(artifact_path.exists())

    @mock.patch("mreg.api.v1.snapshot._write_snapshot_data", side_effect=fake_write_snapshot_data)
    def test_json_import_media_type_is_negotiated(self, _write_snapshot_data):
        response = SnapshotView.as_view()(
            self.request(
                allowed=True,
                path="/api/v1/snapshot?format=mreg-import-json-v1",
                HTTP_ACCEPT="application/json",
                HTTP_ACCEPT_ENCODING="gzip",
            )
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        response.close()

    @parametrize(
        ("error", "status_code", "error_code"),
        [
            param(
                SnapshotNotAcceptable("not acceptable"),
                406,
                "snapshot_not_acceptable",
                id="not_acceptable",
            ),
            param(
                SnapshotRequestError("invalid request"),
                400,
                "invalid_snapshot_request",
                id="invalid_request",
            ),
            param(
                SnapshotUnavailable("unavailable"),
                503,
                "snapshot_unavailable",
                id="unavailable",
            ),
            param(
                SnapshotError("invalid source", model="Host", object_id=7),
                409,
                "snapshot_failed",
                id="snapshot_error",
            ),
            param(
                OSError("disk unavailable"),
                503,
                "snapshot_unavailable",
                id="os_error",
            ),
        ],
    )
    def test_snapshot_errors_are_mapped_to_responses(self, error, status_code, error_code):
        with mock.patch("mreg.api.v1.snapshot.create_snapshot_artifact", side_effect=error):
            response = SnapshotView.as_view()(self.request(allowed=True))
        self.assertEqual(response.status_code, status_code)
        self.assertEqual(response.data["error"], error_code)
        if isinstance(error, SnapshotError) and error.model is not None:
            self.assertEqual(response.data["source"], {"model": "Host", "id": 7})

    def test_unsupported_media_type_uses_standard_drf_error_handling(self):
        response = SnapshotView.as_view()(self.request(allowed=True, HTTP_ACCEPT="text/plain"))
        self.assertEqual(response.status_code, 406)


class SnapshotItemTranslationTests(TestCase):
    """Exercise the complete successful legacy-to-snapshot translation graph."""

    @classmethod
    def setUpTestData(cls):
        cls.label = Label.objects.create(name="production", description="Production")
        cls.nameserver = NameServer.objects.create(name="ns1.example.org", ttl=3600)
        permission = NetGroupRegexPermission.objects.create(
            group="dns-admins",
            range="192.0.2.0/24",
            regex=r".*\.example\.org",
        )
        permission.labels.add(cls.label)

        cls.attribute = NetworkPolicyAttribute.objects.get(name="isolated")
        cls.policy = NetworkPolicy.objects.create(name="campus", description="Campus policy", community_template_pattern="community")
        NetworkPolicyAttributeValue.objects.create(policy=cls.policy, attribute=cls.attribute, value=True)
        cls.network = Network.objects.create(
            network="192.0.2.0/24",
            description="Example network",
            vlan=123,
            dns_delegated=True,
            category="server",
            location="Oslo",
            reserved=2,
            max_communities=5,
            policy=cls.policy,
        )
        NetworkExcludedRange.objects.create(network=cls.network, start_ip="192.0.2.200", end_ip="192.0.2.210")
        cls.community = Community.objects.create(name="web", description="Web", network=cls.network)

        cls.forward_zone = ForwardZone.objects.create(
            name="example.org",
            primary_ns=cls.nameserver.name,
            email="hostmaster@example.org",
        )
        cls.forward_zone.nameservers.add(cls.nameserver)
        cls.reverse_zone = ReverseZone.objects.create(
            name="2.0.192.in-addr.arpa",
            primary_ns=cls.nameserver.name,
            email="hostmaster@example.org",
        )
        cls.reverse_zone.nameservers.add(cls.nameserver)
        forward_delegation = ForwardZoneDelegation.objects.create(zone=cls.forward_zone, name="delegated.example.org", comment="Delegated")
        forward_delegation.nameservers.add(cls.nameserver)
        reverse_delegation = ReverseZoneDelegation.objects.create(
            zone=cls.reverse_zone, name="128-25.2.0.192.in-addr.arpa", comment="Delegated"
        )
        reverse_delegation.nameservers.add(cls.nameserver)

        cls.host = Host.objects.create(name="app.example.org", zone=cls.forward_zone, ttl=600, comment="Application")
        cls.ip = Ipaddress.objects.create(host=cls.host, ipaddress="192.0.2.20", macaddress="aa:bb:cc:dd:ee:ff")
        Hinfo.objects.create(host=cls.host, cpu="x86_64", os="Linux")
        Loc.objects.create(host=cls.host, loc="59 54 0 N 10 42 0 E 50m 1m 2m 3m")
        Mx.objects.create(host=cls.host, priority=10, mx="mail.example.org")
        Txt.objects.get_or_create(host=cls.host, txt="v=spf1 -all")
        cls.long_txt = Txt.objects.create(host=cls.host, txt="k" * 600)
        Naptr.objects.create(
            host=cls.host,
            order=100,
            preference=10,
            flag="s",
            service="sip",
            regex="",
            replacement="sip.example.org",
        )
        Sshfp.objects.create(
            host=cls.host,
            ttl=300,
            algorithm=4,
            hash_type=2,
            fingerprint="a" * 64,
        )
        Cname.objects.create(host=cls.host, zone=cls.forward_zone, name="alias.example.org", ttl=300)
        Srv.objects.create(
            host=cls.host,
            zone=cls.forward_zone,
            name="_https._tcp.example.org",
            priority=10,
            weight=5,
            port=443,
            ttl=300,
        )
        PtrOverride.objects.create(host=cls.host, ipaddress=cls.ip.ipaddress)
        BACnetID.objects.create(id=42, host=cls.host)
        contact = HostContact.objects.create(email="operator@example.org")
        contact.hosts.add(cls.host)

        owner = Group.objects.create(name="network-operators")
        parent = HostGroup.objects.create(name="all-servers", description="All servers")
        child = HostGroup.objects.create(name="web-servers", description="Web servers")
        child.parent.add(parent)
        child.hosts.add(cls.host)
        child.owners.add(owner)
        HostCommunityMapping.objects.create(host=cls.host, ipaddress=cls.ip, community=cls.community)

        atom = HostPolicyAtom.objects.create(name="patched", description="Patched")
        role = HostPolicyRole.objects.create(name="web", description="Web role")
        role.atoms.add(atom)
        role.hosts.add(cls.host)
        role.labels.add(cls.label)

        wildcard = Host.objects.create(name="*.wild.example.org", zone=cls.forward_zone, ttl=120)
        Ipaddress.objects.create(host=wildcard, ipaddress="192.0.2.99")
        Txt.objects.create(host=wildcard, txt="wildcard")
        Hinfo.objects.create(host=wildcard, cpu="x86_64", os="Linux")
        Loc.objects.create(host=wildcard, loc="59 54 0 N 10 42 0 E 50m")
        Sshfp.objects.create(
            host=wildcard,
            algorithm=4,
            hash_type=2,
            fingerprint="b" * 64,
        )

    def test_dependency_ordered_translation_covers_supported_legacy_models(self):
        items = list(iter_import_items(10))
        json.dumps(items)
        kinds = {item["kind"] for item in items}
        self.assertTrue(
            {
                "label",
                "nameserver",
                "network_policy_attribute",
                "network_policy",
                "network_policy_attribute_value",
                "network",
                "excluded_range",
                "community",
                "forward_zone",
                "reverse_zone",
                "forward_zone_delegation",
                "reverse_zone_delegation",
                "host",
                "host_attachment",
                "ip_address",
                "record",
                "ptr_override",
                "bacnet_id",
                "host_contact",
                "host_group",
                "attachment_community_assignment",
                "host_policy_atom",
                "host_policy_role",
                "host_policy_role_atom",
                "host_policy_role_host",
                "host_policy_role_label",
            }
            <= kinds
        )
        positions = {item["ref"]: index for index, item in enumerate(items)}
        attachment = next(item for item in items if item["kind"] == "host_attachment")
        address = next(item for item in items if item["kind"] == "ip_address")
        self.assertLess(positions[attachment["ref"]], positions[address["ref"]])
        self.assertEqual(address["attributes"]["attachment_id_ref"], attachment["ref"])
        wildcard_records = [item for item in items if item["kind"] == "record" and item["attributes"]["owner_name"] == "*.wild.example.org"]
        self.assertEqual({item["attributes"]["type_name"] for item in wildcard_records}, {"A", "TXT"})
        wildcard_txt_values = {
            tuple(item["attributes"]["data"]["value"]) for item in wildcard_records if item["attributes"]["type_name"] == "TXT"
        }
        self.assertIn(("wildcard",), wildcard_txt_values)
        long_txt_record = next(item for item in items if item["ref"] == f"record_txt:{self.long_txt.pk}")
        self.assertEqual(
            [len(chunk.encode("utf-8")) for chunk in long_txt_record["attributes"]["data"]["value"]],
            [255, 255, 90],
        )

        deferred_records = list(iter_deferred_record_items(10))
        self.assertEqual(
            {item["attributes"]["type_name"] for item in deferred_records},
            {"HINFO", "LOC", "SSHFP"},
        )
        self.assertTrue(all(item["deferred"]["requires_manual_handling"] for item in deferred_records))

        permissions = list(iter_permission_items(10))
        self.assertEqual(
            permissions,
            [
                {
                    "ref": f"netgroup_regex_permission:{NetGroupRegexPermission.objects.get().pk}",
                    "kind": "netgroup_regex_permission",
                    "operation": "create",
                    "attributes": {
                        "group": "dns-admins",
                        "range": "192.0.2.0/24",
                        "regex": r".*\.example\.org",
                        "labels": ["production"],
                    },
                }
            ],
        )

    def test_network_index_returns_none_when_no_network_matches(self):
        self.assertIsNone(NetworkIndex().match("203.0.113.1"))

    def test_mx_record_requires_a_forward_zone(self):
        host = Host.objects.create(name="orphan.example.org")
        Mx.objects.create(host=host, priority=10, mx="mail.example.org")

        with self.assertRaisesMessage(SnapshotError, "MX owner has no forward zone"):
            list(_host_dns_record_items(set(), 10, deferred=False))
