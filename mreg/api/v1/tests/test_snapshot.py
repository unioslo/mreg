import gzip
import hashlib
import io
import json
import tarfile
import tempfile
from contextlib import nullcontext
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import psycopg
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import DatabaseError, connection, connections
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings
from rest_framework.request import Request
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate
from unittest_parametrize import ParametrizedTestCase, param, parametrize

from mreg.api.v1.snapshot import (
    ARCHIVE_FORMAT,
    JSON_FORMAT,
    SNAPSHOT_ADVISORY_LOCK_ID,
    NetworkIndex,
    SnapshotArtifact,
    SnapshotData,
    SnapshotDataFile,
    SnapshotBusy,
    SnapshotError,
    SnapshotFileResponse,
    SnapshotLimitExceeded,
    SnapshotNotAcceptable,
    SnapshotRateThrottle,
    SnapshotRequestError,
    SnapshotResourceBudget,
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
    _topological_group_order,
    _write_snapshot_data,
    create_snapshot_artifact,
    iter_deferred_record_items,
    iter_deferred_items,
    iter_import_items,
    iter_permission_items,
    snapshot_generation_lock,
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
from mreg.models.snapshot import SnapshotThrottleState
from mreg.models.zone import ForwardZone, ForwardZoneDelegation, ReverseZone, ReverseZoneDelegation
from mreg.api.v1.tests.tests import MregAPITestCase


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

DEFERRED_ITEMS = [
    {
        "ref": "ip_address:42",
        "kind": "ip_address",
        "operation": "create",
        "attributes": {"host_name_ref": "host:7", "address": "198.51.100.20", "mac_address": "aa:bb:cc:dd:ee:ff"},
        "deferred": {"reasons": ["ip_address_outside_registered_networks"], "requires_manual_handling": True},
    }
]


def write_values(path, values):
    digest = hashlib.sha256()
    with path.open("wb") as output:
        for value in values:
            line = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"
            output.write(line)
            digest.update(line)
    return SnapshotDataFile(path=path, count=len(values), sha256=digest.hexdigest(), size=path.stat().st_size)


def fake_write_snapshot_data(directory, chunk_size, *, include_permissions, budget=None):
    items = write_values(directory / "items.ndjson", ITEMS)
    deferred_records = write_values(
        directory / "deferred-records.ndjson",
        DEFERRED_RECORDS,
    )
    permissions = write_values(directory / "permissions.ndjson", PERMISSIONS) if include_permissions else None
    return SnapshotData(
        items=items,
        deferred_records=deferred_records,
        deferred_items=write_values(directory / "deferred-items.ndjson", DEFERRED_ITEMS),
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
            self.assertEqual(artifact.path.stat().st_size, artifact.size)
            self.assertEqual([path.name for path in artifact.path.parent.iterdir()], [artifact.filename])
            with tarfile.open(fileobj=io.BytesIO(compressed), mode="r:gz") as archive:
                self.assertEqual(
                    archive.getnames(),
                    ["manifest.json", "items.ndjson", "deferred-records.ndjson", "deferred-items.ndjson"],
                )
                manifest = json.load(archive.extractfile("manifest.json"))
                item_bytes = archive.extractfile("items.ndjson").read()
                deferred_bytes = archive.extractfile("deferred-records.ndjson").read()
                deferred_item_bytes = archive.extractfile("deferred-items.ndjson").read()
            self.assertEqual(manifest["format"], "no.uio.mreg.snapshot")
            self.assertEqual(manifest["format_version"], 1)
            self.assertTrue(manifest["snapshot"]["consistent"])
            self.assertEqual(manifest["items"]["count"], 2)
            self.assertEqual(manifest["items"]["bytes"], len(item_bytes))
            self.assertEqual(manifest["items"]["sha256"], hashlib.sha256(item_bytes).hexdigest())
            self.assertFalse(manifest["semantics"]["fully_importable"])
            self.assertEqual(manifest["deferred_items"]["count"], len(DEFERRED_ITEMS))
            self.assertEqual(manifest["deferred_items"]["sha256"], hashlib.sha256(deferred_item_bytes).hexdigest())
            self.assertEqual([json.loads(line) for line in deferred_item_bytes.splitlines()], DEFERRED_ITEMS)
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

    def test_archive_accepts_members_at_the_ustar_size_limit(self):
        large_size = 8 * 1024**3
        copyfileobj = tarfile.copyfileobj

        def large_data(*args, **kwargs):
            data = fake_write_snapshot_data(*args, **kwargs)
            return replace(data, items=replace(data.items, size=large_size))

        def copy_without_large_payload(source, destination, length=None, **kwargs):
            # Exercise real tar header encoding without writing an 8 GiB body.
            if length != large_size:
                return copyfileobj(source, destination, length, **kwargs)

        with (
            mock.patch("mreg.api.v1.snapshot._write_snapshot_data", side_effect=large_data),
            mock.patch("tarfile.copyfileobj", side_effect=copy_without_large_payload),
        ):
            artifact = create_snapshot_artifact(ARCHIVE_FORMAT, "snapshotter", "mreg.example.org")
        try:
            with tarfile.open(artifact.path, mode="r:gz") as archive:
                self.assertEqual(archive.next().name, "manifest.json")
                member = archive.next()
                self.assertEqual(member.name, "items.ndjson")
                self.assertEqual(member.size, large_size)
                self.assertEqual(member.pax_headers["size"], str(large_size))
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
                    "deferred_items": DEFERRED_ITEMS,
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
                        "deferred-items.ndjson",
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
        empty_file = SnapshotDataFile(path=Path("items.ndjson"), count=0, sha256=hashlib.sha256().hexdigest(), size=0)
        write_snapshot_data.return_value = SnapshotData(
            items=empty_file,
            deferred_records=empty_file,
            deferred_items=empty_file,
            permissions=None,
            database_timestamp=datetime(2026, 7, 12, 10, 14, 58, tzinfo=timezone.utc),
        )

        with self.assertRaisesMessage(SnapshotError, "contains no snapshot items"):
            create_snapshot_artifact(ARCHIVE_FORMAT, "snapshotter", "mreg.example.org")

    @parametrize("snapshot_format", [param(ARCHIVE_FORMAT, id="archive"), param(JSON_FORMAT, id="json")])
    def test_snapshot_with_only_deferred_data_is_not_empty(self, snapshot_format):
        def deferred_only(directory, chunk_size, **kwargs):
            data = fake_write_snapshot_data(directory, chunk_size, **kwargs)
            return replace(data, items=write_values(data.items.path, []))

        with mock.patch("mreg.api.v1.snapshot._write_snapshot_data", side_effect=deferred_only):
            artifact = create_snapshot_artifact(snapshot_format, "snapshotter", "mreg.example.org")
        try:
            if snapshot_format == ARCHIVE_FORMAT:
                with tarfile.open(artifact.path, mode="r:gz") as archive:
                    manifest = json.load(archive.extractfile("manifest.json"))
                self.assertEqual(manifest["items"]["count"], 0)
                self.assertFalse(manifest["semantics"]["fully_importable"])
                self.assertEqual(manifest["deferred_items"]["count"], len(DEFERRED_ITEMS))
            else:
                data = json.loads(gzip.decompress(artifact.path.read_bytes()))
                self.assertEqual(data["items"], [])
                self.assertEqual(data["deferred_items"], DEFERRED_ITEMS)
        finally:
            artifact.cleanup()

    @override_settings(MREG_SNAPSHOT_MAX_BYTES=1)
    @mock.patch("mreg.api.v1.snapshot._write_snapshot_data", side_effect=fake_write_snapshot_data)
    def test_rejects_artifact_over_storage_limit(self, _write_snapshot_data):
        with self.assertRaisesMessage(SnapshotLimitExceeded, "storage limit"):
            create_snapshot_artifact(ARCHIVE_FORMAT, "snapshotter", "mreg.example.org")

    @override_settings(MREG_SNAPSHOT_CHUNK_SIZE=0)
    def test_rejects_invalid_chunk_size(self):
        with self.assertRaisesMessage(SnapshotUnavailable, "must be positive"):
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
        for value in ("not-a-mac", "gg:gg:gg:gg:gg:gg", "åå:åå:åå:åå:åå:åå", "aa!!bb!!cc!!dd!!ee!!ff"):
            with self.subTest(value=value), self.assertRaisesMessage(SnapshotError, "Invalid MAC address"):
                _normalized_mac(value)
        self.assertEqual(_normalized_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")

    def test_txt_values_are_split_by_encoded_octets(self):
        chunks = _split_dns_character_strings("a" * 510 + "ø" * 128)
        self.assertEqual("".join(chunks), "a" * 510 + "ø" * 128)
        self.assertTrue(all(len(chunk.encode("utf-8")) <= 255 for chunk in chunks))

    def test_resource_budget_enforces_size_and_deadline(self):
        with self.assertRaisesMessage(SnapshotLimitExceeded, "storage limit"):
            SnapshotResourceBudget(max_bytes=1, deadline=float("inf")).consume(2)
        with self.assertRaisesMessage(SnapshotLimitExceeded, "time limit"):
            SnapshotResourceBudget(max_bytes=10, deadline=0).consume(1)


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
            mock.patch("mreg.api.v1.snapshot.iter_deferred_items", return_value=DEFERRED_ITEMS),
            mock.patch("mreg.api.v1.snapshot.iter_permission_items", return_value=PERMISSIONS),
        ):
            data = _write_snapshot_data(Path(directory), 10, include_permissions=True)

        self.assertEqual(data.items.count, len(ITEMS))
        self.assertEqual(data.deferred_records.count, len(DEFERRED_RECORDS))
        self.assertEqual(data.deferred_items.count, len(DEFERRED_ITEMS))
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


class SnapshotGenerationLockTests(SimpleTestCase):
    def fake_connection(self, *, acquired=True):
        cursor = mock.MagicMock()
        cursor.fetchone.return_value = (acquired,)
        cursor_manager = mock.MagicMock()
        cursor_manager.__enter__.return_value = cursor
        return SimpleNamespace(vendor="postgresql", cursor=mock.Mock(return_value=cursor_manager), close=mock.Mock()), cursor

    def test_lock_is_acquired_and_released(self):
        connection, cursor = self.fake_connection()
        with mock.patch("mreg.api.v1.snapshot.connection", connection), snapshot_generation_lock():
            pass
        self.assertEqual(cursor.execute.call_count, 2)

    def test_busy_lock_is_rejected(self):
        connection, _cursor = self.fake_connection(acquired=False)
        with (
            mock.patch("mreg.api.v1.snapshot.connection", connection),
            self.assertRaisesMessage(SnapshotBusy, "already being generated"),
        ):
            with snapshot_generation_lock():
                pass


class SnapshotTranslationValidationTests(ParametrizedTestCase, SimpleTestCase):
    def ip_row(self, *, pk=1, host_id=1, ipaddress="192.0.2.10", macaddress=None):
        return SimpleNamespace(
            pk=pk,
            host_id=host_id,
            ipaddress=ipaddress,
            macaddress=macaddress,
        )

    def test_wildcard_ip_does_not_invent_an_attachment(self):
        row = self.ip_row(macaddress="aa:bb:cc:dd:ee:ff")
        with mock.patch("mreg.api.v1.snapshot._ip_rows", return_value=[row]):
            self.assertEqual(list(_attachment_items(mock.Mock(), {row.host_id}, 10)), [])

    def test_unregistered_ip_does_not_invent_an_attachment(self):
        row = self.ip_row()
        index = mock.Mock()
        index.match.return_value = None
        with mock.patch("mreg.api.v1.snapshot._ip_rows", return_value=[row]):
            self.assertEqual(list(_attachment_items(index, set(), 10)), [])

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

    def test_unregistered_ip_preserves_its_host_and_mac(self):
        row = self.ip_row(macaddress="aa:bb:cc:dd:ee:ff")
        index = mock.Mock()
        index.match.return_value = None
        with (
            mock.patch("mreg.api.v1.snapshot._shared_ip_addresses", return_value=set()),
            mock.patch("mreg.api.v1.snapshot._ip_rows", return_value=[row]),
        ):
            self.assertEqual(list(_ip_items(index, set(), 10)), [])
            item = list(_ip_items(index, set(), 10, deferred=True))[0]
        self.assertEqual(item["attributes"], {"host_name_ref": "host:1", "address": row.ipaddress, "mac_address": row.macaddress})
        self.assertEqual(item["deferred"]["reasons"], ["ip_address_outside_registered_networks"])

    def test_host_group_cycles_are_left_out_of_topological_order(self):
        self.assertEqual(_topological_group_order({1, 2, 3}, [(1, 1), (2, 1)]), ([3], {1: {1}, 2: {1}, 3: set()}))


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


@override_settings(
    MREG_SNAPSHOT_TMPDIR=None,
    MREG_SNAPSHOT_CHUNK_SIZE=10,
    MREG_SNAPSHOT_THROTTLE_RATE="1000/minute",
)
class SnapshotViewTests(ParametrizedTestCase, SimpleTestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        lock = mock.patch("mreg.api.v1.snapshot.snapshot_generation_lock", return_value=nullcontext())
        lock.start()
        self.addCleanup(lock.stop)
        throttle = mock.patch("mreg.api.v1.snapshot.SnapshotRateThrottle.allow_request", return_value=True)
        throttle.start()
        self.addCleanup(throttle.stop)

    def request(self, *, allowed, admin=False, path="/api/v1/snapshot", **headers):
        request = self.factory.get(path, **headers)
        user = SimpleNamespace(
            pk=1,
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

    @mock.patch("mreg.api.v1.snapshot.SnapshotRateThrottle.wait", return_value=60)
    @mock.patch("mreg.api.v1.snapshot.SnapshotRateThrottle.allow_request", return_value=False)
    def test_rate_limited_response_uses_snapshot_contract(self, _allow_request, _wait):
        response = SnapshotView.as_view()(self.request(allowed=True))
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.data["error"], "snapshot_throttled")
        self.assertEqual(response["Retry-After"], "60")

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
                SnapshotBusy("busy"),
                429,
                "snapshot_busy",
                id="busy",
            ),
            param(
                SnapshotLimitExceeded("limited"),
                503,
                "snapshot_limit_exceeded",
                id="limited",
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


@override_settings(
    MREG_SNAPSHOT_TMPDIR=None,
    MREG_SNAPSHOT_CHUNK_SIZE=10,
    MREG_SNAPSHOT_THROTTLE_RATE="1000/minute",
)
class SnapshotMiddlewareIntegrationTests(MregAPITestCase):
    @mock.patch("mreg.api.v1.snapshot.snapshot_generation_lock", return_value=nullcontext())
    @mock.patch("mreg.api.v1.snapshot._write_snapshot_data", side_effect=fake_write_snapshot_data)
    def test_json_snapshot_passes_through_http_middleware(self, _write_snapshot_data, _generation_lock):
        response = self.client.get(
            "/api/v1/snapshot?format=mreg-import-json-v1",
            HTTP_ACCEPT="application/json",
            HTTP_ACCEPT_ENCODING="gzip",
        )
        try:
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.streaming)
            self.assertEqual(response["Content-Type"], "application/json")
            self.assertTrue(gzip.decompress(b"".join(response.streaming_content)).startswith(b'{"requested_by":'))
        finally:
            response.close()


@override_settings(MREG_SNAPSHOT_THROTTLE_RATE="2/hour")
class SnapshotRateThrottleTests(TransactionTestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="rate-limited")
        self.request = SimpleNamespace(user=self.user)

    def test_limit_survives_new_connections_and_is_per_principal(self):
        with mock.patch.object(SnapshotRateThrottle, "timer", return_value=1000):
            self.assertTrue(SnapshotRateThrottle().allow_request(self.request, None))
            self.assertTrue(SnapshotRateThrottle().allow_request(self.request, None))
            connection.close()
            throttle = SnapshotRateThrottle()
            self.assertFalse(throttle.allow_request(self.request, None))
            self.assertEqual(throttle.wait(), 3600)
            other_user = get_user_model().objects.create_user(username="other-snapshotter")
            self.assertTrue(SnapshotRateThrottle().allow_request(SimpleNamespace(user=other_user), None))
        self.assertEqual(SnapshotThrottleState.objects.get(user=self.user).history, [1000, 1000])

    def test_expired_attempts_are_removed(self):
        with mock.patch.object(SnapshotRateThrottle, "timer", side_effect=[1000, 1001, 1002, 4600]):
            self.assertTrue(SnapshotRateThrottle().allow_request(self.request, None))
            self.assertTrue(SnapshotRateThrottle().allow_request(self.request, None))
            throttle = SnapshotRateThrottle()
            self.assertFalse(throttle.allow_request(self.request, None))
            self.assertEqual(throttle.wait(), 3598)
            self.assertTrue(SnapshotRateThrottle().allow_request(self.request, None))
        self.assertEqual(SnapshotThrottleState.objects.get(user=self.user).history, [4600, 1001])

    def test_concurrent_connections_share_an_atomic_limit(self):
        barrier = Barrier(4)

        def attempt():
            try:
                barrier.wait(timeout=10)
                return SnapshotRateThrottle().allow_request(self.request, None)
            finally:
                connections.close_all()

        with ThreadPoolExecutor(max_workers=4) as workers:
            attempts = [workers.submit(attempt) for _ in range(4)]
            self.assertEqual(sum(future.result(timeout=20) for future in attempts), 2)
        self.assertEqual(len(SnapshotThrottleState.objects.get(user=self.user).history), 2)

    def test_anonymous_requests_do_not_create_state(self):
        with self.assertNumQueries(0):
            self.assertTrue(SnapshotRateThrottle().allow_request(SimpleNamespace(user=None), None))

    @override_settings(MREG_SNAPSHOT_THROTTLE_RATE=None)
    def test_disabled_throttle_does_not_create_state(self):
        with self.assertNumQueries(0):
            self.assertTrue(SnapshotRateThrottle().allow_request(self.request, None))


@override_settings(MREG_SNAPSHOT_TMPDIR=None, MREG_SNAPSHOT_THROTTLE_RATE="1000/minute")
class SnapshotDatabaseIntegrationTests(ParametrizedTestCase, TransactionTestCase):
    """Exercise real snapshot transactions and locks, including pooled connections."""

    def setUp(self):
        user = get_user_model().objects.create_user(username="database-snapshotter")
        user.groups.add(Group.objects.create(name=settings.SNAPSHOT_GROUP))
        self.client = APIClient()
        self.client.force_authenticate(user)
        Network.objects.create(network="192.0.2.0/24")
        self.host = Host.objects.create(name="snapshot.example.org")
        self.address = Ipaddress.objects.create(host=self.host, ipaddress="192.0.2.10")

    @parametrize("snapshot_format", [param(ARCHIVE_FORMAT, id="archive"), param(JSON_FORMAT, id="json")])
    def test_download_preserves_shared_and_unregistered_assignments(self, snapshot_format):
        second = Host.objects.create(name="second.example.org", comment="Shared service address")
        duplicate = Ipaddress.objects.create(host=second, ipaddress=self.address.ipaddress, macaddress="aa:bb:cc:dd:ee:ff")
        outside = Ipaddress.objects.create(host=self.host, ipaddress="198.51.100.20", macaddress="aa:bb:cc:dd:ee:00")
        PtrOverride.objects.create(host=self.host, ipaddress=outside.ipaddress)
        response = self.client.get(f"/api/v1/snapshot?format={snapshot_format}", HTTP_ACCEPT_ENCODING="gzip")
        try:
            self.assertEqual(response.status_code, 200)
            compressed = b"".join(response.streaming_content)
            if snapshot_format == ARCHIVE_FORMAT:
                with tarfile.open(fileobj=io.BytesIO(compressed), mode="r:gz") as archive:
                    manifest = json.load(archive.extractfile("manifest.json"))
                    raw = archive.extractfile("deferred-items.ndjson").read()
                    deferred = [json.loads(line) for line in raw.splitlines()]
                self.assertFalse(manifest["semantics"]["fully_importable"])
                self.assertEqual(manifest["deferred_records"]["count"], 0)
                self.assertEqual(manifest["deferred_items"]["count"], 5)
                self.assertEqual(manifest["deferred_items"]["sha256"], hashlib.sha256(raw).hexdigest())
            else:
                deferred = json.loads(gzip.decompress(compressed))["deferred_items"]
            self.assertEqual(
                {item["ref"] for item in deferred if item["kind"] == "ip_address"},
                {
                    f"ip_address:{self.address.pk}",
                    f"ip_address:{duplicate.pk}",
                    f"ip_address:{outside.pk}",
                },
            )
            self.assertEqual(sum(item["kind"] == "ptr_override" for item in deferred), 2)
        finally:
            response.close()
        self.assertFalse(response.artifact.path.exists())

    @parametrize("snapshot_format", [param(ARCHIVE_FORMAT, id="archive"), param(JSON_FORMAT, id="json")])
    def test_download_preserves_untranslatable_source_data(self, snapshot_format):
        wildcard = Host.objects.create(name="*.legacy.example.org", comment="Keep this comment")
        ip = Ipaddress.objects.create(host=wildcard, ipaddress="203.0.113.50", macaddress="broken MAC")
        ptr = PtrOverride.objects.create(host=wildcard, ipaddress=ip.ipaddress)
        loc = Loc.objects.create(host=wildcard, loc="unparseable LOC")
        mx = Mx.objects.create(host=self.host, priority=10, mx="mail.example.org")
        contact = HostContact.objects.create(email="legacy@example.org")
        contact.hosts.add(wildcard)
        role = HostPolicyRole.objects.create(name="legacy", description="Role description")
        role.hosts.add(wildcard)
        BACnetID.objects.create(id=1200, host=wildcard)
        group = HostGroup.objects.create(name="cyclic", description="Group description")
        # Historical corruption can exist below the current signal validation.
        HostGroup.parent.through.objects.create(from_hostgroup_id=group.pk, to_hostgroup_id=group.pk)
        group.hosts.add(wildcard)
        policy = NetworkPolicy.objects.create(name="legacy")
        network = Network.objects.get(network="192.0.2.0/24")
        network.policy = policy
        network.save(update_fields=["policy"])
        community = Community.objects.create(name="legacy", network=network, description="Community description")
        mapping = HostCommunityMapping.objects.create(host=wildcard, ipaddress=ip, community=community)
        Network.objects.filter(pk=network.pk).update(policy=None)
        response = self.client.get(f"/api/v1/snapshot?format={snapshot_format}", HTTP_ACCEPT_ENCODING="gzip")
        try:
            self.assertEqual(response.status_code, 200)
            compressed = b"".join(response.streaming_content)
            if snapshot_format == ARCHIVE_FORMAT:
                with tarfile.open(fileobj=io.BytesIO(compressed), mode="r:gz") as archive:
                    manifest = json.load(archive.extractfile("manifest.json"))
                    sections = {}
                    for key in ("items", "deferred_items", "deferred_records"):
                        raw = archive.extractfile(manifest[key]["path"]).read()
                        sections[key] = [json.loads(line) for line in raw.splitlines()]
                        self.assertEqual(manifest[key]["count"], len(sections[key]))
                        self.assertEqual(manifest[key]["bytes"], len(raw))
                        self.assertEqual(manifest[key]["sha256"], hashlib.sha256(raw).hexdigest())
                self.assertFalse(manifest["semantics"]["fully_importable"])
            else:
                sections = json.loads(gzip.decompress(compressed))
            deferred = {item["ref"]: item for item in sections["deferred_items"] + sections["deferred_records"]}
            expected = {
                f"host:{wildcard.pk}",
                f"ip_address:{ip.pk}",
                f"ptr_override:{ptr.pk}",
                f"record_loc:{loc.pk}",
                f"record_mx:{mx.pk}",
                f"host_group:{group.pk}",
                f"host_contact_host:{contact.pk}:{wildcard.pk}",
                f"host_policy_role_host:{role.pk}:{wildcard.pk}",
                "bacnet_id:1200",
                f"community:{community.pk}",
                f"host_community_mapping:{mapping.pk}",
            }
            self.assertEqual(set(deferred), expected)
            self.assertEqual(deferred[f"ip_address:{ip.pk}"]["attributes"]["mac_address"], "broken MAC")
            self.assertEqual(deferred[f"record_loc:{loc.pk}"]["attributes"]["data"], {"raw_loc": "unparseable LOC"})
            self.assertEqual(deferred[f"host:{wildcard.pk}"]["attributes"]["comment"], "Keep this comment")
            self.assertEqual(deferred[f"host_community_mapping:{mapping.pk}"]["attributes"]["ip_address_ref"], f"ip_address:{ip.pk}")
            normal_refs = {item["ref"] for item in sections["items"]}
            self.assertFalse(normal_refs & expected)
            self.assertTrue(all(set(snapshot_references(item)) <= normal_refs for item in sections["items"]))
            self.assertTrue(all(set(snapshot_references(item)) <= normal_refs | expected for item in deferred.values()))
            self.assertTrue(all(item["deferred"]["requires_manual_handling"] for item in deferred.values()))
            # Reading the snapshot must not repair or normalize the source rows.
            self.assertEqual(Ipaddress.objects.get(pk=ip.pk).macaddress, "broken MAC")
            self.assertEqual(Loc.objects.get(pk=loc.pk).loc, "unparseable LOC")
            self.assertTrue(group.parent.filter(pk=group.pk).exists())
        finally:
            response.close()
        self.assertFalse(response.artifact.path.exists())

    @parametrize(
        ("snapshot_format", "media_type"),
        [
            param(ARCHIVE_FORMAT, "application/vnd.uio.mreg-snapshot+tar", id="archive"),
            param(JSON_FORMAT, "application/json", id="json"),
        ],
    )
    def test_download_releases_transaction_and_lock_before_streaming(self, snapshot_format, media_type):
        response = self.client.get(
            f"/api/v1/snapshot?format={snapshot_format}",
            HTTP_ACCEPT=media_type,
            HTTP_ACCEPT_ENCODING="gzip",
        )
        try:
            self.assertEqual(response.status_code, 200)
            self.assertFalse(connection.in_atomic_block)
            self.assertTrue(connection.get_autocommit())
            with psycopg.connect(**connection.get_connection_params(), autocommit=True) as other_connection:
                with other_connection.cursor() as cursor:
                    cursor.execute("SELECT pg_try_advisory_lock(%s)", [SNAPSHOT_ADVISORY_LOCK_ID])
                    self.assertTrue(cursor.fetchone()[0])
            compressed = b"".join(response.streaming_content)
            self.assertEqual(hashlib.sha256(compressed).hexdigest(), response.artifact.digest_hex)
            if snapshot_format == ARCHIVE_FORMAT:
                with tarfile.open(fileobj=io.BytesIO(compressed), mode="r:gz") as archive:
                    items = [json.loads(line) for line in archive.extractfile("items.ndjson")]
            else:
                items = json.loads(gzip.decompress(compressed))["items"]
            by_ref = {item["ref"]: item for item in items}
            self.assertEqual(by_ref[f"host:{self.host.pk}"]["attributes"]["name"], self.host.name)
            self.assertEqual(by_ref[f"ip_address:{self.address.pk}"]["attributes"]["address"], self.address.ipaddress)
        finally:
            response.close()
        self.assertFalse(response.artifact.path.exists())


class SnapshotItemTranslationTests(ParametrizedTestCase, TestCase):
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

    def test_host_group_relationships_are_deterministic(self):
        first = Host.objects.create(name="first.example.org", zone=self.forward_zone)
        second = Host.objects.create(name="second.example.org", zone=self.forward_zone)
        group = HostGroup.objects.create(name="deterministic", description="Ordered relationships")
        group.hosts.add(second, first)

        item = next(item for item in _host_group_items(set(), 1) if item["ref"] == f"host_group:{group.pk}")

        self.assertEqual(item["attributes"]["hosts"], [f"host:{first.pk}", f"host:{second.pk}"])

    def test_mx_without_forward_zone_is_deferred(self):
        host = Host.objects.create(name="orphan.example.org")
        record = Mx.objects.create(host=host, priority=10, mx="mail.example.org")
        reference = f"record_mx:{record.pk}"
        self.assertNotIn(reference, {item["ref"] for item in _host_dns_record_items(set(), 10, deferred=False)})
        item = next(item for item in iter_deferred_record_items(10) if item["ref"] == reference)
        self.assertEqual(item["attributes"]["data"], {"preference": 10, "exchange": "mail.example.org"})
        self.assertEqual(item["source_host_ref"], f"host:{host.pk}")
        self.assertEqual(item["deferred"]["reasons"], ["mx_owner_without_forward_zone"])

    @parametrize("mac", [param("", id="macless"), param("aa:bb:cc:dd:ee:ff", id="shared_mac")])
    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=False)
    def test_mixed_assigned_and_unassigned_attachment_is_deferred(self, mac):
        self.ip.macaddress = mac
        self.ip.save(update_fields=["macaddress"])
        unassigned = Ipaddress.objects.create(host=self.host, ipaddress="192.0.2.21", macaddress=mac)
        self.assertFalse(any(item["kind"] == "attachment_community_assignment" for item in iter_import_items(10)))
        mappings = [item for item in iter_deferred_items(10) if item["kind"] == "host_community_mapping"]
        self.assertEqual(len(mappings), 1)
        self.assertEqual(mappings[0]["attributes"]["ip_address_ref"], f"ip_address:{self.ip.pk}")
        self.assertNotEqual(mappings[0]["attributes"]["ip_address_ref"], f"ip_address:{unassigned.pk}")
        self.assertEqual(mappings[0]["deferred"]["reasons"], ["attachment_mixes_assigned_and_unassigned_ips"])

    @override_settings(MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=False)
    def test_matching_community_memberships_can_share_an_attachment(self):
        self.ip.macaddress = ""
        self.ip.save(update_fields=["macaddress"])
        second = Ipaddress.objects.create(host=self.host, ipaddress="192.0.2.21")
        HostCommunityMapping.objects.create(host=self.host, ipaddress=second, community=self.community)
        items = list(iter_import_items(10))
        self.assertEqual(sum(item["kind"] == "attachment_community_assignment" for item in items), 1)
        self.assertEqual(sum(item["kind"] == "ip_address" for item in items), 2)

    def test_unassigned_ip_on_a_different_attachment_is_preserved(self):
        second = Ipaddress.objects.create(host=self.host, ipaddress="192.0.2.21", macaddress="aa:bb:cc:dd:ee:00")
        items = list(iter_import_items(10))
        assignment = next(item for item in items if item["kind"] == "attachment_community_assignment")
        address = next(item for item in items if item["ref"] == f"ip_address:{second.pk}")
        self.assertNotEqual(assignment["attributes"]["attachment_id_ref"], address["attributes"]["attachment_id_ref"])

    def test_conflicting_communities_on_one_attachment_are_deferred(self):
        second = Ipaddress.objects.create(host=self.host, ipaddress="192.0.2.21", macaddress=self.ip.macaddress)
        community = Community.objects.create(name="other", network=self.network)
        HostCommunityMapping.objects.create(host=self.host, ipaddress=second, community=community)
        self.assertFalse(any(item["kind"] == "attachment_community_assignment" for item in iter_import_items(10)))
        mappings = [item for item in iter_deferred_items(10) if item["kind"] == "host_community_mapping"]
        self.assertEqual(
            {item["attributes"]["community_name_ref"] for item in mappings}, {f"community:{self.community.pk}", f"community:{community.pk}"}
        )
        self.assertTrue(all(item["deferred"]["reasons"] == ["attachment_has_conflicting_communities"] for item in mappings))

    @parametrize(
        ("address", "record_type"),
        [param("192.0.2.20", "A", id="ipv4"), param("2001:db8::20", "AAAA", id="ipv6")],
    )
    def test_wildcard_records_can_share_allocated_addresses(self, address, record_type):
        if record_type == "AAAA":
            Network.objects.create(network="2001:db8::/64")
            Ipaddress.objects.create(host=self.host, ipaddress=address)
        for name in ("*.one.example.org", "*.two.example.org"):
            wildcard = Host.objects.create(name=name, zone=self.forward_zone)
            Ipaddress.objects.create(host=wildcard, ipaddress=address)
        items = list(iter_import_items(10))
        allocations = [item for item in items if item["kind"] == "ip_address" and item["attributes"]["address"] == address]
        records = [
            item
            for item in items
            if item["kind"] == "record"
            and item["attributes"]["type_name"] == record_type
            and item["attributes"]["data"]["address"] == address
        ]
        self.assertEqual(len(allocations), 1)
        self.assertEqual(len(records), 2)

    @parametrize("address", [param("192.0.2.20", id="ipv4"), param("2001:db8::20", id="ipv6")])
    def test_shared_allocations_preserve_every_owner_and_ptr_target(self, address):
        if ":" in address:
            Network.objects.create(network="2001:db8::/64")
            first = Ipaddress.objects.create(host=self.host, ipaddress=address, macaddress="aa:bb:cc:dd:ee:ff")
        else:
            first = self.ip
        host = Host.objects.create(name="duplicate.example.org", zone=self.forward_zone, comment="Secondary owner")
        second = Ipaddress.objects.create(host=host, ipaddress=address, macaddress="aa:bb:cc:dd:ee:01")
        items = list(iter_import_items(10))
        deferred = list(iter_deferred_items(10))
        allocations = [item for item in deferred if item["kind"] == "ip_address" and item["attributes"]["address"] == address]
        self.assertEqual(
            {(item["ref"], item["attributes"]["host_name_ref"], item["attributes"]["mac_address"]) for item in allocations},
            {
                (f"ip_address:{first.pk}", f"host:{self.host.pk}", first.macaddress),
                (f"ip_address:{second.pk}", f"host:{host.pk}", second.macaddress),
            },
        )
        self.assertTrue(all(item["deferred"]["reasons"] == ["ip_address_shared_by_multiple_hosts"] for item in allocations))
        self.assertFalse(any(item["kind"] == "ip_address" and item["attributes"]["address"] == address for item in items))
        references = {item["ref"] for item in items}
        self.assertTrue(all(item["attributes"]["attachment_id_ref"] in references for item in allocations))
        ptr = next(item for item in deferred if item["kind"] == "ptr_override")
        self.assertEqual(ptr["attributes"], {"host_name_ref": f"host:{self.host.pk}", "address": address})
        self.assertEqual(next(item for item in items if item["ref"] == f"host:{host.pk}")["attributes"]["comment"], "Secondary owner")

    @parametrize("address", [param("198.51.100.20", id="ipv4"), param("2001:db8::20", id="ipv6")])
    def test_unregistered_allocations_and_ptrs_are_preserved(self, address):
        ip = Ipaddress.objects.create(host=self.host, ipaddress=address, macaddress="aa:bb:cc:dd:ee:01")
        ptr = PtrOverride.objects.create(host=self.host, ipaddress=address)
        items = list(iter_import_items(10))
        deferred = {item["ref"]: item for item in iter_deferred_items(10)}
        self.assertEqual(
            deferred[f"ip_address:{ip.pk}"]["attributes"],
            {
                "host_name_ref": f"host:{self.host.pk}",
                "address": address,
                "mac_address": ip.macaddress,
            },
        )
        self.assertEqual(
            deferred[f"ptr_override:{ptr.pk}"]["attributes"],
            {
                "host_name_ref": f"host:{self.host.pk}",
                "address": address,
            },
        )
        self.assertTrue(
            all(
                deferred[reference]["deferred"]["reasons"] == ["ip_address_outside_registered_networks"]
                for reference in (f"ip_address:{ip.pk}", f"ptr_override:{ptr.pk}")
            )
        )
        self.assertFalse(any(item["ref"] in deferred for item in items))

    def test_unattached_contacts_are_preserved(self):
        contact = HostContact.objects.create(email="unattached@example.org")
        item = next(item for item in iter_import_items(10) if item["ref"] == f"host_contact:{contact.pk}")
        self.assertEqual(item["attributes"], {"email": contact.email, "hosts": []})


def snapshot_references(value):
    """References can cross deferred sections, but normal items must stand alone."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key.endswith("_ref"):
                yield child
            elif key in {"hosts", "nameservers", "parent_groups"}:
                yield from child
            else:
                yield from snapshot_references(child)
    elif isinstance(value, list):
        for child in value:
            yield from snapshot_references(child)


class SnapshotDeferredDataTests(ParametrizedTestCase, TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.policy = NetworkPolicy.objects.create(name="legacy", description="Legacy policy")
        cls.network = Network.objects.create(network="192.0.2.0/24", policy=cls.policy)
        cls.community = Community.objects.create(name="legacy", network=cls.network, description="Preserve this description")
        cls.host = Host.objects.create(name="ordinary.example.org", comment="Ordinary host")

    def snapshot(self):
        normal = list(iter_import_items(1))
        deferred_records = list(iter_deferred_record_items(1))
        deferred = list(iter_deferred_items(1))
        all_items = normal + deferred_records + deferred
        references = {item["ref"] for item in all_items}
        self.assertEqual(len(references), len(all_items))
        seen = set()
        for item in normal:
            self.assertTrue(set(snapshot_references(item)) <= seen, item)
            seen.add(item["ref"])
        for item in deferred_records + deferred:
            self.assertTrue(set(snapshot_references(item)) <= references, item)
            self.assertTrue(item["deferred"]["requires_manual_handling"])
            self.assertTrue(item["deferred"]["reasons"])
        return {item["ref"]: item for item in normal}, {item["ref"]: item for item in deferred_records + deferred}

    def test_wildcard_inventory_and_relationships_survive_alongside_dns_records(self):
        host = Host.objects.create(name="*.example.org", comment="Legacy wildcard", ttl=123)
        ip = Ipaddress.objects.create(host=host, ipaddress="192.0.2.40", macaddress="aa:bb:cc:dd:ee:ff")
        ptr = PtrOverride.objects.create(host=host, ipaddress=ip.ipaddress)
        BACnetID.objects.create(id=1200, host=host)
        contact = HostContact.objects.create(email="wildcard@example.org")
        contact.hosts.add(host, self.host)
        group = HostGroup.objects.create(name="legacy", description="Legacy group")
        group.hosts.add(host, self.host)
        role = HostPolicyRole.objects.create(name="legacy", description="Legacy role")
        role.hosts.add(host, self.host)
        mapping = HostCommunityMapping.objects.create(host=host, ipaddress=ip, community=self.community)

        normal, deferred = self.snapshot()

        self.assertEqual(deferred[f"host:{host.pk}"]["attributes"], {"name": host.name, "ttl": 123, "comment": host.comment})
        self.assertEqual(
            deferred[f"ip_address:{ip.pk}"]["attributes"],
            {"address": ip.ipaddress, "host_name_ref": f"host:{host.pk}", "mac_address": ip.macaddress},
        )
        self.assertEqual(deferred[f"ptr_override:{ptr.pk}"]["attributes"]["host_name_ref"], f"host:{host.pk}")
        self.assertEqual(deferred["bacnet_id:1200"]["attributes"], {"bacnet_id": 1200, "host_name_ref": f"host:{host.pk}"})
        self.assertEqual(
            deferred[f"host_contact_host:{contact.pk}:{host.pk}"]["attributes"],
            {"contact_ref": f"host_contact:{contact.pk}", "host_name_ref": f"host:{host.pk}"},
        )
        self.assertEqual(
            deferred[f"host_group_host:{group.pk}:{host.pk}"]["attributes"],
            {"group_ref": f"host_group:{group.pk}", "host_name_ref": f"host:{host.pk}"},
        )
        self.assertEqual(
            deferred[f"host_policy_role_host:{role.pk}:{host.pk}"]["attributes"],
            {"role_name_ref": f"host_policy_role:{role.pk}", "host_name_ref": f"host:{host.pk}"},
        )
        self.assertEqual(
            deferred[f"host_community_mapping:{mapping.pk}"]["attributes"],
            {
                "host_name_ref": f"host:{host.pk}",
                "ip_address_ref": f"ip_address:{ip.pk}",
                "community_name_ref": f"community:{self.community.pk}",
            },
        )
        self.assertEqual(normal[f"record_ip_address:{ip.pk}"]["attributes"]["data"], {"address": ip.ipaddress})
        self.assertEqual(normal[f"host_contact:{contact.pk}"]["attributes"]["hosts"], [f"host:{self.host.pk}"])
        self.assertEqual(normal[f"host_group:{group.pk}"]["attributes"]["hosts"], [f"host:{self.host.pk}"])

    def test_wildcard_without_dns_data_is_preserved(self):
        host = Host.objects.create(name="*.empty.example.org")
        _, deferred = self.snapshot()
        self.assertEqual(deferred[f"host:{host.pk}"]["attributes"], {"name": host.name, "comment": ""})

    def test_all_reasons_are_retained_for_shared_unregistered_ip_with_invalid_mac(self):
        other = Host.objects.create(name="other.example.org")
        ip = Ipaddress.objects.create(host=self.host, ipaddress="203.0.113.50", macaddress="broken MAC")
        Ipaddress.objects.create(host=other, ipaddress=ip.ipaddress)
        _, deferred = self.snapshot()
        self.assertEqual(
            deferred[f"ip_address:{ip.pk}"]["deferred"]["reasons"],
            ["ip_address_shared_by_multiple_hosts", "ip_address_outside_registered_networks", "invalid_mac_address"],
        )

    @parametrize("mac", [param("not-a-mac", id="text"), param("AA:BB:CC", id="short"), param("aa!!bb!!cc!!dd", id="punctuation")])
    def test_malformed_mac_is_preserved_without_an_attachment(self, mac):
        ip = Ipaddress.objects.create(host=self.host, ipaddress="192.0.2.50", macaddress=mac)
        ptr = PtrOverride.objects.create(host=self.host, ipaddress=ip.ipaddress)
        mapping = HostCommunityMapping.objects.create(host=self.host, ipaddress=ip, community=self.community)
        normal, deferred = self.snapshot()
        self.assertFalse(any(item["kind"] == "host_attachment" for item in normal.values()))
        self.assertEqual(
            deferred[f"ip_address:{ip.pk}"]["attributes"],
            {"address": ip.ipaddress, "host_name_ref": f"host:{self.host.pk}", "mac_address": mac},
        )
        self.assertEqual(deferred[f"ip_address:{ip.pk}"]["deferred"]["reasons"], ["invalid_mac_address"])
        self.assertEqual(deferred[f"ptr_override:{ptr.pk}"]["deferred"]["reasons"], ["ip_assignment_has_invalid_mac_address"])
        self.assertEqual(deferred[f"host_community_mapping:{mapping.pk}"]["deferred"]["reasons"], ["invalid_mac_address"])

    @parametrize(
        "value",
        [
            param("original unparseable value", id="text"),
            param("42 N 71 W", id="missing_altitude"),
            param("NaN N 71 W 0m", id="nan"),
            param("42 N 71 W inf", id="infinity"),
            param("91 N 71 W 0m", id="latitude"),
            param("42 60 0 N 71 W 0m", id="minutes"),
            param("42 N 71 W 0m 1m 2m 3m 4m", id="extra_precision"),
        ],
    )
    def test_malformed_loc_retains_exact_source_text(self, value):
        loc = Loc.objects.create(host=self.host, loc=value)
        normal, deferred = self.snapshot()
        reference = f"record_loc:{loc.pk}"
        self.assertNotIn(reference, normal)
        self.assertEqual(deferred[reference]["attributes"]["data"], {"raw_loc": value})
        self.assertEqual(deferred[reference]["source_host_ref"], f"host:{self.host.pk}")
        self.assertEqual(deferred[reference]["deferred"]["reasons"], ["untranslatable_loc_value"])
        json.dumps(deferred, allow_nan=False)

    def test_community_without_policy_preserves_description_and_memberships(self):
        ip = Ipaddress.objects.create(host=self.host, ipaddress="192.0.2.50")
        mapping = HostCommunityMapping.objects.create(host=self.host, ipaddress=ip, community=self.community)
        Network.objects.filter(pk=self.network.pk).update(policy=None)
        normal, deferred = self.snapshot()
        self.assertNotIn(f"community:{self.community.pk}", normal)
        self.assertEqual(
            deferred[f"community:{self.community.pk}"]["attributes"],
            {"network_cidr_ref": f"network:{self.network.pk}", "name": self.community.name, "description": self.community.description},
        )
        self.assertEqual(deferred[f"host_community_mapping:{mapping.pk}"]["deferred"]["reasons"], ["community_network_without_policy"])

    @parametrize(
        ("address", "reason"),
        [
            param("198.51.100.50", "community_does_not_match_ip_network", id="different_network"),
            param("203.0.113.50", "ip_address_outside_registered_networks", id="no_network"),
        ],
    )
    def test_community_mapping_to_another_or_no_network_is_preserved(self, address, reason):
        Network.objects.create(network="198.51.100.0/24")
        ip = Ipaddress.objects.create(host=self.host, ipaddress=address)
        mapping = HostCommunityMapping.objects.create(host=self.host, ipaddress=ip, community=self.community)
        normal, deferred = self.snapshot()
        self.assertFalse(any(item["kind"] == "attachment_community_assignment" for item in normal.values()))
        item = deferred[f"host_community_mapping:{mapping.pk}"]
        self.assertEqual(item["deferred"]["reasons"], [reason])
        self.assertEqual(item["attributes"]["ip_address_ref"], f"ip_address:{ip.pk}")
        self.assertEqual(item["attributes"]["community_name_ref"], f"community:{self.community.pk}")

    def test_mismatching_community_host_is_preserved_without_reassigning_ip(self):
        other = Host.objects.create(name="different.example.org")
        ip = Ipaddress.objects.create(host=self.host, ipaddress="192.0.2.50")
        mapping = HostCommunityMapping.objects.create(host=other, ipaddress=ip, community=self.community)
        normal, deferred = self.snapshot()
        self.assertFalse(any(item["kind"] == "attachment_community_assignment" for item in normal.values()))
        item = deferred[f"host_community_mapping:{mapping.pk}"]
        self.assertEqual(item["attributes"]["host_name_ref"], f"host:{other.pk}")
        self.assertEqual(item["attributes"]["ip_address_ref"], f"ip_address:{ip.pk}")
        self.assertEqual(item["deferred"]["reasons"], ["community_host_does_not_match_ip_host"])

    def test_cycles_and_dependent_groups_preserve_all_edges_and_metadata(self):
        first = HostGroup.objects.create(name="cycle-first", description="First description")
        second = HostGroup.objects.create(name="cycle-second", description="Second description")
        descendant = HostGroup.objects.create(name="dependent", description="Dependent description")
        root = HostGroup.objects.create(name="unaffected")
        first.parent.add(second, root)
        second.parent.add(first)
        descendant.parent.add(second)
        first.hosts.add(self.host)
        owner = Group.objects.create(name="operators")
        first.owners.add(owner)
        normal, deferred = self.snapshot()
        self.assertIn(f"host_group:{root.pk}", normal)
        for group in (first, second, descendant):
            reference = f"host_group:{group.pk}"
            self.assertNotIn(reference, normal)
            self.assertEqual(deferred[reference]["attributes"]["description"], group.description)
            self.assertEqual(
                set(deferred[reference]["attributes"]["parent_groups"]), {f"host_group:{parent.pk}" for parent in group.parent.all()}
            )
        self.assertEqual(deferred[f"host_group:{first.pk}"]["attributes"]["owner_groups"], ["operators"])
        self.assertEqual(deferred[f"host_group:{first.pk}"]["attributes"]["hosts"], [f"host:{self.host.pk}"])
