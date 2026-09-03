# Portable snapshots

`GET /api/v1/snapshot` creates a consistent, implementation-independent
snapshot for backup, transfer, and recovery workflows. The endpoint is
synchronous and intended for rare, operator-driven work.

The caller must authenticate with an MREG token and either belong to the group
named by `MREG_SNAPSHOT_GROUP` or be an MREG administrator or superuser.

## Archive format

```text
GET /api/v1/snapshot?format=mreg-snapshot-v1
Accept: application/vnd.uio.mreg-snapshot+tar
Accept-Encoding: gzip
```

The response is a gzip-compressed tar archive containing `manifest.json`,
`items.ndjson`, and `deferred-records.ndjson`. Each line in `items.ndjson`
is a dependency-ordered import item. The manifest records the source,
consistent database timestamp, item counts, and checksums.

Wildcard HINFO, LOC, and SSHFP records are valid source data, but cannot be
represented by the version 1 import contract because those record types require
hostname owners. They are preserved, with their source references and data, in
`deferred-records.ndjson`. Each entry includes a `deferred` reason and must be
handled manually by a consumer. The manifest's
`semantics.fully_importable` value is false when this file contains records.

Set `include_permissions=true` to add a separately checksummed
`permissions.ndjson` member. It contains the legacy netgroup-regex authorization
rules, including their group, CIDR range, hostname regular expression, and label
names. Permission records are kept separate from portable domain items so
consumers can translate or inspect the legacy authorization model explicitly.

```json
{"ref":"netgroup_regex_permission:17","kind":"netgroup_regex_permission","operation":"create","attributes":{"group":"dns-admins","range":"192.0.2.0/24","regex":".*\\.example\\.org","labels":["production"]}}
```

To produce a single JSON import file rather than a tar archive, request
`format=mreg-import-json-v1` with `Accept: application/json`. The response is a
gzip-compressed JSON document containing `{ "requested_by": ..., "items": [...],
"deferred_records": [...] }`. The `items` array contains the dependency-ordered
import payload; consumers must inspect `deferred_records` separately.
`include_permissions=true` is not supported for this JSON representation.

Version 1 only accepts these option values:

| Option | Supported value |
| --- | --- |
| `include_audit` | `false` |
| `include_permissions` | `false` or `true` for `mreg-snapshot-v1` |
| `validate` | `true` |
| `redact` | `false` |

Users, tokens, history, and Django authorization group membership are not
included. Legacy netgroup-regex permission rules are optional. Host and network
policy domain objects are always included. Generated A, AAAA, PTR, and zone NS
records are omitted because the restored MREG state derives them from
structural objects. Wildcard host DNS data is converted to explicit record
items.

## Operation

The snapshot generator reads through one PostgreSQL repeatable-read, read-only
transaction. It writes the translated items and completed artifact to the
directory selected by `MREG_SNAPSHOT_TMPDIR`, or the operating-system
temporary directory when unset. Ensure this filesystem can hold both the
uncompressed NDJSON and compressed response. `MREG_SNAPSHOT_CHUNK_SIZE`
controls ORM iterator batches and defaults to 2000.

Only one artifact is generated at a time across application workers sharing
the PostgreSQL cluster. Additional concurrent attempts receive `429 Too Many
Requests`; a separate per-principal throttle defaults to two attempts per hour.
`MREG_SNAPSHOT_MAX_BYTES` limits peak temporary storage per generation and
defaults to 10 GiB, while `MREG_SNAPSHOT_MAX_DURATION_SECONDS` defaults to 900
seconds. These limits should be sized for the installation before enabling
snapshot access.

The database transaction is closed before the artifact is downloaded. A client
disconnect therefore does not leave a snapshot transaction open, and temporary
files are removed when the response closes. Uncompressed intermediate files are
removed before download begins. Snapshot creation and download closure are
recorded as structured audit events with the principal, format, size, and
artifact digest. Use a private, preferably encrypted or ephemeral filesystem
for `MREG_SNAPSHOT_TMPDIR`, and remove stale temporary directories after an
unclean process or host shutdown.

This snapshot is a portable application-data contract rather than a forensic
replica. Preserve a separate SQL dump until recovery has been validated.
