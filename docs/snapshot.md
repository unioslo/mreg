# Portable snapshots

`GET /api/v1/snapshot` creates a consistent, implementation-independent
snapshot for backup, transfer, and recovery workflows. The endpoint is
synchronous and intended for rare, operator-driven work.

The caller must authenticate with an MREG token and belong to the group named
by `MREG_SNAPSHOT_GROUP`. MREG administrators and superusers do not get
this permission implicitly.

## Archive format

```text
GET /api/v1/snapshot?format=mreg-snapshot-v1
Accept: application/vnd.uio.mreg-snapshot+tar
Accept-Encoding: gzip
```

The response is a gzip-compressed tar archive containing `manifest.json` and
`items.ndjson`. Each NDJSON line is a dependency-ordered snapshot item. The
manifest records the source, consistent database timestamp, item count, and
checksum.

Set `include_permissions=true` to add a separately checksummed
`permissions.ndjson` member. It contains the legacy netgroup-regex authorization
rules, including their group, CIDR range, hostname regular expression, and label
names. Permission records are kept separate from portable domain items so
consumers can translate or inspect the legacy authorization model explicitly.

```json
{"ref":"netgroup_regex_permission:17","kind":"netgroup_regex_permission","operation":"create","attributes":{"group":"dns-admins","range":"192.0.2.0/24","regex":".*\\.example\\.org","labels":["production"]}}
```

For compatibility with the current import endpoint, request
`format=mreg-import-json-v1` with `Accept: application/json`. This returns the
same items as a gzip-compressed `{ "requested_by": ..., "items": [...] }`
document. `include_permissions=true` is not supported for this compatibility
representation.

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

The database transaction is closed before the artifact is downloaded. A client
disconnect therefore does not leave a snapshot transaction open, and temporary
files are removed when the response closes.

This snapshot is a portable application-data contract rather than a forensic
replica. Preserve a separate SQL dump until recovery has been validated.
