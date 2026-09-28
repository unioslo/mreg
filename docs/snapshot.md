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

The response is a gzip-compressed PAX tar archive containing `manifest.json`,
`items.ndjson`, `deferred-records.ndjson`, and `deferred-items.ndjson`. Each line in `items.ndjson`
is a dependency-ordered import item. The manifest records the source,
consistent database timestamp, item counts, and checksums.
PAX extended headers support individual members of 8 GiB or more, subject to
the configured temporary-storage budget.

Wildcard HINFO, LOC, and SSHFP records are valid source data, but cannot be
represented by the version 1 import contract because those record types require
hostname owners. They are preserved, with their source references and data, in
`deferred-records.ndjson`. Each entry includes a `deferred` reason and must be
handled manually by a consumer. The manifest's
`semantics.fully_importable` value is false when either deferred file contains entries.

Ordinary hosts may share an IP address, and addresses need not belong to a
registered network in Django MREG. Such assignments are preserved in
`deferred-items.ndjson`, together with their PTR overrides, instead of failing
the snapshot. Every source assignment retains its own `ref`, `host_name_ref`,
address, and MAC address when present. Shared assignments in registered networks
also retain `attachment_id_ref`; addresses outside registered networks do not
cause synthetic networks or attachments to be created. An address may have both
deferral reasons. References in deferred items resolve against `items.ndjson`.

```json
{"ref":"ip_address:42","kind":"ip_address","operation":"create","attributes":{"host_name_ref":"host:7","address":"198.51.100.20","mac_address":"aa:bb:cc:dd:ee:ff"},"deferred":{"reasons":["ip_address_outside_registered_networks"],"requires_manual_handling":true}}
```

The other assignment reason is `ip_address_shared_by_multiple_hosts`. All
ordinary assignments of a shared address are deferred; the exporter does not
choose one owner. A PTR override's `host_name_ref` identifies its original DNS
target. A mapper must process these entries explicitly, choosing how to preserve
shared DNS ownership and represent addresses without an IPAM network. Importing
only `items.ndjson` when either deferred file is nonempty produces an incomplete
migration.

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
"deferred_records": [...], "deferred_items": [...] }`. The `items` array contains the dependency-ordered
import payload; consumers must inspect both deferred arrays separately.
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
items and may share an address with a regular host or another wildcard.

IP addresses on the same host, network, and MAC address become one attachment.
Since community assignments apply to that whole attachment, snapshots reject
attachments with conflicting communities or a mixture of assigned and
unassigned IPs. This also applies to MAC-less IPs when
`MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=false`. Resolve those memberships
before exporting; the exporter never implicitly enrolls an unassigned IP.

## Data coverage and mapping

Descriptions are retained for labels, networks, network policies and their
attributes, communities, host groups, and host-policy atoms and roles. Host
comments and delegation comments are retained. Contacts are included even when
they have no attached hosts. The source has no description field for excluded
ranges and no display-name field for contacts; a destination requiring these
fields must supply its own defaults.

DNS TTLs, SOA values, nameservers, delegations, explicit records, addresses,
MAC addresses, PTR targets, host-group ownership, host policies, and network
community assignments are included. Generated records must be reconstructed
from those objects by the destination. In Django MREG, `soa_ttl` is the negative
cache value and the SOA record's TTL inherits `default_ttl`. A destination with
separate `negative_ttl` and `soa_record_ttl` fields must map both values. A PTR
override names the target host; an absent target must not be interpreted as a
request to suppress reverse DNS.

This is not an unconditional export of every legacy shape. Wildcard hosts with
comments, contacts, groups, policy memberships, BACnet IDs, MAC addresses, PTR
overrides, or no DNS data still fail validation, as do the ambiguous community
mappings described above. Communities without a network policy, mappings to a
different or missing IP network, and MX owners without a forward zone are also
rejected. These cases require separate source-data handling before this version
can export them. Malformed MAC/LOC data and cyclic host groups also fail
validation. Validate the production dataset before planning a cutover.

Object creation/update timestamps and zone update bookkeeping are not retained.
User accounts, credentials, authorization memberships, and audit/history remain
outside this domain snapshot. Optional legacy permission rules do not include
their users or memberships. Keep a SQL backup for these excluded data.

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
Throttle history is stored in PostgreSQL and updated under a row lock, so the
limit is shared across workers and survives restarts. Apply database migrations
before deploying this endpoint. This operational state is excluded from exports.
`MREG_SNAPSHOT_MAX_BYTES` limits peak temporary storage per generation and
defaults to 10 GiB, while `MREG_SNAPSHOT_MAX_DURATION_SECONDS` defaults to 900
seconds. These limits should be sized for the installation before enabling
snapshot access.

The shipped Gunicorn configuration sets both worker and graceful shutdown
timeouts to the effective snapshot duration budget plus 60 seconds (960 seconds
by default). Custom deployments should load `python:mregsite.gunicorn` or set
compatible timeouts themselves. Reverse-proxy and client timeouts must also allow
for generation and download; larger downloads may require additional time.

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
