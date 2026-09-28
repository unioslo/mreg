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
`deferred-records.ndjson`. Each entry includes `deferred.reasons` and
`requires_manual_handling=true`. The original single `deferred.reason` field is
also retained for record consumers. The manifest's
`semantics.fully_importable` value is false when either deferred file contains entries.

Ordinary hosts may share an IP address, and addresses need not belong to a
registered network in Django MREG. Such assignments are preserved in
`deferred-items.ndjson`, together with their PTR overrides, instead of failing
the snapshot. Every source assignment retains its own `ref`, `host_name_ref`,
address, and MAC address when present. Shared assignments in registered networks
also retain `attachment_id_ref` when their MAC can be translated; addresses outside registered networks do not
cause synthetic networks or attachments to be created. An address may have both
deferral reasons. References in deferred entries can resolve against either
`items.ndjson` or a deferred section. Only `items.ndjson` is dependency-ordered;
deferred relationships can contain cycles.

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
Community assignments apply to that whole attachment. If an attachment has
conflicting communities, or a mixture of assigned and unassigned IPs, its
original per-IP mappings are deferred instead. This also applies to MAC-less
IPs when `MREG_REQUIRE_MAC_FOR_BINDING_IP_TO_COMMUNITY=false`. The exporter never
chooses one community or implicitly enrolls an unassigned IP.

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

## Deferred source information

Deferred sections preserve source information that cannot safely become an
automatically applied import item. They are non-authoritative for restoration:
consumers must inspect, translate, repair, or explicitly retain them as
information before applying them. The source values and relationships remain
available; deferral does not modify the source database or silently discard the
problematic data. A `create` operation in a deferred item's envelope is not an
instruction to apply it without that handling.

The following cases succeed as snapshots and set `fully_importable=false`:

| Source data | Preserved representation |
| --- | --- |
| Wildcard hosts, including hosts without DNS data | Deferred `host` with its name, zone reference, TTL, and comment; addresses, MACs, BACnet IDs, PTR overrides, and memberships are retained separately. Translatable wildcard DNS records remain in `items.ndjson`. |
| Wildcard contact, group, and policy memberships | Deferred `host_contact_host`, `host_group_host`, and `host_policy_role_host` entries retain both ends of each relationship. Contacts, ordinary group memberships, and policy definitions remain in normal items. |
| Communities without a network policy | Deferred `community` with its original network, name, and description; no policy is invented. |
| Ambiguous or inconsistent community mappings | Deferred `host_community_mapping` entries preserve every original host/IP/community reference, including mismatching hosts, missing or different IP networks, and mappings whose IP assignments are themselves deferred. No attachment-level community assignment is emitted for an affected attachment. |
| MX owners without a forward zone | Deferred record with the owner name, source host reference, TTL, preference, and exchange. |
| Malformed MAC addresses | Deferred IP assignment with the exact original string in `mac_address`; no attachment is constructed from the invalid MAC. Related PTR overrides are also deferred. |
| Untranslatable LOC values | Deferred record with the exact original text in `attributes.data.raw_loc`, its owner, source host reference, and TTL. |
| Cyclic host groups and groups depending on those cycles | Deferred `host_group` entries retain descriptions, all parent links, hosts, and owner-group names. Unaffected groups remain dependency-ordered normal items. |

Every deferred entry has a stable source-derived `ref`, one or more
`deferred.reasons`, and `requires_manual_handling=true`. Reasons can accumulate;
for example, one IP can be shared, outside registered networks, and have an
invalid MAC. Deferred attributes may contain raw invalid values or source
relationships that differ from the normal import contract. Consumers must not
validate them as ordinary import items or discard an entire snapshot because
of them.

All wildcard inventory hosts are retained in the deferred section, even when
their DNS data translates completely. Thus `fully_importable=false` can mean
additional inventory information needs handling, not necessarily that DNS
records are missing. Consumers must process both deferred sections and resolve
references across the complete snapshot before considering a migration
complete. The listed cases do not require source cleanup before export.

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
