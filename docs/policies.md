# TreeTop Authorization

MREG can evaluate authorization with the TreeTop Cedar policy engine. The
integration is request-scoped, synchronous, bundle-based, and has three modes:

| Mode | TreeTop call | Returned decision |
| --- | --- | --- |
| `off` | none | legacy MREG permission |
| `shadow` | one synchronous call per protected endpoint | legacy MREG permission |
| `enforce` | one synchronous call per protected endpoint | TreeTop composite; errors deny |

An empty `MREG_POLICY_BASE_URL` makes the default `shadow` mode behave like
`off`. `enforce` requires a URL at startup and has no legacy error fallback.
Authentication remains local; token acquisition, health checks, metrics, schema,
and admin pages are the explicit policy exemptions.

## Why there is no queue or async dispatcher

Authorization must complete before request processing can continue. Queuing the
work would either allow an unauthorised request to proceed or still require the
request to wait for the queue result. An async HTTP client would change how the
thread waits, not remove the dependency. The Django/DRF request path is
synchronous, so MREG uses the synchronous `treetop-client` API directly.

Shadow mode also waits. This ensures its comparison uses the policy bundle that
was active for the request and exercises the exact latency, timeout, circuit,
and response-validation path that enforcement will use. The former PostgreSQL
outbox, migration, dispatcher, and retry/dead-letter state are intentionally
absent.

## One endpoint stack and one HTTP call

An endpoint builds a tree of `PolicyLeaf`, `PolicyAll`, and `PolicyAny` nodes.
Every leaf is included in one batched `authorize` request. MREG then composes the
ordered results locally using the tree's AND/OR structure. Examples include:

- all old and new targets required for a hostname rename;
- any IP attached to a host matching a NetGroup rule;
- the exact host-policy role together with the candidate hostname and IP;
- DNS-name, reserved-address, ownership, and target checks in the same endpoint
  decision.

State attached to the underlying Django request caches an identical repeated
stack. A second different stack is rejected and increments
`mreg_policy_stack_conflicts_total`: shadow mode returns the legacy result and
enforce mode fails closed. This makes the one-stack invariant independent of
middleware and explicit at the authorization boundary.

## Principal, action, resource, and facts

Each leaf sends:

- a qualified principal such as `MREG::User::"alice"`, with current group
  memberships;
- one explicit action such as `MREG::Action::"host_update"`;
- a typed resource such as `MREG::Host::"host.example.org"`;
- contract-typed attributes needed by Cedar. NetGroup and DNS-name checks send
  the raw `hostname` and, when available, `ip`; TreeTop derives `nameLabels`
  from the bundle. Other endpoints can send business relationship attributes
  such as `selfAccess` or `requesterIsOwner`.

MREG does not send a precomputed `allow` fact. Relationship booleans such as
`selfAccess` and `requesterIsOwner` describe request state; Cedar decides what
those facts mean.

`mreg/policy/contracts.py` is the dependency-free source of truth for resource
kinds, optional attributes, operations, and actions. `mreg/policy/resources.py`
resolves model/view data to stable IDs and normalized attributes. Unknown kinds
must be registered explicitly; view class names are not an authority fallback.
The generated schema is checked in CI.

## Mapping mutable database permissions

User group membership remains dynamic and is sent on every call. Mutable
`NetGroupRegexPermission` rows cannot remain an independent authority when
TreeTop is authoritative. Their equivalents must be reviewed and added to the
deployed bundle:

| Database field | Bundle representation |
| --- | --- |
| `group` | Cedar principal group |
| `range` | Cedar `ip.isInRange(...)` or exact network condition |
| `regex` | named pattern in `labels.json` |
| `labels` | conversion-only join key to exact `HostPolicyRole` names |

TreeTop applies all regexes in the bundle to the raw `hostname` fact and adds
`nameLabels`. Cedar checks deterministic generated labels; MREG neither runs
the bundle regex nor sends those labels. Legacy permission and role labels are
not runtime facts. The converter uses them only to discover which exact roles
each network permission used to cover, then writes rules whose resource is that
specific `MREG::HostPolicyRole`.

In `enforce`, the NetGroupRegexPermission API remains readable but returns HTTP
409 for POST, PUT, PATCH, and DELETE. This prevents the database from appearing
to change authoritative policy. In `off` and `shadow`, writes retain their
legacy behavior so policy authors can stage and compare a migration. Bundle
publication is a separate reviewed deployment operation.

## Local responsibilities and Cedar responsibilities

MREG still owns authentication, serializer validation, object lookup, database
transactions, conflicts, and business invariants. Cedar owns authorization for
protected endpoints in `enforce`, including:

- authenticated reads and explicit introspection actions;
- super/admin/network/group/host-policy roles;
- host, record, BACnet, network, community, zone, label, and host-policy CRUD;
- NetGroup hostname/range rules through derived labels;
- DNS wildcard/underscore restrictions;
- restricted IP assignment;
- host-group ownership and membership changes;
- host-policy role-to-host mapping generated from the legacy permission export.

## Failure behavior

The timeout defaults to five seconds. Each application process owns a reusable
client and a thread-safe closed/open/half-open circuit breaker. After the
configured consecutive failures, the circuit rejects calls until its cooldown;
one request then probes the service.

- `shadow`: log/metric the error and return the legacy result.
- `enforce`: log at critical severity, increment `error_deny`, and deny.

Malformed result counts and per-result errors are failures just like transport
exceptions. `disable_policy_parity()` can suppress only shadow calls in narrow
test scopes; it cannot bypass enforcement.

## Bundle source and build

| Artifact | Path |
| --- | --- |
| Organization manifest | `treetop/data/treetop-bundle.toml` |
| MREG module manifest | `treetop/data/treetop-mreg-module.toml` |
| Global module manifest | `treetop/data/treetop-global-module.toml` |
| Global super policy | `treetop/data/global.cedar` |
| Hand-written endpoint policy | `treetop/data/mreg.cedar` |
| Generated NetGroup/role policy | `treetop/data/netgroup.cedar` |
| Generated TreeTop labels | `treetop/data/labels.json` |
| Conversion report | `treetop/data/netgroup-conversion-report.json` |
| Normalized API snapshot | `treetop/fixtures/policy-source.json` |
| Generated schema | `treetop/data/mreg.cedarschema` |
| Generated archive | `treetop/data/mreg-bundle.tar.gz` |

Refresh the conversion input directly from the MREG instance whose policy is
being migrated:

```bash
export MREG_API_BASE_URL=https://mreg.example
export MREG_API_TOKEN='replace-with-an-MREG-API-token'
python scripts/generate-treetop-policy.py
unset MREG_API_TOKEN
```

The generator paginates the existing `/api/v1/labels/`,
`/api/v1/permissions/netgroupregex/`, and `/api/v1/hostpolicy/roles/`
endpoints. It authenticates with `Authorization: Token`, resolves label IDs to
names, and writes a deterministic snapshot containing only the fields needed by
the conversion. No `mreg-cli` installation or new export endpoint is required.
Use HTTPS outside a trusted local environment, and use a token with authenticated
read access to all three endpoints. The token is read only from the environment
and is never written to the snapshot.

The converter validates every CIDR and regular expression, removes duplicate
permission rows, collapses redundant ranges, and emits stable hashed IDs.
Review the snapshot, generated Cedar, and `netgroup-conversion-report.json`,
especially unmatched or unused legacy labels. The checked-in snapshot is a
sanitized example, not production policy. `MREG_API_TIMEOUT` optionally changes
the per-page timeout from 20 seconds.

Without `MREG_API_BASE_URL`, the generator uses the checked-in snapshot. CI uses
that offline path:

```bash
python scripts/generate-treetop-policy.py --check
```

The restricted-address examples in `mreg.cedar` are also based on the sample
networks. Replace and review them for the deployment before enabling `enforce`.

Build with `treetop-bundle` 0.0.5:

```bash
python scripts/generate-treetop-schema.py --check
python scripts/generate-treetop-policy.py --check
TREETOP_BUNDLE_BIN=treetop-bundle scripts/build-treetop-bundle.sh
TREETOP_BUNDLE_BIN=treetop-bundle scripts/check-treetop-bundle.sh
```

Bundle output is deterministic and CI compares it byte-for-byte. Bundles are
currently unsigned; the development server explicitly uses
`TREETOP_BUNDLE_SIGNATURE_POLICY=allow-unsigned`.

No `treetop-client` change is required for bundle support. MREG sends ordinary
authorization requests to `treetop-rest`; the REST server downloads, validates,
atomically loads, and refreshes the bundle.

## Local setup and rollout

Start `treetop-rest` 0.0.14 and the bundle file server:

```bash
docker compose -f treetop/docker-compose.yml up -d
```

Observe synchronously first:

```bash
export MREG_POLICY_MODE=shadow
export MREG_POLICY_BASE_URL=http://localhost:9999
export MREG_POLICY_NAMESPACE=MREG
```

After the bundle mapping is reviewed and the rollout gate passes, enable
authority and restart all workers:

```bash
export MREG_POLICY_MODE=enforce
```

Roll back by setting the mode to `shadow` or `off` and restarting workers. If
MREG itself runs in a container, use a TreeTop URL reachable from that
container—not its own `localhost`.

## Adding a protected endpoint

1. Register its typed resource contract and any custom action.
2. Choose the final semantic authorization point. Use the early DRF permission
   hook only when all facts are available there; otherwise authorize after
   serializer/object resolution.
3. Build the complete AND/OR stack and call `authorize_policy_stack()` once.
4. Add Cedar permits/forbids and derived label rules together.
5. Regenerate the schema and archive.
6. Test legacy behavior, shadow comparison, enforce allow/deny/error behavior,
   and the one-stack invariant.
