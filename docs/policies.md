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
thread waits, not remove the dependency. The DRF/Gunicorn application is
synchronous, so MREG uses the synchronous `treetop-client` API directly.

Shadow mode also waits. This ensures its comparison uses the policy bundle that
was active for the request and exercises the exact latency, timeout, circuit,
and response-validation path that enforcement will use. The former PostgreSQL
outbox, migration, dispatcher, retry/dead-letter state, and Gunicorn background
thread are intentionally absent.

## One endpoint stack and one HTTP call

An endpoint builds a tree of `PolicyLeaf`, `PolicyAll`, and `PolicyAny` nodes.
Every leaf is included in one batched `authorize` request. MREG then composes the
ordered results locally using the tree's AND/OR structure. Examples include:

- all old and new targets required for a hostname rename;
- any IP attached to a host matching a NetGroup rule;
- any host-policy role label matching the host's derived labels;
- DNS-name, reserved-address, ownership, and target facts in the same endpoint
  decision.

The request scope caches an identical repeated stack and rejects a second
different stack. `mreg_policy_authorize_calls_per_request` makes violations of
the one-call invariant observable.

## Principal, action, resource, and facts

Each leaf sends:

- a qualified principal such as `MREG::User::"alice"`, with current group
  memberships;
- one explicit action such as `MREG::Action::"host_update"`;
- a typed resource such as `MREG::Host::"host.example.org"`;
- raw facts needed by Cedar, including hostname, IP, network, DNS-name shape,
  target/self relationship, host-group ownership, or host-policy role label.

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
| `labels` | derived label name used by Cedar/host-policy rules |

TreeTop applies all regexes in the bundle to the raw `hostname` fact and adds
`nameLabels`. Cedar checks labels such as `netgroup_example_org`; MREG neither
runs the bundle regex nor invents the label. This is the intended TreeTop label
boundary.

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
- host-policy role-to-host label matching.

## Failure behavior

The timeout defaults to five seconds. Each Gunicorn worker owns a reusable
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
| Cedar policy | `treetop/data/mreg.cedar` |
| Global super policy | `treetop/data/global.cedar` |
| Derived labels | `treetop/data/labels.json` |
| Generated schema | `treetop/data/mreg.cedarschema` |
| Generated archive | `treetop/data/mreg-bundle.tar.gz` |

Build with `treetop-bundle` 0.0.5:

```bash
python scripts/generate-treetop-schema.py --check
treetop-bundle check bundle treetop/data/treetop-bundle.toml
treetop-bundle build \
  --manifest treetop/data/treetop-bundle.toml \
  --output treetop/data/mreg-bundle.tar.gz
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
   and the one-call invariant.
