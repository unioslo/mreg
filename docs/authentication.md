# Authentication

mreg supports local API tokens and optional Keycloak access tokens. Both identify
an mreg user and use the existing group, network, hostname, and hostpolicy
permission checks. API history records the requesting user's username.

## Local API tokens

Existing clients can continue posting a username and password to
`/api/token-auth/` and sending the returned token as `Authorization: Token <token>`.
The configured Django authentication backends, including LDAP, remain in use.

`POST /api/token-logout/` revokes the local token. It retains the local user and
groups, since the same account may also be used with Keycloak. This changes the
previous behavior, which deleted the user on logout. Local users therefore remain
in the database after logout. Local tokens retain their existing expiry behavior.
An in-flight request cannot recreate a token deleted by logout. Requests already
authenticated before logout may still finish.

### Optional directory refresh for local tokens

Set `MREG_LDAP_REFRESH_LOCAL_TOKENS=true` to apply the shared directory refresh and
outage-grace policy to local tokens owned by LDAP-managed users. It defaults to
`false` and works independently of `MREG_OIDC_ENABLED`. Token validity, expiry,
and local account disabling are checked before refresh; a failed refresh does
not update token usage. Grace never makes an expired or revoked token valid.

A user is LDAP-managed only when a `LDAPUserState` row is associated with that
account following a successful directory refresh. A failed first lookup does not
establish management or a usable permission snapshot. Unmarked local accounts
remain independent of LDAP. Existing LDAP users must be enrolled through a
successful password login, OIDC request, or explicit operator refresh.

With the switch enabled, the default Django authentication backends become:

```python
AUTHENTICATION_BACKENDS = (
    "mreg.directory_auth.LocalUserBackend",
    "mreg.directory_auth.LDAPPasswordBackend",
)
```

Custom backend configurations must use these entries in this order; startup
rejects other configurations while the switch is enabled. Local password checks
run first for unmarked accounts, allowing local/emergency accounts to authenticate
without contacting LDAP. LDAP-managed accounts cannot use local password fallback.
Use separate unmarked accounts for emergency access; enrolling an account in LDAP
refresh makes directory policy authoritative for that account.

LDAP password login always requires a live, successful password bind. The backend
uses django-auth-ldap for verification without creating or updating a user during
that phase. It then forces the shared refresher to populate user data and verify
eligibility. A successful bind alone never advances the refresh timestamp. If
only the subsequent directory population fails transiently, a previously verified
account may use grace; an unverified password can never use retained permissions.
Passwords are not cached or copied into local accounts. Wrong-password attempts
do not invalidate another session's verified directory eligibility.

A successful refresh through either OIDC or password/local-token authentication
updates the same metadata and permissions. Normal token requests reuse these data
for the configured interval. Local logout can revoke a valid token even when the
directory is unavailable or directory eligibility has been denied; it does not
perform an LDAP refresh.

Before enabling the switch, explicitly enroll existing LDAP-backed users:

```console
python manage.py refresh_ldap_users alice bob
```

The command refreshes only named, existing accounts and requires fresh directory
information; grace is not reported as successful enrollment. It commits each
user separately and stops on the first failure. Exclude local/emergency accounts.
Do not assign a current timestamp to unverified historical memberships. Users
left unmarked keep the previous local-token behavior until successful enrollment.

**Enabling this policy changes availability for LDAP-managed local-token users:**
after refresh plus grace expires, LDAP unavailability returns 503. Previously,
local-token requests did not depend on directory availability. Roll out the flag
across workers after reviewing the retained-permission window. Disabling the flag
restores the default legacy backends and token behavior; if you explicitly set
`AUTHENTICATION_BACKENDS` in `local_settings.py`, restore that override as well.

## Keycloak user access tokens

This feature is disabled by default. A webapp sends a Keycloak **access token** as
`Authorization: Bearer <access_token>`. mreg does not perform browser login,
refresh tokens, exchange tokens, or issue a local token for these requests.

The supported token profile is a signed Keycloak JWT with payload `typ: "Bearer"`,
nonempty `sub`, `iss`, `aud`, `azp`, `iat`, `exp`, and the configured directory
username claim. ID tokens (`typ: "ID"`) and refresh tokens are rejected. The JWT
header's `typ: "JWT"` is separate from the payload's token-type claim.

mreg verifies the signature, allowed algorithm, exact issuer, API audience,
expiry, issue time, optional not-before time, and allowed issuing client before
looking up the directory account. A token's `kid` selects a key from the configured
JWKS endpoint. Incoming `iss`, `jku`, `x5u`, and embedded key headers never determine
where verification keys are fetched. The JWT algorithm must match both the
configured allowlist and the selected JWK's algorithm.

### Keycloak setup

1. Configure an audience representing this API, for example `mreg`, and add it to
   access tokens issued to the permitted webapp through an audience mapper. The
   webapp's `azp` value identifies the client; it does not replace the API audience.
2. Use a user-login client. Keep service accounts disabled on allowed clients;
   client-credentials authentication is outside this integration's scope. A bearer
   JWT alone does not provide a universal way to distinguish its grant type.
3. Include a unique LDAP username claim in **access tokens**. Its value must be
   controlled by the identity provider and must not be editable to another user's
   account name. Confirm the rules for account renaming and username reuse.
4. Record the exact realm issuer, HTTPS JWKS endpoint, signing algorithm, and
   permitted webapp client IDs. The realm discovery document at
   `<issuer>/.well-known/openid-configuration` identifies its `jwks_uri`.

Use a trusted claim such as `preferred_username` or a custom `ldap_username`
claim. Its presence in an application profile or UserInfo response does not
establish that it is present in the access token. Confirm its inclusion and
authoritative source before enabling the integration.

Select exactly one claim for each deployment. There is no fallback between claim
names, no email matching, and no parsing usernames out of `sub`. Missing, blank,
non-string, or invalid usernames are rejected. Profile names are not used for
authentication or permissions. No persistent subject-to-user mapping is created;
the trusted username claim is resolved against LDAP on each request. If your
identity lifecycle requires a durable `(issuer, sub)` binding, establish that
mapping before deploying this username-based integration.

### mreg configuration

Example environment configuration (replace all example endpoints and client IDs):

```dotenv
MREG_OIDC_ENABLED=true
MREG_OIDC_ISSUER=https://login.example.org/realms/example
MREG_OIDC_AUDIENCE=mreg
MREG_OIDC_JWKS_URL=https://login.example.org/realms/example/protocol/openid-connect/certs
MREG_OIDC_USERNAME_CLAIM=ldap_username
MREG_OIDC_ALLOWED_CLIENT_IDS=webapp-name
MREG_OIDC_ALGORITHMS=RS256
```

`MREG_OIDC_USERNAME_CLAIM` must match the claim containing the trusted directory
username. See [environment variables](env.md#keycloak-authentication) for the
complete configuration. Python `local_settings.py` overrides are also supported;
use lists for algorithms and allowed client IDs.

Enabling OIDC adds the bearer authenticator alongside the configured default DRF
authenticators, after `local_settings.py` is loaded. Startup validates the trust
configuration without contacting Keycloak. Keep `ExpiringTokenAuthentication`
first if overriding the DRF authentication list, so existing local tokens and
scheme-appropriate authentication challenges remain supported.

### LDAP eligibility and permissions

The configured `AUTH_LDAP_BIND_DN` and `AUTH_LDAP_BIND_PASSWORD` must allow reading
user attributes and group membership without the user's password. Existing TLS,
DN-template/search, group attribute, and group-regex settings apply. Connections
should use StartTLS or LDAPS according to the deployment's LDAP configuration.

Bearer requests use a shared directory refresher backed by the `LDAPUserState`
database model. Run database migrations before enabling OIDC. The state records
the directory username, associated local account, last successful refresh,
eligibility, and retry deadline. New accounts are created only after successful
LDAP population; a failed first lookup may retain retry metadata without creating
a user. Existing local accounts have no assumed refresh timestamp.

By default, user attributes and groups are refreshed at most once every **300
seconds per active user**, on demand. Requests within that interval use the stored
user and permissions. Refreshes include `AUTH_LDAP_REQUIRE_GROUP`,
`AUTH_LDAP_DENY_GROUP`, and `AUTH_LDAP_USER_FLAGS_BY_GROUP`. Library DN/group caches
are disabled during refresh so the timestamp describes fresh directory data.
`AUTH_LDAP_NO_NEW_USERS` is respected. `AUTH_LDAP_USER_QUERY_FIELD` is unsupported;
identity resolution must use the directory username.

If LDAP becomes unavailable, previously verified users can keep using retained
information for an additional **3600 seconds** after freshness expires. The hard
deadline is `last_success_at + refresh_seconds + grace_seconds`. For a refresh at
12:00 with the defaults, normal reuse ends at 12:05 and outage grace ends at 13:05.
Failed attempts, new access tokens, and process restarts never extend that deadline.
The first failure after a long idle period does not start a new grace period.

Only `SERVER_DOWN`, `TIMEOUT`, `UNAVAILABLE`, and `BUSY` errors qualify for grace.
Other directory errors do not. Missing/ambiguous accounts, failed eligibility
checks, and inactive users are rejected; a definitive directory denial invalidates
previous eligibility even if the next attempt encounters an outage. A later
successful refresh can restore directory eligibility. A local `is_active=False`
block is always enforced and cannot be removed by population.

Failed refreshes roll back attribute/group changes while retaining retry and
eligibility state. If no verified information is available, or grace has expired,
directory unavailability returns **503** with `Retry-After`. Invalid credentials
and directory eligibility denials return **401**. Normal authorization denials
return **403**. A new user cannot be provisioned from a JWT alone during an outage.

Retries are throttled per username across workers (default **30 seconds**), and
concurrent requests share one refresh. LDAP connections and individual operations
have a configurable **five-second timeout**; nested searches can require several
operations, so this is not an overall request deadline. Grace access and refresh
failures are logged as `ldap_grace_access` and `ldap_refresh_failed`.

**Increasing the refresh interval delays permission and account-eligibility
changes. During an LDAP outage, retained permissions may remain usable for the
refresh interval plus the grace period after the last successful synchronization.**
This applies to retained write/admin permissions as well as reads. JWT validation
and local account disabling still happen on every request. Directory replication
can add its own delay. A retry cooldown can also delay observing directory recovery.

Set `MREG_LDAP_REFRESH_SECONDS`, `MREG_LDAP_GRACE_SECONDS`,
`MREG_LDAP_RETRY_SECONDS`, and `MREG_LDAP_TIMEOUT_SECONDS` through the environment
or `local_settings.py`; see [environment variables](env.md#directory-refresh).
Zero refresh means refresh on every request; zero grace disables outage fallback;
zero retry disables failure backoff. The timeout must be positive. The shared
refresher overrides LDAP network/operation timeout options with this timeout.

The default database must use `ATOMIC_REQUESTS=False`. Failure metadata must commit
before returning an authentication error, so wrapping the entire HTTP request (or
refresher) in an outer transaction that rolls back on error is unsupported.

Mapped profile fields are updated using `AUTH_LDAP_USER_ATTR_MAP`. An absent
attribute retains its previous value, following django-auth-ldap behavior. Local
group memberships are replaced by the matching LDAP groups, including removal of
manual local memberships. Mapping the username through `AUTH_LDAP_USER_ATTR_MAP`
is unsupported; username renames are not migrated automatically.

OIDC rejects `LDAPSearchUnion` in either `AUTH_LDAP_USER_SEARCH` or
`AUTH_LDAP_GROUP_SEARCH` at startup. Its asynchronous searches can suppress LDAP
errors and return empty or partial results, which could bypass deny-group checks.
Configure a single `LDAPSearch` for each search instead. This restriction also
applies when using nested groups; ordinary `LDAPSearch` errors follow the failure policy above.
Legacy password-login configuration is unaffected when both OIDC and local-token
directory refresh are disabled.

An inactive local user is rejected before LDAP attribute updates can reactivate
it. An inactive populated user is also rejected. Configure directory account
eligibility explicitly, for example with `AUTH_LDAP_USER_FLAGS_BY_GROUP` mapping
`is_active` to an enabled-users group. Reading an LDAP entry does **not** prove
that password login is still enabled for that entry. Directory-specific lock or
disable attributes are not inferred automatically.

Provisioning is transactional. Concurrent first requests create one account and
serialize its group updates; new accounts initially have unusable passwords.
When `AUTH_LDAP_NO_NEW_USERS` is enabled, no account is inserted.

A valid user with no matching groups receives the normal permissions of an
authenticated user, which include read access to many mreg resources. Configure
required-group eligibility if those users must be denied access entirely.

Successful refreshes also change permissions seen by local-token clients sharing
the user. Local-token requests trigger this policy only when
`MREG_LDAP_REFRESH_LOCAL_TOKENS=true` and the user is LDAP-managed.

### Key rotation, failures, and logout

JWKS are cached per worker for 300 seconds by default. Individual signing keys
are not cached indefinitely. Unknown key IDs can trigger refresh after the
configured cooldown (30 seconds by default). Publish a new verification key before
issuing tokens with it, allowing for that cooldown. Removed keys may remain usable
until the JWKS cache expires. The HTTPS fetch has a five-second default timeout;
redirects are not followed.

While a cached key set is still valid, existing keys can validate tokens during
a Keycloak outage. If a required key cannot be retrieved, or the cache has expired
and fetching fails, authentication is rejected. There is no fallback to local
credentials when JWT validation fails. LDAP outage grace does not bypass token
validation or extend token expiry. Raw bearer tokens are not included in the
authentication result or error messages.

The webapp owns Keycloak logout and token refresh. Local offline JWT validation
does not immediately observe Keycloak session revocation or account disabling:
an issued token can remain acceptable until expiry, subject to LDAP eligibility.
Use an appropriate access-token lifetime. This integration does not implement
introspection or a token denylist.

Bearer credentials cannot call `/api/token-logout/`, which only revokes local
tokens. `/api/token-is-valid/` and `/api/meta/user` accept either authentication
method. For a user without a local token, `/api/meta/user` returns `token: null`;
its `last_login` field continues to describe the local password-login flow.

### Gravitee and rollout

If using Gravitee, forward the original `Authorization: Bearer ...` header to
mreg. mreg independently validates it and enforces its own permissions. No
superuser credential or trusted username header is required. Use HTTPS on the
webapp/gateway/API connections and avoid logging bearer credentials.

Deploy disabled first. Before enabling, verify the real access-token claim and
audience, directory-reader permissions, account eligibility, group removal,
signing-key rotation, local-token coexistence, and request latency in staging.
Restart workers with `MREG_OIDC_ENABLED=false` to disable bearer access. This
leaves local-token authentication available; the refresh-state table can remain
in the database.

References: [Keycloak endpoints](https://www.keycloak.org/securing-apps/oidc-layers),
[audience configuration](https://www.keycloak.org/docs/latest/server_admin/#_audience),
[LDAP user population](https://django-auth-ldap.readthedocs.io/en/stable/users.html),
[PyJWT validation](https://pyjwt.readthedocs.io/en/stable/api.html).
