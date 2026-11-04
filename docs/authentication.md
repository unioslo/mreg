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

Each bearer-authenticated request resolves the LDAP account and refreshes local
memberships using the existing population signal. Directory group/DN caching is
disabled for this path, including checks configured through
`AUTH_LDAP_REQUIRE_GROUP`, `AUTH_LDAP_DENY_GROUP`, and `AUTH_LDAP_USER_FLAGS_BY_GROUP`.
`AUTH_LDAP_NO_NEW_USERS` is respected. `AUTH_LDAP_USER_QUERY_FIELD` is unsupported
for OIDC; identity resolution must use the directory username.

OIDC rejects `LDAPSearchUnion` in either `AUTH_LDAP_USER_SEARCH` or
`AUTH_LDAP_GROUP_SEARCH` at startup. Its asynchronous searches can suppress LDAP
errors and return empty or partial results, which could bypass deny-group checks.
Configure a single `LDAPSearch` for each search instead. This restriction also
applies when using nested groups; ordinary `LDAPSearch` errors reject the request.
It does not change password-login configuration when OIDC is disabled.

An inactive local user is rejected before LDAP attribute updates can reactivate
it. An inactive populated user is also rejected. Configure directory account
eligibility explicitly, for example with `AUTH_LDAP_USER_FLAGS_BY_GROUP` mapping
`is_active` to an enabled-users group. Reading an LDAP entry does **not** prove
that password login is still enabled for that entry. Directory-specific lock or
disable attributes are not inferred automatically.

Provisioning is transactional. Concurrent first requests create one account and
serialize its group updates; new accounts initially have unusable passwords.
When `AUTH_LDAP_NO_NEW_USERS` is enabled, no account is inserted.

Missing/ambiguous accounts and directory failures reject the request rather than
using stored permissions. A valid user with no
matching groups receives the normal permissions of an authenticated user, which
include read access to many mreg resources. Configure required-group eligibility
if those users must be denied access entirely.

The additional directory reads and membership updates occur on every bearer
request. Measure their cost in staging before a broad rollout. Successful updates
also change permissions seen by local-token clients of the same user; local-token
requests themselves retain the existing login-based group refresh behavior.

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
credentials or stale directory permissions. Authentication failures return 401;
normal permission denials return 403. Raw bearer tokens are not included in the
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
requires no database migration and leaves local-token authentication available.

References: [Keycloak endpoints](https://www.keycloak.org/securing-apps/oidc-layers),
[audience configuration](https://www.keycloak.org/docs/latest/server_admin/#_audience),
[LDAP user population](https://django-auth-ldap.readthedocs.io/en/stable/users.html),
[PyJWT validation](https://pyjwt.readthedocs.io/en/stable/api.html).
