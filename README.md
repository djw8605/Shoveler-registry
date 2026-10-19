# Shoveler Auth Portal

A small, self-contained OAuth2 token issuer for the
[`xrootd-monitoring-shoveler`](https://github.com/opensciencegrid/xrootd-monitoring-shoveler).
It lets site operators **onboard shovelers themselves** and mints the
short-lived JWTs that RabbitMQ validates against this service's published
public keys. Shovelers hold their own RSA key; **no shared secret exists
anywhere**. It replaces a Keycloak deployment with a few hundred lines of
Python.

It does four things:

1. **Self-service portal** (browser, CILogon login) — operators create one-time
   **registration tokens** for their site, and disable / re-enable the shovelers
   registered with them.
2. **Registration endpoint** (`POST /register`) — a shoveler presents a
   registration token and its **public key** (RFC 7591 request format) and gets
   a `client_id` bound to that site.
3. **Token endpoint** (`POST /token`) — OAuth2 `client_credentials` grant,
   authenticated with a JWT signed by the shoveler's private key
   (`private_key_jwt`, RFC 7523) → signed access token. The **JWKS endpoint**
   (`GET /.well-known/jwks.json`) publishes the keys RabbitMQ verifies it with.
4. **Idle-expiry job** — disables shovelers unused for `IDLE_DAYS`.

> **Two kinds of credentials — don't conflate them.**
> The portal is itself a *confidential OIDC client of CILogon* (`CILOGON_CLIENT_ID`/
> `CILOGON_CLIENT_SECRET`), which it uses to log humans in. That is entirely
> separate from the shoveler clients this service *issues* to sites, which
> authenticate with their own keys, not secrets.

## Stack

Python 3.12 · FastAPI · Uvicorn · stdlib `sqlite3` (WAL) · PyJWT + `cryptography`
for signing and client-assertion verification · httpx for the CILogon OIDC flow ·
Jinja2 templates · Tailwind CSS (compiled via the Tailwind CLI, **not** the Play CDN).

## Layout

```
portal/
  config.py     env-driven settings
  db.py         sqlite schema + queries (WAL)
  keys.py       key gen/load, JWKS, rotation CLI
  registration.py  /register: registration tokens, client metadata validation
  tokens.py     /token private_key_jwt verification, claim building, rate limiting
  authz.py      COmanage group-based site authorization
  auth.py       CILogon OIDC relying-party flow + session (captures isMemberOf)
  main.py       FastAPI app, routes, middleware, CSRF
  expire.py     idle-expiry subcommand
  templates/    base, macros, login, dashboard, registration_token, not_authorized, admin
  static/css/   compiled app.css (build artifact)
assets/app.css  Tailwind source (source of truth)
tailwind.config.js, package.json
.env.example
Dockerfile      multi-stage (node build → python runtime), non-root
k8s/            deployment, cronjob, ingress + secret examples
.github/        CI: pytest, GHCR image build
tests/
```

## Configuration (environment variables)

See [`.env.example`](./.env.example) for the annotated list. Summary:

| Variable | Default | Purpose |
| --- | --- | --- |
| `CILOGON_CLIENT_ID` | _required_ | Portal's own OIDC client id at CILogon |
| `CILOGON_CLIENT_SECRET` | _required_ | Portal's own OIDC client secret |
| `CILOGON_DISCOVERY_URL` | CILogon well-known | OIDC discovery document |
| `PORTAL_BASE_URL` | _required_ | Public base URL; `redirect_uri` = `+/auth/callback` |
| `SESSION_SECRET` | _required_ | Signs the session cookie |
| `DB_PATH` | `./data/portal.db` | SQLite file |
| `SIGNING_KEY_DIR` | `./data/keys` | Signing keys + `manifest.json` |
| `COMANAGE_GROUP_PREFIX` | `shoveler-` | Group-name prefix; site = group name after the prefix |
| `TOKEN_ISSUER` | _required_ | JWT `iss` (= RabbitMQ `auth_oauth2.issuer`) |
| `RESOURCE_SERVER_ID` | _required_ | JWT `aud` (= RabbitMQ `auth_oauth2.resource_server_id`), exact |
| `TOKEN_TTL_SECONDS` | `14400` | JWT lifetime (4h) |
| `SCOPE_CLAIM` | `extra_scope` | Custom claim key (= RabbitMQ `additional_scopes_key`) |
| `SCOPE_VALUE` | `my_rabbit_server.write:*/xrd-shoveled` | Permission written into the scope claim |
| `IDLE_DAYS` | `30` | Idle-expiry threshold |
| `ADMIN_CONTACT` | _generic_ | Shown on the not-authorized page |
| `REGISTRY_ADMIN_GROUP` | _empty_ | COmanage group whose members are registry-wide admins |
| `TOKEN_RATE_LIMIT` / `TOKEN_RATE_WINDOW` | `30` / `60` | Per-`client_id` `/token` rate limit |
| `REGISTRATION_TOKEN_TTL_SECONDS` | `259200` | Lifetime of a one-time registration token (72h) |
| `REGISTER_RATE_LIMIT` / `REGISTER_RATE_WINDOW` | `10` / `60` | Per-client-IP `/register` rate limit |
| `ASSERTION_MAX_LIFETIME_SECONDS` | `300` | Reject client assertions whose `exp` is further out than this |

## CILogon client registration

Register a **confidential** OIDC client at <https://cilogon.org/oauth2/register>:

- **Redirect URI:** `${PORTAL_BASE_URL}/auth/callback` (exact match)
- **Scopes:** `openid email profile org.cilogon.userinfo`
- **Client type:** confidential (the portal keeps a client secret)
- **Grant:** authorization code (the portal adds PKCE + `state` + `nonce`)

CILogon issues the `client_id`/`client_secret`; set them as
`CILOGON_CLIENT_ID` / `CILOGON_CLIENT_SECRET`. The `sub` claim is the stable
identity; the `isMemberOf` claim carries the user's COmanage group memberships
(used for authorization, below). The ID token is fully validated (signature via
CILogon's JWKS, plus `iss`/`aud`/`exp`/`nonce`).

> The `org.cilogon.userinfo` scope (already requested) is what releases
> `isMemberOf`. If your CILogon/COmanage deployment only returns it from the
> userinfo endpoint rather than in the ID token, the portal fetches it from
> there automatically.

## Authorization (COmanage groups)

Who may manage which site is driven by the user's **COmanage group
memberships**, delivered by CILogon in the `isMemberOf` claim. There is no
local allow-list file to maintain: access follows directly from the groups the
central admin manages in COmanage.

**Convention:** a group named `<COMANAGE_GROUP_PREFIX><site>` grants management
of `<site>`. With the default `shoveler-` prefix, membership in the COmanage
group `shoveler-nebraska` lets a user manage site `nebraska`. The site name is
the part of the group name after the prefix; groups that don't start with the
prefix (e.g. COmanage's built-in `CO:members:active`) are ignored. The
`REGISTRY_ADMIN_GROUP` is never a site group, even when it starts with the
prefix: `shoveler-admins` makes its members registry admins, not managers of a
site called `admins`.

Group memberships are captured into the session **at login**, so changes in
COmanage take effect on the user's next login rather than instantly. A user
who is in no site group sees a friendly "not yet authorized; contact
`${ADMIN_CONTACT}`" page.

### Registry-wide admins

Site operators see only their own sites. Members of the COmanage group named in
`REGISTRY_ADMIN_GROUP` are **registry-wide admins**: they get an **Admin** link
to `GET /admin`, a read-only table of *every* registered shoveler across *all*
sites (site, `client_id`, name, key thumbprint, owner email, status, created,
last_used). It makes idle/dead sites easy to scan. Admins may also disable any
client (`disabled_reason='revoked-by-admin'`). The owner can't re-enable an
admin-disabled client, since it may have a compromised key: recovery is a new
registration token. Leave `REGISTRY_ADMIN_GROUP` empty to disable the admin
view entirely.

## Local development

```bash
# 1. Python env
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

# 2. Build the CSS once, or watch it while you edit templates
npm install
npm run build:css          # one-shot, minified
npm run watch:css          # rebuild on change (run alongside uvicorn)

# 3. Config
cp .env.example .env       # fill in CILOGON_*, SESSION_SECRET, COMANAGE_GROUP_PREFIX, etc.
set -a; . ./.env; set +a   # export the vars into your shell

# 4. Run (factory mode — create_app() reads settings from the env)
uvicorn --factory portal.main:create_app --reload --port 8080
```

Run the tests with `pytest`.

## Registration and token endpoints

### `POST /register` (one-time registration)

The shoveler generates an RSA keypair locally and registers the **public** key,
presenting a registration token from the dashboard as a bearer token:

```http
POST /register
Content-Type: application/json
Authorization: Bearer <registration token>

{"client_name": "xrootd-01.example.edu",
 "grant_types": ["client_credentials"],
 "token_endpoint_auth_method": "private_key_jwt",
 "jwks": {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256",
                    "kid": "<kid>", "n": "...", "e": "AQAB"}]}}
```

`201` returns `client_id`, `client_id_issued_at`, `client_name`, `grant_types`
and `token_endpoint_auth_method`. No `registration_access_token` is issued
(RFC 7592 client management is not offered), so no long-lived management
credential exists. The client is active immediately: being minted by a member
of `<COMANAGE_GROUP_PREFIX><site>` is the approval, and the client gets the
normal `SCOPE_VALUE` (any requested scope is ignored).

- The token is **single-use** and expires after `REGISTRATION_TOKEN_TTL_SECONDS`.
  Until it is used, **any** manager of its site (not only its creator) can
  revoke it on the dashboard.
  Spending it and creating the client happen in one transaction, so of two
  concurrent uses exactly one succeeds.
- A missing, unknown, expired, revoked or already-used token gets
  `401 {"error":"invalid_token"}` with `WWW-Authenticate: Bearer error="invalid_token"`.
- **Retry is idempotent:** if the response was lost, presenting the same (used,
  unexpired) token with the **same key** returns the same `client_id`. A
  different key gets `401`.
- Metadata must use `private_key_jwt`, `grant_types` (if present) exactly
  `["client_credentials"]`, and exactly one RSA key with a non-empty `kid`, at
  least 2048 bits, `use` absent or `sig`, `alg` absent or `RS256`, and **no
  private members**. `jwks_uri` is not supported. Violations get
  `400 {"error":"invalid_client_metadata","error_description":...}` and do not
  spend the token. Unknown fields (e.g. `software_version`) are ignored.
- Rate-limited per client IP (`429` with `Retry-After`).

### `POST /token` (`private_key_jwt`)

```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<RS256 JWT signed with the registered private key>
```

The client assertion's header carries the registered `kid`; its claims are
`iss = sub = client_id`, `aud` = the token URL (`PORTAL_BASE_URL/token`, the
`TOKEN_ISSUER` base + `/token`, or `TOKEN_ISSUER`; a trailing slash on the base
doesn't matter), `iat`, `exp` and a unique `jti`. Only RS256 is accepted;
`exp`/`iat` get 60s leeway; an `exp` more than `ASSERTION_MAX_LIFETIME_SECONDS`
ahead is refused; each `jti` is accepted once per client.

On success it returns `{"access_token", "token_type":"Bearer", "expires_in"}`
and updates the client's `last_used_at`. Any authentication failure (unknown or
disabled client, bad signature or `kid`, wrong `aud`, expired, too long-lived or
replayed assertion) returns a uniform `401 {"error":"invalid_client"}`. Requests
that exceed the per-`client_id` rate limit get `429` with a `Retry-After`
header. `client_secret_basic` / `client_secret_post` are not supported.

The minted RS256 access token (header carries `kid`) has claims:

```
iss = TOKEN_ISSUER
sub = client_id
aud = RESOURCE_SERVER_ID         # exact, no surrounding whitespace
iat = now
exp = now + TOKEN_TTL_SECONDS
jti = random
<SCOPE_CLAIM> = SCOPE_VALUE      # e.g. extra_scope = my_rabbit_server.write:*/xrd-shoveled
```

`/.well-known/openid-configuration` advertises `token_endpoint`,
`registration_endpoint`, `jwks_uri`, `token_endpoint_auth_methods_supported:
["private_key_jwt"]` and `token_endpoint_auth_signing_alg_values_supported:
["RS256"]`.

## RabbitMQ configuration

Point RabbitMQ at this issuer so it can discover the JWKS and validate tokens:

```ini
# rabbitmq.conf
auth_backends.1 = rabbit_auth_backend_oauth2

auth_oauth2.issuer                = https://shoveler-auth.osg.example/   # = TOKEN_ISSUER
auth_oauth2.resource_server_id    = my_rabbit_server                     # = RESOURCE_SERVER_ID
auth_oauth2.additional_scopes_key = extra_scope                          # = SCOPE_CLAIM
auth_oauth2.preferred_username_claims.1 = sub
```

RabbitMQ fetches public keys from `${TOKEN_ISSUER}/.well-known/jwks.json` (advertised
by `${TOKEN_ISSUER}/.well-known/openid-configuration`). `resource_server_id` must
equal the token's `aud` **exactly**, and the permission lives in the
`additional_scopes_key` claim.

## Shoveler configuration

Requires a shoveler with OAuth self-registration support (`amqp.oauth`). On the
dashboard, click **Create registration token** for the site. The one-time page
shows the token and a ready-to-paste snippet (merge it into the `amqp:` section
alongside your RabbitMQ `url` / `exchange`):

```yaml
amqp:
  oauth:
    enabled: true
    token_url: https://shoveler-auth.osg.example/token
    registration_url: https://shoveler-auth.osg.example/register
    bootstrap_token_file: /etc/xrootd-monitoring-shoveler/oauth/bootstrap.token
    client_name: nebraska
```

Write the token to `bootstrap.token` with mode `0600`, readable by the user the
shoveler runs as. On first start the shoveler generates its key, registers, and
starts writing access tokens to `amqp.token_location`. After that first
successful start the token file can be deleted.

The shoveler persists its private key and `client_id` under
`/etc/xrootd-monitoring-shoveler/oauth/`. **That directory must survive
restarts and redeploys** (e.g. a persistent volume for a containerised
shoveler). If it is lost, create a new registration token; the old client can
be disabled on the dashboard.

## Signing keys & rotation

On first start the portal generates an RSA-2048 signing key in
`SIGNING_KEY_DIR` (written `0600`), recorded in `manifest.json`. **All** public
keys are published in the JWKS; only the newest (active) key signs new tokens,
so tokens from a recently-retired key keep validating until they expire.

Keys are never committed, never logged, and never appear in responses.

```bash
# List keys (active is marked)
python -m portal.keys list

# Rotate: generate a NEW active key WITHOUT deleting old ones.
# Old keys stay in the JWKS so outstanding tokens still verify.
python -m portal.keys generate
```

Rotation procedure: run `generate`, then reload/restart the portal so it loads
the new active key. After the previous tokens' TTL has elapsed (`TOKEN_TTL_SECONDS`),
the retired key may be removed from `manifest.json` if you wish.

## Idle-expiry

```bash
python -m portal.expire
```

Disables credentials whose reference time (`last_used_at`, or `created_at` if
never used) is older than `IDLE_DAYS`, setting `disabled_reason='idle'`. Rows
are never deleted (audit + recovery). **Recovery is self-service:** the owner
logs in and clicks **Re-enable**, which clears the disabled flag; the shoveler
keeps its key and `client_id`, so nothing changes on its side. Owners can also
re-enable clients they disabled themselves, but **not** ones a registry admin
disabled (`revoked-by-admin`): that may mean a compromised key, so recovery is
a new registration token (a new client and key). Deploy it via
[`k8s/cronjob.yaml`](./k8s/cronjob.yaml) or cron.

## Docker

```bash
docker build -t shoveler-auth-portal .
```

Stage 1 (`node:20-slim`) compiles and purges the CSS; stage 2
(`python:3.12-slim`) runs the app as a non-root user with no Node or
`node_modules` in the final image.

CI ([`.github/workflows/image.yml`](./.github/workflows/image.yml)) builds the
image on every PR and publishes `ghcr.io/djw8605/shoveler-auth-portal` from
`main` (`:latest`, `:sha-<short>`) and from `v*` tags (`:1.2.3`, `:1.2`). Cut a
release with `git tag v0.1.0 && git push origin v0.1.0`. A new GHCR package is
private by default: make it public in the package settings, or give the
cluster an `imagePullSecret`.

## Deploying to Kubernetes

Prerequisites:

- A DNS name with TLS (an ingress controller, plus cert-manager or a TLS
  Secret). HTTPS is required: the session cookie is `Secure`, and RabbitMQ and
  the shovelers fetch `/.well-known/jwks.json` and `/token` over https.
- A CILogon confidential client whose redirect URI is
  `<PORTAL_BASE_URL>/auth/callback` (see above).
- COmanage groups named `<COMANAGE_GROUP_PREFIX><site>` (plus the
  `REGISTRY_ADMIN_GROUP`, if used), released to the portal's CILogon client in
  the `isMemberOf` claim (see Authorization above).
- A StorageClass for a small ReadWriteOnce volume. Prefer block storage;
  SQLite in WAL mode is not safe on NFS.
- A published image tag (see Docker above); the manifests pin `:0.1.0`.

Apply in this order:

```bash
# 1. Secret (portal's CILogon creds, session secret, issued-token claims).
#    Fill values from k8s/secret.example.yaml; never commit the real one.
kubectl create secret generic shoveler-auth-portal --from-env-file=prod.env

# 2. PVC, Deployment, Service
kubectl apply -f k8s/deployment.yaml

# 3. Ingress (copy and edit host / class / issuer first)
kubectl apply -f k8s/ingress.yaml

# 4. Nightly idle-expiry job
kubectl apply -f k8s/cronjob.yaml
```

On first start the portal creates the SQLite DB and an active signing key on
the volume; no bootstrap step is needed. Then check:

```bash
curl -s https://shoveler-auth.osg.example/healthz
curl -s https://shoveler-auth.osg.example/.well-known/openid-configuration
curl -s https://shoveler-auth.osg.example/.well-known/jwks.json
```

and configure RabbitMQ as described above (`issuer`, `resource_server_id` and
`additional_scopes_key` must match the Secret exactly).

Notes:

- Keep `replicas: 1`. The Deployment uses `strategy: Recreate` because the
  volume is ReadWriteOnce and SQLite must have a single writer; expect a few
  seconds of downtime per rollout.
- The CronJob shares the same volume, so it has pod affinity to run on the
  portal pod's node. If the portal pod is down, the run waits up to an hour
  for it and is then skipped.
- Rotate keys with
  `kubectl exec deploy/shoveler-auth-portal -- python -m portal.keys generate`,
  then `kubectl rollout restart deploy/shoveler-auth-portal`.

## Security notes

- No shared secret between the registry and shovelers. Each shoveler's private
  key never leaves its host; the registry stores only the public JWK, its `kid`
  and its RFC 7638 thumbprint.
- Registration tokens are `secrets.token_urlsafe(32)`, single-use, expiring,
  revocable, and shown exactly once. Only their SHA-256 hash is stored (a fast
  hash is fine for 256 random bits, and lets `/register` look them up).
- `/token` accepts only RS256 client assertions verified against the registered
  key, with audience, lifetime and one-time-`jti` checks, and returns a uniform
  `invalid_client` for every failure. `/register` returns a uniform
  `invalid_token` for every bad token.
- Private signing keys are `0600`, never logged, never returned, never in git.
- CSRF tokens protect all browser POSTs; destructive actions confirm first.
- Session cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` when
  `PORTAL_BASE_URL` is https.
- Rate limits: per-`client_id` on `/token`, per-IP on `/register`. No
  registration token, client assertion or access token is ever logged.
