# Shoveler Auth Portal

A small, self-contained OAuth2 token issuer for the
[`xrootd-monitoring-shoveler`](https://github.com/opensciencegrid/xrootd-monitoring-shoveler).
It lets site operators **self-provision credentials** for the shoveler and
mints the short-lived JWTs that RabbitMQ validates against this service's
published public keys. It replaces a Keycloak deployment with a few hundred
lines of Python.

It does four things:

1. **Self-service portal** (browser, CILogon login) — operators create / recreate
   / disable a `client_id` + `client_secret` for their site.
2. **Token endpoint** (`POST /token`) — OAuth2 `client_credentials` grant → signed JWT.
3. **JWKS endpoint** (`GET /.well-known/jwks.json`) — RabbitMQ fetches public keys here.
4. **Idle-expiry job** — disables credentials unused for `IDLE_DAYS`.

> **Two kinds of credentials — don't conflate them.**
> The portal is itself a *confidential OIDC client of CILogon* (`CILOGON_CLIENT_ID`/
> `CILOGON_CLIENT_SECRET`), which it uses to log humans in. That is entirely
> separate from the shoveler `client_id`/`client_secret` pairs that this service
> *issues* to sites.

## Stack

Python 3.12 · FastAPI · Uvicorn · stdlib `sqlite3` (WAL) · PyJWT + `cryptography`
for signing · `argon2-cffi` for secret hashing · httpx for the CILogon OIDC flow ·
Jinja2 templates · Tailwind CSS (compiled via the Tailwind CLI, **not** the Play CDN).

## Layout

```
portal/
  config.py     env-driven settings
  db.py         sqlite schema + queries (WAL)
  keys.py       key gen/load, JWKS, rotation CLI
  tokens.py     /token logic, claim building, argon2, rate limiting
  authz.py      site-admins allow-list
  auth.py       CILogon OIDC relying-party flow + session
  main.py       FastAPI app, routes, middleware, CSRF
  expire.py     idle-expiry subcommand
  templates/    base, macros, login, dashboard, secret_once, not_authorized
  static/css/   compiled app.css (build artifact)
assets/app.css  Tailwind source (source of truth)
tailwind.config.js, package.json
site-admins.example.yaml, .env.example
Dockerfile      multi-stage (node build → python runtime), non-root
k8s/            deployment, cronjob, secret example
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
| `SITE_ADMINS_FILE` | `./site-admins.yaml` | Allow-list (reloaded each request) |
| `TOKEN_ISSUER` | _required_ | JWT `iss` (= RabbitMQ `auth_oauth2.issuer`) |
| `RESOURCE_SERVER_ID` | _required_ | JWT `aud` (= RabbitMQ `auth_oauth2.resource_server_id`), exact |
| `TOKEN_TTL_SECONDS` | `14400` | JWT lifetime (4h) |
| `SCOPE_CLAIM` | `extra_scope` | Custom claim key (= RabbitMQ `additional_scopes_key`) |
| `SCOPE_VALUE` | `my_rabbit_server.write:*/xrd-shoveled` | Permission written into the scope claim |
| `IDLE_DAYS` | `30` | Idle-expiry threshold |
| `ADMIN_CONTACT` | _generic_ | Shown on the not-authorized page |
| `REGISTRY_ADMIN_SUBS` | _empty_ | Comma-separated CILogon subs of registry-wide admins |
| `TOKEN_RATE_LIMIT` / `TOKEN_RATE_WINDOW` | `30` / `60` | Per-`client_id` `/token` rate limit |

## CILogon client registration

Register a **confidential** OIDC client at <https://cilogon.org/oauth2/register>:

- **Redirect URI:** `${PORTAL_BASE_URL}/auth/callback` (exact match)
- **Scopes:** `openid email profile org.cilogon.userinfo`
- **Client type:** confidential (the portal keeps a client secret)
- **Grant:** authorization code (the portal adds PKCE + `state` + `nonce`)

CILogon issues the `client_id`/`client_secret`; set them as
`CILOGON_CLIENT_ID` / `CILOGON_CLIENT_SECRET`. Only the `sub` claim is used as
the stable identity; the ID token is fully validated (signature via CILogon's
JWKS, plus `iss`/`aud`/`exp`/`nonce`).

## Authorization (site-admins allow-list)

Who may manage which site is controlled by [`site-admins.yaml`](./site-admins.example.yaml),
keyed by CILogon `sub`:

```yaml
nebraska:
  - sub: "http://cilogon.org/serverA/users/12345"
    email: "derek@unl.edu"
```

The file is reloaded on **every request**, so edits take effect without a
restart. There is no email-domain auto-grant — adding a person here is the
central admin's only recurring action. A `sub` mapped to no site sees a
friendly "not yet authorized; contact `${ADMIN_CONTACT}`" page.

### Registry-wide admins

Site-admins see only their own sites. A separate, smaller group of
**registry-wide admins** — listed by CILogon `sub` in `REGISTRY_ADMIN_SUBS`
(comma-separated, kept in deploy config rather than the editable allow-list) —
get an **Admin** link to `GET /admin`, a read-only table of *every* credential
across *all* sites (site, `client_id`, owner email, status, created,
last_used). It makes idle/dead sites easy to scan. Admins may also disable any
credential (`disabled_reason='revoked-by-admin'`); recovery is still
self-service via the owner's Recreate. Leave `REGISTRY_ADMIN_SUBS` empty to
disable the admin view entirely.

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
cp .env.example .env       # fill in CILOGON_*, SESSION_SECRET, etc.
cp site-admins.example.yaml site-admins.yaml
set -a; . ./.env; set +a   # export the vars into your shell

# 4. Run (factory mode — create_app() reads settings from the env)
uvicorn --factory portal.main:create_app --reload --port 8080
```

Run the tests with `pytest`.

## Token / JWT details

`POST /token` accepts a form-encoded `client_credentials` grant (or HTTP Basic
per RFC 6749). On success it returns
`{"access_token", "token_type":"Bearer", "expires_in"}` and updates the
credential's `last_used_at`. Any authentication failure (unknown id, disabled,
or wrong secret) returns a uniform `401 {"error":"invalid_client"}` — the secret
check is constant-time and never reveals which of id/secret was wrong. Requests
that exceed the per-`client_id` rate limit instead get `429` with a `Retry-After`
header (a throttling signal, distinct from the auth-failure response).

The minted RS256 JWT (header carries `kid`) has claims:

```
iss = TOKEN_ISSUER
sub = client_id
aud = RESOURCE_SERVER_ID         # exact, no surrounding whitespace
iat = now
exp = now + TOKEN_TTL_SECONDS
jti = random
<SCOPE_CLAIM> = SCOPE_VALUE      # e.g. extra_scope = my_rabbit_server.write:*/xrd-shoveled
```

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

After creating a credential, the one-time page shows a ready-to-paste snippet
(adjust host/exchange to your RabbitMQ deployment):

```yaml
# xrootd-monitoring-shoveler config.yaml
mq: amqp
amqp:
  url: amqps://your-rabbit-host:5671
  exchange: shoveled
  token:
    client_id: "shoveler-xxxxxxxxxxxxxxxx"
    client_secret: "<shown once>"
    token_endpoint: "https://shoveler-auth.osg.example/token"
```

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
logs in and clicks **Recreate**, which rotates a fresh secret and clears the
disabled flag. Deploy it via [`k8s/cronjob.yaml`](./k8s/cronjob.yaml) or cron.

## Docker

```bash
docker build -t shoveler-auth-portal .
```

Stage 1 (`node:20-slim`) compiles and purges the CSS; stage 2
(`python:3.12-slim`) runs the app as a non-root user with no Node or
`node_modules` in the final image.

## Security notes

- Secrets generated with `secrets.token_urlsafe(32)`; only the argon2 hash is
  stored; the secret is shown exactly once.
- Private signing keys are `0600`, never logged, never returned, never in git.
- `/token` does a constant-time secret check and returns a uniform `invalid_client`.
- CSRF tokens protect all browser POSTs; destructive actions confirm first.
- Session cookies are `HttpOnly`, `SameSite=Lax`, and `Secure` when
  `PORTAL_BASE_URL` is https.
- Modest per-`client_id` rate limit on `/token`. No secret or token values are
  ever logged.
