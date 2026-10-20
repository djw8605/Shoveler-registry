# Shoveler Auth Portal

A small, self-contained OAuth2 token issuer for the
[`xrootd-monitoring-shoveler`](https://github.com/opensciencegrid/xrootd-monitoring-shoveler).
It lets site operators **onboard shovelers themselves** and mints the
short-lived JWTs that RabbitMQ validates against this service's published
public keys. Shovelers hold their own RSA key; **no shared secret exists
anywhere**. It replaces a Keycloak deployment with a few hundred lines of
Python.

It does five things:

1. **Admin portal** (browser, CILogon login, members of one COmanage admin
   group only) — admins **approve** or reject shovelers that registered
   themselves, label each with its site, create one-time **registration
   tokens**, and disable / re-enable shovelers. Site operators never log in.
2. **Registration endpoint** (`POST /register`) — a shoveler sends its **public
   key** (RFC 7591 request format) and waits as **pending** until an admin
   approves it. With an admin-made registration token it is active at once.
3. **Token endpoint** (`POST /token`) — OAuth2 `client_credentials` grant,
   authenticated with a JWT signed by the shoveler's private key
   (`private_key_jwt`, RFC 7523) → signed access token. The **JWKS endpoint**
   (`GET /.well-known/jwks.json`) publishes the keys RabbitMQ verifies it with.
4. **Health reports** (`POST /report`) — each shoveler periodically sends its
   packet counts and queue size with its access token; the dashboard shows
   which shovelers are healthy, with a day of charts per shoveler.
5. **Expiry job** — disables shovelers unused for `IDLE_DAYS`, deletes
   pending registrations nobody approved, and drops old health reports.

> **Two kinds of credentials — don't conflate them.**
> The portal is itself a *confidential OIDC client of CILogon* (`CILOGON_CLIENT_ID`/
> `CILOGON_CLIENT_SECRET`), which it uses to log humans in. That is entirely
> separate from the shoveler clients this service *issues* to sites, which
> authenticate with their own keys, not secrets.

## Stack

Python 3.12 · FastAPI · Uvicorn · stdlib `sqlite3` (WAL) · PyJWT + `cryptography`
for signing and client-assertion verification · Authlib (+ httpx) for the CILogon OIDC flow ·
Jinja2 templates · Tailwind CSS (compiled via the Tailwind CLI, **not** the Play CDN) ·
[uPlot](https://github.com/leeoniya/uPlot) for the health charts (vendored from npm at
build time, no CDN, no JS framework).

## Layout

```
portal/
  config.py     env-driven settings
  db.py         sqlite schema + queries (WAL)
  keys.py       key gen/load, JWKS, rotation CLI
  registration.py  /register: registration tokens, pending (token-less) registration, metadata validation
  tokens.py     /token private_key_jwt verification, claim building, rate limiting
  health.py     /report validation; rates, sparklines and health status for the dashboard
  authz.py      the one COmanage admin group
  auth.py       CILogon OIDC relying-party flow + session (captures isMemberOf)
  main.py       FastAPI app, routes, middleware, CSRF
  expire.py     expiry subcommand (idle clients, stale pending registrations, old reports)
  templates/    base, macros, login, dashboard, shoveler, registration_token, not_authorized
  static/js/    charts.js: the health charts (uPlot); refresh.js: pausable auto-refresh
  static/css/   compiled app.css (build artifact)
  static/vendor/  uPlot, copied from node_modules (build artifact)
assets/app.css  Tailwind source (source of truth)
tailwind.config.js, package.json
.env.example
Dockerfile      multi-stage (node build → python runtime), non-root
k8s/            kustomize base + overlays (tiger)
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
| `SESSION_SECRET` | _generated_ | Signs the session cookie; if unset, generated once and kept in `SIGNING_KEY_DIR/session.secret` (0600) |
| `DB_PATH` | `./data/portal.db` | SQLite file |
| `SIGNING_KEY_DIR` | `./data/keys` | Generated signing keys + `manifest.json` (and `session.secret`) |
| `SIGNING_KEY_FILE` | _empty_ | An existing RSA private key (PEM) to sign with instead of generating keys, e.g. the one RabbitMQ already trusts |
| `SIGNING_KEY_ID` | key thumbprint | The `kid` for `SIGNING_KEY_FILE` (the name RabbitMQ knows the key by) |
| `TOKEN_ISSUER` | _required_ | JWT `iss` (= RabbitMQ `auth_oauth2.issuer`) |
| `RESOURCE_SERVER_ID` | _required_ | JWT `aud` (= RabbitMQ `auth_oauth2.resource_server_id`), exact |
| `TOKEN_TTL_SECONDS` | `14400` | JWT lifetime (4h) |
| `SCOPE_CLAIM` | `scope` | Claim holding the permission (RabbitMQ reads `scope` by default; another name needs `additional_scopes_key`) |
| `SCOPE_VALUE` | `my_rabbit_server.write:xrd-mon/shoveled-xrd` | Permission written into that claim (vhost `xrd-mon`, exchange `shoveled-xrd`) |
| `IDLE_DAYS` | `30` | Idle-expiry threshold |
| `ADMIN_CONTACT` | _generic_ | Shown on the not-authorized page |
| `ADMIN_GROUP` | _required_ | COmanage group whose members may log in and manage shovelers |
| `ADMIN_SUBS` | _empty_ | Comma-separated CILogon `sub`s that are admins regardless of groups (a stopgap when group claims aren't released) |
| `TOKEN_RATE_LIMIT` / `TOKEN_RATE_WINDOW` | `30` / `60` | Per-`client_id` `/token` rate limit |
| `REGISTRATION_TOKEN_TTL_SECONDS` | `259200` | Lifetime of a one-time registration token (72h) |
| `REGISTER_RATE_LIMIT` / `REGISTER_RATE_WINDOW` | `10` / `60` | Per-client-IP `/register` rate limit |
| `ASSERTION_MAX_LIFETIME_SECONDS` | `300` | Reject client assertions whose `exp` is further out than this |
| `ALLOW_PENDING_REGISTRATION` | `true` | Accept token-less registrations as pending (`false`: a token is required) |
| `MAX_PENDING_CLIENTS` | `100` | Most pending registrations at once; more get `503` |
| `PENDING_CLIENT_TTL_SECONDS` | `604800` | Unapproved pending registrations are deleted after this (7 days) |
| `METRICS_RETENTION_HOURS` | `24` | Health reports kept (and charted) this long; each shoveler's latest is kept longer |
| `REPORT_RATE_LIMIT` / `REPORT_RATE_WINDOW` | `10` / `60` | Per-`client_id` `/report` rate limit |

## CILogon client registration

Register a **confidential** OIDC client at <https://cilogon.org/oauth2/register>:

- **Redirect URI:** `${PORTAL_BASE_URL}/auth/callback` (exact match)
- **Scopes:** `openid email profile org.cilogon.userinfo`
- **Client type:** confidential (the portal keeps a client secret)
- **Grant:** authorization code (the portal adds PKCE + `state` + `nonce`)

CILogon issues the `client_id`/`client_secret`; set them as
`CILOGON_CLIENT_ID` / `CILOGON_CLIENT_SECRET`. The `sub` claim is the stable
identity; the `isMemberOf` claim carries the user's COmanage group memberships
(used to check `ADMIN_GROUP`, below). The ID token is fully validated (signature via
CILogon's JWKS, plus `iss`/`aud`/`exp`/`nonce`).

> The `org.cilogon.userinfo` scope (already requested) is what releases
> `isMemberOf`. If your CILogon/COmanage deployment only returns it from the
> userinfo endpoint rather than in the ID token, the portal fetches it from
> there automatically.

## Authorization (one admin group)

Only admins can use the portal: members of the COmanage group named in
`ADMIN_GROUP`, delivered by CILogon in the `isMemberOf` claim, plus anyone
whose CILogon `sub` is listed (exactly) in `ADMIN_SUBS`. The allow-list is a
stopgap for when the CILogon client doesn't receive group claims; prefer the
group. Anyone else who logs in sees a "not authorized" page naming
`${ADMIN_CONTACT}`, the groups CILogon reported for them, and their CILogon
ID (the value to put in `ADMIN_SUBS`). Site operators don't need accounts:
they just run shovelers, which register themselves.

Admins see one dashboard with:

- **Awaiting approval:** shovelers that registered without a token, with their
  `client_id`, name, key thumbprint, source IP and time. **Approve** asks for a
  site label (known sites are suggested); **Reject** deletes the registration.
- **Registered shovelers:** every approved shoveler (site, `client_id`, name,
  key thumbprint, who approved it, status, created, last used), with
  **Disable** (`disabled_reason='disabled-by-admin'`) and **Re-enable**.
- **Health:** every enabled shoveler's health from its reports, worst first.
  A row that isn't healthy says what is wrong and since when ("Nothing
  published since 02:32 UTC (46 min ago)"). Each row also shows the packet
  rate now, a 24-hour strip of its health, its queue and when it last
  reported, and links to the shoveler's page (below).
- **Registration tokens:** create a one-time token for a site, for a shoveler
  that should be active without a separate approval; revoke unused ones.

Each approved shoveler also has a page, `/shovelers/<client_id>`:

- what is wrong, since when, and what to check (including when its newest
  token from this registry expired, if it has);
- received → queued → published right now, and the last 24 hours' failed
  validations, bus reconnects and restarts;
- a 24-hour tracker of 15-minute blocks in the same states as the badges,
  with its changes listed in words;
- uPlot charts of packets per second (received and published), queue size
  and errors per minute over the last 2 or 24 hours (drag to zoom), with the
  same figures as an hourly table;
- its registration details, and Disable / Re-enable.

All times are UTC. The page reloads every minute unless paused.

A site is only a label for grouping and display; it grants nobody access.
Group memberships are captured into the session **at login**, so COmanage
changes take effect on the user's next login.

## Local development

```bash
# 1. Python env
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

# 2. Build the CSS and vendor uPlot once, or watch the CSS while you edit templates
npm install
npm run build              # one-shot: minified CSS + uPlot into portal/static/vendor/
npm run watch:css          # rebuild the CSS on change (run alongside uvicorn)

# 3. Config
cp .env.example .env       # fill in CILOGON_*, ADMIN_GROUP, etc.
set -a; . ./.env; set +a   # export the vars into your shell

# 4. Run (factory mode — create_app() reads settings from the env)
uvicorn --factory portal.main:create_app --reload --port 8080
```

Run the tests with `pytest`.

## Registration and token endpoints

### `POST /register`

The shoveler generates an RSA keypair locally and registers the **public** key.
There are two ways:

- **Without a token** (no `Authorization` header at all; the usual way): the
  client is **pending**, with no site. It can't get access tokens until an
  admin approves it on the dashboard and labels its site. Rejecting it deletes
  it.
- **With a registration token** an admin created (bearer token): the client is
  active immediately, labelled with the token's site.

```http
POST /register
Content-Type: application/json
Authorization: Bearer <registration token>      # omit for a pending registration

{"client_name": "xrootd-01.example.edu",
 "grant_types": ["client_credentials"],
 "token_endpoint_auth_method": "private_key_jwt",
 "jwks": {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256",
                    "kid": "<kid>", "n": "...", "e": "AQAB"}]}}
```

`201` returns `client_id`, `client_id_issued_at`, `client_name`, `grant_types`
and `token_endpoint_auth_method`. No `registration_access_token` is issued
(RFC 7592 client management is not offered), so no long-lived management
credential exists. Every client gets the normal `SCOPE_VALUE` (any requested
scope is ignored).

With a token:

- An admin creating the token is the approval, so the client is active
  immediately.
- The token is **single-use** and expires after `REGISTRATION_TOKEN_TTL_SECONDS`.
  Spending it and creating the client happen in one transaction, so of two
  concurrent uses exactly one succeeds. Until it is used, any admin can revoke
  it on the dashboard.
- An unknown, expired, revoked or already-used token, or any `Authorization`
  header that isn't `Bearer <token>`, gets `401 {"error":"invalid_token"}` with
  `WWW-Authenticate: Bearer error="invalid_token"`. A bad token never falls back
  to a pending registration.
- **Retry is idempotent:** if the response was lost, presenting the same (used,
  unexpired) token with the **same key** returns the same `client_id`. A
  different key gets `401`.
- Metadata must use `private_key_jwt`, `grant_types` (if present) exactly
  `["client_credentials"]`, and exactly one RSA key with a non-empty `kid`, at
  least 2048 bits, `use` absent or `sig`, `alg` absent or `RS256`, and **no
  private members**. `jwks_uri` is not supported. Violations get
  `400 {"error":"invalid_client_metadata","error_description":...}` and do not
  spend the token. Unknown fields (e.g. `software_version`) are ignored.

Without a token (pending):

- Allowed while `ALLOW_PENDING_REGISTRATION` is on (the default); otherwise a
  missing token is `401 invalid_token`.
- Registering again with the **same key** returns the same `client_id`.
- At most `MAX_PENDING_CLIENTS` may wait at once; beyond that the registry
  answers `503 {"error":"temporarily_unavailable"}` with `Retry-After`.
- The dashboard lists pending shovelers with their `client_id`, name, key
  thumbprint, source IP and time. The shoveler logs its `client_id` when it
  registers, so the admin can match the two before approving.
- Pending registrations nobody approves within `PENDING_CLIENT_TTL_SECONDS`
  are deleted by the nightly expire job.

Both modes are rate-limited per client IP (`429` with `Retry-After`).

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
and updates the client's `last_used_at`. A **pending** client whose assertion
verifies gets `400 {"error":"authorization_pending"}` instead; the shoveler
keeps polling until it is approved. Any authentication failure (unknown or
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
<SCOPE_CLAIM> = SCOPE_VALUE      # by default scope = my_rabbit_server.write:xrd-mon/shoveled-xrd
```

`/.well-known/openid-configuration` advertises `token_endpoint`,
`registration_endpoint`, `jwks_uri`, `token_endpoint_auth_methods_supported:
["private_key_jwt"]` and `token_endpoint_auth_signing_alg_values_supported:
["RS256"]`.

## Health reports

### `POST /report`

Once this service has issued it an access token, a shoveler reports its
health right away and then every `amqp.oauth.report_interval` seconds (default
60), authenticated with **that access token** (the one it uses for RabbitMQ).
The shoveler's `docs/registry-protocol.md` ("Health report endpoint")
describes its side:

```
POST /report
Authorization: Bearer <access token>
Content-Type: application/json

{"started_at": "2026-10-21T02:00:00Z",       # process start: same value = same process
 "interval_seconds": 60,
 "version": "1.5.0",
 "metrics": {"packets_received": 120345,      # counters since started_at
             "validations_failed": 12,
             "messages_published": 120333,
             "rabbitmq_reconnects": 0,
             "queue_size": 0}}                 # current
```

→ `204`. The token must carry this service's signature (any key in the JWKS,
so retired keys still work), `iss = TOKEN_ISSUER`, `aud = RESOURCE_SERVER_ID`
and an unexpired `exp`, and name an approved, enabled client; anything else is
`401 {"error":"invalid_token"}`. A malformed body is `400 invalid_request` with
a description; unknown metric names are ignored, so a newer shoveler can send
more. Limited per client (`REPORT_RATE_LIMIT` per `REPORT_RATE_WINDOW`).

Reports are kept for `METRICS_RETENTION_HOURS` (24 h): each new report trims
that shoveler's older ones, and the expiry job trims the rest, always keeping
each shoveler's latest so the dashboard can say when it was last heard from.

### Health status

From the latest report and the last 15 minutes:

| Status | When |
| --- | --- |
| Not publishing | Packets received but none published to the bus (e.g. RabbitMQ unreachable, token rejected) |
| Not reporting | No report for 3 report intervals (at least 3 minutes) |
| No packets | No packets received (XRootD isn't sending to it) |
| Healthy | Otherwise |
| No reports | Never reported (an older shoveler, or `amqp.oauth.report_health: false`) |

Traffic checks wait until a process has run for 5 minutes. Rates come from the
difference between consecutive reports of the same process; a restart (new
`started_at`) or missed reports break the charts' lines instead of averaging
over the gap.

## RabbitMQ configuration

Point RabbitMQ at this issuer so it can discover the JWKS and validate tokens:

```ini
# rabbitmq.conf
auth_backends.1 = rabbit_auth_backend_oauth2

auth_oauth2.issuer                = https://shoveler-auth.osg.example/   # = TOKEN_ISSUER
auth_oauth2.resource_server_id    = my_rabbit_server                     # = RESOURCE_SERVER_ID
auth_oauth2.preferred_username_claims.1 = sub
# Only if SCOPE_CLAIM isn't the standard "scope":
# auth_oauth2.additional_scopes_key = <SCOPE_CLAIM>
```

RabbitMQ fetches public keys from `${TOKEN_ISSUER}/.well-known/jwks.json` (advertised
by `${TOKEN_ISSUER}/.well-known/openid-configuration`). `resource_server_id` must
equal the token's `aud` **exactly**. With the defaults the tokens carry the
same `aud` and `scope` as the shoveler's `createtoken` tool mints, so they
pass `shoveler-status`'s token check, and a RabbitMQ that already accepts
those tokens only needs the new `issuer` (and the registry's JWKS).

## Shoveler configuration

Requires a shoveler with OAuth self-registration support (`amqp.oauth`). Add
this to the `amqp:` section alongside your RabbitMQ `url` / `exchange`:

```yaml
amqp:
  oauth:
    enabled: true
    token_url: https://shoveler-auth.osg.example/token
    registration_url: https://shoveler-auth.osg.example/register
```

On first start the shoveler generates its key, registers as pending, logs its
`client_id` and key fingerprint, queues data on disk and polls. Send that
`client_id` to a registry admin, who finds it under **Awaiting approval**,
checks the fingerprint and approves it with the site label; the shoveler
starts sending within a minute and writes access tokens to
`amqp.token_location` from then on.

**With a registration token** (to skip the approval step): an admin creates
one for the site on the dashboard. The one-time page shows the token, how to
install it, and the same snippet with
`bootstrap_token_file: /var/lib/xrootd-monitoring-shoveler/bootstrap.token`
added. Write the token there with mode `0600`, owned by the
`xrootd-monitoring-shoveler` user the shoveler runs as; the shoveler is active
as soon as it registers, and the file can be deleted after that first start.

Once it has a token the shoveler also reports its health to this registry
(**Health** on the dashboard), at the `/report` endpoint beside `token_url`;
there is nothing to configure. `amqp.oauth.report_interval` (seconds, default
60) sets how often, and `amqp.oauth.report_health: false` stops it.

The shoveler keeps its private key, `client_id` and access token in
`/var/lib/xrootd-monitoring-shoveler/`, which its packages create for the
service user. **That directory must survive restarts and redeploys** (e.g. a
persistent volume for a containerised shoveler). If it is lost, the shoveler
registers again as a new pending client; an admin can disable the old one.

## Signing keys & rotation

**Bringing your own key.** Set `SIGNING_KEY_FILE` to an RSA private key (PKCS#1
or PKCS#8 PEM, unencrypted) and `SIGNING_KEY_ID` to its `kid`. The portal then
signs every access token with that key and publishes only its public half in
the JWKS; nothing is generated, and rotation means replacing the file. Use this
to keep a RabbitMQ that already trusts a key (e.g. the one the shoveler's
`createtoken` signs with, `kid` `xrdshoveler`) without changing its key
configuration. The tiger overlay does this, from Secret
`shoveler-auth-signing-key`.

**Generated keys** (the default, when `SIGNING_KEY_FILE` is unset). On first
start the portal generates an RSA-2048 signing key in
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
are never deleted (audit + recovery). To recover, an admin clicks
**Re-enable**, which clears the disabled flag; the shoveler keeps its key and
`client_id` and picks it up on its next 60-second retry, so nothing changes on
its side. (If a key may be compromised, disable that shoveler and have it
register again with a new key instead.) The same job deletes pending
registrations nobody approved within `PENDING_CLIENT_TTL_SECONDS`, and health
reports older than `METRICS_RETENTION_HOURS` (keeping each shoveler's latest).
Deploy it via [`k8s/base/cronjob.yaml`](./k8s/base/cronjob.yaml) or cron.

## Docker

```bash
docker build -t shoveler-auth-portal .
```

Stage 1 (`node:20-slim`) compiles and purges the CSS and copies uPlot out of
`node_modules`; stage 2
(`python:3.12-slim`) runs the app as a non-root user with no Node or
`node_modules` in the final image.

CI ([`.github/workflows/image.yml`](./.github/workflows/image.yml)) builds the
image on every PR and publishes `ghcr.io/djw8605/shoveler-auth-portal` from
`main` (`:latest`, `:sha-<short>`) and from `v*` tags (`:1.2.3`, `:1.2`). Cut a
release with `git tag v0.1.0 && git push origin v0.1.0`. A new GHCR package is
private by default: make it public in the package settings, or give the
cluster an `imagePullSecret`.

## Deploying to Kubernetes

The manifests are a kustomize base plus one overlay per deployment:

```
k8s/base/             generic: Deployment, Service, PVC, CronJob, Traefik Ingress,
                      cert-manager Certificate, NetworkPolicy (Traefik only)
k8s/overlays/tiger/   the tiger cluster (namespace osgdev), following tiger-osg-config
  kustomization.yaml  namespace, image tag, storage class (3x-replica-nvme-raddus)
  host.yaml           the public host for the Ingress and Certificate
  config.env          settings -> ConfigMap (committed; nothing secret)
  signing-key.yaml    mounts Secret shoveler-auth-signing-key as the signing key
```

Two Secrets must already exist in the namespace; nothing in this repo is
secret. On tiger both are SealedSecrets in tiger-osg-config's
`manifests/development`:

- `shoveler-auth-oidc-secret` (keys `client.id`, `client.secret`): the
  portal's CILogon client, read by the Deployment and CronJob. The
  CILogon/COmanage admin created it.
- `shoveler-auth-signing-key` (key `private.pem`): the RSA key RabbitMQ
  already trusts, used to sign access tokens (`signing-key.yaml`; its `kid` is
  `SIGNING_KEY_ID` in `config.env`). Seal it with:

  ```bash
  kubectl create secret generic shoveler-auth-signing-key -n osgdev \
      --dry-run=client --from-file=private.pem=<key.pem> -o json \
    | kubeseal -o yaml --cert tiger-cert.pem \
    > manifests/development/shoveler-auth-signing-key.yaml
  ```

  and list it in `manifests/development/kustomization.yaml`. Without this
  Secret the pod won't start; to have the portal generate its own key
  instead, drop `signing-key.yaml` from the overlay and point RabbitMQ at the
  JWKS.

The session secret is generated by the portal on its volume.

Prerequisites:

- A DNS name for the portal pointing at the namespace's Traefik. On tiger the
  record is created from the Ingress host when the Ingress is deployed; the
  tiger overlay uses `shoveler-auth.osgdev.chtc.io`, served by osgdev's
  Traefik (128.105.82.131). cert-manager's `letsencrypt-prod` ClusterIssuer
  issues the certificate once the name resolves. HTTPS is required: the session cookie
  is `Secure`, and RabbitMQ and the shovelers use `/register`, `/token` and
  `/.well-known/jwks.json` over https.
- A CILogon confidential client whose redirect URI is
  `<PORTAL_BASE_URL>/auth/callback` (see above).
- A COmanage group for the registry admins (`ADMIN_GROUP`), released to the
  portal's CILogon client in the `isMemberOf` claim (see Authorization above).
- The `shoveler-auth-oidc-secret` and `shoveler-auth-signing-key` Secrets in
  the namespace (above).
- A published image tag (see Docker above); the overlay pins `:0.2.2`.

Configure the overlay (tiger shown):

```bash
cd k8s/overlays/tiger
# 1. Host: edit host.yaml, and PORTAL_BASE_URL / TOKEN_ISSUER in config.env.
# 2. Settings: check config.env (RESOURCE_SERVER_ID and SCOPE_VALUE must match
#    RabbitMQ; ADMIN_GROUP must match the isMemberOf value exactly).
# 3. Check the result.
kubectl kustomize .
```

Then deploy it one of two ways:

- **Through tiger-osg-config (the normal way).** tiger's namespaces are
  synced by Flux from tiger-osg-config: `osgdev` from `manifests/development`,
  `osg` from `manifests/production`. Copy the overlay to
  `manifests/development/shoveler-auth-portal/` there, point its base at this
  repo (`resources: [https://github.com/djw8605/Shoveler-registry//k8s/base?ref=v0.2.2]`),
  and add `shoveler-auth-portal` to `manifests/development/kustomization.yaml`.
  If Flux refuses remote bases, copy `k8s/base` alongside instead. Moving to
  production later means `namespace: osg`, an `*.osg.chtc.io` (or
  `osg-htc.org`) host, and a `shoveler-auth-oidc-secret` in `osg` (with a
  CILogon client whose redirect URI uses that host).
- **Directly, for testing.** Only with write access to the namespace (OSG
  staff dex accounts are typically read-only), and Flux may overwrite manual
  changes. Use the tiger dex context, not the default nautilus one:

  ```bash
  kubectl --context dweitzel2-tiger-dex apply -k k8s/overlays/tiger
  ```

For another cluster, copy `overlays/tiger`, change the namespace, host,
storage class and Traefik/cert-manager details, and create the
`shoveler-auth-oidc-secret` there however that cluster provides Secrets.

On first start the portal creates the SQLite DB and an active signing key on
the volume; no bootstrap step is needed. Then check:

```bash
curl -s https://shoveler-auth.osgdev.chtc.io/healthz
curl -s https://shoveler-auth.osgdev.chtc.io/.well-known/openid-configuration
curl -s https://shoveler-auth.osgdev.chtc.io/.well-known/jwks.json
```

and configure RabbitMQ as described above (`issuer` and `resource_server_id`
must match `config.env` exactly).

Notes:

- Keep `replicas: 1`. The Deployment uses `strategy: Recreate` because the
  volume is ReadWriteOnce and SQLite must have a single writer; expect a few
  seconds of downtime per rollout. Editing `config.env` rolls the Deployment
  (the ConfigMap name carries a content hash).
- The CronJob shares the same volume, so it has pod affinity to run on the
  portal pod's node. If the portal pod is down, the run waits up to an hour
  for it and is then skipped.
- The NetworkPolicy admits only Traefik pods (`app: traefik`); egress stays
  open for CILogon.
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
- Token-less registration only creates a **pending** client with no site and
  no access; a member of `ADMIN_GROUP` must approve it.
  It is capped (`MAX_PENDING_CLIENTS`), expires, and can be turned off
  (`ALLOW_PENDING_REGISTRATION=false`). `/token` reveals pending status only to
  the holder of the registered private key.
- `/report` accepts only access tokens this service signed (RS256, any
  published `kid`), for an approved, enabled client, with `iss`/`aud`/`exp`
  checked, and a uniform `invalid_token` for every failure. A token sent to
  RabbitMQ could be replayed to `/report` until it expires; that can only add
  health reports for that one shoveler, never grant access.
- Rate limits: per-`client_id` on `/token` and `/report`, per-IP on
  `/register`. No registration token, client assertion or access token is
  ever logged.
