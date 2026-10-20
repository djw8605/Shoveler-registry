# CLAUDE.md

Guidance for working in this repo. Keep it current when conventions change.

## What this is

A small, self-contained **OAuth2 token issuer** for the
`xrootd-monitoring-shoveler` (replaces a Keycloak deployment). Site operators
never log in: the shoveler generates its own RSA key, registers the public key
at `/register`, and waits as pending until a member of the one admin group
(CILogon login) approves it, unless an admin gave it a one-time registration
token. It then authenticates at `/token` with a JWT signed by its private key
(`private_key_jwt`) to fetch short-lived RS256 JWTs that RabbitMQ validates
against this service's published JWKS. No shared secret.

Design ethos: **small and boring**. A few hundred lines across a handful of
files, clarity over cleverness. Do not add infrastructure (Celery, Redis, an
ORM, a JS framework, the Tailwind Play CDN) — the stack is fixed (see README).

## Module map (`portal/`)

| File | Responsibility |
| --- | --- |
| `config.py` | `Settings` dataclass loaded once from env via `get_settings()` (lru_cache). All env parsing lives here. |
| `db.py` | stdlib `sqlite3` (WAL), schema init, and all SQL. No ORM. One connection per operation. |
| `keys.py` | RSA key gen/load, JWKS, `KeyStore`, manifest-based rotation. CLI: `python -m portal.keys generate|list`. |
| `registration.py` | `/register` logic (`register`): token-less pending registration or an admin-made bearer registration token, RFC 7591 metadata validation, idempotent retry. |
| `tokens.py` | `/token` logic (`issue_token`): `private_key_jwt` assertion verification + replay check, claim building, registration-token generation/hashing, in-process `RateLimiter`. |
| `authz.py` | `is_admin(admin_group, groups)`: the only authorization check. |
| `auth.py` | CILogon OIDC relying-party flow (auth-code + PKCE + nonce), ID-token validation, `isMemberOf` group capture, session helpers. |
| `main.py` | `create_app(settings)` factory: routes, `SessionMiddleware`, CSRF, the `render()`/`admin_user()`/`refuse()` helpers, machine endpoints. |
| `expire.py` | Expiry subcommand (idle clients, stale pending registrations): `python -m portal.expire`. |
| `templates/` | Jinja2: `base`, `macros`, `login`, `dashboard`, `registration_token`, `not_authorized`, `admin`. |

## Dev setup & commands

```bash
# Python 3.12 is REQUIRED (pyproject requires-python >=3.12); 3.11 will fail to install.
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

# CSS (Node only at build time). Tailwind v3 — uses @tailwind directives + tailwind.config.js.
npm install
npm run build:css          # one-shot minified; npm run watch:css to rebuild on change

# Run (factory mode — create_app() reads settings from env)
uvicorn --factory portal.main:create_app --reload --port 8080

# Tests
pytest
```

Required env vars to run/serve: see `.env.example`. Tests do NOT need env —
they construct `Settings(...)` directly (see `tests/conftest.py`).

## Conventions & invariants (don't break these)

- **Two credential kinds, never conflated.** `CILOGON_*` = the portal's OWN
  OIDC client creds, including a client secret (logs humans in). The clients
  in the `clients` table = what this service ISSUES to shovelers; they have
  **keys, not secrets** (we store only their public JWK). Keep naming explicit
  in code and docs.
- **No shared secrets with shovelers.** Never reintroduce client secrets or
  accept a client's private key: `/register` rejects JWKs with private members.
- **Registration tokens:** `secrets.token_urlsafe(32)`, single-use, expiring,
  shown exactly once. Store only the **SHA-256** hash (fast hash is deliberate:
  256 random bits, and `/register` looks tokens up by hash; don't "upgrade" it
  to argon2). Spend + create client atomically (`db.register_client`). Never log
  a registration token, client assertion or minted token at any level.
- **Signing keys** (and the generated `session.secret` beside them): written
  `0600`, never logged, never returned,
  never committed (`.gitignore` covers `*.pem`, `manifest.json`, `data/`). All
  public keys (active + retired) are published in JWKS; only the newest signs.
- **`/token`:** `private_key_jwt` only. Verify with `algorithms=["RS256"]`
  ONLY (no `none`/HS256 confusion), the stored `kid`, `iss == sub ==
  client_id`, an accepted `aud` (`Settings.token_endpoint_audiences`), required
  `exp`/`iat`/`jti`, a capped lifetime, and a one-time `jti`. Every failure is
  a uniform `401 {"error":"invalid_client"}` (never reveal which). Minted
  tokens' `aud` must equal `RESOURCE_SERVER_ID` exactly — no surrounding
  whitespace.
- **`/register`:** every bad token is the same `401 invalid_token`; bad
  metadata is `400 invalid_client_metadata` and must NOT spend the token. No
  `registration_access_token` (RFC 7592 is out of scope).
- **Pending (token-less) registration:** only when there is NO Authorization
  header (a present-but-bad token is always 401, never pending). Pending
  clients have NULL site/owner, get `400 authorization_pending` at `/token`
  only AFTER their assertion verifies, are kept out of the client list and
  idle-expiry, and are capped and purged. An admin approves one and types its
  site label; `owner_*` records that admin (or the token's creator).
- **Browser POSTs are CSRF-protected.** Every form includes the per-session
  `csrf_token`; handlers call `_check_csrf`. Destructive actions also confirm
  via a JS `confirm()` in the template. New POST routes must do the same.
- **Authorization:** one rule. Only members of `ADMIN_GROUP` (COmanage, via
  CILogon's `isMemberOf`, captured into the session at login) may use the
  portal; everyone else gets the not-authorized page. Every browser route
  calls `admin_user()` first (POSTs answer non-admins with `refuse()`).
  Admins can do everything: approve/reject, tokens, disable/re-enable any
  shovelers. A site is only a display label, never a grant. No per-site
  groups, no owner-only checks, no allow-list file. Group changes take effect
  on next login.
- **Sessions:** cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` whenever
  `PORTAL_BASE_URL` is https.
- **Config:** add new settings in `config.py` (parse env + default there), then
  thread through `create_app`. Don't read `os.environ` elsewhere.
- **DB access:** open a connection with `db.connect(...)`, do work in
  `try/finally: conn.close()`. Add new SQL as functions in `db.py`, not inline.
  Clients with `pending = 1` have no site: filter them out of anything that
  treats clients as belonging to a site.

## CSS / templates

- `assets/app.css` + `tailwind.config.js` are the **source of truth**.
  `portal/static/css/app.css` is a **build artifact** — gitignored, regenerated
  by `npm run build:css` and by the Docker build. After editing templates, the
  build re-scans `portal/templates/**/*.html` and purges unused classes.
- Reuse `templates/macros.html` (`button`, `card`, `badge`, `flash`) instead of
  copy-pasting long utility-class strings. The base template links the compiled
  CSS and nothing else (no CDN).

## Testing notes

- `tests/conftest.py` builds an isolated `Settings` per test (tmp DB, tmp key
  dir, `admin_group="shoveler-admins"`) and a `TestClient` with
  `base_url="https://testserver"` so the **Secure** session cookie is sent back.
- `tests/helpers.py` (imported as `helpers`) generates shoveler RSA keys, JWKs,
  Go-client-shaped assertions, and seeds tokens/clients (`seed_token`,
  `seed_client`, `seed_pending`). Use it rather than inserting rows by hand.
- For routes needing a logged-in user, monkeypatch `portal.main.current_user`
  to return a `UserInfo` with the right `groups` (`("shoveler-admins",)` for an
  admin);
  it's resolved as a module global at call time. CSRF token is scraped from a
  prior `GET` of the page.
- Coverage lives in `test_register`, `test_token` (incl. discovery),
  `test_db`, `test_jwks`, `test_authz`, `test_expire`, `test_flow` (browser
  lifecycle), `test_admin`. Add to the matching file.

## Gotchas

- Installing on Python 3.11 fails the `requires-python` gate — use 3.12.
- A `Secure` cookie won't round-trip over plain http (TestClient or local). Use
  an https base URL in tests; locally the app still works, but the CSRF-guarded
  POST flow needs https to exercise end to end.
- The rate limiter and key cache are in-process — they assume a single replica
  (the k8s Deployment is `replicas: 1` with a shared volume by design).
- The data PVC is ReadWriteOnce: the Deployment must stay `strategy: Recreate`
  and the CronJob keeps its pod affinity to the portal pod's node. Never give
  the CronJob pod the `app: shoveler-auth-portal` label (Service/Deployment
  select on it).
- Python deps live only in `pyproject.toml`; the Dockerfile reads them from
  there. Don't re-list them in the Dockerfile.

## Ops quick reference

- Rotate keys: `python -m portal.keys generate`, then reload/restart so the new
  active key loads. Retired keys stay in JWKS until old tokens expire.
- Expiry: `python -m portal.expire` (k8s CronJob in `k8s/base/cronjob.yaml`).
- Build image: `docker build -t shoveler-auth-portal .` (multi-stage; final
  image has no Node/node_modules; runs non-root).
- Publish image: CI pushes to GHCR from `main` (`:latest`) and `v*` tags
  (semver). Release = push a `vX.Y.Z` tag, then bump `images: newTag` in the
  overlay (`k8s/overlays/*/kustomization.yaml`). Full deploy steps: README
  "Deploying to Kubernetes".
- k8s layout: kustomize `k8s/base` (generic) + `k8s/overlays/tiger` (tiger
  cluster, namespace `osgdev`, host `shoveler-auth.osgdev.chtc.io` (osgdev's
  own Traefik), context `dweitzel2-tiger-dex`, NOT the default
  nautilus context). Settings live in the overlay's committed `config.env`
  (ConfigMap); nothing in this repo is secret. The CILogon client comes from
  the pre-existing Secret `shoveler-auth-oidc-secret` (keys `client.id`,
  `client.secret`); the session secret is generated on the volume
  (`keys.load_or_create_session_secret`). Never commit a Secret. Validate with
  `kubectl kustomize k8s/overlays/tiger`. No `commonLabels` in the base (see
  the CronJob label gotcha).

## Repo hygiene

- Default branch is `main`. Don't commit `data/`, `*.pem`, `manifest.json`,
  `.env`, `node_modules/`, or the compiled CSS.
- Keep README, `.env.example`, and the overlays' `config.env` in sync when env
  vars change.
