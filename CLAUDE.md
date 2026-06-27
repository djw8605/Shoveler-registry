# CLAUDE.md

Guidance for working in this repo. Keep it current when conventions change.

## What this is

A small, self-contained **OAuth2 token issuer** for the
`xrootd-monitoring-shoveler` (replaces a Keycloak deployment). Site operators
log in with CILogon, self-provision a `client_id`/`client_secret` for their
site, and the shoveler uses those at `/token` to fetch short-lived RS256 JWTs
that RabbitMQ validates against this service's published JWKS.

Design ethos: **small and boring**. A few hundred lines across a handful of
files, clarity over cleverness. Do not add infrastructure (Celery, Redis, an
ORM, a JS framework, the Tailwind Play CDN) — the stack is fixed (see README).

## Module map (`portal/`)

| File | Responsibility |
| --- | --- |
| `config.py` | `Settings` dataclass loaded once from env via `get_settings()` (lru_cache). All env parsing lives here. |
| `db.py` | stdlib `sqlite3` (WAL), schema init, and all SQL. No ORM. One connection per operation. |
| `keys.py` | RSA key gen/load, JWKS, `KeyStore`, manifest-based rotation. CLI: `python -m portal.keys generate|list`. |
| `tokens.py` | `/token` logic (`issue_token`), claim building, argon2 hashing/verify, in-process `RateLimiter`. |
| `authz.py` | COmanage group-based authz: `sites_for_groups`/`may_manage_site` (group `<prefix><site>` → site) + `is_registry_admin`. No file. |
| `auth.py` | CILogon OIDC relying-party flow (auth-code + PKCE + nonce), ID-token validation, `isMemberOf` group capture, session helpers. |
| `main.py` | `create_app(settings)` factory: routes, `SessionMiddleware`, CSRF, the `render()` helper, machine endpoints. |
| `expire.py` | Idle-expiry subcommand: `python -m portal.expire`. |
| `templates/` | Jinja2: `base`, `macros`, `login`, `dashboard`, `secret_once`, `not_authorized`, `admin`. |

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
  OIDC client creds (logs humans in). The `client_id`/`client_secret` pairs in
  the `clients` table = what this service ISSUES to shovelers. Keep naming
  explicit in code and docs.
- **Secrets:** generated with `secrets.token_urlsafe(32)`; store only the
  argon2 hash; shown to the user exactly once. Never log a secret or a minted
  token at any level.
- **Signing keys:** private keys written `0600`, never logged, never returned,
  never committed (`.gitignore` covers `*.pem`, `manifest.json`, `data/`). All
  public keys (active + retired) are published in JWKS; only the newest signs.
- **`/token`:** must return a uniform `401 {"error":"invalid_client"}` for
  unknown id / disabled / wrong secret (constant-time; never reveal which).
  `aud` must equal `RESOURCE_SERVER_ID` exactly — no surrounding whitespace.
- **Browser POSTs are CSRF-protected.** Every form includes the per-session
  `csrf_token`; handlers call `_check_csrf`. Destructive actions also confirm
  via a JS `confirm()` in the template. New POST routes must do the same.
- **Authorization:** driven by COmanage group membership from CILogon's
  `isMemberOf` claim (captured into the session at login). A group
  `<COMANAGE_GROUP_PREFIX><site>` grants management of `<site>`
  (`authz.sites_for_groups`); members of `REGISTRY_ADMIN_GROUP` see all via
  `/admin`. No allow-list file, no email-domain auto-grant — group membership
  is the only grant. Group changes take effect on next login, not instantly.
- **Sessions:** cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` whenever
  `PORTAL_BASE_URL` is https.
- **Config:** add new settings in `config.py` (parse env + default there), then
  thread through `create_app`. Don't read `os.environ` elsewhere.
- **DB access:** open a connection with `db.connect(...)`, do work in
  `try/finally: conn.close()`. Add new SQL as functions in `db.py`, not inline.

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
  dir, `comanage_group_prefix`/`registry_admin_group`) and a `TestClient` with
  `base_url="https://testserver"` so the **Secure** session cookie is sent back.
- For routes needing a logged-in user, monkeypatch `portal.main.current_user`
  to return a `UserInfo` with the right `groups` (e.g. `("shoveler-nebraska",)`);
  it's resolved as a module global at call time. CSRF token is scraped from a
  prior `GET` of the page.
- Coverage lives in `test_token`, `test_jwks`, `test_authz`, `test_expire`,
  `test_flow` (browser lifecycle), `test_admin`. Add to the matching file.

## Gotchas

- Installing on Python 3.11 fails the `requires-python` gate — use 3.12.
- A `Secure` cookie won't round-trip over plain http (TestClient or local). Use
  an https base URL in tests; locally the app still works, but the CSRF-guarded
  POST flow needs https to exercise end to end.
- The rate limiter and key cache are in-process — they assume a single replica
  (the k8s Deployment is `replicas: 1` with a shared volume by design).

## Ops quick reference

- Rotate keys: `python -m portal.keys generate`, then reload/restart so the new
  active key loads. Retired keys stay in JWKS until old tokens expire.
- Idle-expiry: `python -m portal.expire` (k8s CronJob in `k8s/cronjob.yaml`).
- Build image: `docker build -t shoveler-auth-portal .` (multi-stage; final
  image has no Node/node_modules; runs non-root).

## Repo hygiene

- Default branch is `main`. Don't commit `data/`, `*.pem`, `manifest.json`,
  `.env`, `node_modules/`, or the compiled CSS.
- Keep README, `.env.example`, and `k8s/secret.example.yaml` in sync when env
  vars change.
