# syntax=docker/dockerfile:1

# --- Stage 1: build the Tailwind CSS (Node only at build time) ---
FROM node:20-slim AS css
WORKDIR /build
COPY package.json package-lock.json* ./
RUN npm ci || npm install
# Templates are required so Tailwind can scan them and purge unused classes.
COPY tailwind.config.js ./
COPY assets/ ./assets/
COPY portal/templates/ ./portal/templates/
RUN npm run build:css

# --- Stage 2: Python runtime (no Node, no node_modules) ---
FROM python:3.12-slim AS runtime
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install Python dependencies first for better layer caching.
COPY pyproject.toml ./
RUN pip install --no-cache-dir \
        "fastapi>=0.110" "uvicorn[standard]>=0.29" "jinja2>=3.1" \
        "python-multipart>=0.0.9" "itsdangerous>=2.1" "httpx>=0.27" \
        "pyjwt[crypto]>=2.8" "cryptography>=42.0" "argon2-cffi>=23.1" "pyyaml>=6.0"

# Application code.
COPY portal/ ./portal/

# Compiled stylesheet from stage 1 (build artifact).
COPY --from=css /build/portal/static/css/app.css ./portal/static/css/app.css

# Writable data dir for the SQLite DB and signing keys.
RUN mkdir -p /data && \
    useradd --system --uid 10001 --no-create-home portal && \
    chown -R portal:portal /app /data

ENV DB_PATH=/data/portal.db \
    SIGNING_KEY_DIR=/data/keys

USER 10001
EXPOSE 8080

CMD ["uvicorn", "--factory", "portal.main:create_app", \
     "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
