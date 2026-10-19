# Deployment Guide

This guide covers four hosted deployment paths for Harpocrates: Docker Compose on a VPS, Railway, Render, and Fly.io.

All paths share the same two containers:

| Container | Source | Default port |
|-----------|--------|-------------|
| `harpocrates-backend` | `backend/` — gunicorn / Flask | 5050 |
| `harpocrates-frontend` | `frontend/` — nginx serving Vite build | 8080 |

---

## Environment variables reference

### Backend (runtime — no rebuild needed)

| Variable | Required | Notes |
|----------|----------|-------|
| `DATABASE_URL` | ✅ | `postgresql://USER:PASS@HOST/DB?sslmode=require` |
| `APP_ENV` | ✅ | Set to `production` |
| `CORS_ORIGINS` | ✅ | Comma-separated list of allowed frontend origins |
| `HOST` | — | Default `0.0.0.0` |
| `PORT` | — | Default `5050` |
| `MAX_CONTENT_LENGTH` | — | Default `314572800` (300 MB) |
| `MAX_VIDEO_BYTES` | — | Default `262144000` (250 MB) |
| `MAX_JSON_BYTES` | — | Default `1048576` (1 MB) |
| `MAX_METADATA_BYTES` | — | Default `16384` (16 KB) |
| `SECURITY_HEADERS_ENABLED` | — | Default `true` |
| `EXPOSE_METADATA_HEADER` | — | Default `false`; keep off in production |
| `METRICS_ENABLED` | — | Default `true` |
| `METRICS_TOKEN` | — | Protect the `/metrics` endpoint |
| `METRICS_PATH` | — | Default `/metrics` |
| `REGISTER_API_KEY` | — | Bearer credential for `/api/proofs/register`; unset keeps the existing development-only open behavior |
| `REGISTER_API_KEY_EXPIRES` | — | Optional timezone-aware ISO-8601 expiry for the primary registration key |
| `REGISTER_API_KEY_PREVIOUS` | — | Optional old key accepted during a zero-downtime rotation |
| `REGISTER_API_KEY_PREVIOUS_EXPIRES` | — | Optional expiry for the previous key; remove the previous key after migration |
| `NOIR_WORKER_ENABLED` | — | Default `false`; keep off unless running a dedicated prover |
| `NOIR_PROOF_TIMEOUT_SECONDS` | — | Default `180` |

### Frontend (build time — rebuild required on change)

The Vite bundler bakes these values into the static output at compile time.

| Variable | Required | Notes |
|----------|----------|-------|
| `VITE_API_BASE` | ✅ | Public URL of the deployed backend, e.g. `https://api.example.com` |
| `VITE_STELLAR_RPC_URL` | ✅ | e.g. `https://soroban-testnet.stellar.org` |
| `VITE_STELLAR_READONLY_SOURCE` | ✅ | Funded `G…` testnet account |
| `VITE_HARPOCRATES_REGISTRY_ID` | ✅ | Deployed registry contract `C…` |

---

## Option 1 — Docker Compose (VPS / bare metal)

Suitable for a single server (e.g. a $6 Hetzner VPS or DigitalOcean Droplet).

### Prerequisites

- Docker Engine ≥ 24 and Docker Compose plugin
- A PostgreSQL database (managed or self-hosted)
- A reverse proxy with TLS (nginx, Caddy, or Traefik)

### Steps

**1. Clone the repository**

```bash
git clone https://github.com/YOUR_ORG/harpocrates.git
cd harpocrates
```

**2. Configure backend environment**

```bash
cp backend/.env.example backend/.env
# Edit backend/.env — set DATABASE_URL, CORS_ORIGINS, METRICS_TOKEN, and
# REGISTER_API_KEY. During rotation, set REGISTER_API_KEY_PREVIOUS as well.
```

**3. Configure frontend build args**

Create a `.env` file in the project root (read by docker compose):

```bash
# .env  —  project root
VITE_API_BASE=https://api.example.com
VITE_STELLAR_RPC_URL=https://soroban-testnet.stellar.org
VITE_STELLAR_READONLY_SOURCE=G...
VITE_HARPOCRATES_REGISTRY_ID=C...
```

**4. Build and start**

```bash
docker compose up --build -d
```

The backend is available at `:5050` and the frontend at `:8080`. Point your reverse proxy at these ports.

**5. Confirm health**

```bash
curl http://localhost:5050/ready
# → {"status":"ok", ...}
```

**6. Updating**

```bash
git pull
docker compose up --build -d
```

**7. API Gateway Schema**

For deployments leveraging an API Gateway, WAF, or Swagger UI, you can generate an OpenAPI 3.1 schema natively:

```bash
python devx/generate_api_schema.py --output openapi.json
```

**8. Rollback**

If a deployment introduces critical failures or regressions, you can orchestrate a privacy-safe rollback using the provided CLI tooling. This rolls back the active containers bounds safely without leaking credentials, media, or breaking backwards compatibility.

```bash
python devx/deploy.py rollback --manifest-file release/compatibility-manifest.json
```

Or on PowerShell:
```powershell
.\scripts\rollback.ps1 -ManifestFile .\release\compatibility-manifest.json
```

### Caddy reverse proxy example

```
api.example.com {
    reverse_proxy localhost:5050
}

example.com {
    reverse_proxy localhost:8080
}
```

---

## Option 2 — Railway

Railway runs each service as a separate project service, with automatic deploys from GitHub.

### Backend

1. Create a new project in [Railway](https://railway.app) → **Deploy from GitHub repo**.
2. Set the **Root Directory** to `backend`.
3. Set **Build Command** (optional; Railway auto-detects the Dockerfile).
4. Add all backend environment variables in the Railway **Variables** panel.
5. Expose port `5050` and note the generated public URL (e.g. `https://harpocrates-api.up.railway.app`).

### Frontend

1. Add a second service to the same Railway project → **Deploy from GitHub repo**.
2. Set the **Root Directory** to `frontend`.
3. Add the four `VITE_*` variables in the Railway **Variables** panel.
   - Set `VITE_API_BASE` to the backend URL from the step above.
4. Railway passes **Build Variables** to Docker `ARG` automatically.
5. Expose port `8080`.

### Notes

- Railway's internal networking lets you use a private URL (`http://backend.railway.internal:5050`) for `VITE_API_BASE` if you prefer to avoid public backend exposure — but the frontend must be rebuilt whenever this URL changes.
- Add a PostgreSQL plugin or use an external managed database and set `DATABASE_URL` accordingly.
- Set `CORS_ORIGINS` on the backend to the Railway-provided frontend URL.

---

## Option 3 — Render

Render supports Docker-based web services.

### Backend

1. New → **Web Service** → connect GitHub repo.
2. **Root Directory**: `backend`
3. **Environment**: Docker
4. **Port**: `5050`
5. Add all backend environment variables under the **Environment** tab.
6. Copy the public URL assigned by Render (e.g. `https://harpocrates-api.onrender.com`).

### Frontend

1. New → **Web Service** → same GitHub repo.
2. **Root Directory**: `frontend`
3. **Environment**: Docker
4. **Port**: `8080`
5. Add the four `VITE_*` variables under **Environment**, setting `VITE_API_BASE` to the backend URL.
6. Under **Advanced → Docker Build Args**, verify the variables are passed through (Render maps environment variables to build args for Dockerfile `ARG` declarations).

### Notes

- Render free-tier services spin down after inactivity; use a paid plan for production.
- Set `CORS_ORIGINS` on the backend to the Render-assigned frontend URL.
- Use Render's managed PostgreSQL service or an external provider for `DATABASE_URL`.

---

## Option 4 — Fly.io

Fly.io deploys apps from a `fly.toml` manifest and supports Docker natively.

### Backend

**1. Install flyctl and authenticate**

```bash
brew install flyctl       # macOS; see https://fly.io/docs/hands-on/install-flyctl/
fly auth login
```

**2. Create the app and deploy**

```bash
cd backend
fly launch --name harpocrates-api --dockerfile Dockerfile --no-deploy
fly secrets set \
  APP_ENV=production \
  DATABASE_URL="postgresql://..." \
  CORS_ORIGINS="https://harpocrates-app.fly.dev" \
  METRICS_TOKEN="your-scrape-token"
fly deploy
```

**3. Verify**

```bash
fly status --app harpocrates-api
curl https://harpocrates-api.fly.dev/ready
```

### Frontend

**1. Create the app**

```bash
cd frontend
fly launch --name harpocrates-app --dockerfile Dockerfile --no-deploy
```

**2. Set build secrets (baked in at build time)**

Fly.io passes `--build-arg` values via `fly deploy --build-arg`:

```bash
fly deploy \
  --build-arg VITE_API_BASE=https://harpocrates-api.fly.dev \
  --build-arg VITE_STELLAR_RPC_URL=https://soroban-testnet.stellar.org \
  --build-arg VITE_STELLAR_READONLY_SOURCE=G... \
  --build-arg VITE_HARPOCRATES_REGISTRY_ID=C...
```

Or set them persistently in `fly.toml` under `[build.args]`:

```toml
[build.args]
  VITE_API_BASE            = "https://harpocrates-api.fly.dev"
  VITE_STELLAR_RPC_URL     = "https://soroban-testnet.stellar.org"
  VITE_STELLAR_READONLY_SOURCE = "G..."
  VITE_HARPOCRATES_REGISTRY_ID = "C..."
```

**3. Deploy**

```bash
fly deploy --app harpocrates-app
```

### Fly.io `fly.toml` reference (backend)

```toml
app = "harpocrates-api"
primary_region = "iad"

[build]
  dockerfile = "Dockerfile"

[http_service]
  internal_port = 5050
  force_https = true
  auto_stop_machines = true
  auto_start_machines = true

[[vm]]
  memory = "512mb"
  cpu_kind = "shared"
  cpus = 1

[checks]
  [checks.health]
    grace_period = "15s"
    interval = "30s"
    method = "GET"
    path = "/ready"
    port = 5050
    timeout = "10s"
    type = "http"
```

### Fly.io `fly.toml` reference (frontend)

```toml
app = "harpocrates-app"
primary_region = "iad"

[build]
  dockerfile = "Dockerfile"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = true
  auto_start_machines = true

[[vm]]
  memory = "256mb"
  cpu_kind = "shared"
  cpus = 1
```

---

## GitHub Container Registry images

The release workflow (`.github/workflows/release.yml`) publishes pre-built images to `ghcr.io` on every GitHub release:

```
ghcr.io/YOUR_ORG/harpocrates-backend:1.2.3
ghcr.io/YOUR_ORG/harpocrates-backend:latest

ghcr.io/YOUR_ORG/harpocrates-frontend:1.2.3
ghcr.io/YOUR_ORG/harpocrates-frontend:latest
```

To pull a pre-built frontend image you must still rebuild with your own `VITE_*` values because they are baked into the bundle:

```bash
docker build \
  --build-arg VITE_API_BASE=https://api.example.com \
  --build-arg VITE_STELLAR_RPC_URL=https://soroban-testnet.stellar.org \
  --build-arg VITE_STELLAR_READONLY_SOURCE=G... \
  --build-arg VITE_HARPOCRATES_REGISTRY_ID=C... \
  -t harpocrates-frontend:local \
  ./frontend
```

The backend image is environment-agnostic and can be pulled and run directly.

---

### Non-Root Container Execution

Both production deployment containers run as dedicated unprivileged non-root users:

| Image | User:Group | UID:GID | Purpose |
|-------|------------|---------|---------|
| `harpocrates-backend` | `harpocrates:harpocrates` | `10001:10001` | Dedicated system user with `/app` and `/tmp/harpocrates_jobs` access |
| `harpocrates-frontend` | `nginx:nginx` | `101:101` | Alpine unprivileged nginx user with `/tmp/nginx.pid` and local cache |

#### Container Hardening Benefits
- **Least privilege:** Execution boundaries prevent processes from modifying system binaries, mounting filesystems, or accessing host namespaces.
- **Privilege escalation prevention:** Docker Compose stacks set `security_opt: ["no-new-privileges:true"]` to block setuid/setgid privilege escalation.
- **Privacy preservation:** In the event of a remote code execution bug in parsing libraries (e.g. ffmpeg or image decoders), attacker execution is constrained to an unprivileged account, preventing host root compromise or access to secrets/evidence in adjacent workloads.

#### Orchestrator Security Contexts (Kubernetes / ECS / Nomad)
Both images satisfy Kubernetes Pod Security Standards (`restricted` profile). You can enforce non-root execution in pod manifests:

```yaml
securityContext:
  runAsNonRoot: true
  seccompProfile:
    type: RuntimeDefault

# Container securityContext for backend:
containers:
  - name: backend
    image: ghcr.io/YOUR_ORG/harpocrates-backend:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 10001
      runAsGroup: 10001
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL

# Container securityContext for frontend:
  - name: frontend
    image: ghcr.io/YOUR_ORG/harpocrates-frontend:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 101
      runAsGroup: 101
      allowPrivilegeEscalation: false
      capabilities:
        drop:
          - ALL
```

#### Migration and Volume Permissions
- **Zero-downtime compatibility:** Existing HTTP/RPC interfaces, exposed ports (`:5050`, `:8080`), and environment variables remain identical.
- **Persistent/Mounted Volumes:** If mounting persistent storage to `/tmp` or `HARPOCRATES_STORAGE_DIR`, ensure the mounted host directory is writable by UID `10001` (e.g. `chown -R 10001:10001 /path/to/storage`).
- **Rollback:** If reverting to legacy root containers is required for legacy host environments, images can be rebuilt from previous tags or run with `user: "0:0"` at the compose/orchestrator level without data migration.

---

### Docker HEALTHCHECK

Both images declare a Dockerfile `HEALTHCHECK` so standalone `docker run` and
platforms that honor image-level healthchecks mark containers correctly:

| Image | Probe | Purpose |
|-------|-------|---------|
| `harpocrates-backend` | `GET /health` on `:5050` | Process liveness (no dependency gate) |
| `harpocrates-frontend` | `GET /` on `:8080` | nginx serving the SPA |

Compose still uses `GET /ready` for the backend service readiness gate
(`depends_on: condition: service_healthy`). Failures never log secrets,
media, witness values, or private keys — probes are URL-only.

## Health and readiness endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Liveness probe — returns 200 if the process is alive |
| `GET /ready` | Readiness probe — checks DB connection, ffmpeg, and local worker |

Use `/ready` for orchestrator/load balancer health checks.

---

## Cross-origin isolation note

The frontend requires `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp` headers to enable `SharedArrayBuffer`, which is needed by Barretenberg (bb.js) for multi-threaded WASM proof generation. The `nginx.conf` already sets these headers.

If you put a CDN (e.g. Cloudflare) in front of the frontend, ensure the CDN forwards these headers without stripping them. Some CDN configurations strip non-standard response headers by default.
