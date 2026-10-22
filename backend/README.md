# Harpocrates Video Service

Flask service for video proof packaging, steganographic metadata extraction,
and local developer proof tooling.

## Webhooks

Outbound webhook request fields, headers, HMAC-SHA-256 signature verification,
replay guidance, and retry/backoff behaviour are documented in
[Webhook delivery and signature verification](docs/webhooks.md).

## Steganography

`POST /api/stego/embed` accepts a video and JSON metadata, then returns an
embedded `video/mp4` artifact. The encoder writes two layers:

- border encoding for lossy-transcode-tolerant recovery
- LSB encoding as a secondary fallback

Response headers include the source video hash, embedded video hash, and
canonical metadata hash. The frontend registers the embedded video hash on
Stellar.

`POST /api/stego/extract` reads the embedded artifact, hashes the received file,
and returns extracted Harpocrates metadata when present.


## Configuration

This section documents all environment variables that can be used to configure the Harpocrates backend service.

| Variable Name | Type | Default | Bounds | Purpose | Secret? | Required in Production? |
|---------------|------|---------|--------|---------|---------|-------------------------|
| Variable Name | Type | Default | Bounds | Purpose | Secret? | Required in Production? |
|---------------|------|---------|--------|---------|---------|-------------------------|
| ADMISSION_TIMEOUT_SECONDS | float | 5.0 | must be positive | Timeout for admission control (seconds) | no | no |
| ALLOW_WILDCARD_CORS | string |  |  | Allow wildcard CORS origins when set to 'true' (only effective in non-production) | no | no |
| ANALYTICS_CONSENT_ENABLED | string |  |  | Enable or disable analytics consent check feature | no | no |
| ANALYTICS_DURABLE_PATH | string |  |  | Path for durable analytics logs | no | no |
| ANALYTICS_EXPORT_TOKEN_REQUIRED | string |  |  | Require export token for analytics data export | yes | no |
| ANALYTICS_MAX_EVENT_BYTES | string |  |  | Maximum size of an analytics event in bytes | no | no |
| ANALYTICS_MAX_LOG_ENTRIES | string |  |  | Maximum number of log entries per analytics request | no | no |
| ANALYTICS_PERSISTENCE_ENABLED | string |  |  | Enable or disable analytics persistence to durable storage | no | no |
| ANALYTICS_ROLLOUT | string | RolloutPhase.SHADOW |  | Analytics rollout phase (off, shadow, canary, full) | no | no |
| ANALYTICS_SAMPLING_RATE | string |  |  | Sampling rate for analytics (0.0 to 1.0) | no | no |
| ANALYTICS_SESSION_REPLAY_PROTECTION | string |  |  | Enable or disable analytics session replay protection | no | no |
| APP_ENV | string | development |  | Application environment (development, production, etc.) | no | no |
| CORS_ORIGINS | list of strings | http://localhost:5173,http://127.0.0.1:5173 |  | Comma-separated list of allowed CORS origins | no | no |
| DATABASE_URL | string |  |  | PostgreSQL database connection URL | no | yes |
| DB_CONNECT_DEADLINE_SECONDS | float | 15.0 | must be positive | Overall connection deadline for database retries (seconds) | no | no |
| DB_CONNECT_MAX_ATTEMPTS | integer | 4 | must be positive | Maximum number of database connection attempts | no | no |
| DB_CONNECT_RETRY_BASE_SECONDS | float | 0.05 | must be positive | Base backoff time for database connection retries (seconds) | no | no |
| DB_CONNECT_TIMEOUT_SECONDS | float | 5.0 | must be positive | Per-attempt database connection timeout (seconds) | no | no |
| EXPOSE_METADATA_HEADER | boolean | false |  | Expose metadata in HTTP response header (X-Harpocrates-Metadata) | no | no |
| EXTERNAL_FETCH_CONNECT_TIMEOUT_SECONDS | float | 5.0 | must be positive | Timeout for establishing external evidence fetch connections (seconds) | no | no |
| EXTERNAL_FETCH_MAX_RESPONSE_BYTES | integer | 65536 | must be positive | Maximum response body size for external evidence fetches (bytes) | no | no |
| EXTERNAL_FETCH_READ_TIMEOUT_SECONDS | float | 10.0 | must be positive | Timeout for reading external evidence fetch responses (seconds) | no | no |
| FLASK_DEBUG | string | false |  | Enable Flask debug mode | no | no |
| HARPOCRATES_RELEASE_ID | string | harpocrates-1.0.0 |  | Release identifier for compatibility (must be 'harpocrates-1.0.0') | no | no |
| HARPOCRATES_RELEASE_NETWORK | string | testnet |  | Stellar network to use (local, testnet, mainnet) | no | no |
| HARPOCRATES_STORAGE_DIR | string | /tmp/harpocrates_jobs |  | Directory for storing temporary job files | no | no |
| HOST | string | 127.0.0.1 |  | Host interface to bind the Flask server | no | no |
| MASTER_ENCRYPTION_KEY | string |  |  | Base64-encoded encryption key for protecting data encryption keys (DEKs) | yes | yes |
| MAX_CONCURRENT_PER_IDENTITY | integer | 5 | must be positive | Maximum concurrent requests per identity (API key or IP) | no | no |
| MAX_CONCURRENT_REQUESTS | integer | 50 | must be positive | Maximum concurrent requests overall | no | no |
| MAX_CONTENT_LENGTH | integer | 314572800 | must be positive | Maximum request body size in bytes | no | no |
| MAX_JSON_BYTES | integer | 1048576 | must be positive | Maximum JSON request body size in bytes | no | no |
| MAX_METADATA_BYTES | integer | 16384 | must be positive | Maximum metadata payload size in bytes | no | no |
| MAX_QUEUE_SIZE | integer | 100 | must be positive | Maximum size of the request queue | no | no |
| MAX_VIDEO_BYTES | integer | 262144000 | must be positive | Maximum video file upload size in bytes | no | no |
| METRICS_ENABLED | boolean | true |  | Enable or disable the Prometheus metrics endpoint | no | no |
| METRICS_PATH | string | /metrics |  | URL path for the Prometheus metrics endpoint | no | no |
| METRICS_TOKEN | string |  |  | Authentication token for the metrics endpoint (Bearer token) | yes | no |
| NOIR_PROOF_TIMEOUT_SECONDS | string | 300 |  | Timeout for Noir proof generation (seconds) | no | no |
| NOIR_WORKER_ENABLED | boolean | app_env != "production" |  | Enable or disable the Noir worker for proof generation | no | no |
| OTEL_ENABLED | boolean | false |  | Enable or disable OpenTelemetry tracing | no | no |
| OTEL_EXPORTER_OTLP_TRACES_ENDPOINT | string |  |  | OTLP/HTTP endpoint for exporting traces | no | no |
| OTEL_EXPORT_TIMEOUT_SECONDS | float | 5.0 | must be positive | Timeout for exporting traces (seconds) | no | no |
| OTEL_SERVICE_NAME | string |  |  | Service name for OpenTelemetry traces | no | no |
| OTEL_TRACES_SAMPLER_ARG | float | 0.1 | must be between 0 and 1 inclusive | Sampling ratio for OpenTelemetry traces (0.0 to 1.0) | no | no |
| PORT | string | 5050 |  | Port to bind the Flask server | no | no |
| RATELIMIT_EMBED | string |  |  | Rate limit for embed endpoint (flask-limiter format, e.g., '30 per minute') | no | no |
| RATELIMIT_ENABLED | boolean | true |  | Enable or disable rate limiting | no | no |
| RATELIMIT_EXTRACT | string |  |  | Rate limit for extract endpoint (flask-limiter format) | no | no |
| RATELIMIT_REGISTER | string |  |  | Rate limit for register endpoint (flask-limiter format) | no | no |
| RATELIMIT_SILENT_WITNESS | string |  |  | Rate limit for silent witness endpoint (flask-limiter format) | no | no |
| RATELIMIT_STORAGE_URI | string | memory:// |  | Storage URI for rate limiting (e.g., 'redis://localhost:6379') | no | no |
| RATELIMIT_UPLOAD_CHUNK | string |  |  | Rate limit for upload chunk endpoint (flask-limiter format) | no | no |
| RATELIMIT_UPLOAD_SESSION | string |  |  | Rate limit for upload session endpoint (flask-limiter format) | no | no |
| REGISTER_API_KEY | string |  |  | API key for proof registration (primary) | yes | yes |
| REGISTER_API_KEY_EXPIRES | datetime string (ISO-8601 with timezone) |  |  | Expiration timestamp for the primary registration API key (ISO-8601) | yes | no |
| REGISTER_API_KEY_PREVIOUS | string |  |  | Previous API key for proof registration (used during key rotation) | yes | no |
| REGISTER_API_KEY_PREVIOUS_EXPIRES | datetime string (ISO-8601 with timezone) |  |  | Expiration timestamp for the previous registration API key (ISO-8601) | yes | no |
| REGISTER_SCOPED_KEYS | string |  |  | Comma-separated list of owner-scoped keys (format: <address>:<token-digest>) | yes | no |
| RETENTION_INTERVAL_SECONDS | integer | 3600 | must be positive | Interval between retention worker runs (seconds) | no | no |
| RETENTION_WORKER_ENABLED | boolean | false |  | Enable or disable the retention worker | no | no |
| SECURITY_HEADERS_ENABLED | boolean | true |  | Enable or disable security headers (X-Content-Type-Options, etc.) | no | no |
| TRUSTED_PROXIES | list of strings |  |  | Comma-separated list of trusted proxy CIDR ranges for IP address resolution | no | no |
| UPLOAD_CHUNK_BYTES | string |  |  | Size of upload chunks in bytes (clamped between 4096 and 1048576) | no | no |
| VERIFIER_CACHE_MAX_SIZE | integer | 10000 | must be positive | Maximum number of entries in the verifier proof cache | no | no |
| VERIFIER_CACHE_NEGATIVE_TTL_SECONDS | float | 300.0 | must be positive | Time-to-live for negative verifier cache entries (seconds) | no | no |
| VERIFIER_CACHE_POSITIVE_TTL_SECONDS | float | 86400.0 | must be positive | Time-to-live for positive verifier cache entries (seconds) | no | no |

## Upload and Verification Load Test

With FFmpeg installed and a local testing backend running, execute a bounded
load run from this directory:

```bash
python load_test.py --base-url http://127.0.0.1:5050 --mode load --concurrency 2 --total-ops 10 --output /tmp/harpocrates-load-report.json
```

The `upload_verification` workload sends generated synthetic video through
`POST /api/stego/embed`, then sends the returned artifact through
`POST /api/stego/extract` and checks that its synthetic marker and proof ID
match. It uses no real media, credentials, proofs, or private keys. Failure
reports contain status codes or dependency categories, never response bodies;
the configured URL is reduced to its origin before it is written to a report.
Run it only against a local or dedicated test backend: successful uploads may
create ordinary synthetic proof-event records when a database is configured.
No protocol, API schema, or database migration is introduced. Rollback is
limited to removing the workload, its focused coverage, and this documentation;
use normal test-data retention procedures for any synthetic events already
created.

## Noir Developer Worker

`POST /api/noir/silent-witness` generates video-specific Silent Witness proof
artifacts using the local WSL Noir toolchain.

The request must include `videoHash`, `credentialSecret`, and
`nullifierSecret`.

Environment override:

```text
NOIR_PROOF_TIMEOUT_SECONDS=180
```

The product flow now uses browser-side Noir JS and bb.js, so user-entered
private seeds stay in the browser. This endpoint is kept for local parity tests,
debugging, and CI-style proof generation.

## Database Migrations

Schema changes run through the ordered, idempotent ledger in `migration.py`.
`init_db()` applies every pending migration on startup and records the SHA-256
checksum of the migration SQL in the `schema_migrations` table.

### Checksum Verification at Startup

Before applying anything, startup replays each applied migration's recorded
checksum against its in-code definition:

- `checksum_mismatch` — an applied migration's SQL changed after it was applied.
- `missing_checksum` — a ledger row carries no digest.
- `unknown_migration` — the ledger references an id the code no longer defines.

Any discrepancy aborts startup with `migration.MigrationChecksumError`, so a
drifted ledger cannot silently serve traffic. The error and the
`verify_migration_checksums()` helper report only migration ids, names, and
digests — never migration SQL, media, secrets, witness values, or private keys.

`MIGRATION_CHECKSUM_ENFORCEMENT` selects the failure mode:

```text
MIGRATION_CHECKSUM_ENFORCEMENT=enforce   # default: abort startup on mismatch
MIGRATION_CHECKSUM_ENFORCEMENT=warn      # break-glass: report and continue
```

Rollback: this check is additive and stores no new evidence. Revert the commit
to restore the previous startup behaviour, or set
`MIGRATION_CHECKSUM_ENFORCEMENT=warn` for a temporary boot while the ledger is
reconciled. Never edit an applied migration's SQL to silence a mismatch; add a
new numbered migration instead.

## Database Maintenance CLI

`manage.py` is the single entry point for database maintenance. Run it from
`backend/` with `DATABASE_URL` set:

```bash
python manage.py migrate                    # apply pending migrations
python manage.py migrate --check            # verify checksums, list pending; applies nothing
python manage.py drift                      # compare live schema with the expected schema
python manage.py retention --dry-run        # count expired, non-held proof events
python manage.py retention --run            # purge them (batch: HARPOCRATES_RETENTION_BATCH_SIZE)
python manage.py retention --run --batch-size 500
python manage.py reconcile --limit 25       # reconcile pending registration txs (max 50)
python manage.py --json drift               # machine-readable JSON output
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Success; no problems found |
| `1` | Schema drift detected or migration checksum mismatch |
| `2` | Invalid command-line usage |
| `3` | `DATABASE_URL` is not configured |
| `4` | Unexpected error (e.g. database unreachable); only the error type is printed |

Output never includes connection strings or secrets: every line is scrubbed of
the `DATABASE_URL` value, URL credentials, and `password=`/`token=`-style
values, and unexpected exceptions are reported by type name only.

## Privacy-Safe Service Metrics

`GET /metrics` exposes service workload, latency, status code distributions, and bounded upload-size metrics in standard Prometheus format.

### Privacy Guarantees

- Metric labels strictly record generic HTTP attributes: HTTP `method`, parameterized route rule `endpoint` (e.g., `/api/proofs/by-video/<video_hash>`), and HTTP `status`.
- Filenames, video hashes, metadata hashes, wallet addresses, proof payload data, and secret seeds are strictly excluded.
- Upload sizes are recorded in bounded histogram buckets.

### Endpoint Protection

- `METRICS_ENABLED`: Enable or disable the metrics endpoint (`true`/`false`, default `true`). Returns `404` when disabled.
- `METRICS_TOKEN`: Optional authentication token. When set, requests must provide `Authorization: Bearer <METRICS_TOKEN>` or header `X-Metrics-Token: <METRICS_TOKEN>`.
- `METRICS_PATH`: Endpoint URI path (defaults to `/metrics`).

### Prometheus Scraping Configuration

Example `prometheus.yml` snippet:

```yaml
scrape_configs:
  - job_name: 'harpocrates-backend'
    scrape_interval: 15s
    metrics_path: '/metrics'
    authorization:
      credentials: 'secret-scraping-token' # matches METRICS_TOKEN
    static_configs:
      - targets: ['127.0.0.1:5050']
```

  ## OpenTelemetry Tracing

  Tracing is opt-in and does not change HTTP routes, response schemas, proof encodings, or database schemas. Enable it per backend process and send OTLP/HTTP traces to a trusted collector:

  ```text
  OTEL_ENABLED=true
  OTEL_SERVICE_NAME=harpocrates-backend
  OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://otel-collector.example/v1/traces
  OTEL_TRACES_SAMPLER_ARG=0.1
  OTEL_EXPORT_TIMEOUT_SECONDS=5
  ```

  `OTEL_ENABLED` defaults to `false`. When enabled, the traces endpoint is required and must be an HTTP(S) URL without embedded credentials or a query string. Configure collector authorization using `OTEL_EXPORTER_OTLP_HEADERS` through the deployment secret store. The SDK uses deterministic trace-ID-ratio sampling; inbound `traceparent` flags cannot raise the configured sample rate. The exporter queue is bounded to 2,048 spans, batches at most 256 spans, and times out within 1 to 60 seconds.

  ### Instrumentation and Privacy

  - Server spans accept valid W3C `traceparent` parents and use parameterized route names. Malformed parents are ignored; baggage is not extracted.
  - Child spans cover media embed/extract, PostgreSQL connection lifetimes, Noir proof generation, and Stellar Horizon transaction verification. Errors record only the exception class and status, never exception messages or stack traces.
  - Internal queued jobs carry only a validated `traceparent` link outside their payload. The job-status API omits this internal field. Workers create linked spans rather than pretending delayed work is a synchronous child.
  - Span attributes do not include media bytes, file paths, filenames, evidence/proof hashes, proof contents, witness values, secrets, authorization headers, database URLs, raw request URLs, or transaction hashes.
  - Existing structured request logs contain the trace ID. Prometheus metrics keep their existing low-cardinality method/route/status labels; correlate metrics to traces through these shared dimensions and the request log, not trace-ID metric labels.

  ### Rollout, Rollback, and Troubleshooting

  No migration, durable artifact, or data repair is required. Install the pinned OpenTelemetry dependencies with the backend requirements, deploy with tracing disabled, then enable it for a canary and verify spans at the collector before increasing the sample ratio. Collector outages do not block request processing; bounded export batches time out and may be dropped. Sampling can be reduced to `0` or tracing disabled immediately with `OTEL_ENABLED=false`.

  Rollback by setting `OTEL_ENABLED=false` and restarting the backend; existing request/trace response headers and privacy-safe logs remain compatible. Reverting the feature also requires removing the three OpenTelemetry pins from `requirements.txt`. No job payload or database migration cleanup is needed. Check collector reachability/TLS, endpoint configuration, sample ratio, and backend exporter warnings when spans are missing. A missing parent usually means the caller omitted or supplied an invalid `traceparent`.

  Limitations: backend Stellar spans cover Horizon transaction-status reads; this backend does not submit Soroban contract transactions. The current queued-job implementation is process-local, so trace links survive only as long as its in-memory job record; this change does not claim cross-process job durability. The API does not expose trace IDs as metric labels or support baggage propagation.

## Run

```powershell
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
python app.py
```

The service listens on `http://127.0.0.1:5050`.

## Runtime Configuration

```text
APP_ENV=development
HOST=127.0.0.1
PORT=5050
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
MAX_CONTENT_LENGTH=262144000
MAX_METADATA_BYTES=16384
SECURITY_HEADERS_ENABLED=true
EXPOSE_METADATA_HEADER=false
METRICS_ENABLED=true
METRICS_TOKEN=secret-scraping-token
METRICS_PATH=/metrics
NOIR_WORKER_ENABLED=true
NOIR_PROOF_TIMEOUT_SECONDS=180
DATABASE_URL=postgresql://...
VERIFIER_CACHE_MAX_SIZE=10000
VERIFIER_CACHE_POSITIVE_TTL_SECONDS=86400.0
VERIFIER_CACHE_NEGATIVE_TTL_SECONDS=300.0
```

Production notes:

- Set `APP_ENV=production`.
- Set `NOIR_WORKER_ENABLED=false` unless this service is intentionally acting as a hardened prover.
- Keep `EXPOSE_METADATA_HEADER=false`; extracted metadata is available through `/api/stego/extract`.
- Protect the `/metrics` endpoint in production by configuring `METRICS_TOKEN` or restricting access at the reverse proxy/ingress layer.
- Avoid wildcard CORS. `CORS_ORIGINS=*` requires `ALLOW_WILDCARD_CORS=true`.
- Configured origins are enforced server-side: requests carrying an `Origin`
  outside `CORS_ORIGINS` are rejected with `403 FORBIDDEN_ORIGIN` before route
  handlers run (privacy-safe envelope; the origin value is never echoed or
  logged). Requests without an `Origin` header and the `/health`, `/ready`, and
  `/metrics` paths are exempt.
- Uploaded files are processed in temporary directories and removed after each request.

## Health

```text
GET /health   liveness only
GET /ready    database, ffmpeg/ffprobe, and local worker readiness
GET /metrics  privacy-safe Prometheus metrics endpoint
```

## Verifier Proof Cache

`verifier_cache.py` memoizes Noir verifier results with positive and negative
TTLs. Cache keys are **domain-separated**: a SHA-256 digest over the versioned
cryptographic domain tag `harpocrates:verifier-cache:v1` followed by
length-prefixed `domain`, `network`, `circuit_version`, `verifier_version`,
`proof_hex`, and `public_inputs_hex` fields. Length-prefixed framing makes the
payload injective over the field tuple, so separator-like characters in any
field cannot shift a boundary and collide two distinct results. Proof and
public-input hex are case- and whitespace-canonicalized so the same proof
cannot fragment into case-variant entries.

Bump `CACHE_KEY_DOMAIN_TAG` (e.g. to `...:v2`) whenever the key field layout
changes: it orphans every previously cached entry instead of silently reusing
results derived under a different scheme. Keys are digests only — proof
material is never stored in plaintext or logged.

## Test

```powershell
python -m unittest test_app.py test_stego.py
```

The service uses temporary files while processing and does not persist uploaded
source videos.

