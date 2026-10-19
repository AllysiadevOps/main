# Harpocrates Video Service

Flask service for video proof packaging, steganographic metadata extraction,
and local developer proof tooling.

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

