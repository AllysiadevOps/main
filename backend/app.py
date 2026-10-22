from __future__ import annotations

import base64
import functools
import ipaddress
import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
from workspace import EncryptedWorkspace
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


from flask import Flask, Response, g, jsonify, request, send_file
from flask_cors import CORS

from http_security import (
    CORS_EXEMPT_PATHS,
    apply_security_headers,
    cors_kwargs,
    is_origin_allowed,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from config import load_config
import register_auth
from errors import (
    DEPENDENCY_UNAVAILABLE,
    FORBIDDEN,
    FORBIDDEN_ORIGIN,
    GONE,
    INTERNAL_ERROR,
    MALFORMED_INPUT,
    NOT_FOUND,
    OVERSIZED_INPUT,
    PAYLOAD_TOO_LARGE,
    RATE_LIMITED,
    UNSUPPORTED_INPUT,
    UNSUPPORTED_MEDIA_TYPE,
    VALIDATION_ERROR,
    classify_cli_error,
    error_response,
)
from db import (
    check_db,
    database_url,
    decode_proof_events_cursor,
    find_proof_events_by_video,
    find_proof_owner,
    find_lineage_by_output_digest,
    find_lineage_by_actor,
    init_db,
    insert_lineage_event,
    insert_proof_event,
    insert_proof_history_event,
    list_lineage_events,
    list_proof_events,
    list_proof_history_events,
    make_idempotency_key,
    upsert_register_event,
    set_legal_hold,
    ConflictError,
    enqueue_job,
    get_job,
    cancel_job,
)
try:
    from registration_reconcile import (
        clamp_reconcile_limit,
        default_min_confirmations,
        reconcile_pending_registrations,
        reconcile_registration,
    )
except ImportError:
    clamp_reconcile_limit = None
    default_min_confirmations = None
    reconcile_pending_registrations = None
    reconcile_registration = None
from idempotency import idempotent
from lineage import (
    LineageValidationError,
    canonical_lineage_manifest,
    lineage_manifest_digest,
    validate_lineage_graph,
)
from storage import get_job_output_path
from retention import init_retention_worker
from metrics import collector as metrics_collector
try:
    from noir import generate_silent_witness, generate_aggregated_proof
except ImportError:
    generate_silent_witness = None
    generate_aggregated_proof = None
from envelope import ALLOWED_TIERS, validate_v2 as validate_embed_metadata
from metadata_errors import (
    METADATA_MALFORMED,
    METADATA_OVERSIZED,
    MetadataError,
    classify_validation_error,
    metadata_error_response,
)
from schema import discover_schemas, resolve_schema, validate_selective_disclosure_input
from verification_receipt import build_verification_receipt
from stego import canonical_metadata_hash, embed_metadata, extract_metadata, sha256_file
from capture_attestation import (
    canonical_attestation_hash,
    decode_attestation,
    verify_device_commitment,
)
from c2pa import (
    C2paParseError,
    C2paTrustStatus,
    corroborate_binding,
    export_c2pa_manifest,
    parse_c2pa_manifest,
)
from logging_utils import log_structured, redact_sensitive
from errors import (
    INTERNAL_ERROR,
    NOT_FOUND,
    PAYLOAD_TOO_LARGE,
    VALIDATION_ERROR,
    error_response,
    ok_response,
    register_request_id_propagation,
)
from trace_fields import (
    build_trace_fields,
    format_traceparent,
    merge_trace_into_event,
)
from tracing import (
    begin_request_span,
    configure_tracing,
    finish_request_span,
)
from readiness import ReadinessManager
from verifier_cache import VerifierCache
from admission import AdmissionController, require_capacity
from webhook import WebhookWorker, queue_webhook_deliveries
from quarantine import QuarantineError, isolate_upload, sniff_media_type_stream, sniff_media_type_path
from strkey import validate_source_address, validate_contract_id
from streaming_upload import (
    StreamingFileStorage,
    create_streaming_file_storage,
    hash_paths_concat,
)
from werkzeug.datastructures import ImmutableMultiDict

# ---------------------------------------------------------------------------
# Bounded aggregation constants
# ---------------------------------------------------------------------------
# These MUST match the values in the Noir circuit and the Soroban contract.
MAX_AGGREGATION_SIZE = 8
AGGREGATION_ELEMENT_COST = 128  # bytes per aggregated public-input element

LOGGER = logging.getLogger("harpocrates.requests")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)
LOGGER.propagate = True

# ---------------------------------------------------------------------------
# Declared upload-body budget
# ---------------------------------------------------------------------------
# A ``multipart/form-data`` upload carries framing bytes (boundaries, part
# headers, and the small metadata part) on top of the video/chunk payload, so
# the declared ``Content-Length`` budget allows a fixed overhead on top of the
# per-file budget.  Without this allowance a payload sitting exactly on
# ``MAX_VIDEO_BYTES`` would be rejected purely because of framing.
UPLOAD_MULTIPART_OVERHEAD_BYTES = 1_048_576


def get_ratelimit_storage_kind(storage_uri: str | None) -> str:
    """Classify the rate limit storage URI into memory/redis/other without exposing credentials."""
    if not storage_uri:
        return "memory"
    uri = storage_uri.strip()
    if not uri:
        return "memory"
    if "://" in uri:
        scheme = uri.split("://", 1)[0].lower()
    elif ":" in uri:
        scheme = uri.split(":", 1)[0].lower()
    else:
        scheme = uri.lower()

    if scheme == "memory":
        return "memory"
    if scheme in ("redis", "rediss"):
        return "redis"
    return "other"


def _detect_worker_count() -> int:
    """Detect worker count from WEB_CONCURRENCY, GUNICORN_CMD_ARGS, or sys.argv."""
    raw = os.getenv("WEB_CONCURRENCY")
    if raw is not None:
        try:
            val = int(raw.strip())
            if val > 0:
                return val
        except ValueError:
            pass

    gunicorn_args = os.getenv("GUNICORN_CMD_ARGS")
    if gunicorn_args:
        tokens = gunicorn_args.split()
        for i, token in enumerate(tokens):
            if token in ("-w", "--workers") and i + 1 < len(tokens):
                try:
                    val = int(tokens[i + 1])
                    if val > 0:
                        return val
                except ValueError:
                    pass
            elif token.startswith(("--workers=", "-w=")):
                try:
                    val = int(token.split("=", 1)[1])
                    if val > 0:
                        return val
                except ValueError:
                    pass

    import sys as _sys
    for i, token in enumerate(_sys.argv):
        if token in ("-w", "--workers") and i + 1 < len(_sys.argv):
            try:
                val = int(_sys.argv[i + 1])
                if val > 0:
                    return val
            except ValueError:
                pass
        elif token.startswith(("--workers=", "-w=")):
            try:
                val = int(token.split("=", 1)[1])
                if val > 0:
                    return val
            except ValueError:
                pass

    return 1


def declared_upload_limit_bytes(config) -> int:
    """Return the largest acceptable declared ``Content-Length`` for an upload.

    The per-file budget is ``UPLOAD_MAX_BYTES`` when the deployment sets it,
    otherwise ``MAX_VIDEO_BYTES``; multipart framing is permitted on top of it.
    The whole body must still fit under ``MAX_CONTENT_LENGTH`` when that cap is
    the lower of the two, so the effective limit is the minimum of the two.
    """
    per_file = int(getattr(config, "upload_max_bytes", 0) or config.max_video_bytes)
    limit = per_file + UPLOAD_MULTIPART_OVERHEAD_BYTES
    global_cap = int(getattr(config, "max_content_length", 0) or 0)
    if global_cap and limit > global_cap:
        limit = global_cap
    return limit


def _make_key_func(config):
    """Return a rate-limit key function that uses the real client IP.

    If ``trusted_proxies`` is configured the leftmost *untrusted* address in
    ``X-Forwarded-For`` is used, preventing spoofing by clients who inject
    extra entries.  When no trusted proxies are configured the WSGI
    ``REMOTE_ADDR`` is used unconditionally, which is always safe.
    """

    trusted = set()
    for entry in config.trusted_proxies:
        try:
            trusted.add(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            pass

    def _key_func() -> str:
        if not trusted:
            # No proxies trusted – use the direct peer address, cannot be spoofed.
            return get_remote_address()

        # Walk X-Forwarded-For right-to-left, skipping trusted proxy IPs.
        # The first address that is NOT a trusted proxy is the real client.
        xff = request.headers.get("X-Forwarded-For", "")
        addrs = [a.strip() for a in xff.split(",") if a.strip()]
        # Append the direct peer so we always have at least one candidate.
        addrs.append(request.remote_addr or "127.0.0.1")

        for addr in reversed(addrs):
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if not any(ip in net for net in trusted):
                return str(ip)

        # Fallback: direct peer (always safe).
        return get_remote_address()

    return _key_func


def clamp_lineage_limit(value: object, *, default: int = 25, maximum: int = 100) -> int:
    """Clamp a lineage list ``limit`` to the documented range ``[1, maximum]``.

    Mirrors ``clamp_proof_events_limit`` semantics: non-positive values are
    rejected with ``ValueError`` and oversized values are clamped to
    ``maximum``.  Callers translate the ``ValueError`` into the standard
    ``VALIDATION_ERROR`` envelope.
    """
    parsed = int(value)
    if parsed < 1:
        raise ValueError("limit must be a positive integer")
    return min(parsed, maximum)


def create_app() -> Flask:
    load_dotenv()
    config = load_config()
    configure_tracing(
        enabled=config.tracing_enabled,
        service_name=config.tracing_service_name,
        endpoint=config.tracing_endpoint,
        sample_ratio=config.tracing_sample_ratio,
        export_timeout_seconds=config.tracing_export_timeout_seconds,
        service_version=config.release_id,
    )
    app = Flask(__name__)
    # Initialize verifier cache using config
    app.extensions["verifier_cache"] = VerifierCache(
        max_size=config.verifier_cache_max_size,
        positive_ttl_seconds=config.verifier_cache_positive_ttl_seconds,
        negative_ttl_seconds=config.verifier_cache_negative_ttl_seconds,
    )
    # Log config summary on startup
    LOGGER.info("App started with config summary")
    log_structured(LOGGER, logging.INFO, {"event": "app_start", "config": config.redacted_summary()})
    # Continue setup
    CORS(app, **cors_kwargs(config.cors_origins))
    app.config["MAX_CONTENT_LENGTH"] = config.max_content_length
    # Propagate the request id through every response (header + JSON body).
    register_request_id_propagation(app)
    


    # ------------------------------------------------------------------ #
    # Rate limiting                                                        #
    # ------------------------------------------------------------------ #
    storage_uri = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
    storage_kind = get_ratelimit_storage_kind(storage_uri)
    worker_count = _detect_worker_count()

    if config.ratelimit_enabled and storage_kind == "memory" and worker_count > 1:
        log_structured(
            LOGGER,
            logging.WARNING,
            {
                "event": "ratelimit_unshared_storage",
                "message": (
                    "Rate limits are stored in memory and not shared across workers; "
                    "limits will multiply with concurrency. Configure RATELIMIT_STORAGE_URI."
                ),
                "storage_kind": storage_kind,
                "workers": worker_count,
            },
        )

    try:
        limiter = Limiter(
            key_func=_make_key_func(config),
            app=app,
            enabled=config.ratelimit_enabled,
            # In-memory storage is fine for a single-process server; swap for
            # Redis via RATELIMIT_STORAGE_URI env var in multi-worker deployments.
            storage_uri=storage_uri,
            default_limits=[],   # No global limit – each endpoint opts in explicitly.
            headers_enabled=True,  # Emit X-RateLimit-* headers on every response.
            swallow_errors=True,   # Never crash the app due to storage errors.
        )
    except Exception:
        # Fall back gracefully if the storage backend driver is unavailable (e.g. redis package
        # when running without optional dependencies).
        limiter = Limiter(
            key_func=_make_key_func(config),
            app=app,
            enabled=config.ratelimit_enabled,
            storage_uri="memory://",
            default_limits=[],
            headers_enabled=True,
            swallow_errors=True,
        )

    @limiter.request_filter
    def _health_exempt():
        """Health and readiness probes must never be rate-limited."""
        return request.path in {"/health", "/ready"}

    init_db()
    init_retention_worker()

    readiness_manager = ReadinessManager(timeout_seconds=1.0, cache_ttl_seconds=5.0)
    readiness_manager.add_dependency("database", check_db, critical=True)
    readiness_manager.add_dependency("video_tools", video_tooling_ready, critical=True)

    admission_controller = AdmissionController(
        max_concurrent=config.max_concurrent_requests,
        max_queue=config.max_queue_size,
        max_per_identity=config.max_concurrent_per_identity,
        timeout_seconds=config.admission_timeout_seconds,
    )

    @app.before_request
    def start_request_context():
        g.start_time = time.perf_counter()
        g.request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        g.request_started_at = time.perf_counter()

    @app.before_request
    def initialize_trace_context():
        g.trace_fields = build_trace_fields(
            request.headers,
            request_id=g.request_id,
            method=request.method,
            route=request.url_rule.rule if request.url_rule else request.path,
            path=request.path,
        )
        g.request_id = g.trace_fields["request_id"]
        g.otel_request_span = begin_request_span(
            request.headers,
            method=request.method,
            route=request.url_rule.rule if request.url_rule else g.trace_fields["endpoint_pattern"],
            request_id=g.request_id,
        )
        span_context = g.otel_request_span.span.get_span_context()
        if span_context.is_valid:
            g.trace_fields["trace_id"] = f"{span_context.trace_id:032x}"
            g.trace_fields["span_id"] = f"{span_context.span_id:016x}"
            g.trace_fields["trace_flags"] = f"{int(span_context.trace_flags):02x}"

    @app.before_request
    def enforce_cors_origins():
        """Reject browser requests whose Origin is not on the configured allow-list.

        flask-cors alone only *withholds* ``Access-Control-Allow-Origin`` on
        disallowed origins; the request still executes server-side and its
        response is readable by non-browser clients. This hook closes that gap
        for real cross-origin browser traffic:

        - Requests without an ``Origin`` header are same-origin/curl/server
          callers and are never rejected (CORS does not apply to them).
        - ``null``/opaque Origins are rejected — they are indistinguishable
          from a sandboxed attacker context.
        - Configured wildcard (``*``) short-circuits to allow, exactly matching
          the flask-cors behavior and remaining gated by ``ALLOW_WILDCARD_CORS``.
        - Health, readiness, and metrics paths are exempt: probes and scrapers
          are server-to-server callers without an ``Origin``.

        Rejections use the standardized, privacy-safe error envelope and are
        counted in the admission-rejection metrics; the offending Origin value
        is never logged.
        """
        origin = request.headers.get("Origin")
        if origin is None or request.path in CORS_EXEMPT_PATHS:
            return None
        if is_origin_allowed(origin, config.cors_origins):
            return None
        metrics_collector.record_rejection(
            "cors_origin_not_allowed",
            request.url_rule.rule if request.url_rule else request.path,
        )
        log_structured(
            LOGGER,
            logging.INFO,
            {
                "event": "cors_origin_rejected",
                "request_id": request_id(),
                "method": request.method,
                "path": request.path,
            },
        )
        return error_response(
            code=FORBIDDEN_ORIGIN,
            message="request origin is not allowed",
            status=403,
        )
    @app.after_request
    def process_response(response: Response):
        # X-Request-ID and the body-level request_id are applied by the
        # request-id propagation hook registered in create_app().
        trace = current_trace_fields()
        if trace.get("trace_id"):
            response.headers["X-Trace-ID"] = str(trace["trace_id"])
        if trace.get("correlation_id"):
            response.headers["X-Correlation-ID"] = str(trace["correlation_id"])
        if trace.get("span_id"):
            response.headers["X-Span-ID"] = str(trace["span_id"])
        traceparent = format_traceparent(trace)
        if traceparent:
            response.headers["traceparent"] = traceparent
        apply_security_headers(
            response.headers,
            enabled=config.security_headers_enabled,
        )
        response.headers.setdefault("X-Harpocrates-Release", config.release_id)
        response.headers.setdefault("X-Harpocrates-Network", config.release_network)

        if config.metrics_enabled and request.path != config.metrics_path:
            start_time = getattr(g, "start_time", None)
            duration = time.perf_counter() - start_time if start_time is not None else 0.0
            endpoint_rule = request.url_rule.rule if request.url_rule else "unmatched"
            metrics_collector.record_request(
                method=request.method,
                endpoint=endpoint_rule,
                status=response.status_code,
                duration_seconds=duration,
                upload_bytes=request.content_length,
            )

        if response.status_code >= 400:
            log_error_response(response.status_code)
        log_structured(
            LOGGER,
            logging.INFO,
            merge_trace_into_event(
                {
                    "event": "request",
                    "request_id": request_id(),
                    "method": request.method,
                    "route": request_route(),
                    "path": request.path,
                    "status": response.status_code,
                    "duration_ms": request_duration_ms(),
                },
                trace,
            ),
        )
        finish_request_span(
            getattr(g, "otel_request_span", None),
            status_code=response.status_code,
        )
        return response

    @app.teardown_request
    def finish_unhandled_request_span(error: BaseException | None):
        if getattr(g, "otel_request_span", None) is not None:
            finish_request_span(
                g.otel_request_span,
                status_code=500 if error is not None else 200,
                error=error,
            )

    def require_register_auth(fn):
        """Decorator that enforces ownership-scoped auth on proof registration.

        Behaviour:
        - If neither REGISTER_API_KEY nor REGISTER_SCOPED_KEYS is configured the
          endpoint is open (development convenience, unchanged).
        - Otherwise the request must carry ``Authorization: Bearer <key>``.
        - If REGISTER_API_KEY_EXPIRES is set and the current UTC time is at or
          past that instant the primary and owner-scoped credentials are
          expired and the request is rejected with 401, even when the token
          would match.
        - ``REGISTER_API_KEY_PREVIOUS`` can overlap the primary key during a
          rotation.  It is accepted until its optional expiry, allowing
          already-deployed clients to transition without downtime.
        - The legacy keys are unscoped. An owner-scoped key may only register a
          ``sourceAddress`` equal to its owner (403 otherwise).

        This must wrap ``@idempotent``: replays are keyed on the request body
        alone, so authorization and the owner check have to run first or a
        cached success could be replayed to a caller who may not register it.
        """

        def reject(reason: str, message: str):
            # Reason codes only; never the token, its digest, or an address.
            log_structured(
                LOGGER,
                logging.WARNING,
                {"event": "register_auth_rejected", "reason": reason, "request_id": request_id()},
            )
            return jsonify({"error": message}), 401

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            legacy_key = config.register_api_key
            scoped_keys = config.register_scoped_keys
            if legacy_key is None and not scoped_keys:
                # No credential configured – allow the request (dev mode).
                return fn(*args, **kwargs)

            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return reject(
                    register_auth.REASON_MISSING,
                    "Authorization header with Bearer token is required",
                )

            token = auth_header[len("Bearer "):].strip()
            now = datetime.now(tz=timezone.utc)

            # Every configured credential is compared on every call; do not
            # reveal whether a key is primary, previous, scoped, or expired.
            principal = register_auth.authenticate(
                token,
                legacy_key=legacy_key,
                scoped_keys=scoped_keys,
            )
            previous_key = config.register_api_key_previous
            previous_principal = (
                register_auth.authenticate(token, legacy_key=previous_key, scoped_keys=())
                if previous_key
                else None
            )
            # REGISTER_API_KEY_EXPIRES applies to the primary and scoped keys;
            # REGISTER_API_KEY_PREVIOUS has its own optional expiry.
            expires = config.register_api_key_expires
            primary_expired = expires is not None and now >= expires
            previous_expires = config.register_api_key_previous_expires
            if primary_expired:
                principal = None
            if principal is None and previous_principal is not None and (
                previous_expires is None or now < previous_expires
            ):
                principal = previous_principal
            if principal is None:
                if primary_expired:
                    return reject(register_auth.REASON_EXPIRED, "API key has expired")
                return reject(register_auth.REASON_INVALID, "Invalid API key")

            if principal.is_scoped:
                # Bound the body we parse before the handler's own size check.
                if (request.content_length or 0) > config.max_json_bytes:
                    return jsonify({"error": "JSON payload exceeds size limit"}), 413
                payload = request.get_json(silent=True)
                # A non-object body is left for the handler to reject with 400.
                if isinstance(payload, dict):
                    try:
                        claimed_owner = validate_source_address(payload.get("sourceAddress"))
                    except ValueError as exc:
                        return jsonify({"error": str(exc)}), 400
                    if not register_auth.scope_allows(principal, claimed_owner):
                        log_structured(
                            LOGGER,
                            logging.WARNING,
                            {
                                "event": "register_auth_rejected",
                                "reason": register_auth.REASON_SCOPE,
                                "request_id": request_id(),
                            },
                        )
                        return error_response(
                            code=FORBIDDEN,
                            message="credential is not authorized for this sourceAddress",
                            status=403,
                            field="sourceAddress",
                        )

            g.register_principal = principal
            return fn(*args, **kwargs)

        return wrapper

    @app.errorhandler(RequestEntityTooLarge)
    def request_too_large(_error: RequestEntityTooLarge):
        return error_response(
            code=PAYLOAD_TOO_LARGE,
            message="request body is too large",
            status=413,
        )

    @app.errorhandler(ValueError)
    def bad_request(error: ValueError):
        # Metadata failures carry a canonical taxonomy code; serialize them
        # with the shared metadata envelope so every boundary agrees.
        if isinstance(error, MetadataError):
            return metadata_error_response(error)
        return error_response(
            code=VALIDATION_ERROR,
            message=str(error),
            status=400,
        )

    @app.errorhandler(RuntimeError)
    def runtime_error(error: RuntimeError):
        app.logger.error("Unhandled runtime error: %s", error, exc_info=True)
        return error_response(
            code=INTERNAL_ERROR,
            message="internal server error",
            status=500,
        )

    @app.errorhandler(429)
    def rate_limit_exceeded(_error: Exception):
        """Stable, privacy-safe envelope for per-client throttle responses.

        Flask-Limiter injects the precise ``Retry-After`` value during
        ``after_request``; the fallback below keeps the response well formed
        for callers that exercise the handler directly.
        """
        response, status = error_response(
            code=RATE_LIMITED,
            message="rate limit exceeded",
            status=429,
        )
        response.headers.setdefault("Retry-After", "60")
        return response, status

    @app.get(config.metrics_path)
    def metrics():
        if not config.metrics_enabled:
            return jsonify({"error": "metrics service disabled"}), 404

        if config.metrics_token:
            auth_header = request.headers.get("Authorization", "")
            token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else ""
            custom_token = request.headers.get("X-Metrics-Token", "").strip()
            # Constant-time comparison; both candidates are always evaluated so
            # neither the match position nor the header used is observable.
            import hmac as _hmac

            expected_token = config.metrics_token.encode("utf-8")
            bearer_ok = _hmac.compare_digest(token.encode("utf-8"), expected_token)
            header_ok = _hmac.compare_digest(custom_token.encode("utf-8"), expected_token)
            if not (bearer_ok or header_ok):
                return jsonify({"error": "unauthorized metrics access"}), 401

        output = metrics_collector.generate_prometheus_metrics()
        return Response(output, mimetype="text/plain; version=0.0.4; charset=utf-8")

    @app.get("/health")
    def health():
        trace = current_trace_fields()
        return jsonify(
            {
                "ok": True,
                "service": "harpocrates-stego",
                "release_id": config.release_id,
                "network": config.release_network,
                "request_id": request_id(),
                "trace_id": trace.get("trace_id"),
                "correlation_id": trace.get("correlation_id"),
            }
        )

    @app.get("/ready")
    def ready():
        status = readiness_manager.check()
        for dependency in readiness_manager.deps:
            metrics_collector.record_dependency_status(
                dependency.name,
                status.get(dependency.name, "unknown"),
                dependency.critical,
            )
        trace = current_trace_fields()
        return jsonify(
            {
                "ok": status["ok"],
                "service": "harpocrates-stego",
                "database": status.get("database", "not_configured"),
                "video_tools": status.get("video_tools", "missing"),
                "noir_worker": "enabled" if config.noir_worker_enabled else "disabled",
                "aggregation": "enabled" if config.noir_worker_enabled else "disabled",
                "max_aggregation_size": MAX_AGGREGATION_SIZE,
                "ratelimit_storage": storage_kind,
                "storage_kind": storage_kind,
                "request_id": request_id(),
                "trace_id": trace.get("trace_id"),
                "correlation_id": trace.get("correlation_id"),
            }
        ), 200 if status["ok"] else 503

    def _enforce_video_size(video) -> bool:
        # StreamingFileStorage enforces the limit mid-stream during save();
        # avoid seek() which can force whole-body buffering on the WSGI input.
        if isinstance(video, StreamingFileStorage):
            if video.bytes_written > 0:
                return video.bytes_written <= config.max_video_bytes
            if request.content_length is not None:
                # Content-Length includes multipart overhead; still a useful gate.
                return request.content_length <= config.max_content_length
            return True
        video.seek(0, 2)
        size = video.tell()
        video.seek(0)
        return size <= config.max_video_bytes

    def _enable_streaming_for_large_uploads():
        """Wrap large multipart uploads with bounded-chunk stream hashing."""
        threshold = getattr(
            config, "upload_stream_threshold_bytes", 1_048_576
        )
        if not request.content_length or request.content_length <= threshold:
            return
        if not request.files:
            return

        g.upload_config = config
        # Access files first so the cached_property is populated, then replace.
        current = request.files
        new_items = []
        for field_name, field_storage in current.items(multi=True):
            new_items.append(
                (field_name, create_streaming_file_storage(field_storage))
            )
        # Shadow the cached_property with stream-hashing wrappers.
        request.__dict__["files"] = ImmutableMultiDict(new_items)

    def _enforce_json_size() -> int:
        raw = request.get_data()
        return len(raw) if raw else 0

    @app.post("/api/stego/embed")
    @limiter.limit(config.ratelimit_embed)
    @require_capacity(admission_controller)
    @idempotent("embed")
    def embed():
        # Enable streaming for large uploads
        _enable_streaming_for_large_uploads()
        
        video = request.files.get("video")
        metadata_raw = request.form.get("metadata")
        if video is None or metadata_raw is None:
            return jsonify({"error": "video and metadata are required"}), 400
        if not _enforce_video_size(video):
            return jsonify({"error": "video payload exceeds size limit"}), 413
        validate_video_upload(video)
        if len(metadata_raw.encode("utf-8")) > config.max_metadata_bytes:
            return metadata_error_response(
                MetadataError(METADATA_OVERSIZED, "metadata is too large")
            )

        try:
            metadata = json.loads(metadata_raw)
        except json.JSONDecodeError:
            return metadata_error_response(
                MetadataError(METADATA_MALFORMED, "metadata must be valid JSON")
            )
        try:
            validate_embed_metadata(metadata)
        except MetadataError as exc:
            return metadata_error_response(exc)
        except ValueError as exc:
            return metadata_error_response(classify_validation_error(exc))

        normalized_name = normalize_filename(video.filename)
        try:
            quarantine_context = isolate_upload(
                video,
                filename=normalized_name,
                content_type=video.content_type,
            )
            with quarantine_context as quarantined_path, EncryptedWorkspace() as workspace:
                source_url = workspace.get_url("source.video")
                output_url = workspace.get_url("embedded.mp4")
                with quarantined_path.open("rb") as quarantined:
                    workspace.write_encrypted(
                        "source.video",
                        quarantined,
                        size=quarantined_path.stat().st_size,
                    )

                embed_metadata(source_url, output_url, metadata)
                output_bytes = workspace.read_decrypted("embedded.mp4")
                source_hash = workspace.sha256("source.video")
                embedded_hash = workspace.sha256("embedded.mp4")
                metadata_hash = canonical_metadata_hash(metadata)
        except QuarantineError as exc:
            return error_response(
                code=UNSUPPORTED_MEDIA_TYPE,
                message=str(exc),
                status=400,
            )

        db_event = insert_proof_event(
            event_type="embed",
            file_name=normalized_name,
            video_hash=embedded_hash,
            metadata_hash=metadata_hash,
            proof_id=metadata.get("proofId"),
            tier=metadata.get("tier"),
            embedded_hash=embedded_hash,
            metadata=redact_metadata(metadata),
        )

        if db_event and db_event.get("id"):
            queue_webhook_deliveries(db_event["id"])

        response = Response(output_bytes, mimetype="video/mp4")
        response.headers["Content-Disposition"] = 'attachment; filename="harpocrates-evidence.mp4"'
        response.headers["X-Harpocrates-Source-Hash"] = source_hash
        response.headers["X-Harpocrates-Embedded-Hash"] = embedded_hash
        response.headers["X-Harpocrates-Metadata-Hash"] = metadata_hash
        response.headers["X-Harpocrates-Db-Event"] = str(db_event)
        if config.expose_metadata_header:
            response.headers["X-Harpocrates-Metadata"] = base64.b64encode(
                json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
            ).decode("ascii")
        return response

    @app.post("/api/stego/upload-session")
    @limiter.limit(config.ratelimit_upload_session)
    def create_upload_session():
        session_id = str(uuid.uuid4())
        session_dir = Path(tempfile.gettempdir()) / f"harpocrates-session-{session_id}"
        session_dir.mkdir(parents=True, exist_ok=True)
        return jsonify({"sessionId": session_id})

    @app.put("/api/stego/upload-session/<session_id>/chunk/<int:chunk_index>")
    @limiter.limit(config.ratelimit_upload_chunk)
    def upload_chunk(session_id: str, chunk_index: int):
        session_dir = Path(tempfile.gettempdir()) / f"harpocrates-session-{session_id}"
        if not session_dir.exists():
            return jsonify({"error": "session not found"}), 404
        
        chunk = request.files.get("chunk")
        if chunk is None:
            return jsonify({"error": "chunk is required"}), 400
        if chunk_index < 0:
            return jsonify({"error": "chunk_index must be non-negative"}), 400

        # Persist each session chunk with bounded-chunk hashing for integrity.
        g.upload_config = config
        streaming_chunk = create_streaming_file_storage(chunk)
        chunk_path = session_dir / f"chunk-{chunk_index}"
        try:
            streaming_chunk.save(str(chunk_path))
        except RequestEntityTooLarge:
            return jsonify({"error": "chunk exceeds size limit"}), 413
        return jsonify({
            "ok": True,
            "bytes": streaming_chunk.bytes_written,
            "sha256": streaming_chunk.computed_hash,
        })

    @app.post("/api/stego/upload-session/<session_id>/commit")
    @limiter.limit(config.ratelimit_upload_session)
    @require_capacity(admission_controller)
    def commit_upload_session(session_id: str):
        session_dir = Path(tempfile.gettempdir()) / f"harpocrates-session-{session_id}"
        if not session_dir.exists():
            return jsonify({"error": "session not found"}), 404

        metadata_raw = request.form.get("metadata")
        if metadata_raw is None:
            return jsonify({"error": "metadata is required"}), 400

        try:
            metadata = json.loads(metadata_raw)
        except json.JSONDecodeError:
            return metadata_error_response(
                MetadataError(METADATA_MALFORMED, "metadata must be valid JSON")
            )
        try:
            validate_embed_metadata(metadata)
        except MetadataError as exc:
            return metadata_error_response(exc)
        except ValueError as exc:
            return metadata_error_response(classify_validation_error(exc))

        combined_path = session_dir / "combined.video"
        chunk_files = sorted(
            [f for f in session_dir.iterdir() if f.name.startswith("chunk-")],
            key=lambda f: int(f.name.split("-")[1]),
        )
        if not chunk_files:
            return jsonify({"error": "session has no chunks"}), 400

        # Bounded-chunk concat + SHA-256 so commit never buffers whole chunks.
        source_hash, _written = hash_paths_concat(
            chunk_files,
            combined_path,
            chunk_size=getattr(config, "upload_chunk_bytes", None),
            max_size=getattr(config, "upload_max_bytes", config.max_video_bytes),
        )

        # Sniff assembled file before handing it to ffmpeg.
        try:
            sniff_media_type_path(combined_path)
        except QuarantineError as exc:
            return error_response(
                code=UNSUPPORTED_MEDIA_TYPE,
                message=str(exc),
                status=400,
            )

        with tempfile.TemporaryDirectory(prefix="harpocrates-") as tmp_dir:
            output_path = Path(tmp_dir) / "embedded.mp4"
            embed_metadata(combined_path, output_path, metadata)
            output_bytes = output_path.read_bytes()
            embedded_hash = sha256_file(output_path)
            metadata_hash = canonical_metadata_hash(metadata)

        retention_class = request.headers.get("X-Harpocrates-Retention-Class") or metadata.get("retentionClass", "default")
        if retention_class not in config.retention_classes:
            return jsonify({"error": f"invalid retention class: {retention_class}"}), 400
        retention_days = config.retention_classes[retention_class]
        expires_at = None
        if retention_days >= 0:
            expires_at = datetime.now(timezone.utc) + timedelta(days=retention_days)

        db_event = insert_proof_event(
            event_type="embed",
            file_name=normalize_filename(metadata.get("fileName", "unknown.mp4")),
            video_hash=embedded_hash,
            metadata_hash=metadata_hash,
            proof_id=metadata.get("proofId"),
            tier=metadata.get("tier"),
            embedded_hash=embedded_hash,
            retention_class=retention_class,
            expires_at=expires_at,
            metadata=redact_metadata(metadata),
        )

        response = Response(output_bytes, mimetype="video/mp4")
        response.headers["Content-Disposition"] = 'attachment; filename="harpocrates-evidence.mp4"'
        response.headers["X-Harpocrates-Source-Hash"] = source_hash
        response.headers["X-Harpocrates-Embedded-Hash"] = embedded_hash
        response.headers["X-Harpocrates-Metadata-Hash"] = metadata_hash
        response.headers["X-Harpocrates-Db-Event"] = str(db_event)
        response.headers["X-Harpocrates-Retention-Class"] = retention_class
        if config.expose_metadata_header:
            response.headers["X-Harpocrates-Metadata"] = base64.b64encode(
                json.dumps(metadata, separators=(",", ":"), sort_keys=True).encode("utf-8")
            ).decode("ascii")

        import shutil
        shutil.rmtree(session_dir, ignore_errors=True)

        return response

    @app.post("/api/stego/extract")
    @limiter.limit(config.ratelimit_extract)
    @require_capacity(admission_controller)
    @idempotent("extract")
    def extract():
        # Enable streaming for large uploads
        _enable_streaming_for_large_uploads()
        
        video = request.files.get("video")
        if video is None:
            return jsonify({"error": "video is required"}), 400
        if not _enforce_video_size(video):
            return jsonify({"error": "video payload exceeds size limit"}), 413
        validate_video_upload(video)

        normalized_name = normalize_filename(video.filename)
        try:
            quarantine_context = isolate_upload(
                video,
                filename=normalized_name,
                content_type=video.content_type,
            )
            with quarantine_context as quarantined_path, EncryptedWorkspace() as workspace:
                source_url = workspace.get_url("source.video")
                with quarantined_path.open("rb") as quarantined:
                    workspace.write_encrypted(
                        "source.video",
                        quarantined,
                        size=quarantined_path.stat().st_size,
                    )
                metadata = extract_metadata(source_url)
                video_hash = workspace.sha256("source.video")
                metadata_hash = canonical_metadata_hash(metadata) if metadata else None
        except QuarantineError as exc:
            return error_response(
                code=UNSUPPORTED_MEDIA_TYPE,
                message=str(exc),
                status=400,
            )

        retention_class = request.headers.get("X-Harpocrates-Retention-Class") or (metadata.get("retentionClass", "default") if metadata else "default")
        if retention_class not in config.retention_classes:
            return jsonify({"error": f"invalid retention class: {retention_class}"}), 400
        retention_days = config.retention_classes[retention_class]
        expires_at = None
        if retention_days >= 0:
            expires_at = datetime.now(timezone.utc) + timedelta(days=retention_days)

        db_event = insert_proof_event(
            event_type="extract",
            file_name=normalized_name,
            video_hash=video_hash,
            metadata_hash=metadata_hash,
            proof_id=metadata.get("proofId") if metadata else None,
            tier=metadata.get("tier") if metadata else None,
            retention_class=retention_class,
            expires_at=expires_at,
            metadata=redact_metadata(metadata),
        )

        if db_event and db_event.get("id"):
            queue_webhook_deliveries(db_event["id"])

        return jsonify(
            {
                "video_hash": video_hash,
                "metadata_hash": metadata_hash,
                "metadata": metadata,
                "db_event": db_event,
            }
        )

    @app.get("/api/proofs")
    def proofs():
        limit = request.args.get("limit", "25")
        cursor_token = request.args.get("cursor")
        try:
            parsed_limit = int(limit)
        except ValueError:
            return error_response(
                code=VALIDATION_ERROR,
                message="limit must be an integer",
                status=400,
            )

        cursor_id = None
        if cursor_token is not None and cursor_token != "":
            try:
                cursor_id = decode_proof_events_cursor(cursor_token)
            except ValueError:
                return jsonify({"error": "invalid cursor"}), 400

        events, next_cursor = list_proof_events(parsed_limit, cursor_id=cursor_id)
        return jsonify({"ok": True, "events": events, "nextCursor": next_cursor})

    @app.get("/api/proofs/lineage")
    def lineage_events():
        limit = request.args.get("limit", "25")
        try:
            parsed_limit = clamp_lineage_limit(limit)
        except (TypeError, ValueError):
            return error_response(
                code=VALIDATION_ERROR,
                message="limit must be a positive integer",
                status=400,
            )
        return jsonify({"ok": True, "events": list_lineage_events(parsed_limit)})

    @app.get("/api/proofs/by-video/<video_hash>")
    def proof_by_video(video_hash: str):
        if not is_hex_32(video_hash):
            return error_response(
                code=VALIDATION_ERROR,
                message="video_hash must be a 32-byte hex string",
                status=400,
            )

        limit = request.args.get("limit", "25")
        cursor_token = request.args.get("cursor")
        try:
            parsed_limit = int(limit)
        except ValueError:
            return error_response(
                code=VALIDATION_ERROR,
                message="limit must be an integer",
                status=400,
            )

        cursor_id = None
        if cursor_token is not None and cursor_token != "":
            try:
                cursor_id = decode_proof_events_cursor(cursor_token)
            except ValueError:
                return jsonify({"error": "invalid cursor"}), 400

        events, next_cursor = find_proof_events_by_video(
            video_hash, parsed_limit, cursor_id=cursor_id
        )
        return ok_response({"events": events, "nextCursor": next_cursor})

    @app.get("/api/lineage/by-actor/<actor_address>")
    def lineage_by_actor(actor_address: str):
        limit = request.args.get("limit", "25")
        try:
            parsed_limit = clamp_lineage_limit(limit)
        except (TypeError, ValueError):
            return error_response(
                code=VALIDATION_ERROR,
                message="limit must be a positive integer",
                status=400,
            )

        try:
            validated_actor_address = validate_source_address(actor_address)
            if not validated_actor_address:
                raise ValueError("actor_address must be a valid Stellar G-address")
        except ValueError:
            return error_response(
                code=VALIDATION_ERROR,
                message="actor_address must be a valid Stellar G-address",
                status=400,
            )

        return jsonify({"ok": True, "events": find_lineage_by_actor(validated_actor_address, parsed_limit)})

    @app.get("/api/lineage/<output_digest>")
    def lineage_by_output_digest(output_digest: str):
        if not is_hex_32(output_digest):
            return error_response(
                code=VALIDATION_ERROR,
                message="output_digest must be a 32-byte hex string",
                status=400,
            )

        record = find_lineage_by_output_digest(output_digest)
        if not record:
            return error_response(
                code=NOT_FOUND,
                message="lineage record not found",
                status=404,
            )

        return ok_response({"record": record})

    @app.post("/api/proofs/lineage")
    def register_lineage_event():
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON body is required"}), 400

        output_digest = payload.get("outputDigest")
        if not output_digest:
            return jsonify({"error": "outputDigest is required"}), 400
        if not is_hex_32(output_digest):
            return jsonify({"error": "outputDigest must be a 32-byte hex string"}), 400

        try:
            manifest_canonical = canonical_lineage_manifest(payload)
            manifest_digest = lineage_manifest_digest(payload)
            parent_ids = payload.get("parentProofIds", [])
            actor_address = str(payload.get("actorAddress", ""))
            
            # Validate basic constraints
            validate_lineage_graph(
                parent_ids,
                depth=1,
                actor_address=actor_address,
                output_digest=output_digest,
                get_lineage_fn=find_lineage_by_output_digest,
            )
        except LineageValidationError as exc:
            return jsonify({"error": str(exc)}), 400

        # Check for duplicate submission
        existing = find_lineage_by_output_digest(output_digest)
        if existing:
            return jsonify({"error": "lineage already registered for this output digest"}), 409

        # Insert into lineage_events table
        db_event = insert_lineage_event(
            manifest_digest=manifest_digest,
            manifest=json.loads(manifest_canonical),
            actor_address=actor_address,
            parent_proof_ids=[str(parent) for parent in parent_ids],
        )
        
        if not db_event:
            return jsonify({"error": "failed to record lineage event"}), 500

        return jsonify({"ok": True, "manifestDigest": manifest_digest, "db_event": db_event})

    @app.post("/api/proofs/verify-batch")
    @require_capacity(admission_controller)
    def verify_batch():
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or not isinstance(payload.get("proofs"), list):
            return jsonify({"error": "JSON body with a 'proofs' array is required"}), 400

        proofs = payload["proofs"]
        if len(proofs) > config.max_batch_size:
            return jsonify({"error": f"batch size exceeds limit of {config.max_batch_size}"}), 413

        results = []
        for idx, item in enumerate(proofs):
            if not isinstance(item, dict):
                results.append({"status": "malformed", "error": "item must be a JSON object", "index": idx})
                continue
            
            video_hash = item.get("videoHash")
            proof_id = item.get("proofId")
            
            if video_hash is not None and not is_hex_32(video_hash):
                results.append({"videoHash": video_hash, "proofId": proof_id, "status": "malformed", "error": "invalid videoHash", "index": idx})
                continue
            if proof_id is not None and not is_hex_32(proof_id):
                results.append({"videoHash": video_hash, "proofId": proof_id, "status": "malformed", "error": "invalid proofId", "index": idx})
                continue
            if not video_hash and not proof_id:
                results.append({"status": "malformed", "error": "must provide videoHash or proofId", "index": idx})
                continue

            try:
                events = []
                if video_hash:
                    events, _ = find_proof_events_by_video(video_hash)
                    if proof_id:
                        events = [e for e in events if e.get("proof_id") == proof_id]
                else:
                    events = find_proof_events_by_proof_id(proof_id)
                
                if not events:
                    results.append({"videoHash": video_hash, "proofId": proof_id, "status": "not_found", "events": [], "index": idx})
                else:
                    # Determine status from db events.
                    # Since on-chain revocation isn't visible here, we use tx_status if available.
                    has_confirmed = any(e.get("tx_status") == "confirmed" for e in events)
                    has_failed = any(e.get("tx_status") == "failed" for e in events)
                    has_revoked = any(e.get("tx_status") == "revoked" for e in events)  # Future compat
                    
                    if has_revoked:
                        status = "revoked"
                    elif has_confirmed:
                        status = "verified"
                    elif has_failed:
                        status = "failed"
                    else:
                        status = "pending"
                        
                    results.append({"videoHash": video_hash, "proofId": proof_id, "status": status, "events": events, "index": idx})
            except Exception as e:
                # Catch dependency failure (e.g. database down) gracefully for the batch item
                results.append({"videoHash": video_hash, "proofId": proof_id, "status": "dependency_failure", "error": str(e), "index": idx})

        return jsonify({"ok": True, "results": results})

    @app.post("/api/proofs/register")
    @limiter.limit(config.ratelimit_register)
    @require_register_auth
    @idempotent("register")
    def register_proof_event():
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return error_response(
                code=VALIDATION_ERROR,
                message="JSON body is required",
                status=400,
            )
        if len(json.dumps(payload, separators=(",", ":")).encode("utf-8")) > config.max_metadata_bytes:
            return error_response(
                code=PAYLOAD_TOO_LARGE,
                message="registration payload is too large",
                status=413,
                cli_code=OVERSIZED_INPUT,
            )

        video_hash = payload.get("videoHash")
        metadata_hash = payload.get("metadataHash")
        proof_id = payload.get("proofId")
        tx_hash = payload.get("txHash")
        tx_status = payload.get("txStatus")

        for name, value in (
            ("videoHash", video_hash),
            ("metadataHash", metadata_hash),
            ("proofId", proof_id),
        ):
            if not is_hex_32(value):
                return error_response(
                    code=VALIDATION_ERROR,
                    message=f"{name} must be a 32-byte hex string",
                    status=400,
                    cli_code=MALFORMED_INPUT,
                )

        tier = payload.get("tier")
        if tier not in ALLOWED_TIERS:
            return error_response(
                code=VALIDATION_ERROR,
                message="tier must be one of: silent, source, seal",
                status=400,
                cli_code=UNSUPPORTED_INPUT,
            )

        try:
            normalized_tx_hash = normalize_tx_hash(tx_hash)
            normalized_tx_status = normalize_tx_status(tx_status)
            if normalized_tx_hash:
                normalized_tx_status = "pending"
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        # Validate Stellar identifiers with StrKey semantics
        try:
            validated_source_address = validate_source_address(payload.get("sourceAddress"))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        try:
            validated_contract_id = validate_contract_id(payload.get("contractId"))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        # Proof ownership: a scoped credential may not register a proof that a
        # different address already owns. Fail closed if the lookup fails.
        principal = g.get("register_principal")
        if principal is not None and principal.is_scoped:
            try:
                existing_owner = find_proof_owner(proof_id)
            except Exception:
                log_structured(
                    LOGGER,
                    logging.ERROR,
                    {"event": "register_owner_lookup_failed", "request_id": request_id()},
                )
                return error_response(
                    code=DEPENDENCY_UNAVAILABLE,
                    message="ownership check unavailable; registration was not applied",
                    status=503,
                )
            if existing_owner is not None and existing_owner != validated_source_address:
                log_structured(
                    LOGGER,
                    logging.WARNING,
                    {
                        "event": "register_auth_rejected",
                        "reason": register_auth.REASON_OWNER_CONFLICT,
                        "request_id": request_id(),
                    },
                )
                return error_response(
                    code=FORBIDDEN,
                    message="proof is registered to a different owner",
                    status=403,
                    field="proofId",
                )

        # Handle time attestation if provided
        time_attestation_data = None
        claimed_capture_time = None
        if "timeAttestation" in payload:
            from time_attestation import decode_time_attestation, validate_time_attestation, encode_time_attestation
            try:
                time_att = decode_time_attestation(payload["timeAttestation"])
                errors = validate_time_attestation(time_att, video_hash)
                if errors:
                    return error_response(
                        code=VALIDATION_ERROR,
                        message="Invalid time attestation",
                        status=400,
                        cli_code=classify_cli_error("time attestation is invalid"),
                    )
                time_attestation_data = encode_time_attestation(time_att)
                if time_att.claimed_time:
                    claimed_capture_time = datetime.fromtimestamp(
                        time_att.claimed_time.unix_ms / 1000, tz=timezone.utc
                    ).isoformat()
            except (ValueError, TypeError) as exc:
                return error_response(
                    code=VALIDATION_ERROR,
                    message=f"Time attestation error: {str(exc)}",
                    status=400,
                    cli_code=classify_cli_error(str(exc)),
                )

        idempotency_key = make_idempotency_key(video_hash, proof_id, normalized_tx_hash)

        retention_class = payload.get("retentionClass", "default")
        if retention_class not in config.retention_classes:
            return error_response(
                code=VALIDATION_ERROR,
                message=f"invalid retention class: {retention_class}",
                status=400,
                cli_code=UNSUPPORTED_INPUT,
            )
        retention_days = config.retention_classes[retention_class]
        expires_at = None
        if retention_days >= 0:
            expires_at = datetime.now(timezone.utc) + timedelta(days=retention_days)

        try:
            db_event, created = upsert_register_event(
                idempotency_key=idempotency_key,
                file_name=normalize_filename(payload.get("fileName")),
                video_hash=video_hash,
                metadata_hash=metadata_hash,
                proof_id=proof_id,
                tier=tier,
                tx_hash=normalized_tx_hash,
                tx_status=normalized_tx_status,
                source_address=validated_source_address,
                contract_id=validated_contract_id,
                retention_class=retention_class,
                expires_at=expires_at,
                metadata=redact_metadata(payload),
                time_attestation=time_attestation_data,
                claimed_capture_time=claimed_capture_time,
            )
        except ConflictError as exc:
            return jsonify({
                "error": "idempotency key reused with conflicting payload",
                "conflict_field": exc.field,
            }), 409

        if db_event and db_event.get("id") and created:
            # A newly registered proof can change the on-chain verification
            # result. Evict all cached results for this proof before clients
            # perform the next verification lookup.
            app.extensions["verifier_cache"].invalidate_proof(proof_id)
            queue_webhook_deliveries(db_event["id"])
            if normalized_tx_hash:
                enqueue_job("verify_tx", {"proof_id": proof_id, "tx_hash": normalized_tx_hash, "contract_id": validated_contract_id})

        status = 201 if created else 200
        return jsonify({"ok": True, "db_event": db_event, "created": created}), status

    @app.post("/api/proofs/reconcile")
    def reconcile_registration_confirmations():
        """Reconcile pending registration tx hashes against on-chain Horizon state.

        Body (all optional):
        - ``txHash``: reconcile a single hash; omit to batch pending rows
        - ``limit``: max pending rows when batching (1–50, default 50)
        - ``minConfirmations``: confirmation depth policy (default TX_MIN_CONFIRMATIONS)
        - ``force``: overwrite terminal statuses (repair path)

        Responses are privacy-safe: no metadata envelopes, media, or secrets.
        """
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413

        payload = request.get_json(silent=True)
        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            return error_response(
                code=VALIDATION_ERROR,
                message="JSON body must be an object",
                status=400,
            )

        if len(json.dumps(payload, separators=(",", ":")).encode("utf-8")) > config.max_metadata_bytes:
            return jsonify({"error": "reconcile payload is too large"}), 413

        force = bool(payload.get("force", False))
        min_confirmations = payload.get("minConfirmations")
        if min_confirmations is None:
            min_confirmations = default_min_confirmations()
        else:
            try:
                min_confirmations = int(min_confirmations)
            except (TypeError, ValueError):
                return error_response(
                    code=VALIDATION_ERROR,
                    message="minConfirmations must be an integer >= 1",
                    status=400,
                )
            if min_confirmations < 1:
                return error_response(
                    code=VALIDATION_ERROR,
                    message="minConfirmations must be an integer >= 1",
                    status=400,
                )

        tx_hash = payload.get("txHash")
        if tx_hash is not None:
            try:
                result = reconcile_registration(
                    tx_hash,
                    previous_status=None if force else "pending",
                    min_confirmations=min_confirmations,
                    force=force,
                )
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400

            if result.get("error") == "malformed_tx_hash":
                return error_response(
                    code=VALIDATION_ERROR,
                    message="txHash must be a 32-byte hex string",
                    status=400,
                )
            if result.get("status") == "error":
                return jsonify({
                    "ok": False,
                    "error": "horizon_dependency_failure",
                    "result": result,
                }), 503
            return jsonify({"ok": True, "result": result})

        try:
            limit = clamp_reconcile_limit(payload.get("limit", 50))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        try:
            report = reconcile_pending_registrations(
                limit=limit,
                min_confirmations=min_confirmations,
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        return jsonify(report)

    @app.post("/api/time-attestation/create")
    def create_time_attestation_endpoint():
        """Create a new time attestation envelope."""
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413
        
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON body is required"}), 400
        
        evidence_digest = payload.get("evidenceDigest")
        if not is_hex_32(evidence_digest):
            return jsonify({"error": "evidenceDigest must be a 32-byte hex string"}), 400
        
        from time_attestation import create_time_attestation, encode_time_attestation, check_backdating_risk
        
        claimed_time_ms = payload.get("claimedTimeMs")
        claimed_source_label = payload.get("claimedSourceLabel", "device_clock")
        uncertainty_ms = payload.get("uncertaintyMs", 0)
        
        try:
            attestation = create_time_attestation(
                evidence_digest=evidence_digest,
                claimed_time_ms=claimed_time_ms,
                claimed_source_label=claimed_source_label,
                uncertainty_ms=uncertainty_ms,
            )
            
            encoded = encode_time_attestation(attestation)
            risk_assessment = check_backdating_risk(attestation)
            
            return jsonify({
                "ok": True,
                "timeAttestation": encoded,
                "riskAssessment": risk_assessment,
            })
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/api/time-attestation/anchor")
    def anchor_time_attestation():
        """Add anchors to an existing time attestation."""
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413
        
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON body is required"}), 400
        
        from time_attestation import (
            decode_time_attestation,
            add_stellar_anchor,
            add_rfc3161_anchor,
            encode_time_attestation,
            check_backdating_risk,
        )
        
        try:
            attestation = decode_time_attestation(payload.get("timeAttestation", {}))
        except (ValueError, TypeError) as exc:
            return jsonify({"error": f"Invalid time attestation: {str(exc)}"}), 400
        
        # Add Stellar anchor if provided
        if "stellarAnchor" in payload:
            stellar = payload["stellarAnchor"]
            try:
                attestation = add_stellar_anchor(
                    attestation,
                    ledger_sequence=stellar["ledgerSequence"],
                    ledger_timestamp=stellar["ledgerTimestamp"],
                    transaction_hash=stellar["transactionHash"],
                    network_passphrase=stellar["networkPassphrase"],
                )
            except (ValueError, KeyError) as exc:
                return jsonify({"error": f"Invalid Stellar anchor: {str(exc)}"}), 400
        
        # Add RFC 3161 anchor if provided
        if "rfc3161Anchor" in payload:
            rfc3161 = payload["rfc3161Anchor"]
            try:
                attestation = add_rfc3161_anchor(
                    attestation,
                    token_bytes=rfc3161["tokenBytes"],
                    tsa_url=rfc3161["tsaUrl"],
                    gen_time=rfc3161["genTime"],
                    policy_oid=rfc3161.get("policyOid"),
                    cert_fingerprint=rfc3161.get("certFingerprint"),
                    verification_status=rfc3161.get("verificationStatus", "unverified"),
                    verification_error=rfc3161.get("verificationError"),
                )
            except (ValueError, KeyError) as exc:
                return jsonify({"error": f"Invalid RFC 3161 anchor: {str(exc)}"}), 400
        
        encoded = encode_time_attestation(attestation)
        risk_assessment = check_backdating_risk(attestation)
        
        return jsonify({
            "ok": True,
            "timeAttestation": encoded,
            "riskAssessment": risk_assessment,
        })

    @app.post("/api/time-attestation/validate")
    def validate_time_attestation_endpoint():
        """Validate a time attestation envelope."""
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413
        
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON body is required"}), 400
        
        evidence_digest = payload.get("evidenceDigest")
        if not is_hex_32(evidence_digest):
            return jsonify({"error": "evidenceDigest must be a 32-byte hex string"}), 400
        
        from time_attestation import (
            decode_time_attestation,
            validate_time_attestation,
            check_backdating_risk,
        )
        
        try:
            attestation = decode_time_attestation(payload.get("timeAttestation", {}))
            errors = validate_time_attestation(attestation, evidence_digest)
            risk_assessment = check_backdating_risk(attestation)
            
            return jsonify({
                "ok": len(errors) == 0,
                "errors": errors,
                "riskAssessment": risk_assessment,
            })
        except (ValueError, TypeError) as exc:
            return jsonify({"error": f"Invalid time attestation: {str(exc)}"}), 400

    @app.get("/api/proofs/history/<proof_id>")
    def proof_history(proof_id: str):
        if not is_hex_32(proof_id):
            return jsonify({"error": "proof_id must be a 32-byte hex string"}), 400

        limit = request.args.get("limit", "50")
        offset = request.args.get("offset", "0")
        try:
            parsed_limit = int(limit)
            parsed_offset = int(offset)
        except ValueError:
            return jsonify({"error": "limit and offset must be integers"}), 400

        return jsonify(
            {"ok": True, "events": list_proof_history_events(proof_id, parsed_limit, parsed_offset)}
        )

    @app.post("/api/proofs/history")
    def register_proof_history_event():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON body is required"}), 400

        proof_id = payload.get("proofId")
        action = payload.get("action")
        actor = payload.get("actor")
        reason_code = payload.get("reasonCode")
        contract_id = payload.get("contractId")
        tx_hash = payload.get("txHash")

        if not is_hex_32(proof_id):
            return jsonify({"error": "proofId must be a 32-byte hex string"}), 400
        if not isinstance(action, str) or not action:
            return jsonify({"error": "action is required"}), 400
        if reason_code is None or not isinstance(reason_code, int):
            return jsonify({"error": "reasonCode is required"}), 400

        db_event = insert_proof_history_event(
            proof_id=proof_id,
            action=action,
            actor=actor,
            reason_code=reason_code,
            contract_id=contract_id,
            tx_hash=tx_hash,
        )

        return ok_response({"db_event": db_event})

    @app.post("/api/noir/silent-witness")
    @limiter.limit(config.ratelimit_silent_witness)
    @require_capacity(admission_controller)
    @idempotent("silent-witness")
    def silent_witness_proof():
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413
        if not config.noir_worker_enabled:
            return error_response(
                code=NOT_FOUND,
                message="local Noir worker is disabled",
                status=404,
            )

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return error_response(
                code=VALIDATION_ERROR,
                message="JSON body is required",
                status=400,
            )

        video_hash = payload.get("videoHash")
        if not is_hex_32(video_hash):
            return error_response(
                code=VALIDATION_ERROR,
                message="videoHash must be a 32-byte hex string",
                status=400,
            )
        credential_secret = payload.get("credentialSecret")
        nullifier_secret = payload.get("nullifierSecret")
        if not is_field_decimal(credential_secret):
            return error_response(
                code=VALIDATION_ERROR,
                message="credentialSecret must be a decimal field string",
                status=400,
            )
        if not is_field_decimal(nullifier_secret):
            return error_response(
                code=VALIDATION_ERROR,
                message="nullifierSecret must be a decimal field string",
                status=400,
            )

        verifier_scope = payload.get("verifierScope", "0")
        if not is_field_decimal(verifier_scope):
            return jsonify({"error": "verifierScope must be a decimal field string"}), 400
        epoch = payload.get("epoch", 0)
        if not isinstance(epoch, int) or epoch < 0:
            return jsonify({"error": "epoch must be a non-negative integer"}), 400

        try:
            proof = generate_silent_witness(
                video_hash,
                credential_secret,
                nullifier_secret,
                verifier_scope,
                epoch,
            )
        except RuntimeError as exc:
            app.logger.error("Noir proof generation failed: %s", exc, exc_info=True)
            return error_response(
                code=INTERNAL_ERROR,
                message="Noir proof generation failed",
                status=500,
            )

        return jsonify({"job_id": job_id, "status": "pending"}), 202

    @app.get("/api/jobs/<int:job_id>")
    def get_job_status(job_id: int):
        job = get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        return jsonify({"ok": True, "job": public_job_view(job)})

    @app.get("/api/jobs/<int:job_id>/download")
    def download_job_result(job_id: int):
        job = get_job(job_id)
        if not job:
            return jsonify({"error": "Job not found"}), 404
        if job.get("purged"):
            return error_response(
                code=GONE,
                message="Job output has been purged",
                status=410,
            )
        if job["type"] != "embed" or job["status"] != "completed":
            return jsonify({"error": "No output available for download"}), 400
            
        output_path = get_job_output_path(job_id)
        if not output_path.exists():
            return error_response(
                code=GONE,
                message="Job output has been purged",
                status=410,
            )
            
        result = job.get("result", {})
        etag = result.get("embedded_hash")
        if not etag:
            etag = sha256_file(output_path)
            
        response = send_file(
            output_path,
            mimetype="video/mp4",
            as_attachment=True,
            download_name="harpocrates-evidence.mp4",
            conditional=True,
            etag=etag,
        )
        if result.get("source_hash"):
            response.headers["X-Harpocrates-Source-Hash"] = result["source_hash"]
        if result.get("embedded_hash"):
            response.headers["X-Harpocrates-Embedded-Hash"] = result["embedded_hash"]
        if result.get("metadata_hash"):
            response.headers["X-Harpocrates-Metadata-Hash"] = result["metadata_hash"]
        if result.get("db_event"):
            response.headers["X-Harpocrates-Db-Event"] = str(result["db_event"])
            
        return response

    @app.post("/api/jobs/<int:job_id>/cancel")
    def cancel_job_endpoint(job_id: int):
        if cancel_job(job_id):
            return jsonify({"ok": True, "message": "Job cancelled"})
        return jsonify({"error": "Job cannot be cancelled or not found"}), 400

    # Start webhook worker if DB is enabled
    if database_url():
        webhook_worker = WebhookWorker()
        webhook_worker.start()
        app.webhook_worker = webhook_worker

    @app.post("/api/noir/silent-witness/aggregate")
    def silent_witness_aggregate():
        """Generate a bounded aggregated proof for multiple video hashes.

        Accepts up to ``MAX_AGGREGATION_SIZE`` (8) video hashes and produces
        a single UltraHonk proof that covers all of them under the same
        credential identity.

        Request body:
        ```json
        {
            "videoHashes": ["32-byte-hex", ...],  // 1-8 video hashes
            "credentialSecret": "decimal-field",
            "nullifierSecret": "decimal-field"
        }
        ```

        Response (200):
        ```json
        {
            "ok": true,
            "proof": { ... aggregated proof artifacts ... }
        }
        ```
        """
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413
        if not config.noir_worker_enabled:
            return jsonify({"error": "local Noir worker is disabled"}), 404

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON body is required"}), 400

        video_hashes = payload.get("videoHashes")
        if not isinstance(video_hashes, list) or len(video_hashes) == 0:
            return jsonify({"error": "videoHashes must be a non-empty array"}), 400

        if len(video_hashes) > MAX_AGGREGATION_SIZE:
            return jsonify({
                "error": f"videoHashes exceeds maximum aggregation size ({MAX_AGGREGATION_SIZE})"
            }), 400

        for i, video_hash in enumerate(video_hashes):
            if not is_hex_32(video_hash):
                return jsonify({"error": f"videoHashes[{i}] must be a 32-byte hex string"}), 400

        credential_secret = payload.get("credentialSecret")
        nullifier_secret = payload.get("nullifierSecret")
        if not is_field_decimal(credential_secret):
            return jsonify({"error": "credentialSecret must be a decimal field string"}), 400
        if not is_field_decimal(nullifier_secret):
            return jsonify({"error": "nullifierSecret must be a decimal field string"}), 400

        # Redact secrets from logs before calling the generator.
        safe_fields = {
            "event": "aggregate_proof_request",
            "request_id": request_id(),
            "batch_size": len(video_hashes),
        }
        log_structured(LOGGER, logging.INFO, safe_fields)

        try:
            proof = generate_aggregated_proof(
                video_hashes,
                credential_secret,
                nullifier_secret,
            )
        except (ValueError, RuntimeError) as exc:
            return jsonify({"error": str(exc)}), 500

        return jsonify({"ok": True, "proof": proof})

    # -------------------------------------------------------------------
    # Schema discovery and selective disclosure
    # -------------------------------------------------------------------

    @app.get("/api/schemas")
    def list_schemas():
        schemas = discover_schemas()
        hashes = sorted(
            s.get("schemaHash", "")
            for s in schemas
            if isinstance(s, dict) and s.get("schemaHash")
        )
        etag = '"' + hashlib.sha256("".join(hashes).encode()).hexdigest() + '"'
        if request.headers.get("If-None-Match") == etag:
            return "", 304
        response = jsonify({"ok": True, "schemas": schemas})
        response.headers["ETag"] = etag
        return response

    @app.get("/api/schemas/<schema_hash>")
    def get_schema(schema_hash: str):
        if not is_hex_32(schema_hash):
            return jsonify({"error": "schemaHash must be a 32-byte hex string"}), 400
        schema = resolve_schema(schema_hash)
        if schema is None:
            return jsonify({"error": "schema not found"}), 404
        etag = '"' + schema_hash.lower() + '"'
        if request.headers.get("If-None-Match") == etag:
            resp = app.response_class("", status=304)
            resp.headers["ETag"] = etag
            resp.headers["Cache-Control"] = "public, max-age=86400, immutable"
            return resp
        response = jsonify({"ok": True, "schema": schema})
        response.headers["ETag"] = etag
        response.headers["Cache-Control"] = "public, max-age=86400, immutable"
        return response

    @app.post("/api/verify/selective-disclosure")
    def verify_selective_disclosure():
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify({"error": "JSON body is required"}), 400

        err = validate_selective_disclosure_input(payload)
        if err is not None:
            return jsonify({"error": err}), 400

        response = {
            "ok": True,
            "message": "Selective disclosure proof submission accepted.",
            "note": "On-chain verification must be performed via verify_selective_disclosure on the registry contract.",
        }
        receipt_context = payload.get("receiptContext")
        if receipt_context is not None:
            if not isinstance(receipt_context, dict):
                return jsonify({"error": "receiptContext must be a JSON object"}), 400
            try:
                response["verificationReceipt"] = build_verification_receipt(receipt_context)
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400
        return jsonify(response)

    @app.post("/api/capture-attestation/verify")
    @limiter.limit(config.ratelimit_verify)
    def verify_capture_attestation():
        if _enforce_json_size() > config.max_json_bytes:
            return jsonify({"error": "JSON payload exceeds size limit"}), 413

        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return error_response(
                code=VALIDATION_ERROR,
                message="JSON body is required",
                status=400,
                cli_code=MALFORMED_INPUT,
            )

        if "attestation" not in payload or payload["attestation"] is None:
            return error_response(
                code=VALIDATION_ERROR,
                message="attestation is required",
                status=400,
                cli_code=MALFORMED_INPUT,
            )

        attestation_raw = payload["attestation"]
        if not isinstance(attestation_raw, dict):
            return error_response(
                code=VALIDATION_ERROR,
                message="attestation must be a JSON object",
                status=400,
                cli_code=MALFORMED_INPUT,
            )

        evidence_digest = payload.get("evidence_digest")
        if evidence_digest is None:
            evidence_digest = payload.get("evidenceDigest")

        if evidence_digest is None:
            return error_response(
                code=VALIDATION_ERROR,
                message="evidence_digest is required",
                status=400,
                cli_code=MALFORMED_INPUT,
            )

        if not is_hex_32(evidence_digest):
            return error_response(
                code=VALIDATION_ERROR,
                message="evidence_digest must be a 32-byte hex string",
                status=400,
                cli_code=MALFORMED_INPUT,
            )

        device_key = payload.get("device_key")
        if device_key is None:
            device_key = payload.get("deviceKey")

        if device_key is not None and not is_hex_32(device_key):
            return error_response(
                code=VALIDATION_ERROR,
                message="device_key must be a 32-byte hex string",
                status=400,
                cli_code=MALFORMED_INPUT,
            )

        try:
            decoded = decode_attestation(attestation_raw)
        except (ValueError, TypeError, KeyError, AttributeError):
            return error_response(
                code=VALIDATION_ERROR,
                message="malformed attestation payload",
                status=400,
                cli_code=MALFORMED_INPUT,
            )

        try:
            attestation_hash = canonical_attestation_hash(decoded)
        except (ValueError, TypeError):
            return error_response(
                code=VALIDATION_ERROR,
                message="malformed attestation payload",
                status=400,
                cli_code=MALFORMED_INPUT,
            )

        evidence_binding_valid = (
            decoded.evidence_digest_binding.lower() == evidence_digest.lower()
        )
        checks: dict[str, bool] = {
            "evidence_binding": evidence_binding_valid,
        }

        if device_key is not None:
            try:
                checks["device_commitment"] = verify_device_commitment(
                    decoded, bytes.fromhex(device_key)
                )
            except (ValueError, TypeError):
                checks["device_commitment"] = False

        valid = all(checks.values())

        return ok_response(
            {
                "valid": valid,
                "attestation_hash": attestation_hash,
                "checks": checks,
            }
        )

    # -----------------------------------------------------------------------
    # C2PA interoperability
    # -----------------------------------------------------------------------

    @app.post("/api/c2pa/export")
    def c2pa_export():
        """
        Export a C2PA-compatible authenticity manifest from Harpocrates evidence
        digests.

        Request body (JSON):
            video_hash    string  32-byte hex (embedded video hash registered on-chain)
            metadata_hash string  32-byte hex
            proof_id      string  32-byte hex
            tier          string  'silent' | 'source' | 'seal'
            network       string  Stellar network passphrase
            contract_id   string  Soroban registry contract ID
            claim_generator string  Optional override for the C2PA claim_generator field

        Response body (JSON):
            ok            bool    true
            manifest      object  Serialisable C2PA-compatible manifest
            digest        string  SHA-256 of the canonical JSON (for round-trip checks)
            trust_status  string  Always 'signature_not_checked' — C2PA trust is
                                  independent of on-chain / ZK status

        The C2PA trust status is explicitly separate from Harpocrates on-chain or
        ZK verification status.  Callers MUST NOT treat the exported manifest as
        a Harpocrates proof or an on-chain confirmation.
        """
        if not request.is_json:
            return error_response(
                code=VALIDATION_ERROR,
                message="JSON body is required",
                status=400,
            )
        body = request.get_json(silent=True) or {}

        required_fields = ("video_hash", "metadata_hash", "proof_id", "tier", "network", "contract_id")
        for field_name in required_fields:
            if field_name not in body:
                return error_response(
                    code=VALIDATION_ERROR,
                    message=f"missing required field: {field_name}",
                    status=400,
                )

        try:
            exported = export_c2pa_manifest(
                video_hash=body["video_hash"],
                metadata_hash=body["metadata_hash"],
                proof_id=body["proof_id"],
                tier=body["tier"],
                network=body["network"],
                contract_id=body["contract_id"],
                claim_generator=body.get("claim_generator"),
            )
        except ValueError as exc:
            return error_response(
                code=VALIDATION_ERROR,
                message=str(exc),
                status=400,
            )

        return ok_response({
            "manifest": exported.manifest,
            "digest": exported.digest,
            # Explicit trust separation: C2PA export never implies on-chain status.
            "trust_status": C2paTrustStatus.SIGNATURE_NOT_CHECKED.value,
            "note": (
                "C2PA trust status is independent of Harpocrates on-chain and ZK "
                "verification. Do not treat this manifest as a Harpocrates proof."
            ),
        })

    @app.post("/api/c2pa/import")
    def c2pa_import():
        """
        Parse, validate, and corroborate a C2PA-compatible authenticity manifest.

        Request body (JSON):
            manifest  string | object  Raw manifest (JSON string or pre-parsed object)
            expected  object           Optional hashes the caller claims, compared
                                       against the binding embedded in the manifest.
                                       Keys: video_hash, metadata_hash, proof_id,
                                       tier, network, contract_id

        Response body (JSON):
            ok              bool    true
            binding         object  Extracted Harpocrates binding fields
            trust_status    string  'signature_not_checked' — always; see note
            hashes_verified bool    true only when *expected* was supplied and every
                                    supplied field matched the embedded binding
            hashes_compared list    Field names actually compared ([] when no
                                    *expected* was supplied)
            unknown_assertions  list  Assertions not recognised by this version
                                      (unsupported_semantics: true)
            note            string  Trust model clarification

        The binding is embedded twice (named assertion and top-level object); a
        manifest whose two copies disagree is rejected rather than resolved in
        favour of one of them.  When *expected* is supplied, a submitted value
        that disagrees with the embedded binding is rejected with
        VALIDATION_ERROR carrying the offending field *name* only.

        The trust_status is always 'signature_not_checked'.  C2PA signature
        verification is out of scope, and a matching *expected* block is
        integrity corroboration only — never an on-chain or ZK verification.
        The extracted binding must still be corroborated against on-chain
        records before any trust decision is made.
        """
        if not request.is_json:
            return error_response(
                code=VALIDATION_ERROR,
                message="JSON body is required",
                status=400,
            )
        body = request.get_json(silent=True) or {}

        if "manifest" not in body:
            return error_response(
                code=VALIDATION_ERROR,
                message="missing required field: manifest",
                status=400,
            )

        manifest_raw = body["manifest"]
        # Accept either a pre-parsed object or a raw JSON string.
        if isinstance(manifest_raw, dict):
            try:
                import json as _json
                manifest_bytes = _json.dumps(manifest_raw, separators=(",", ":")).encode("utf-8")
            except (TypeError, ValueError):
                return error_response(
                    code=VALIDATION_ERROR,
                    message="manifest object could not be serialised",
                    status=400,
                )
        elif isinstance(manifest_raw, str):
            manifest_bytes = manifest_raw.encode("utf-8")
        else:
            return error_response(
                code=VALIDATION_ERROR,
                message="manifest must be a JSON object or string",
                status=400,
            )

        try:
            parsed = parse_c2pa_manifest(manifest_bytes)
        except C2paParseError as exc:
            # Privacy-safe: only the reason code and optional field name are returned.
            err_payload = exc.to_dict()
            return error_response(
                code=VALIDATION_ERROR,
                message=f"C2PA manifest parse failed: {err_payload['reason']}"
                        + (f" (field: {err_payload['field']})" if err_payload.get("field") else ""),
                status=400,
            )

        binding = parsed.binding

        # Submitted-vs-embedded verification. When the caller states which
        # evidence it is asking about, the manifest's embedded binding must
        # describe that same evidence; otherwise a validly-exported manifest for
        # a different video would be accepted here.
        expected = body.get("expected")
        if expected is not None and not isinstance(expected, dict):
            return error_response(
                code=VALIDATION_ERROR,
                message="expected must be a JSON object of submitted hashes",
                status=400,
            )

        corroboration = None
        if expected is not None:
            try:
                corroboration = corroborate_binding(
                    parsed,
                    video_hash=expected.get("video_hash"),
                    metadata_hash=expected.get("metadata_hash"),
                    proof_id=expected.get("proof_id"),
                    tier=expected.get("tier"),
                    network=expected.get("network"),
                    contract_id=expected.get("contract_id"),
                )
            except ValueError as exc:
                # _validate_hex32/field checks emit the field name and static
                # text only — never a submitted value.
                return error_response(
                    code=VALIDATION_ERROR,
                    message=str(exc),
                    status=400,
                )

            if not corroboration.ok:
                return error_response(
                    code=VALIDATION_ERROR,
                    message=(
                        "submitted hashes do not match the embedded C2PA binding: "
                        + ", ".join(corroboration.mismatches)
                    ),
                    status=400,
                    field=corroboration.mismatches[0],
                )

        unknown = [
            {
                "label": ua.label,
                "unsupported_semantics": ua.unsupported_semantics,
            }
            for ua in parsed.unknown_assertions
        ]

        return ok_response({
            "binding": {
                "mapping_version": binding.mapping_version,
                "video_hash": binding.video_hash,
                "metadata_hash": binding.metadata_hash,
                "proof_id": binding.proof_id,
                "tier": binding.tier,
                "network": binding.network,
                "contract_id": binding.contract_id,
            },
            "trust_status": parsed.trust_status.value,
            # True only when the caller supplied hashes AND all of them matched.
            "hashes_verified": bool(corroboration is not None and corroboration.ok),
            "hashes_compared": list(corroboration.compared_fields) if corroboration else [],
            "unknown_assertions": unknown,
            "note": (
                "C2PA trust status is independent of Harpocrates on-chain and ZK "
                "verification. A matching 'expected' block is integrity "
                "corroboration only. Corroborate this binding against on-chain "
                "records before making any trust decision."
            ),
        })

    return app


def request_id() -> str:
    return getattr(g, "request_id", "unknown")


def request_route() -> str:
    return request.url_rule.rule if request.url_rule else request.path


def request_duration_ms() -> float:
    started_at = getattr(g, "request_started_at", None)
    if started_at is None:
        return 0.0
    return round((time.perf_counter() - started_at) * 1000, 2)


def log_error_response(status: int) -> None:
    log_structured(
        LOGGER,
        logging.ERROR,
        merge_trace_into_event(
            {
                "event": "error",
                "request_id": request_id(),
                "method": request.method,
                "route": request_route(),
                "path": request.path,
                "status": status,
                "duration_ms": request_duration_ms(),
            },
            current_trace_fields(),
        ),
    )


def current_trace_fields() -> dict:
    fields = getattr(g, "trace_fields", None)
    if isinstance(fields, dict):
        return fields
    return build_trace_fields(
        getattr(request, "headers", None),
        request_id=request_id(),
        method=getattr(request, "method", None),
        route=request_route() if request else None,
        path=getattr(request, "path", None),
    )


def is_hex_32(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


# Fields of an internal job record that GET /api/jobs/<id> never returns:
# ``payload`` carries request inputs (filenames, metadata, proof secrets) and
# underscore-prefixed keys are internal bookkeeping (trace links, throttle state).
JOB_PRIVATE_FIELDS = frozenset({"payload"})


def public_job_view(job: dict) -> dict:
    """Public shape of a job for ``GET /api/jobs/<id>``.

    Always includes ``progress``: ``{"phase": str, "percent": float | None}``
    while a processor reports it, otherwise ``null``.
    """
    view = {
        key: value
        for key, value in job.items()
        if key not in JOB_PRIVATE_FIELDS and not str(key).startswith("_")
    }
    progress = job.get("progress")
    if isinstance(progress, dict) and isinstance(progress.get("phase"), str):
        view["progress"] = {"phase": progress["phase"], "percent": progress.get("percent")}
    else:
        view["progress"] = None
    return view


def normalize_tx_hash(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("txHash must be a 32-byte hex string")

    normalized = value.strip().lower()
    if not is_hex_32(normalized):
        raise ValueError("txHash must be a 32-byte hex string")
    return normalized


def normalize_tx_status(value: object) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError("txStatus must be one of: pending, confirmed, failed, missing")

    normalized = value.strip().lower()
    if normalized in {"pending", "confirmed", "failed", "missing"}:
        return normalized
    if normalized in {"success", "successful", "succeeded"}:
        return "confirmed"
    if normalized in {"failure", "failed", "error", "errored"}:
        return "failed"
    if normalized in {"not_found", "notfound"}:
        return "missing"
    raise ValueError("txStatus must be one of: pending, confirmed, failed, missing")


def is_field_decimal(value: object) -> bool:
    if not isinstance(value, str) or not value or not value.isdecimal():
        return False
    field_modulus = (
        21888242871839275222246405745257275088548364400416034343698204186575808495617
    )
    return 0 < int(value) < field_modulus


def validate_video_upload(video) -> None:
    """Validate an uploaded video *before* it is saved to disk or handed to ffmpeg.

    Checks (in order):
    1. Filename is present.
    2. Declared ``Content-Type`` is in the ``video/*`` family or the generic
       ``application/octet-stream`` wildcard.
    3. **Media-type sniff** — reads the first 32 bytes of the upload stream and
       verifies that a recognised video magic signature is present and consistent
       with both the filename extension and the declared content type.  The stream
       is rewound to offset 0 after the read so subsequent ``save()`` calls are
       unaffected.

    Raises :class:`QuarantineError` (a ``ValueError`` subclass) on any failure so
    the existing ``except ValueError`` / ``except QuarantineError`` call sites keep
    working unchanged.
    """
    if not video.filename:
        raise ValueError("video filename is required")

    content_type = (video.content_type or "").lower()
    if content_type and not content_type.startswith("video/") and content_type != "application/octet-stream":
        raise QuarantineError("video upload must use a video/* or application/octet-stream content type")

    # Stream-level magic-byte sniff: detects mismatches between declared type
    # and actual file contents before the file is persisted anywhere.
    stream = getattr(video, "stream", None)
    if stream is None:
        # Fallback for duck-typed objects (e.g. test stubs) that expose .read()
        stream = video
    sniff_media_type_stream(
        stream,
        filename=video.filename,
        content_type=video.content_type,
    )




def normalize_filename(value: object) -> str | None:
    """Return a normalized, filesystem-safe version of an uploaded filename.

    Processing steps (in order):
    1. Reject non-string or blank input → ``None``.
    2. ``werkzeug.utils.secure_filename`` — strips path separators, null bytes,
       and non-ASCII characters, reducing the name to ASCII-safe characters.
    3. Lowercase the entire name so that ``My_Video.MP4`` and
       ``my_video.mp4`` are treated identically in the database.
    4. Split on the last ``.`` to isolate the stem and extension, then
       collapse runs of whitespace, underscores, and hyphens in the stem
       into a single ``_``, and strip leading/trailing ``_`` and ``-``.
    5. Reassemble ``stem.ext`` (or just ``stem`` if there was no extension).
    6. Hard-cap at 160 characters.
    """
    if not isinstance(value, str) or not value.strip():
        return None

    # Step 2: strip path traversal, null bytes, non-ASCII
    sanitized = secure_filename(value)
    if not sanitized:
        return None

    # Step 3: lowercase
    sanitized = sanitized.lower()

    # Step 4-5: normalize separators in the stem only
    if "." in sanitized:
        dot = sanitized.rfind(".")
        stem, ext = sanitized[:dot], sanitized[dot:]  # ext includes the leading dot
    else:
        stem, ext = sanitized, ""

    stem = re.sub(r"[\s_\-]+", "_", stem).strip("_-")
    if not stem:
        return None

    normalized = stem + ext

    # Step 6: cap length
    return normalized[:160]


# Keep a backward-compatible alias so external callers (worker.py, tests)
# that already import ``safe_filename`` continue to work unchanged.
safe_filename = normalize_filename


def redact_metadata(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    return redact_sensitive(value)


def video_tooling_ready() -> bool:
    try:
        from stego import _require

        _require("ffmpeg")
        _require("ffprobe")
    except RuntimeError:
        return False
    return True


app = create_app()


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5050")), debug=debug)
