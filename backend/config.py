from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone

from register_auth import ScopedKey, parse_scoped_keys


@dataclass(frozen=True)
class AppConfig:
    app_env: str
    def redacted_summary(self) -> dict[str, any]:
        """Return a dict representation of the config where secret fields are redacted.
        Secret fields (API keys, endpoints, tokens) are replaced with a boolean indicating
        presence (True if set, False otherwise). Non‑secret fields retain their original
        values.
        """
        from dataclasses import asdict
        secret_fields = {
            "metrics_token",
            "tracing_endpoint",
            "register_api_key",
            "register_api_key_previous",
        }
        raw = asdict(self)
        for field in secret_fields:
            if field in raw:
                raw[field] = raw[field] is not None
        return raw
    cors_origins: list[str]
    max_content_length: int
    max_video_bytes: int
    max_json_bytes: int
    max_metadata_bytes: int
    expose_metadata_header: bool
    noir_worker_enabled: bool
    security_headers_enabled: bool
    ratelimit_enabled: bool
    trusted_proxies: list[str]
    ratelimit_embed: str
    ratelimit_extract: str
    ratelimit_silent_witness: str
    ratelimit_register: str
    ratelimit_upload_session: str
    ratelimit_upload_chunk: str
    ratelimit_verify: str
    release_id: str
    release_network: str
    metrics_enabled: bool
    metrics_token: str | None
    metrics_path: str
    tracing_enabled: bool
    tracing_service_name: str
    tracing_endpoint: str | None
    tracing_sample_ratio: float
    tracing_export_timeout_seconds: float
    register_api_key: str | None
    register_api_key_expires: datetime | None
    register_api_key_previous: str | None
    register_api_key_previous_expires: datetime | None
    retention_worker_enabled: bool
    retention_interval_seconds: int
    retention_batch_size: int
    retention_classes: dict[str, int]
    max_concurrent_requests: int
    max_queue_size: int
    max_concurrent_per_identity: int
    admission_timeout_seconds: float
    verifier_cache_max_size: int
    verifier_cache_positive_ttl_seconds: float
    verifier_cache_negative_ttl_seconds: float
    # External evidence fetch safety bounds
    external_fetch_connect_timeout_seconds: float
    external_fetch_read_timeout_seconds: float
    external_fetch_max_response_bytes: int
    # Owner-scoped credentials: each key may only register its own sourceAddress.
    register_scoped_keys: tuple[ScopedKey, ...] = ()
    job_file_ttl_seconds: int = 86_400
    retention_blob_gc_enabled: bool = False
    retention_unreferenced_blobs_enabled: bool = False



def load_config() -> AppConfig:
    app_env = os.getenv("APP_ENV", "development").strip().lower()
    cors_origins = _csv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    if "*" in cors_origins:
        if app_env == "production":
            raise RuntimeError("Wildcard CORS origins are not permitted in production")
        if os.getenv("ALLOW_WILDCARD_CORS") != "true":
            raise RuntimeError("Wildcard CORS requires ALLOW_WILDCARD_CORS=true")

    register_api_key = _api_key_env("REGISTER_API_KEY")
    register_api_key_expires = _datetime_env("REGISTER_API_KEY_EXPIRES")
    register_api_key_previous = _api_key_env("REGISTER_API_KEY_PREVIOUS")
    register_api_key_previous_expires = _datetime_env("REGISTER_API_KEY_PREVIOUS_EXPIRES")
    if register_api_key_previous is not None and register_api_key is None:
        raise RuntimeError("REGISTER_API_KEY is required when REGISTER_API_KEY_PREVIOUS is set")
    if register_api_key_previous_expires is not None and register_api_key_previous is None:
        raise RuntimeError(
            "REGISTER_API_KEY_PREVIOUS is required when REGISTER_API_KEY_PREVIOUS_EXPIRES is set"
        )

    return AppConfig(
        app_env=app_env,
        cors_origins=cors_origins,
        max_content_length=_int_env("MAX_CONTENT_LENGTH", 314_572_800),
        max_video_bytes=_int_env("MAX_VIDEO_BYTES", 262_144_000),
        max_json_bytes=_int_env("MAX_JSON_BYTES", 1_048_576),
        max_metadata_bytes=_int_env("MAX_METADATA_BYTES", 16_384),
        expose_metadata_header=_bool_env("EXPOSE_METADATA_HEADER", False),
        noir_worker_enabled=_bool_env("NOIR_WORKER_ENABLED", app_env != "production"),
        security_headers_enabled=_bool_env("SECURITY_HEADERS_ENABLED", True),
        ratelimit_enabled=_bool_env("RATELIMIT_ENABLED", True),
        # Real client IP resolution behind proxies; empty list trusts no proxy.
        trusted_proxies=_csv("TRUSTED_PROXIES", ""),
        # Per-client rate limits (flask-limiter "N per <window>" strings).
        ratelimit_embed=_str_env("RATELIMIT_EMBED") or "30 per minute",
        ratelimit_extract=_str_env("RATELIMIT_EXTRACT") or "30 per minute",
        ratelimit_silent_witness=_str_env("RATELIMIT_SILENT_WITNESS") or "20 per minute",
        ratelimit_register=_str_env("RATELIMIT_REGISTER") or "30 per minute",
        ratelimit_upload_session=_str_env("RATELIMIT_UPLOAD_SESSION") or "60 per minute",
        ratelimit_upload_chunk=_str_env("RATELIMIT_UPLOAD_CHUNK") or "240 per minute",
        ratelimit_verify=_str_env("RATELIMIT_VERIFY") or "30 per minute",
        release_id=_release_id(os.getenv("HARPOCRATES_RELEASE_ID", "harpocrates-1.0.0")),
        release_network=_release_network(os.getenv("HARPOCRATES_RELEASE_NETWORK", "testnet")),
        metrics_enabled=_bool_env("METRICS_ENABLED", True),
        metrics_token=_str_env("METRICS_TOKEN"),
        metrics_path=os.getenv("METRICS_PATH", "/metrics").strip(),
        tracing_enabled=_bool_env("OTEL_ENABLED", False),
        tracing_service_name=_str_env("OTEL_SERVICE_NAME") or "harpocrates-backend",
        tracing_endpoint=_str_env("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
        tracing_sample_ratio=_sample_ratio_env("OTEL_TRACES_SAMPLER_ARG", 0.1),
        tracing_export_timeout_seconds=_float_env("OTEL_EXPORT_TIMEOUT_SECONDS", 5.0),
        register_api_key=register_api_key,
        register_api_key_expires=register_api_key_expires,
        register_api_key_previous=register_api_key_previous,
        register_api_key_previous_expires=register_api_key_previous_expires,
        retention_worker_enabled=_bool_env("RETENTION_WORKER_ENABLED", False),
        retention_interval_seconds=_int_env("RETENTION_INTERVAL_SECONDS", 3600),
        retention_batch_size=_retention_batch_size_env(),
        retention_classes={"default": 30, "short": 7, "long": 365},
        max_concurrent_requests=_int_env("MAX_CONCURRENT_REQUESTS", 50),
        max_queue_size=_int_env("MAX_QUEUE_SIZE", 100),
        max_concurrent_per_identity=_int_env("MAX_CONCURRENT_PER_IDENTITY", 5),
        admission_timeout_seconds=_float_env("ADMISSION_TIMEOUT_SECONDS", 5.0),
        verifier_cache_max_size=_int_env("VERIFIER_CACHE_MAX_SIZE", 10000),
        verifier_cache_positive_ttl_seconds=_float_env("VERIFIER_CACHE_POSITIVE_TTL_SECONDS", 86400.0),
        verifier_cache_negative_ttl_seconds=_float_env("VERIFIER_CACHE_NEGATIVE_TTL_SECONDS", 300.0),
        external_fetch_connect_timeout_seconds=_float_env("EXTERNAL_FETCH_CONNECT_TIMEOUT_SECONDS", 5.0),
        external_fetch_read_timeout_seconds=_float_env("EXTERNAL_FETCH_READ_TIMEOUT_SECONDS", 10.0),
        external_fetch_max_response_bytes=_int_env("EXTERNAL_FETCH_MAX_RESPONSE_BYTES", 65_536),
        register_scoped_keys=parse_scoped_keys(_str_env("REGISTER_SCOPED_KEYS")),
        job_file_ttl_seconds=_job_file_ttl_env(),
        retention_blob_gc_enabled=_blob_gc_enabled_env(),
        retention_unreferenced_blobs_enabled=_blob_gc_enabled_env(),
    )



def _upload_chunk_bytes() -> int:
    """Load UPLOAD_CHUNK_BYTES clamped into the supported streaming range."""
    raw = os.getenv("UPLOAD_CHUNK_BYTES")
    if raw is None or not raw.strip():
        return 65_536
    parsed = int(raw)
    if parsed < 4_096:
        return 4_096
    if parsed > 1_048_576:
        return 1_048_576
    return parsed


def _csv(name: str, default: str) -> list[str]:
    value = os.getenv(name, default)
    return [item.strip() for item in value.split(",") if item.strip()]


def _int_env(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    parsed = int(value)
    if parsed <= 0:
        raise RuntimeError(f"{name} must be positive")
    return parsed


def _bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _release_id(value: str) -> str:
    if value != "harpocrates-1.0.0":
        raise RuntimeError("HARPOCRATES_RELEASE_ID is not a supported compatibility release")
    return value


def _release_network(value: str) -> str:
    if value not in {"local", "testnet", "mainnet"}:
        raise RuntimeError("HARPOCRATES_RELEASE_NETWORK must be local, testnet, or mainnet")
    return value


def _str_env(name: str) -> str | None:
    value = os.getenv(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def _api_key_env(name: str) -> str | None:
    """Load an API key without ever exposing its value in a config error."""
    value = _str_env(name)
    if value is None:
        return None
    if len(value) > 4096:
        raise RuntimeError(f"{name} is too long")
    return value


def _datetime_env(name: str) -> datetime | None:
    """Parse an optional UTC expiry, accepting ISO-8601 ``Z`` timestamps."""
    value = _str_env(name)
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise RuntimeError(f"{name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _float_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    parsed = float(value)
    if parsed <= 0.0:
        raise RuntimeError(f"{name} must be positive")
    return parsed


def _sample_ratio_env(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be between 0 and 1") from exc
    if not 0.0 <= parsed <= 1.0:
        raise RuntimeError(f"{name} must be between 0 and 1")
    return parsed


# Retention worker batch bounds. The upper bound must match
# db.RETENTION_BATCH_MAX_SIZE, which clamps the value again at the SQL layer.
RETENTION_BATCH_SIZE_DEFAULT = 100
RETENTION_BATCH_SIZE_MAX = 5000


def _retention_batch_size_env(name: str = "HARPOCRATES_RETENTION_BATCH_SIZE", default: int = RETENTION_BATCH_SIZE_DEFAULT) -> int:
    """Load HARPOCRATES_RETENTION_BATCH_SIZE clamped to the 1..5000 range."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        parsed = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    return max(1, min(parsed, RETENTION_BATCH_SIZE_MAX))


JOB_FILE_TTL_SECONDS_DEFAULT = 86_400


def _job_file_ttl_env(
    name: str = "HARPOCRATES_JOB_FILE_TTL_SECONDS",
    default: int = JOB_FILE_TTL_SECONDS_DEFAULT,
) -> int:
    """Load HARPOCRATES_JOB_FILE_TTL_SECONDS (default 24h = 86400s)."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        parsed = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if parsed < 0:
        raise RuntimeError(f"{name} must be non-negative")
    return parsed


def _blob_gc_enabled_env() -> bool:
    """Return whether blob garbage collection is enabled in retention worker."""
    for var in (
        "RETENTION_BLOB_GC_ENABLED",
        "HARPOCRATES_RETENTION_BLOB_GC_ENABLED",
        "RETENTION_UNREFERENCED_BLOBS_ENABLED",
        "HARPOCRATES_RETENTION_UNREFERENCED_BLOBS_ENABLED",
    ):
        val = os.getenv(var)
        if val is not None:
            return val.strip().lower() in {"1", "true", "yes", "on"}
    return False

