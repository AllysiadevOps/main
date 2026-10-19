from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Callable, Dict, List, Tuple

logger = logging.getLogger(__name__)

# Default latency histogram buckets in seconds
LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, float("inf"))

# Bounded upload size histogram buckets in bytes (1KB, 64KB, 1MB, 10MB, 100MB, 256MB, +Inf)
UPLOAD_SIZE_BUCKETS = (1024, 65536, 1048576, 10485760, 104857600, 262144000, float("inf"))


class MetricsCollector:
    """Thread-safe collector for privacy-safe HTTP service metrics in Prometheus format."""

    def __init__(self, job_refresh_interval: float | None = None) -> None:
        self._lock = threading.Lock()
        self._requests_total: Dict[Tuple[str, str, str], int] = {}
        self._latency_histogram: Dict[Tuple[str, str, str], Dict[str, float]] = {}
        self._upload_histogram: Dict[Tuple[str, str], Dict[str, float]] = {}
        self._rejections_total: Dict[Tuple[str, str], int] = {}
        self._dependency_status: Dict[Tuple[str, str, str], int] = {}
        
        # Verifier cache metrics
        self._cache_hits = 0
        self._cache_misses = 0
        self._cache_evictions = 0
        self._deleted_events = 0

        # Job queue backlog metrics (refreshed at most every N seconds)
        self._job_refresh_interval = (
            float(os.getenv("HARPOCRATES_METRICS_JOB_REFRESH_SECONDS", "15.0"))
            if job_refresh_interval is None
            else float(job_refresh_interval)
        )
        self._last_job_refresh: float = 0.0
        self._cached_job_counts: Dict[Tuple[str, str], int] = {}
        self._cached_oldest_queued: Dict[str, float] = {}
        self._job_metrics_fn: Callable[[], dict[str, Any]] | None = None

    def reset(self) -> None:
        """Reset all metrics to clean state (primarily for unit testing)."""
        with self._lock:
            self._requests_total.clear()
            self._latency_histogram.clear()
            self._upload_histogram.clear()
            self._rejections_total.clear()
            self._dependency_status.clear()
            self._cache_hits = 0
            self._cache_misses = 0
            self._cache_evictions = 0
            self._deleted_events = 0
            self._last_job_refresh = 0.0
            self._cached_job_counts.clear()
            self._cached_oldest_queued.clear()

    def set_job_metrics_fn(self, fn: Callable[[], dict[str, Any]] | None) -> None:
        """Set a custom function to fetch job queue metrics (primarily for unit testing)."""
        with self._lock:
            self._job_metrics_fn = fn

    def _fetch_job_metrics(self) -> dict[str, Any]:
        if self._job_metrics_fn is not None:
            return self._job_metrics_fn()
        fn = globals().get("get_job_queue_metrics")
        if callable(fn) and fn is not _default_get_job_queue_metrics:
            return fn()
        try:
            import db
            if hasattr(db, "get_job_queue_metrics"):
                return db.get_job_queue_metrics()
            if hasattr(db, "get_job_metrics"):
                return db.get_job_metrics()
        except Exception as exc:
            logger.warning("Failed to fetch job queue metrics: %s", exc)
        return {"counts": {}, "oldest_queued_seconds": {}}

    def _parse_job_metrics(
        self, data: Any
    ) -> Tuple[Dict[Tuple[str, str], int], Dict[str, float]]:
        counts: Dict[Tuple[str, str], int] = {}
        oldest_queued: Dict[str, float] = {}

        if not data:
            return counts, oldest_queued

        if isinstance(data, dict):
            raw_counts = data.get("counts", {})
            if isinstance(raw_counts, dict):
                for k, v in raw_counts.items():
                    if isinstance(k, tuple) and len(k) == 2:
                        t, s = str(k[0])[:64], str(k[1])[:64]
                        counts[(t, s)] = int(v)
                    elif isinstance(k, str) and isinstance(v, dict):
                        for s_k, s_v in v.items():
                            counts[(k[:64], str(s_k)[:64])] = int(s_v)
            elif isinstance(raw_counts, list):
                for item in raw_counts:
                    if isinstance(item, dict):
                        t = str(item.get("type", ""))[:64]
                        s = str(item.get("state") or item.get("status", ""))[:64]
                        c = int(item.get("count", 0))
                        if t and s:
                            counts[(t, s)] = c

            raw_oldest = data.get("oldest_queued_seconds") or data.get("oldest_queued", {})
            if isinstance(raw_oldest, dict):
                for k, v in raw_oldest.items():
                    if v is not None:
                        oldest_queued[str(k)[:64]] = max(0.0, float(v))
            elif isinstance(raw_oldest, list):
                for item in raw_oldest:
                    if isinstance(item, dict):
                        t = str(item.get("type", ""))[:64]
                        v = item.get("oldest_queued_seconds") or item.get("seconds")
                        if t and v is not None:
                            oldest_queued[t] = max(0.0, float(v))
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    t = str(item.get("type", ""))[:64]
                    s = str(item.get("state") or item.get("status", ""))[:64]
                    c = int(item.get("count", 0))
                    if t and s:
                        counts[(t, s)] = c
                    v = item.get("oldest_queued_seconds")
                    if t and v is not None:
                        oldest_queued[t] = max(0.0, float(v))

        return counts, oldest_queued

    def record_request(
        self,
        method: str,
        endpoint: str,
        status: int,
        duration_seconds: float,
        upload_bytes: int | None = None,
    ) -> None:
        """Record request count, duration, and optional upload size.

        Guarantees: All labels are limited to HTTP method, URL rule/endpoint pattern,
        and HTTP status code. No filenames, hashes, addresses, proof data, or secrets are recorded.
        """
        clean_method = (method or "UNKNOWN").upper()
        clean_endpoint = endpoint if endpoint else "unmatched"
        status_str = str(status)

        with self._lock:
            # Update request total counter
            counter_key = (clean_method, clean_endpoint, status_str)
            self._requests_total[counter_key] = self._requests_total.get(counter_key, 0) + 1

            # Update latency histogram
            lat_key = counter_key
            if lat_key not in self._latency_histogram:
                lat_entry = {f"le_{b}": 0.0 for b in LATENCY_BUCKETS}
                lat_entry["sum"] = 0.0
                lat_entry["count"] = 0.0
                self._latency_histogram[lat_key] = lat_entry

            lat_stats = self._latency_histogram[lat_key]
            lat_stats["sum"] += max(0.0, float(duration_seconds))
            lat_stats["count"] += 1.0
            for bucket in LATENCY_BUCKETS:
                if duration_seconds <= bucket:
                    lat_stats[f"le_{bucket}"] += 1.0

            # Update upload size histogram if content is uploaded
            if upload_bytes is not None and upload_bytes > 0:
                upload_key = (clean_method, clean_endpoint)
                if upload_key not in self._upload_histogram:
                    up_entry = {f"le_{b}": 0.0 for b in UPLOAD_SIZE_BUCKETS}
                    up_entry["sum"] = 0.0
                    up_entry["count"] = 0.0
                    self._upload_histogram[upload_key] = up_entry

                up_stats = self._upload_histogram[upload_key]
                up_stats["sum"] += float(upload_bytes)
                up_stats["count"] += 1.0
                for bucket in UPLOAD_SIZE_BUCKETS:
                    if upload_bytes <= bucket:
                        up_stats[f"le_{bucket}"] += 1.0

    def record_rejection(self, reason: str, endpoint: str) -> None:
        """Record a rejected request due to admission control."""
        clean_endpoint = endpoint if endpoint else "unmatched"
        clean_reason = reason or "unknown"
        with self._lock:
            key = (clean_reason, clean_endpoint)
            self._rejections_total[key] = self._rejections_total.get(key, 0) + 1

    def record_cache_hit(self) -> None:
        """Record a verifier cache hit."""
        with self._lock:
            self._cache_hits += 1

    def record_cache_miss(self) -> None:
        """Record a verifier cache miss."""
        with self._lock:
            self._cache_misses += 1

    def record_cache_eviction(self) -> None:
        """Record a verifier cache eviction."""
        with self._lock:
            self._cache_evictions += 1

    def record_deleted_event(self) -> None:
        """Record a proof event removed by the retention worker."""
        with self._lock:
            self._deleted_events += 1

    def record_dependency_status(self, name: str, status: str, critical: bool) -> None:
        """Record the latest bounded readiness state for one dependency."""
        clean_name = (name or "unknown").strip() or "unknown"
        clean_status = (status or "unknown").strip() or "unknown"
        critical_label = "true" if critical else "false"
        with self._lock:
            for key in tuple(self._dependency_status):
                if key[0] == clean_name:
                    del self._dependency_status[key]
            self._dependency_status[(clean_name, clean_status, critical_label)] = 1

    def generate_prometheus_metrics(self, force_refresh_jobs: bool = False) -> str:
        """Format metrics into Prometheus text format (version 0.0.4)."""
        lines: List[str] = []

        with self._lock:
            # 1. Request total counter
            lines.append("# HELP harpocrates_requests_total Total count of HTTP requests processed.")
            lines.append("# TYPE harpocrates_requests_total counter")
            for (method, endpoint, status), count in sorted(self._requests_total.items()):
                lines.append(
                    f'harpocrates_requests_total{{endpoint="{_escape_label(endpoint)}",'
                    f'method="{_escape_label(method)}",status="{_escape_label(status)}"}} {count}'
                )

            # 2. Latency histogram
            lines.append("")
            lines.append("# HELP harpocrates_request_duration_seconds HTTP request latency in seconds.")
            lines.append("# TYPE harpocrates_request_duration_seconds histogram")
            for (method, endpoint, status), stats in sorted(self._latency_histogram.items()):
                esc_endpoint = _escape_label(endpoint)
                esc_method = _escape_label(method)
                esc_status = _escape_label(status)
                label_prefix = f'endpoint="{esc_endpoint}",method="{esc_method}",status="{esc_status}"'

                for bucket in LATENCY_BUCKETS:
                    le_str = "+Inf" if bucket == float("inf") else _format_float(bucket)
                    bucket_count = int(stats[f"le_{bucket}"])
                    lines.append(f'harpocrates_request_duration_seconds_bucket{{{label_prefix},le="{le_str}"}} {bucket_count}')

                lines.append(f'harpocrates_request_duration_seconds_sum{{{label_prefix}}} {_format_float(stats["sum"])}')
                lines.append(f'harpocrates_request_duration_seconds_count{{{label_prefix}}} {int(stats["count"])}')

            # 3. Upload size histogram
            lines.append("")
            lines.append("# HELP harpocrates_upload_bytes_total Bounded request upload size in bytes.")
            lines.append("# TYPE harpocrates_upload_bytes_total histogram")
            for (method, endpoint), stats in sorted(self._upload_histogram.items()):
                esc_endpoint = _escape_label(endpoint)
                esc_method = _escape_label(method)
                label_prefix = f'endpoint="{esc_endpoint}",method="{esc_method}"'

                for bucket in UPLOAD_SIZE_BUCKETS:
                    le_str = "+Inf" if bucket == float("inf") else _format_float(bucket)
                    bucket_count = int(stats[f"le_{bucket}"])
                    lines.append(f'harpocrates_upload_bytes_total_bucket{{{label_prefix},le="{le_str}"}} {bucket_count}')

                lines.append(f'harpocrates_upload_bytes_total_sum{{{label_prefix}}} {_format_float(stats["sum"])}')
                lines.append(f'harpocrates_upload_bytes_total_count{{{label_prefix}}} {int(stats["count"])}')

            # 4. Rejections total counter
            if self._rejections_total:
                lines.append("")
                lines.append("# HELP harpocrates_admission_rejected_total Total count of requests rejected by admission control.")
                lines.append("# TYPE harpocrates_admission_rejected_total counter")
                for (reason, endpoint), count in sorted(self._rejections_total.items()):
                    lines.append(
                        f'harpocrates_admission_rejected_total{{endpoint="{_escape_label(endpoint)}",'
                        f'reason="{_escape_label(reason)}"}} {count}'
                    )

            lines.append("")
            lines.append("# HELP harpocrates_dependency_up Whether the latest dependency probe succeeded.")
            lines.append("# TYPE harpocrates_dependency_up gauge")
            lines.append("# HELP harpocrates_dependency_status Latest bounded dependency probe status.")
            lines.append("# TYPE harpocrates_dependency_status gauge")
            for (name, status, critical), value in sorted(self._dependency_status.items()):
                labels = f'dependency="{_escape_label(name)}",critical="{critical}"'
                up = 0 if status in {"disconnected", "missing", "error", "initializing", "not_configured"} else 1
                lines.append(f"harpocrates_dependency_up{{{labels}}} {up}")
                lines.append(
                    f'harpocrates_dependency_status{{{labels},status="{_escape_label(status)}"}} {value}'
                )

            # 6. Verifier cache metrics
            lines.append("")
            lines.append("# HELP harpocrates_verifier_cache_hits_total Total count of verifier cache hits.")
            lines.append("# TYPE harpocrates_verifier_cache_hits_total counter")
            lines.append(f"harpocrates_verifier_cache_hits_total {self._cache_hits}")
            
            lines.append("")
            lines.append("# HELP harpocrates_verifier_cache_misses_total Total count of verifier cache misses.")
            lines.append("# TYPE harpocrates_verifier_cache_misses_total counter")
            lines.append(f"harpocrates_verifier_cache_misses_total {self._cache_misses}")
            
            lines.append("")
            lines.append("# HELP harpocrates_verifier_cache_evictions_total Total count of verifier cache evictions.")
            lines.append("# TYPE harpocrates_verifier_cache_evictions_total counter")
            lines.append(f"harpocrates_verifier_cache_evictions_total {self._cache_evictions}")

            lines.append("")
            lines.append("# HELP harpocrates_retention_deleted_events_total Total proof events removed by retention.")
            lines.append("# TYPE harpocrates_retention_deleted_events_total counter")
            lines.append(f"harpocrates_retention_deleted_events_total {self._deleted_events}")

            # 8. Job queue backlog and oldest-job age gauges (refreshed at most every N seconds)
            now = time.monotonic()
            if force_refresh_jobs or (now - self._last_job_refresh >= self._job_refresh_interval):
                try:
                    data = self._fetch_job_metrics()
                    self._cached_job_counts, self._cached_oldest_queued = self._parse_job_metrics(data)
                    self._last_job_refresh = now
                except Exception as exc:
                    logger.warning("Failed to refresh job queue metrics: %s", exc)

            if self._cached_job_counts:
                lines.append("")
                lines.append("# HELP harpocrates_jobs Number of jobs by type and state.")
                lines.append("# TYPE harpocrates_jobs gauge")
                for (job_type, state), count in sorted(self._cached_job_counts.items()):
                    lines.append(
                        f'harpocrates_jobs{{type="{_escape_label(job_type)}",'
                        f'state="{_escape_label(state)}"}} {count}'
                    )

            if self._cached_oldest_queued:
                lines.append("")
                lines.append("# HELP harpocrates_job_oldest_queued_seconds Age of oldest queued job in seconds by type.")
                lines.append("# TYPE harpocrates_job_oldest_queued_seconds gauge")
                for job_type, seconds in sorted(self._cached_oldest_queued.items()):
                    lines.append(
                        f'harpocrates_job_oldest_queued_seconds{{type="{_escape_label(job_type)}"}} {_format_float(seconds)}'
                    )

        lines.append("")
        return "\n".join(lines)


def _escape_label(val: str) -> str:
    return val.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _format_float(val: float) -> str:
    if val == float("inf"):
        return "+Inf"
    if val == int(val):
        return str(int(val))
    return f"{val:.6g}"


def _default_get_job_queue_metrics() -> dict[str, Any]:
    try:
        import db
        if hasattr(db, "get_job_queue_metrics"):
            return db.get_job_queue_metrics()
        if hasattr(db, "get_job_metrics"):
            return db.get_job_metrics()
    except Exception:
        pass
    return {"counts": {}, "oldest_queued_seconds": {}}


get_job_queue_metrics = _default_get_job_queue_metrics
get_job_metrics = get_job_queue_metrics

# Global singleton instance
collector = MetricsCollector()
