import logging
import threading

from config import load_config
from db import purge_expired_events
from metrics import collector as metrics_collector
from logging_utils import log_structured

LOGGER = logging.getLogger("harpocrates.retention")
RETENTION_BATCH_SIZE = 100

class RetentionWorker:
    def __init__(self, interval_seconds: int = 3600, batch_size: int = RETENTION_BATCH_SIZE):
        if batch_size < 1:
            raise ValueError("batch_size must be >= 1")
        self.interval_seconds = interval_seconds
        self.batch_size = batch_size
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True, name="RetentionWorker")
        self._thread.start()
        log_structured(LOGGER, logging.INFO, {"event": "retention_worker_started", "interval_seconds": self.interval_seconds, "batch_size": self.batch_size})

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        log_structured(LOGGER, logging.INFO, {"event": "retention_worker_stopped"})

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._purge()
            except Exception as error:
                log_structured(
                    LOGGER,
                    logging.ERROR,
                    {"event": "retention_worker_error", "error_type": type(error).__name__},
                )

            self._stop_event.wait(self.interval_seconds)

    def _purge(self) -> None:
        while True:
            receipts = purge_expired_events(batch_size=self.batch_size)
            num_deleted = len(receipts)
            if num_deleted > 0:
                log_structured(
                    LOGGER,
                    logging.INFO,
                    {"event": "retention_worker_purged", "count": num_deleted},
                )
                for _ in receipts:
                    metrics_collector.record_deleted_event()
            if num_deleted < self.batch_size:
                break

        try:
            from storage import sweep_job_files
            purged_files = sweep_job_files()
            if purged_files > 0:
                log_structured(
                    LOGGER,
                    logging.INFO,
                    {"event": "retention_job_files_purged", "count": purged_files},
                )
        except Exception as error:
            log_structured(
                LOGGER,
                logging.ERROR,
                {"event": "retention_job_files_error", "error_type": type(error).__name__},
            )

        config = load_config()
        if getattr(config, "retention_blob_gc_enabled", False) or getattr(config, "retention_unreferenced_blobs_enabled", False):
            try:
                from evidence_storage import collect_unreferenced_blobs
                while True:
                    purged_blobs = collect_unreferenced_blobs(limit=self.batch_size)
                    if purged_blobs > 0:
                        log_structured(
                            LOGGER,
                            logging.INFO,
                            {"event": "retention_blobs_purged", "count": purged_blobs},
                        )
                    if purged_blobs < self.batch_size:
                        break
            except Exception as error:
                log_structured(
                    LOGGER,
                    logging.ERROR,
                    {"event": "retention_blobs_error", "error_type": type(error).__name__},
                )


_worker: RetentionWorker | None = None

def init_retention_worker() -> None:
    global _worker
    config = load_config()
    if config.retention_worker_enabled:
        _worker = RetentionWorker(
            interval_seconds=config.retention_interval_seconds,
            batch_size=config.retention_batch_size,
        )
        _worker.start()

def stop_retention_worker() -> None:
    global _worker
    if _worker:
        _worker.stop()
        _worker = None
