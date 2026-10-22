import logging
import time
import os
from logging_utils import log_structured
import threading
import traceback
from pathlib import Path

from db import (
    lease_job,
    heartbeat_job,
    report_job_progress,
    complete_job,
    fail_job,
    insert_proof_event,
    init_db,
    database_url,
    get_connection,
    update_tx_status,
)
from envelope import canonical_metadata_hash
from stego import embed_metadata, extract_metadata, sha256_file
from noir import generate_silent_witness
from app import safe_filename, redact_metadata
from app import normalize_filename, redact_metadata
from config import load_config

from storage import get_job_input_path, get_job_output_path, sweep_job_files
from tx_verification import verify_transaction_status
from tracing import traced_job

LOGGER = logging.getLogger("harpocrates.worker")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)

WORKER_ID = f"worker-{os.getpid()}"

@traced_job("job.media.embed")
def process_embed(job: dict) -> dict:
    payload = job["payload"]
    job_id = job["id"]
    metadata = payload["metadata"]
    filename = payload["filename"]
    
    input_path = get_job_input_path(job_id)
    output_path = get_job_output_path(job_id)
    
    if not input_path.exists():
        raise RuntimeError(f"Input video file missing for job {job_id}")
        
    report_job_progress(job_id, "hashing_source")
    source_hash = sha256_file(input_path)

    def on_frame(frames_done: int, frames_total: int | None) -> None:
        percent = (frames_done / frames_total * 100.0) if frames_total else None
        report_job_progress(job_id, "embedding", percent)

    embed_metadata(input_path, output_path, metadata, progress_callback=on_frame)

    report_job_progress(job_id, "hashing_output")
    embedded_hash = sha256_file(output_path)
    metadata_hash = canonical_metadata_hash(metadata)

    report_job_progress(job_id, "recording")
    db_event = insert_proof_event(
        event_type="embed",
        file_name=normalize_filename(filename),
        video_hash=embedded_hash,
        metadata_hash=metadata_hash,
        proof_id=metadata.get("proofId"),
        tier=metadata.get("tier"),
        embedded_hash=embedded_hash,
        metadata=redact_metadata(metadata),
    )
    
    input_path.unlink(missing_ok=True)
    
    return {
        "source_hash": source_hash,
        "embedded_hash": embedded_hash,
        "metadata_hash": metadata_hash,
        "db_event": db_event
    }

@traced_job("job.media.extract")
def process_extract(job: dict) -> dict:
    payload = job["payload"]
    job_id = job["id"]
    filename = payload["filename"]
    
    input_path = get_job_input_path(job_id)
    
    if not input_path.exists():
        raise RuntimeError(f"Input video file missing for job {job_id}")
        
    metadata = extract_metadata(input_path)
    video_hash = sha256_file(input_path)
    metadata_hash = canonical_metadata_hash(metadata) if metadata else None
    
    db_event = insert_proof_event(
        event_type="extract",
        file_name=normalize_filename(filename),
        video_hash=video_hash,
        metadata_hash=metadata_hash,
        proof_id=metadata.get("proofId") if metadata else None,
        tier=metadata.get("tier") if metadata else None,
        metadata=redact_metadata(metadata),
    )
    
    input_path.unlink(missing_ok=True)
    
    return {
        "video_hash": video_hash,
        "metadata_hash": metadata_hash,
        "metadata": metadata,
        "db_event": db_event
    }

@traced_job("job.proof.noir")
def process_silent_witness(job: dict) -> dict:
    payload = job["payload"]

    video_hash = payload["video_hash"]
    credential_secret = payload["credential_secret"]
    nullifier_secret = payload["nullifier_secret"]

    # Phase names only: proof generation runs as one external command and
    # reports no measurable fraction, so percent stays None.
    report_job_progress(job["id"], "generating_proof")
    proof = generate_silent_witness(
        video_hash,
        credential_secret,
        nullifier_secret,
    )
    
    return {"proof": proof}

def process_verify_tx(job: dict) -> dict:
    """Reconcile a single registration tx enqueued at proof registration time."""
    return process_verify_tx_job(job.get("payload") or {})

def heartbeat_loop(job_id: int, stop_event: threading.Event):
    while not stop_event.is_set():
        heartbeat_job(job_id, lease_duration=300)
        stop_event.wait(60)

def tx_verification_loop(stop_event: threading.Event):
    """
    Periodically reconcile pending registration confirmations against Horizon.

    Prefer the batch reconciler (confirmation depth + privacy-safe signals). Fall
    back to the legacy per-row Horizon probe when the DB helpers are unavailable.
    """
    LOGGER.info("Starting transaction verification / registration reconcile loop")
    while not stop_event.is_set():
        try:
            if not database_url():
                stop_event.wait(10)
                continue

            try:
                report = reconcile_pending_registrations(
                    limit=50,
                    min_confirmations=default_min_confirmations(),
                )
                summary = report.get("summary") or {}
                LOGGER.info(
                    "registration_reconcile_batch scanned=%s updated=%s confirmed=%s failed=%s missing=%s pending=%s error=%s",
                    summary.get("scanned"),
                    summary.get("updated"),
                    summary.get("confirmed"),
                    summary.get("failed"),
                    summary.get("missing"),
                    summary.get("pending"),
                    summary.get("error"),
                )
            except Exception:
                # Legacy fallback path keeps older deployments moving.
                with get_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT id, tx_hash
                            FROM proof_events
                            WHERE tx_hash IS NOT NULL AND tx_status = 'pending'
                            LIMIT 50
                            """
                        )
                        rows = [dict(row) for row in cur.fetchall()]

                for row in rows:
                    if stop_event.is_set():
                        break

                    tx_hash = row["tx_hash"]
                    LOGGER.info("Verifying transaction %s", str(tx_hash)[:8])
                    status = verify_transaction_status(tx_hash)

                    if status in ("confirmed", "failed", "missing"):
                        LOGGER.info(
                            "Transaction %s resolved to %s",
                            str(tx_hash)[:8],
                            status,
                        )
                        update_tx_status(tx_hash, status)

        except Exception as e:
            LOGGER.error("Error in tx verification loop: %s", type(e).__name__)

        stop_event.wait(15)


import signal
import sys

DEFAULT_WORKER_GRACE_PERIOD_SECONDS = 30.0


def _worker_grace_period_seconds() -> float:
    raw = os.getenv("WORKER_GRACE_PERIOD_SECONDS")
    if raw is None or not raw.strip():
        return DEFAULT_WORKER_GRACE_PERIOD_SECONDS
    try:
        val = float(raw)
        return val if val > 0 else DEFAULT_WORKER_GRACE_PERIOD_SECONDS
    except ValueError:
        return DEFAULT_WORKER_GRACE_PERIOD_SECONDS


def run_worker(
    stop_event: threading.Event | None = None,
    grace_period_seconds: float | None = None,
):
    init_db()
    config = load_config()
    LOGGER.info("Worker started with config summary")
    log_structured(LOGGER, logging.INFO, {"event": "worker_start", "config": config.redacted_summary()})
    LOGGER.info(f"Starting worker {WORKER_ID}")

    if stop_event is None:
        stop_event = threading.Event()

    if grace_period_seconds is None:
        grace_period_seconds = _worker_grace_period_seconds()

    def _signal_handler(signum, frame):
        LOGGER.info(f"Received signal {signum}, initiating graceful shutdown")
        stop_event.set()

    try:
        signal.signal(signal.SIGTERM, _signal_handler)
    except (ValueError, AttributeError):
        pass

    try:
        signal.signal(signal.SIGINT, _signal_handler)
    except (ValueError, AttributeError):
        pass

    verification_thread = threading.Thread(target=tx_verification_loop, args=(stop_event,))
    verification_thread.daemon = True
    verification_thread.start()

    while not stop_event.is_set():
        try:
            now_time = time.time()
            if now_time - last_sweep_time >= 300:
                last_sweep_time = now_time
                try:
                    sweep_job_files()
                except Exception as e:
                    LOGGER.error("Job file sweep failed: %s", type(e).__name__)

            job = lease_job(
                WORKER_ID,
                ["embed", "extract", "silent_witness", "verify_tx"],
                lease_duration=300,
            )
            if not job:
                stop_event.wait(2)
                continue

            job_id = job["id"]
            job_type = job["type"]
            LOGGER.info(f"Leased job {job_id} of type {job_type}")

            hb_stop_event = threading.Event()
            hb_thread = threading.Thread(target=heartbeat_loop, args=(job_id, hb_stop_event))
            hb_thread.start()

            def _execute_job():
                try:
                    if job_type == "embed":
                        res = process_embed(job)
                    elif job_type == "extract":
                        res = process_extract(job)
                    elif job_type == "silent_witness":
                        res = process_silent_witness(job)
                    elif job_type == "verify_tx":
                        res = process_verify_tx(job)
                    else:
                        raise ValueError(f"Unknown job type {job_type}")
                    complete_job(job_id, res)
                    LOGGER.info(f"Completed job {job_id}")
                except Exception as err:
                    LOGGER.error(f"Failed job {job_id}: {err}")
                    LOGGER.error(traceback.format_exc())
                    is_fatal = isinstance(err, ValueError) and job_type != "verify_tx"
                    if job_type == "verify_tx":
                        is_fatal = isinstance(err, ValueError)
                    fail_job(job_id, str(err), is_fatal=is_fatal)
                finally:
                    hb_stop_event.set()
                    hb_thread.join()

            work_thread = threading.Thread(target=_execute_job)
            work_thread.daemon = True
            work_thread.start()

            while work_thread.is_alive():
                work_thread.join(timeout=0.1)
                if stop_event.is_set() and work_thread.is_alive():
                    # Stop event received while processing job: give it until grace period expires
                    work_thread.join(timeout=grace_period_seconds)
                    if work_thread.is_alive():
                        LOGGER.warning(
                            f"Job {job_id} did not finish within grace period of {grace_period_seconds}s; releasing job"
                        )
                        hb_stop_event.set()
                        fail_job(job_id, "Worker shutdown grace period exceeded", is_fatal=False)
                    break

        except Exception as e:
            LOGGER.error(f"Worker loop error: {e}")
            stop_event.wait(5)

    LOGGER.info("Worker stop event set, waiting for tx verification loop to terminate")
    verification_thread.join(timeout=5.0)
    LOGGER.info("Worker stopped cleanly")


if __name__ == "__main__":
    run_worker()
    sys.exit(0)

