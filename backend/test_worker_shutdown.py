import os
import signal
import sys
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, backend_dir)
sys.path.insert(0, os.path.join(backend_dir, "backend"))

# Monkeypatch missing exports on main so worker imports cleanly
import verifier_inputs
if not hasattr(verifier_inputs, "MAX_AGGREGATION_SIZE"):
    verifier_inputs.MAX_AGGREGATION_SIZE = 16
if not hasattr(verifier_inputs, "MIN_AGGREGATION_SIZE"):
    verifier_inputs.MIN_AGGREGATION_SIZE = 2
if not hasattr(verifier_inputs, "check_aggregation_batch_size"):
    verifier_inputs.check_aggregation_batch_size = lambda x: None

import tx_verification
if not hasattr(tx_verification, "normalize_tx_hash"):
    tx_verification.normalize_tx_hash = lambda x: str(x) if x else None
if not hasattr(tx_verification, "verify_transaction"):
    tx_verification.verify_transaction = lambda *args, **kwargs: None

import backend.worker as worker


def test_worker_stops_leasing_when_stop_event_set():
    stop_event = threading.Event()
    stop_event.set()

    with patch.object(worker, "init_db") as mock_init_db, \
         patch.object(worker, "lease_job") as mock_lease_job, \
         patch.object(worker, "tx_verification_loop") as mock_verify_loop:
        
        worker.run_worker(stop_event=stop_event, grace_period_seconds=1.0)

        mock_init_db.assert_called_once()
        mock_lease_job.assert_not_called()


def test_worker_completes_inflight_job_within_grace_period():
    stop_event = threading.Event()
    job = {"id": "job-1", "type": "embed", "payload": {}}

    call_count = 0

    def mock_lease(*args, **kwargs):
        nonlocal call_count
        if call_count == 0:
            call_count += 1
            return job
        return None

    def mock_embed(j):
        time.sleep(0.05)
        stop_event.set()
        return {"status": "ok"}

    with patch.object(worker, "init_db"), \
         patch.object(worker, "lease_job", side_effect=mock_lease), \
         patch.object(worker, "process_embed", side_effect=mock_embed) as mock_proc, \
         patch.object(worker, "complete_job") as mock_complete, \
         patch.object(worker, "fail_job") as mock_fail, \
         patch.object(worker, "heartbeat_loop"), \
         patch.object(worker, "tx_verification_loop"):

        worker.run_worker(stop_event=stop_event, grace_period_seconds=2.0)

        mock_complete.assert_called_once_with("job-1", {"status": "ok"})
        mock_fail.assert_not_called()


def test_worker_releases_inflight_job_when_grace_period_exceeded():
    stop_event = threading.Event()
    job = {"id": "job-slow", "type": "embed", "payload": {}}

    call_count = 0

    def mock_lease(*args, **kwargs):
        nonlocal call_count
        if call_count == 0:
            call_count += 1
            return job
        return None

    def mock_embed(j):
        stop_event.set()
        time.sleep(0.5)
        return {"status": "ok"}

    with patch.object(worker, "init_db"), \
         patch.object(worker, "lease_job", side_effect=mock_lease), \
         patch.object(worker, "process_embed", side_effect=mock_embed), \
         patch.object(worker, "complete_job") as mock_complete, \
         patch.object(worker, "fail_job") as mock_fail, \
         patch.object(worker, "heartbeat_loop"), \
         patch.object(worker, "tx_verification_loop"):

        worker.run_worker(stop_event=stop_event, grace_period_seconds=0.1)

        mock_fail.assert_called_once()
        args, kwargs = mock_fail.call_args
        assert args[0] == "job-slow"
        assert kwargs.get("is_fatal") is False or (len(args) > 2 and args[2] is False)


def test_tx_verification_loop_stops_on_stop_event():
    stop_event = threading.Event()
    stop_event.set()

    with patch.object(worker, "database_url") as mock_db_url:
        worker.tx_verification_loop(stop_event)
        mock_db_url.assert_not_called()


def test_worker_grace_period_config(monkeypatch):
    monkeypatch.setenv("WORKER_GRACE_PERIOD_SECONDS", "45.5")
    assert worker._worker_grace_period_seconds() == 45.5

    monkeypatch.setenv("WORKER_GRACE_PERIOD_SECONDS", "invalid")
    assert worker._worker_grace_period_seconds() == worker.DEFAULT_WORKER_GRACE_PERIOD_SECONDS
