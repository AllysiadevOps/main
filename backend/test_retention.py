import os
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from config import RETENTION_BATCH_SIZE_MAX, load_config
from db import (
    RETENTION_BATCH_MAX_SIZE,
    get_connection,
    init_db,
    insert_proof_event,
    purge_expired_events,
    set_legal_hold,
)
from retention import (
    RETENTION_BATCH_SIZE,
    RetentionWorker,
    init_retention_worker,
    stop_retention_worker,
)

@pytest.fixture
def setup_db(monkeypatch):
    db_url = os.environ.get("TEST_DATABASE_URL") or "postgresql://postgres:password@localhost:5432/postgres"
    monkeypatch.setenv("DATABASE_URL", db_url)
    try:
        init_db()
        with get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("truncate table proof_events cascade;")
                cursor.execute("truncate table deletion_receipts cascade;")
            conn.commit()
    except Exception as e:
        pytest.skip(f"Database connection failed: {e}")
    
    yield
    
    stop_retention_worker()

@pytest.mark.integration
def test_purge_expired_events(setup_db):
    # Insert an event that is expired
    expired_time = datetime.now(timezone.utc) - timedelta(days=1)
    ev1 = insert_proof_event(event_type="test", video_hash="1"*64, proof_id="a"*64, expires_at=expired_time)
    
    # Insert an event that is not expired
    future_time = datetime.now(timezone.utc) + timedelta(days=1)
    ev2 = insert_proof_event(event_type="test", video_hash="2"*64, proof_id="b"*64, expires_at=future_time)
    
    # Insert an event that is expired but on legal hold
    ev3 = insert_proof_event(event_type="test", video_hash="3"*64, proof_id="c"*64, expires_at=expired_time)
    set_legal_hold("c"*64, True)
    
    # Insert an event with no expiration
    ev4 = insert_proof_event(event_type="test", video_hash="4"*64, proof_id="d"*64)
    
    receipts = purge_expired_events()
    
    assert len(receipts) == 1
    assert receipts[0]["proof_id"] == "a"*64
    
    # Verify remaining in DB
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("select proof_id from proof_events order by id")
            remaining = [r["proof_id"] for r in cursor.fetchall()]
    assert remaining == ["b"*64, "c"*64, "d"*64]

    # Verify receipt is in table
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("select proof_id from deletion_receipts")
            in_receipts = [r["proof_id"] for r in cursor.fetchall()]
    assert in_receipts == ["a"*64]

@pytest.mark.integration
def test_retention_worker(monkeypatch, setup_db):
    monkeypatch.setenv("RETENTION_INTERVAL_SECONDS", "1")
    
    expired_time = datetime.now(timezone.utc) - timedelta(days=1)
    insert_proof_event(event_type="test", video_hash="5"*64, proof_id="e"*64, expires_at=expired_time)
    
    init_retention_worker()
    time.sleep(2)  # Wait for worker to run at least once
    
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("select count(*) as c from deletion_receipts")
            count = cursor.fetchone()["c"]
    assert count == 1

def test_retention_worker_default_batch_size():
    worker = RetentionWorker()
    assert worker.batch_size == RETENTION_BATCH_SIZE
    assert worker.batch_size == 100


def test_retention_worker_custom_batch_size():
    custom_batch = 250
    worker = RetentionWorker(interval_seconds=60, batch_size=custom_batch)
    assert worker.batch_size == custom_batch

    # Mock purge_expired_events: first call returns 250 receipts,
    # second call returns fewer (50), verifying worker loops then breaks.
    batch_1 = [{"proof_id": f"p1_{i}"} for i in range(custom_batch)]
    batch_2 = [{"proof_id": f"p2_{i}"} for i in range(50)]

    with patch("retention.purge_expired_events", side_effect=[batch_1, batch_2]) as mock_purge, \
         patch("retention.metrics_collector") as mock_metrics:
        worker._purge()

        assert mock_purge.call_count == 2
        mock_purge.assert_called_with(batch_size=custom_batch)
        assert mock_metrics.record_deleted_event.call_count == custom_batch + 50


def test_config_retention_batch_size_default(monkeypatch):
    monkeypatch.delenv("HARPOCRATES_RETENTION_BATCH_SIZE", raising=False)
    config = load_config()
    assert config.retention_batch_size == 100


@pytest.mark.parametrize(
    "env_val, expected",
    [
        ("250", 250),
        ("1", 1),
        ("5000", 5000),
        ("10000", 5000),
        ("0", 1),
        ("-10", 1),
        ("   ", 100),
    ],
)
def test_config_retention_batch_size_clamping(monkeypatch, env_val, expected):
    monkeypatch.setenv("HARPOCRATES_RETENTION_BATCH_SIZE", env_val)
    config = load_config()
    assert config.retention_batch_size == expected


def test_init_retention_worker_configured_batch_size(monkeypatch):
    monkeypatch.setenv("RETENTION_WORKER_ENABLED", "true")
    monkeypatch.setenv("HARPOCRATES_RETENTION_BATCH_SIZE", "500")

    with patch.object(RetentionWorker, "start"):
        init_retention_worker()
        from retention import _worker
        assert _worker is not None
        assert _worker.batch_size == 500
    stop_retention_worker()


def test_config_retention_batch_size_rejects_non_integer(monkeypatch):
    monkeypatch.setenv("HARPOCRATES_RETENTION_BATCH_SIZE", "abc")
    with pytest.raises(RuntimeError, match="must be an integer"):
        load_config()


def test_retention_batch_limits_match_db():
    assert RETENTION_BATCH_SIZE_MAX == RETENTION_BATCH_MAX_SIZE


def test_retention_worker_rejects_non_positive_batch_size():
    with pytest.raises(ValueError, match="batch_size"):
        RetentionWorker(batch_size=0)


def test_retention_worker_start_twice_creates_one_thread_and_stop_joins():
    mock_storage = MagicMock()
    mock_storage.sweep_job_files.return_value = 0
    worker = RetentionWorker(interval_seconds=0.01)
    with patch("retention.purge_expired_events", return_value=[]), \
         patch.dict("sys.modules", {"storage": mock_storage}):
        worker.start()
        thread = worker._thread
        assert thread is not None
        assert thread.is_alive()
        assert thread.name == "RetentionWorker"

        # Calling start() twice is idempotent: does not create a new thread
        worker.start()
        assert worker._thread is thread

        # stop() joins the thread and sets _thread to None
        worker.stop()
        assert not thread.is_alive()
        assert worker._thread is None

        # Calling stop() when thread is already None is safe and idempotent
        worker.stop()
        assert worker._thread is None


def test_retention_worker_purge_full_then_partial_batches():
    batch_size = 50
    worker = RetentionWorker(interval_seconds=60, batch_size=batch_size)

    full_batch = [{"proof_id": f"full_{i}"} for i in range(batch_size)]
    partial_batch = [{"proof_id": f"partial_{i}"} for i in range(20)]

    mock_storage = MagicMock()
    mock_storage.sweep_job_files.return_value = 0

    with patch("retention.purge_expired_events", side_effect=[full_batch, partial_batch]) as mock_purge, \
         patch("retention.metrics_collector") as mock_metrics, \
         patch("retention.log_structured") as mock_log, \
         patch.dict("sys.modules", {"storage": mock_storage}):
        worker._purge()

        assert mock_purge.call_count == 2
        mock_purge.assert_called_with(batch_size=batch_size)
        assert mock_metrics.record_deleted_event.call_count == 70

        purged_logs = [
            call.args[2] for call in mock_log.call_args_list
            if len(call.args) >= 3 and isinstance(call.args[2], dict) and call.args[2].get("event") == "retention_worker_purged"
        ]
        assert [log["count"] for log in purged_logs] == [50, 20]


def test_retention_worker_purge_empty_batch():
    worker = RetentionWorker(interval_seconds=60, batch_size=100)
    mock_storage = MagicMock()
    mock_storage.sweep_job_files.return_value = 0

    with patch("retention.purge_expired_events", return_value=[]) as mock_purge, \
         patch("retention.metrics_collector") as mock_metrics, \
         patch("retention.log_structured") as mock_log, \
         patch.dict("sys.modules", {"storage": mock_storage}):
        worker._purge()

        mock_purge.assert_called_once_with(batch_size=100)
        assert mock_metrics.record_deleted_event.call_count == 0

        purged_logs = [
            call.args[2] for call in mock_log.call_args_list
            if len(call.args) >= 3 and isinstance(call.args[2], dict) and call.args[2].get("event") == "retention_worker_purged"
        ]
        assert len(purged_logs) == 0


def test_retention_worker_purge_job_files_branches():
    worker = RetentionWorker(interval_seconds=60, batch_size=100)

    # Branch 1: sweep_job_files purges > 0 files
    mock_storage_success = MagicMock()
    mock_storage_success.sweep_job_files.return_value = 3
    with patch("retention.purge_expired_events", return_value=[]), \
         patch.dict("sys.modules", {"storage": mock_storage_success}), \
         patch("retention.log_structured") as mock_log:
        worker._purge()

        purged_file_logs = [
            call.args[2] for call in mock_log.call_args_list
            if len(call.args) >= 3 and isinstance(call.args[2], dict) and call.args[2].get("event") == "retention_job_files_purged"
        ]
        assert len(purged_file_logs) == 1
        assert purged_file_logs[0]["count"] == 3

    # Branch 2: sweep_job_files raises an exception
    mock_storage_error = MagicMock()
    mock_storage_error.sweep_job_files.side_effect = OSError("disk error")
    with patch("retention.purge_expired_events", return_value=[]), \
         patch.dict("sys.modules", {"storage": mock_storage_error}), \
         patch("retention.log_structured") as mock_log:
        worker._purge()

        error_logs = [
            call.args[2] for call in mock_log.call_args_list
            if len(call.args) >= 3 and isinstance(call.args[2], dict) and call.args[2].get("event") == "retention_job_files_error"
        ]
        assert len(error_logs) == 1
        assert error_logs[0]["error_type"] == "OSError"


def test_retention_worker_run_logs_error_and_keeps_running():
    first_run_event = threading.Event()
    second_run_event = threading.Event()
    call_count = 0

    def mock_purge_expired(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            first_run_event.set()
            raise RuntimeError("simulated database failure")
        second_run_event.set()
        return []

    mock_storage = MagicMock()
    mock_storage.sweep_job_files.return_value = 0

    worker = RetentionWorker(interval_seconds=0.005)
    with patch("retention.purge_expired_events", side_effect=mock_purge_expired), \
         patch("retention.log_structured") as mock_log, \
         patch.dict("sys.modules", {"storage": mock_storage}):
        worker.start()

        assert first_run_event.wait(timeout=1.0), "Worker did not execute first purge call"
        assert second_run_event.wait(timeout=1.0), "Worker stopped running after exception"

        worker.stop()

    assert worker._thread is None
    error_logs = [
        call.args[2] for call in mock_log.call_args_list
        if len(call.args) >= 3 and isinstance(call.args[2], dict) and call.args[2].get("event") == "retention_worker_error"
    ]
    assert len(error_logs) >= 1
    assert error_logs[0]["error_type"] == "RuntimeError"


def test_init_retention_worker_disabled(monkeypatch):
    monkeypatch.setenv("RETENTION_WORKER_ENABLED", "false")
    stop_retention_worker()

    with patch.object(RetentionWorker, "start") as mock_start:
        init_retention_worker()
        from retention import _worker
        assert _worker is None
        mock_start.assert_not_called()


def test_stop_retention_worker_when_uninitialized():
    import retention
    retention._worker = None
    stop_retention_worker()
    assert retention._worker is None


def test_stop_retention_worker_active():
    import retention
    worker = RetentionWorker(interval_seconds=60)
    with patch.object(worker, "stop") as mock_stop:
        retention._worker = worker
        stop_retention_worker()
        assert retention._worker is None
        mock_stop.assert_called_once()


@pytest.mark.integration
def test_retention_worker_purges_across_pages(setup_db):
    # 260 expired events with a 250-row batch must drain in two pages. With the
    # old SQL-layer cap of 100 the worker stopped after 100 rows and left 160.
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                insert into proof_events (event_type, expires_at)
                select 'test', now() - interval '1 day'
                from generate_series(1, 260)
                """
            )
        conn.commit()

    RetentionWorker(interval_seconds=60, batch_size=250)._purge()

    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute("select count(*) as c from proof_events")
            assert cursor.fetchone()["c"] == 0
            cursor.execute("select count(*) as c from deletion_receipts")
            assert cursor.fetchone()["c"] == 260


def test_retention_worker_blob_gc_disabled_by_default(monkeypatch):
    monkeypatch.delenv("RETENTION_BLOB_GC_ENABLED", raising=False)
    monkeypatch.delenv("HARPOCRATES_RETENTION_BLOB_GC_ENABLED", raising=False)
    monkeypatch.delenv("RETENTION_UNREFERENCED_BLOBS_ENABLED", raising=False)
    monkeypatch.delenv("HARPOCRATES_RETENTION_UNREFERENCED_BLOBS_ENABLED", raising=False)

    worker = RetentionWorker(interval_seconds=60, batch_size=50)

    mock_storage = MagicMock()
    mock_storage.sweep_job_files.return_value = 0
    monkeypatch.setitem(sys.modules, "storage", mock_storage)

    with patch("retention.purge_expired_events", return_value=[]), \
         patch("evidence_storage.collect_unreferenced_blobs") as mock_collect:
        worker._purge()
        mock_collect.assert_not_called()


def test_retention_worker_blob_gc_invoked_when_enabled(monkeypatch):
    monkeypatch.setenv("RETENTION_BLOB_GC_ENABLED", "true")

    worker = RetentionWorker(interval_seconds=60, batch_size=50)

    mock_storage = MagicMock()
    mock_storage.sweep_job_files.return_value = 0
    monkeypatch.setitem(sys.modules, "storage", mock_storage)

    with patch("retention.purge_expired_events", return_value=[]), \
         patch("evidence_storage.collect_unreferenced_blobs", return_value=0) as mock_collect:
        worker._purge()
        mock_collect.assert_called_once_with(limit=50)


def test_retention_worker_blob_gc_handles_error_gracefully(monkeypatch):
    monkeypatch.setenv("RETENTION_BLOB_GC_ENABLED", "true")

    worker = RetentionWorker(interval_seconds=60, batch_size=50)

    mock_storage = MagicMock()
    mock_storage.sweep_job_files.return_value = 0
    monkeypatch.setitem(sys.modules, "storage", mock_storage)

    with patch("retention.purge_expired_events", return_value=[]), \
         patch("evidence_storage.collect_unreferenced_blobs", side_effect=RuntimeError("db error")):
        # Should not raise exception
        worker._purge()


