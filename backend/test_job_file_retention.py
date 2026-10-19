import os
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from config import JOB_FILE_TTL_SECONDS_DEFAULT, load_config
from db import _JOBS
from errors import GONE
from storage import sweep_job_files, purge_stale_job_files

# Non-destructive test-only shims to allow importing real app without touching unrelated modules
import verifier_inputs
if not hasattr(verifier_inputs, "MAX_AGGREGATION_SIZE"):
    verifier_inputs.MAX_AGGREGATION_SIZE = 8
if not hasattr(verifier_inputs, "MIN_AGGREGATION_SIZE"):
    verifier_inputs.MIN_AGGREGATION_SIZE = 2

import tx_verification
if not hasattr(tx_verification, "normalize_tx_hash"):
    tx_verification.normalize_tx_hash = lambda x: str(x).lower().removeprefix("0x")
if not hasattr(tx_verification, "verify_transaction"):
    tx_verification.verify_transaction = lambda *a, **k: None


@pytest.fixture(autouse=True)
def clean_jobs():
    _JOBS.clear()
    yield
    _JOBS.clear()


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------


def test_config_job_file_ttl_default(monkeypatch):
    monkeypatch.delenv("HARPOCRATES_JOB_FILE_TTL_SECONDS", raising=False)
    cfg = load_config()
    assert cfg.job_file_ttl_seconds == JOB_FILE_TTL_SECONDS_DEFAULT
    assert cfg.job_file_ttl_seconds == 86_400


def test_config_job_file_ttl_custom(monkeypatch):
    monkeypatch.setenv("HARPOCRATES_JOB_FILE_TTL_SECONDS", "3600")
    cfg = load_config()
    assert cfg.job_file_ttl_seconds == 3600


def test_config_job_file_ttl_rejects_non_integer(monkeypatch):
    monkeypatch.setenv("HARPOCRATES_JOB_FILE_TTL_SECONDS", "invalid")
    with pytest.raises(RuntimeError, match="must be an integer"):
        load_config()


def test_config_job_file_ttl_rejects_negative(monkeypatch):
    monkeypatch.setenv("HARPOCRATES_JOB_FILE_TTL_SECONDS", "-1")
    with pytest.raises(RuntimeError, match="must be non-negative"):
        load_config()


# ---------------------------------------------------------------------------
# Sweep / Purge logic tests with tmp_path, fake job rows, fixed timestamps
# ---------------------------------------------------------------------------


def test_terminal_state_job_files_older_than_ttl_are_removed(tmp_path):
    fixed_now = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)
    ttl = 86_400  # 24 hours
    old_time = (fixed_now - timedelta(seconds=ttl + 100)).isoformat()
    recent_time = (fixed_now - timedelta(seconds=ttl - 100)).isoformat()

    # Completed job - older than TTL (should be removed)
    _JOBS[1] = {"id": 1, "status": "completed", "completed_at": old_time}
    f1_in = tmp_path / "job_1_input"
    f1_out = tmp_path / "job_1_output"
    f1_in.write_bytes(b"data1-in")
    f1_out.write_bytes(b"data1-out")

    # Failed job - older than TTL (should be removed)
    _JOBS[2] = {"id": 2, "status": "failed", "failed_at": old_time}
    f2 = tmp_path / "job_2_input"
    f2.write_bytes(b"data2")

    # Cancelled job - older than TTL (should be removed)
    _JOBS[3] = {"id": 3, "status": "cancelled", "cancelled_at": old_time}
    f3 = tmp_path / "job_3_input"
    f3.write_bytes(b"data3")

    # Completed job - newer than TTL (should be kept)
    _JOBS[4] = {"id": 4, "status": "completed", "completed_at": recent_time}
    f4 = tmp_path / "job_4_output"
    f4.write_bytes(b"data4")

    count = sweep_job_files(storage_dir=tmp_path, ttl_seconds=ttl, now=fixed_now)

    assert count == 4
    assert not f1_in.exists()
    assert not f1_out.exists()
    assert not f2.exists()
    assert not f3.exists()
    assert f4.exists()

    # Purged jobs should have purged flag set
    assert _JOBS[1].get("purged") is True
    assert _JOBS[2].get("purged") is True
    assert _JOBS[3].get("purged") is True
    assert _JOBS[4].get("purged") is not True


def test_running_and_pending_jobs_files_are_never_removed(tmp_path):
    fixed_now = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)
    ttl = 86_400
    old_time = (fixed_now - timedelta(seconds=ttl * 2)).isoformat()

    # Running job created long ago
    _JOBS[10] = {"id": 10, "status": "running", "created_at": old_time}
    f10_in = tmp_path / "job_10_input"
    f10_out = tmp_path / "job_10_output"
    f10_in.write_bytes(b"running-in")
    f10_out.write_bytes(b"running-out")

    # Pending job created long ago
    _JOBS[11] = {"id": 11, "status": "pending", "created_at": old_time}
    f11_in = tmp_path / "job_11_input"
    f11_in.write_bytes(b"pending-in")

    count = sweep_job_files(storage_dir=tmp_path, ttl_seconds=ttl, now=fixed_now)

    assert count == 0
    assert f10_in.exists()
    assert f10_out.exists()
    assert f11_in.exists()
    assert not _JOBS[10].get("purged")
    assert not _JOBS[11].get("purged")


def test_orphaned_files_with_no_job_row(tmp_path):
    fixed_now = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)
    ttl = 86_400
    old_epoch = fixed_now.timestamp() - (ttl + 500)
    recent_epoch = fixed_now.timestamp() - (ttl - 500)

    # Orphaned job file older than TTL (no row in _JOBS)
    old_orphan = tmp_path / "job_999_input"
    old_orphan.write_bytes(b"orphan-old")
    os.utime(old_orphan, (old_epoch, old_epoch))

    # Orphaned job file newer than TTL (no row in _JOBS, e.g. newly created upload)
    recent_orphan = tmp_path / "job_998_input"
    recent_orphan.write_bytes(b"orphan-recent")
    os.utime(recent_orphan, (recent_epoch, recent_epoch))

    # Non-job file older than TTL
    old_misc = tmp_path / "abandoned_video.bin"
    old_misc.write_bytes(b"misc-data")
    os.utime(old_misc, (old_epoch, old_epoch))

    count = sweep_job_files(storage_dir=tmp_path, ttl_seconds=ttl, now=fixed_now)

    assert count == 2
    assert not old_orphan.exists()
    assert not old_misc.exists()
    assert recent_orphan.exists()


def test_log_counts_only_never_file_names(tmp_path, caplog):
    import logging

    fixed_now = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)
    ttl = 100
    old_time = (fixed_now - timedelta(seconds=200)).isoformat()

    _JOBS[77] = {"id": 77, "status": "completed", "completed_at": old_time}
    secret_filename = "sensitive_user_evidence_name.mp4"
    f = tmp_path / "job_77_output"
    f.write_bytes(b"secret")

    with caplog.at_level(logging.INFO, logger="harpocrates.storage"):
        sweep_job_files(storage_dir=tmp_path, ttl_seconds=ttl, now=fixed_now)

    # File was deleted
    assert not f.exists()

    # Log check: count appears, file name never appears
    messages = [rec.getMessage() for rec in caplog.records]
    assert any("Purged 1 stale job files" in msg for msg in messages)
    assert not any("job_77" in msg for msg in messages)
    assert not any(secret_filename in msg for msg in messages)


# ---------------------------------------------------------------------------
# API endpoint tests: GET /api/jobs/<id>/download returns 410 for purged jobs
# ---------------------------------------------------------------------------


def test_download_purged_job_returns_410_with_standard_envelope(tmp_path, monkeypatch):
    monkeypatch.setenv("HARPOCRATES_STORAGE_DIR", str(tmp_path))
    monkeypatch.setenv("SECURITY_HEADERS_ENABLED", "false")
    monkeypatch.setenv("RATELIMIT_ENABLED", "false")

    from app import app

    client = app.test_client()

    # Job is marked purged
    _JOBS[50] = {
        "id": 50,
        "type": "embed",
        "status": "completed",
        "purged": True,
        "result": {},
    }

    resp = client.get("/api/jobs/50/download")
    assert resp.status_code == 410
    assert resp.headers.get("X-Request-ID") is not None

    data = resp.get_json()
    assert data["ok"] is False
    assert "error" in data
    assert data["error"]["code"] == GONE
    assert "purged" in data["error"]["message"].lower()
    assert "request_id" in data["error"]


def test_download_completed_job_with_purged_file_returns_410(tmp_path, monkeypatch):
    monkeypatch.setenv("HARPOCRATES_STORAGE_DIR", str(tmp_path))
    monkeypatch.setenv("SECURITY_HEADERS_ENABLED", "false")
    monkeypatch.setenv("RATELIMIT_ENABLED", "false")

    from app import app

    client = app.test_client()

    # Job completed, but output file missing (purged from disk)
    _JOBS[51] = {
        "id": 51,
        "type": "embed",
        "status": "completed",
        "result": {},
    }
    # Notice: output file does not exist in tmp_path

    resp = client.get("/api/jobs/51/download")
    assert resp.status_code == 410
    data = resp.get_json()
    assert data["ok"] is False
    assert data["error"]["code"] == GONE


def test_download_active_job_with_existing_file_returns_200(tmp_path, monkeypatch):
    monkeypatch.setenv("HARPOCRATES_STORAGE_DIR", str(tmp_path))
    monkeypatch.setenv("SECURITY_HEADERS_ENABLED", "false")
    monkeypatch.setenv("RATELIMIT_ENABLED", "false")

    from app import app

    client = app.test_client()

    _JOBS[52] = {
        "id": 52,
        "type": "embed",
        "status": "completed",
        "result": {"source_hash": "a" * 64},
    }
    output_file = tmp_path / "job_52_output"
    output_file.write_bytes(b"dummy video data")

    resp = client.get("/api/jobs/52/download")
    assert resp.status_code == 200
    assert resp.data == b"dummy video data"
    assert resp.headers.get("X-Harpocrates-Source-Hash") == "a" * 64


def test_download_unknown_job_returns_404():
    from app import app

    client = app.test_client()
    resp = client.get("/api/jobs/99999999/download")
    assert resp.status_code == 404


def test_retention_worker_triggers_job_file_sweep():
    from retention import RetentionWorker

    worker = RetentionWorker()
    with patch("retention.purge_expired_events", return_value=[]), \
         patch("storage.sweep_job_files") as mock_sweep:
        worker._purge()
        assert mock_sweep.called

