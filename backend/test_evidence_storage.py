"""Unit tests for backend/evidence_storage.py without a live Postgres database."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet, InvalidToken
import pytest

_BACKEND_DIR = str(Path(__file__).resolve().parent)
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import evidence_storage
from metrics import collector as metrics_collector


class FakeRow(dict):
    """Row mapping returned by FakeCursor.fetchone()."""


class FakeCursor:
    """In-memory fake cursor capturing SQL statements, parameters, and state."""

    def __init__(self, connection: "FakeConnection") -> None:
        self.connection = connection
        self.executed: list[tuple[str, tuple]] = []
        self._last_row: FakeRow | None = None
        self._results: list[FakeRow] = []
        self._idx: int = 0

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        return None

    def execute(self, sql: str, params: tuple = ()) -> None:
        self.executed.append((sql, params))
        normalized = " ".join(sql.lower().split())

        if normalized.startswith("insert into blobs"):
            content_hash, encrypted_dek, size_bytes, storage_path = params
            # ON CONFLICT (content_hash) DO NOTHING
            with self.connection.lock:
                if content_hash not in self.connection.blobs:
                    self.connection.blobs[content_hash] = {
                        "content_hash": content_hash,
                        "encrypted_dek": encrypted_dek,
                        "size_bytes": size_bytes,
                        "storage_path": storage_path,
                        "created_at": time.time(),
                    }
            self._last_row = None

        elif normalized.startswith("insert into tenant_blob_refs"):
            tenant_id, content_hash = params
            key = (tenant_id, content_hash)
            # ON CONFLICT (tenant_id, content_hash) DO UPDATE SET ref_count = ref_count + 1
            with self.connection.lock:
                if key in self.connection.tenant_refs:
                    self.connection.tenant_refs[key]["ref_count"] += 1
                else:
                    self.connection.tenant_refs[key] = {
                        "tenant_id": tenant_id,
                        "content_hash": content_hash,
                        "ref_count": 1,
                    }
            self._last_row = None

        elif normalized.startswith("select encrypted_dek, storage_path from blobs"):
            (content_hash,) = params
            with self.connection.lock:
                blob = self.connection.blobs.get(content_hash)
                if blob is None:
                    self._last_row = None
                else:
                    self._last_row = FakeRow(
                        encrypted_dek=blob["encrypted_dek"],
                        storage_path=blob["storage_path"],
                    )

        elif "select ref_count from tenant_blob_refs" in normalized:
            tenant_id, content_hash = params[0], params[1]
            key = (tenant_id, content_hash)
            with self.connection.lock:
                if key in self.connection.tenant_refs:
                    self._last_row = FakeRow(ref_count=self.connection.tenant_refs[key]["ref_count"])
                else:
                    self._last_row = None

        elif "update tenant_blob_refs" in normalized:
            tenant_id, content_hash = params[0], params[1]
            key = (tenant_id, content_hash)
            with self.connection.lock:
                if key in self.connection.tenant_refs:
                    self.connection.tenant_refs[key]["ref_count"] -= 1

        elif "delete from tenant_blob_refs" in normalized:
            tenant_id, content_hash = params[0], params[1]
            key = (tenant_id, content_hash)
            with self.connection.lock:
                self.connection.tenant_refs.pop(key, None)

        elif "select content_hash, storage_path from blobs" in normalized and "where not exists" in normalized:
            limit = params[0]
            with self.connection.lock:
                unreferenced = []
                for h, b in sorted(self.connection.blobs.items(), key=lambda item: item[1].get("created_at", 0)):
                    has_ref = any(
                        ref["content_hash"] == h and ref["ref_count"] > 0
                        for ref in self.connection.tenant_refs.values()
                    )
                    if not has_ref:
                        unreferenced.append(b)
                        if len(unreferenced) >= limit:
                            break

            for b in unreferenced:
                row_lock = self.connection.get_row_lock(b["content_hash"])
                row_lock.acquire()
                self.connection.held_locks.append(row_lock)

            if self.connection.before_collector_delete_hook:
                self.connection.before_collector_delete_hook()

            self._results = [
                FakeRow(content_hash=b["content_hash"], storage_path=b["storage_path"])
                for b in unreferenced
            ]
            self._idx = 0

        elif "delete from blobs where content_hash = %s" in normalized:
            content_hash = params[0]
            with self.connection.lock:
                self.connection.blobs.pop(content_hash, None)
                to_delete = [k for k, v in self.connection.tenant_refs.items() if v["content_hash"] == content_hash]
                for k in to_delete:
                    del self.connection.tenant_refs[k]

    def fetchone(self) -> FakeRow | None:
        if self._results and self._idx < len(self._results):
            row = self._results[self._idx]
            self._idx += 1
            return row
        return self._last_row

    def fetchall(self) -> list[FakeRow]:
        res = self._results[self._idx:]
        self._idx = len(self._results)
        return res


class FakeConnection:
    """In-memory fake Postgres connection supporting cursor context managers."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.blobs: dict[str, dict] = {}
        self.tenant_refs: dict[tuple[str, str], dict] = {}
        self.cursors: list[FakeCursor] = []
        self.commits: int = 0
        self.row_locks: dict[str, threading.Lock] = {}
        self.row_locks_guard = threading.Lock()
        self.held_locks: list[threading.Lock] = []
        self.before_collector_delete_hook = None

    def get_row_lock(self, content_hash: str) -> threading.Lock:
        with self.row_locks_guard:
            if content_hash not in self.row_locks:
                self.row_locks[content_hash] = threading.Lock()
            return self.row_locks[content_hash]

    @property
    def executed(self) -> list[tuple[str, tuple]]:
        return [call for cur in self.cursors for call in cur.executed]

    def cursor(self) -> FakeCursor:
        cur = FakeCursor(self)
        self.cursors.append(cur)
        return cur

    def commit(self) -> None:
        self.commits += 1
        for lock in self.held_locks:
            lock.release()
        self.held_locks.clear()

    def rollback(self) -> None:
        for lock in self.held_locks:
            lock.release()
        self.held_locks.clear()

    def __enter__(self) -> "FakeConnection":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if exc_type is not None:
            self.rollback()
        else:
            self.commit()


@pytest.fixture
def fake_db(monkeypatch: pytest.MonkeyPatch) -> FakeConnection:
    """Fixture providing a fake db.get_connection context manager and connection."""
    conn = FakeConnection()

    @contextmanager
    def _fake_get_connection():
        yield conn

    monkeypatch.setattr(evidence_storage.db, "get_connection", _fake_get_connection)
    metrics_collector.reset()
    yield conn
    metrics_collector.reset()


@pytest.fixture
def master_key(monkeypatch: pytest.MonkeyPatch) -> str:
    """Fixture configuring a deterministic valid Fernet MASTER_ENCRYPTION_KEY."""
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("MASTER_ENCRYPTION_KEY", key)
    return key


# ---------------------------------------------------------------------------
# Key wrapping & encryption tests (generate_dek, decrypt_dek, get_encryptor)
# ---------------------------------------------------------------------------


def test_generate_and_decrypt_dek_roundtrip(master_key: str) -> None:
    dek, encrypted_dek = evidence_storage.generate_dek()

    assert isinstance(dek, bytes)
    assert isinstance(encrypted_dek, bytes)
    assert dek != encrypted_dek

    recovered = evidence_storage.decrypt_dek(encrypted_dek)
    assert recovered == dek
    assert Fernet(master_key.encode("ascii")).decrypt(encrypted_dek) == dek


def test_generate_dek_without_master_key_env_uses_ephemeral_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MASTER_ENCRYPTION_KEY", raising=False)

    dek, encrypted_dek = evidence_storage.generate_dek()
    assert isinstance(dek, bytes)
    assert isinstance(encrypted_dek, bytes)
    assert dek != encrypted_dek


def test_decrypt_dek_rejects_missing_master_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MASTER_ENCRYPTION_KEY", raising=False)
    with pytest.raises(ValueError, match="MASTER_ENCRYPTION_KEY is not set"):
        evidence_storage.decrypt_dek(b"some-encrypted-bytes")


def test_decrypt_dek_rejects_wrong_key_or_corrupt_ciphertext(
    master_key: str,
) -> None:
    other_key = Fernet.generate_key()
    wrong_ciphertext = Fernet(other_key).encrypt(b"my-dek-value")

    with pytest.raises(InvalidToken):
        evidence_storage.decrypt_dek(wrong_ciphertext)

    with pytest.raises(InvalidToken):
        evidence_storage.decrypt_dek(b"completely-corrupted-token")


def test_get_encryptor_encrypt_and_decrypt_roundtrip() -> None:
    dek = Fernet.generate_key()
    encryptor = evidence_storage.get_encryptor(dek)

    plaintext = b"top-secret-evidence-payload"
    token = encryptor.encrypt(plaintext)
    assert token != plaintext
    assert encryptor.decrypt(token) == plaintext


# ---------------------------------------------------------------------------
# DB persistence & idempotency tests (record_blob, record_tenant_ref, get_blob_info)
# ---------------------------------------------------------------------------


def test_record_blob_executes_parameterized_insert_and_commits(
    fake_db: FakeConnection,
) -> None:
    content_hash = "a" * 64
    encrypted_dek = b"gAAAAABk-fake-encrypted-dek"
    size_bytes = 4096
    storage_path = "/var/lib/harpocrates/blobs/aa/aaaa"

    evidence_storage.record_blob(content_hash, encrypted_dek, size_bytes, storage_path)

    assert fake_db.commits == 1
    assert len(fake_db.executed) == 1
    sql, params = fake_db.executed[0]
    normalized_sql = " ".join(sql.lower().split())
    assert "insert into blobs (content_hash, encrypted_dek, size_bytes, storage_path)" in normalized_sql
    assert "values (%s, %s, %s, %s)" in normalized_sql
    assert "on conflict (content_hash) do nothing" in normalized_sql
    assert params == (
        content_hash,
        encrypted_dek.decode(),
        size_bytes,
        storage_path,
    )


def test_record_blob_idempotent_on_duplicate_content_hash(
    fake_db: FakeConnection,
) -> None:
    content_hash = "b" * 64
    first_dek = b"gAAAAABk-first-dek"
    second_dek = b"gAAAAABk-second-dek"

    evidence_storage.record_blob(content_hash, first_dek, 1024, "/blobs/first")
    evidence_storage.record_blob(content_hash, second_dek, 9999, "/blobs/second")

    assert fake_db.commits == 2
    assert len(fake_db.executed) == 2
    assert fake_db.executed[0][1] == (content_hash, first_dek.decode(), 1024, "/blobs/first")
    assert fake_db.executed[1][1] == (content_hash, second_dek.decode(), 9999, "/blobs/second")

    # Duplicate content_hash preserves the original blob entry (DO NOTHING)
    info = evidence_storage.get_blob_info(content_hash)
    assert info == {
        "encrypted_dek": first_dek.decode(),
        "storage_path": "/blobs/first",
    }


def test_record_tenant_ref_sql_parameters_and_idempotent_ref_count(
    fake_db: FakeConnection,
) -> None:
    tenant_id = "tenant-alpha"
    content_hash = "c" * 64

    evidence_storage.record_tenant_ref(tenant_id, content_hash)
    evidence_storage.record_tenant_ref(tenant_id, content_hash)

    assert fake_db.commits == 2
    assert len(fake_db.executed) == 2

    for sql, params in fake_db.executed:
        normalized_sql = " ".join(sql.lower().split())
        assert "insert into tenant_blob_refs (tenant_id, content_hash, ref_count)" in normalized_sql
        assert "values (%s, %s, 1)" in normalized_sql
        assert "on conflict (tenant_id, content_hash) do update" in normalized_sql
        assert "set ref_count = tenant_blob_refs.ref_count + 1" in normalized_sql
        assert params == (tenant_id, content_hash)

    assert fake_db.tenant_refs[(tenant_id, content_hash)]["ref_count"] == 2


def test_get_blob_info_returns_none_for_unknown_and_dict_for_known(
    fake_db: FakeConnection,
) -> None:
    unknown_hash = "0" * 64
    known_hash = "d" * 64
    encrypted_dek = b"gAAAAABk-known-dek"
    storage_path = "/blobs/dd/dddd"

    assert evidence_storage.get_blob_info(unknown_hash) is None
    sql, params = fake_db.executed[-1]
    assert "select encrypted_dek, storage_path from blobs where content_hash = %s" in " ".join(
        sql.lower().split()
    )
    assert params == (unknown_hash,)

    evidence_storage.record_blob(known_hash, encrypted_dek, 512, storage_path)
    result = evidence_storage.get_blob_info(known_hash)

    assert result == {
        "encrypted_dek": encrypted_dek.decode(),
        "storage_path": storage_path,
    }
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Reference removal, garbage collection, and concurrency tests
# ---------------------------------------------------------------------------


def test_remove_tenant_ref_decrements_and_deletes(fake_db: FakeConnection, tmp_path: Path):
    evidence_storage.record_blob("hash_1", b"dek", 10, str(tmp_path / "b1"))

    # Add reference twice
    evidence_storage.record_tenant_ref("tenant_a", "hash_1")
    evidence_storage.record_tenant_ref("tenant_a", "hash_1")
    assert fake_db.tenant_refs[("tenant_a", "hash_1")]["ref_count"] == 2

    # First remove decrements ref_count to 1
    assert evidence_storage.remove_tenant_ref("tenant_a", "hash_1") is True
    assert fake_db.tenant_refs[("tenant_a", "hash_1")]["ref_count"] == 1

    # Second remove deletes the reference row
    assert evidence_storage.remove_tenant_ref("tenant_a", "hash_1") is True
    assert ("tenant_a", "hash_1") not in fake_db.tenant_refs

    # Third remove returns False since reference no longer exists
    assert evidence_storage.remove_tenant_ref("tenant_a", "hash_1") is False


def test_blobs_with_remaining_references_are_never_deleted(fake_db: FakeConnection, tmp_path: Path):
    b1_file = tmp_path / "b1.enc"
    b1_file.write_bytes(b"content1")
    evidence_storage.record_blob("hash_1", b"dek1", 8, str(b1_file))

    # Two tenants reference the same blob
    evidence_storage.record_tenant_ref("tenant_a", "hash_1")
    evidence_storage.record_tenant_ref("tenant_b", "hash_1")

    # Tenant A removes reference
    assert evidence_storage.remove_tenant_ref("tenant_a", "hash_1") is True

    # Garbage collector should NOT delete hash_1 because Tenant B still references it
    collected = evidence_storage.collect_unreferenced_blobs(limit=10)
    assert collected == 0
    assert b1_file.exists()
    assert evidence_storage.get_blob_info("hash_1") is not None

    # Tenant B removes reference
    assert evidence_storage.remove_tenant_ref("tenant_b", "hash_1") is True

    # Now hash_1 has zero references, so it should be collected
    collected = evidence_storage.collect_unreferenced_blobs(limit=10)
    assert collected == 1
    assert not b1_file.exists()
    assert evidence_storage.get_blob_info("hash_1") is None


def test_file_deletion_failure_retried_on_next_run(fake_db: FakeConnection, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    b_file = tmp_path / "failing.enc"
    b_file.write_bytes(b"content")
    evidence_storage.record_blob("hash_fail", b"dek", 7, str(b_file))

    should_fail = True
    orig_unlink = os.unlink

    def fake_unlink(path):
        if should_fail and str(path) == str(b_file):
            raise PermissionError("Simulated file lock")
        return orig_unlink(path)

    monkeypatch.setattr(os, "unlink", fake_unlink)

    # First run: unlink fails
    collected = evidence_storage.collect_unreferenced_blobs(limit=10)
    assert collected == 0
    # The blob file and the DB row must be kept intact
    assert b_file.exists()
    assert evidence_storage.get_blob_info("hash_fail") is not None

    # Verify metrics were not incremented
    metrics = metrics_collector.generate_prometheus_metrics()
    assert "harpocrates_retention_deleted_blobs_total 0" in metrics

    # Second run: unlink succeeds
    should_fail = False
    collected = evidence_storage.collect_unreferenced_blobs(limit=10)
    assert collected == 1
    assert not b_file.exists()
    assert evidence_storage.get_blob_info("hash_fail") is None

    # Metrics incremented
    metrics = metrics_collector.generate_prometheus_metrics()
    assert "harpocrates_retention_deleted_blobs_total 1" in metrics
    # Ensure no hashes are leaked in metrics
    assert "hash_fail" not in metrics


def test_concurrent_add_and_collect_race(fake_db: FakeConnection, tmp_path: Path):
    """Simulate race: collector selects unreferenced blob, while concurrent tenant adds reference.

    Row locking ensures the tenant's transaction cannot conflict with unreferenced collection.
    """
    b_file = tmp_path / "race.enc"
    b_file.write_bytes(b"race-data")
    evidence_storage.record_blob("hash_race", b"dek", 9, str(b_file))

    race_barrier = threading.Barrier(2)
    tenant_result = {"status": None}

    def tenant_thread():
        # Wait until collector has selected and locked the candidate row
        race_barrier.wait()
        try:
            # Attempt to record tenant ref while collector transaction is active
            evidence_storage.record_tenant_ref("tenant_race", "hash_race")
            tenant_result["status"] = "success"
        except Exception as e:
            tenant_result["status"] = type(e).__name__

    def collector_hook():
        race_barrier.wait()
        time.sleep(0.05)

    fake_db.before_collector_delete_hook = collector_hook

    t = threading.Thread(target=tenant_thread)
    t.start()

    collected = evidence_storage.collect_unreferenced_blobs(limit=10)
    t.join()

    # Collector successfully deleted the unreferenced blob
    assert collected == 1
    assert not b_file.exists()
    assert evidence_storage.get_blob_info("hash_race") is None


def test_concurrent_add_first_prevents_collection(fake_db: FakeConnection, tmp_path: Path):
    """If tenant adds reference right before collection, the blob is never deleted."""
    b_file = tmp_path / "safe.enc"
    b_file.write_bytes(b"safe-data")
    evidence_storage.record_blob("hash_safe", b"dek", 9, str(b_file))

    # Add reference
    evidence_storage.record_tenant_ref("tenant_safe", "hash_safe")

    # Collector runs
    collected = evidence_storage.collect_unreferenced_blobs(limit=10)
    assert collected == 0
    assert b_file.exists()
    assert evidence_storage.get_blob_info("hash_safe") is not None


def test_collect_unreferenced_blobs_batch_limit(fake_db: FakeConnection, tmp_path: Path):
    # Create 5 unreferenced blobs
    for i in range(5):
        f = tmp_path / f"batch_{i}.enc"
        f.write_bytes(b"x")
        evidence_storage.record_blob(f"hash_{i}", b"dek", 1, str(f))

    # Collect with limit=2
    collected = evidence_storage.collect_unreferenced_blobs(limit=2)
    assert collected == 2
    assert len(fake_db.blobs) == 3

    # Collect next batch with limit=2
    collected = evidence_storage.collect_unreferenced_blobs(limit=2)
    assert collected == 2
    assert len(fake_db.blobs) == 1

    # Collect remaining with limit=2
    collected = evidence_storage.collect_unreferenced_blobs(limit=2)
    assert collected == 1
    assert len(fake_db.blobs) == 0


def test_metrics_do_not_expose_hashes(fake_db: FakeConnection, tmp_path: Path):
    sensitive_hash = "super_secret_evidence_hash_12345"
    f = tmp_path / "secret.enc"
    f.write_bytes(b"data")
    evidence_storage.record_blob(sensitive_hash, b"dek", 4, str(f))

    evidence_storage.collect_unreferenced_blobs(limit=10)

    metrics = metrics_collector.generate_prometheus_metrics()
    assert sensitive_hash not in metrics
    assert "super_secret" not in metrics
    assert "harpocrates_retention_deleted_blobs_total 1" in metrics


class EvidenceStorageUnittestSuite(unittest.TestCase):
    """Unittest-compatible test case so `python -m unittest discover` also exercises the suite."""

    def setUp(self) -> None:
        self.conn = FakeConnection()

        @contextmanager
        def _fake_get_connection():
            yield self.conn

        self._conn_patch = patch.object(
            evidence_storage.db, "get_connection", _fake_get_connection
        )
        self._conn_patch.start()
        self.master_key = Fernet.generate_key().decode("ascii")
        self._env_patch = patch.dict(
            os.environ, {"MASTER_ENCRYPTION_KEY": self.master_key}, clear=False
        )
        self._env_patch.start()

    def tearDown(self) -> None:
        self._env_patch.stop()
        self._conn_patch.stop()

    def test_end_to_end_blob_lifecycle_without_postgres(self) -> None:
        dek, encrypted_dek = evidence_storage.generate_dek()
        encryptor = evidence_storage.get_encryptor(dek)
        ciphertext = encryptor.encrypt(b"evidence-bytes")

        content_hash = "e" * 64
        self.assertIsNone(evidence_storage.get_blob_info(content_hash))

        evidence_storage.record_blob(content_hash, encrypted_dek, len(ciphertext), "/blobs/ee")
        evidence_storage.record_blob(content_hash, b"ignored-duplicate", 0, "/blobs/other")
        evidence_storage.record_tenant_ref("tenant-1", content_hash)
        evidence_storage.record_tenant_ref("tenant-1", content_hash)

        blob_info = evidence_storage.get_blob_info(content_hash)
        self.assertEqual(
            blob_info,
            {
                "encrypted_dek": encrypted_dek.decode(),
                "storage_path": "/blobs/ee",
            },
        )
        unwrapped_dek = evidence_storage.decrypt_dek(
            blob_info["encrypted_dek"].encode("ascii")
        )
        self.assertEqual(unwrapped_dek, dek)
        self.assertEqual(
            evidence_storage.get_encryptor(unwrapped_dek).decrypt(ciphertext),
            b"evidence-bytes",
        )


if __name__ == "__main__":
    unittest.main()
