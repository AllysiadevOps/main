"""Unit tests for backend/evidence_storage.py without a live Postgres database."""

from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet, InvalidToken
import pytest

_BACKEND_DIR = str(Path(__file__).resolve().parent)
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import evidence_storage


class FakeRow(dict):
    """Row mapping returned by FakeCursor.fetchone()."""


class FakeCursor:
    """In-memory fake cursor capturing SQL statements, parameters, and state."""

    def __init__(self, connection: "FakeConnection") -> None:
        self.connection = connection
        self.executed: list[tuple[str, tuple]] = []
        self._last_row: FakeRow | None = None

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
            if content_hash not in self.connection.blobs:
                self.connection.blobs[content_hash] = {
                    "content_hash": content_hash,
                    "encrypted_dek": encrypted_dek,
                    "size_bytes": size_bytes,
                    "storage_path": storage_path,
                }
            self._last_row = None

        elif normalized.startswith("insert into tenant_blob_refs"):
            tenant_id, content_hash = params
            key = (tenant_id, content_hash)
            # ON CONFLICT (tenant_id, content_hash) DO UPDATE SET ref_count = ref_count + 1
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
            blob = self.connection.blobs.get(content_hash)
            if blob is None:
                self._last_row = None
            else:
                self._last_row = FakeRow(
                    encrypted_dek=blob["encrypted_dek"],
                    storage_path=blob["storage_path"],
                )

    def fetchone(self) -> FakeRow | None:
        return self._last_row


class FakeConnection:
    """In-memory fake Postgres connection supporting cursor context managers."""

    def __init__(self) -> None:
        self.blobs: dict[str, dict] = {}
        self.tenant_refs: dict[tuple[str, str], dict] = {}
        self.cursors: list[FakeCursor] = []
        self.commits: int = 0

    @property
    def executed(self) -> list[tuple[str, tuple]]:
        return [call for cur in self.cursors for call in cur.executed]

    def cursor(self) -> FakeCursor:
        cur = FakeCursor(self)
        self.cursors.append(cur)
        return cur

    def commit(self) -> None:
        self.commits += 1


@pytest.fixture
def fake_db(monkeypatch: pytest.MonkeyPatch) -> FakeConnection:
    """Fixture providing a fake db.get_connection context manager and connection."""
    conn = FakeConnection()

    @contextmanager
    def _fake_get_connection():
        yield conn

    monkeypatch.setattr(evidence_storage.db, "get_connection", _fake_get_connection)
    return conn


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
    # Generated DEK is a valid Fernet key
    encryptor = evidence_storage.get_encryptor(dek)
    assert encryptor.decrypt(encryptor.encrypt(b"probe")) == b"probe"


def test_decrypt_dek_raises_when_master_key_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MASTER_ENCRYPTION_KEY", raising=False)
    with pytest.raises(ValueError, match="MASTER_ENCRYPTION_KEY is not set"):
        evidence_storage.decrypt_dek(b"encrypted-token")


def test_decrypt_dek_rejects_wrong_master_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_a = Fernet.generate_key().decode("ascii")
    key_b = Fernet.generate_key().decode("ascii")

    monkeypatch.setenv("MASTER_ENCRYPTION_KEY", key_a)
    _, encrypted_dek = evidence_storage.generate_dek()

    monkeypatch.setenv("MASTER_ENCRYPTION_KEY", key_b)
    with pytest.raises(InvalidToken):
        evidence_storage.decrypt_dek(encrypted_dek)


def test_get_encryptor_encrypt_decrypt_roundtrip(master_key: str) -> None:
    dek, _ = evidence_storage.generate_dek()
    encryptor = evidence_storage.get_encryptor(dek)

    plaintext = b"content-addressed evidence payload"
    ciphertext = encryptor.encrypt(plaintext)

    assert ciphertext != plaintext
    assert encryptor.decrypt(ciphertext) == plaintext

    other_dek = Fernet.generate_key()
    other_encryptor = evidence_storage.get_encryptor(other_dek)
    with pytest.raises(InvalidToken):
        other_encryptor.decrypt(ciphertext)


# ---------------------------------------------------------------------------
# Database storage helper tests (record_blob, record_tenant_ref, get_blob_info)
# ---------------------------------------------------------------------------


def test_record_blob_sql_parameters_and_commit(fake_db: FakeConnection) -> None:
    content_hash = "a" * 64
    encrypted_dek = b"gAAAAABk-wrapped-dek-token"
    size_bytes = 4096
    storage_path = "/var/harpocrates/blobs/aa/aaaa"

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
