"""Tests for the ``manage.py`` operator CLI.

Unit tests mock the underlying DB functions per subcommand. The integration
test runs each subcommand against a real Postgres (``TEST_DATABASE_URL``) and
is skipped when one is not reachable.
"""

from __future__ import annotations

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

import manage
from migration import (
    MIGRATIONS,
    DriftEntry,
    MigrationChecksumError,
    MigrationChecksumIssue,
)

SECRET_URL = "postgresql://operator:s3cr3t-pass@db.internal:5432/harpocrates"


@pytest.fixture(autouse=True)
def database_url(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", SECRET_URL)


def run(capsys, *argv):
    code = manage.main(list(argv))
    out = capsys.readouterr().out
    assert "s3cr3t-pass" not in out
    assert SECRET_URL not in out
    return code, out


def run_json(capsys, *argv):
    code, out = run(capsys, "--json", *argv)
    return code, json.loads(out)


def _issue(kind="checksum_mismatch"):
    return MigrationChecksumIssue(
        migration_id=1, name="create proof_events table", issue=kind,
        expected="a" * 64, recorded="b" * 64,
    )


# --- migrate ---------------------------------------------------------------


@patch("migration.run_migrations")
def test_migrate_applies_and_exits_zero(mock_run, capsys):
    mock_run.return_value = [
        {"migration_id": 1, "name": "one", "action": "skipped", "checksum_status": "verified"},
        {"migration_id": 2, "name": "two", "action": "applied", "checksum_status": "verified"},
    ]
    code, payload = run_json(capsys, "migrate")
    assert code == manage.EXIT_OK
    assert payload["ok"] is True
    assert payload["applied"] == 1
    assert len(payload["migrations"]) == 2
    mock_run.assert_called_once_with()


@patch("migration.run_migrations")
def test_migrate_checksum_error_exits_one(mock_run, capsys):
    mock_run.side_effect = MigrationChecksumError([_issue()])
    code, payload = run_json(capsys, "migrate")
    assert code == manage.EXIT_PROBLEMS
    assert payload["ok"] is False
    assert payload["checksum_issues"][0]["issue"] == "checksum_mismatch"


@patch("migration.run_migrations")
def test_migrate_warn_mode_mismatch_still_exits_one(mock_run, capsys):
    mock_run.return_value = [
        {"migration_id": 1, "name": "one", "action": "skipped",
         "checksum_status": "checksum_mismatch"},
    ]
    code, payload = run_json(capsys, "migrate")
    assert code == manage.EXIT_PROBLEMS
    assert payload["ok"] is False


@patch("migration._applied_migrations")
@patch("migration.verify_migration_checksums", return_value=[])
def test_migrate_check_reports_pending_without_applying(mock_verify, mock_applied, capsys):
    mock_applied.return_value = {m.id for m in MIGRATIONS[:-1]}
    with patch("migration.run_migrations") as mock_run:
        code, payload = run_json(capsys, "migrate", "--check")
    mock_run.assert_not_called()
    assert code == manage.EXIT_OK
    assert payload["check"] is True
    assert payload["checksum_issues"] == []
    assert payload["pending"] == [{"migration_id": MIGRATIONS[-1].id, "name": MIGRATIONS[-1].name}]


@patch("migration._applied_migrations", return_value=set())
@patch("migration.verify_migration_checksums")
def test_migrate_check_mismatch_exits_one(mock_verify, mock_applied, capsys):
    mock_verify.return_value = [_issue()]
    code, payload = run_json(capsys, "migrate", "--check")
    assert code == manage.EXIT_PROBLEMS
    assert payload["ok"] is False
    assert payload["checksum_issues"][0]["migration_id"] == 1


# --- drift -----------------------------------------------------------------


@patch("migration.detect_drift", return_value=[])
def test_drift_clean_exits_zero(mock_drift, capsys):
    code, payload = run_json(capsys, "drift")
    assert code == manage.EXIT_OK
    assert payload == {"command": "drift", "ok": True, "drift": []}


@patch("migration.detect_drift")
def test_drift_detected_exits_one(mock_drift, capsys):
    mock_drift.return_value = [
        DriftEntry(table_name="blobs", issue="missing_table",
                   detail="Expected table 'blobs' does not exist"),
    ]
    code, payload = run_json(capsys, "drift")
    assert code == manage.EXIT_PROBLEMS
    assert payload["drift"][0]["issue"] == "missing_table"


# --- retention -------------------------------------------------------------


@patch("db.purge_expired_events")
@patch("db.count_expired_events", return_value=7)
def test_retention_dry_run_counts_without_deleting(mock_count, mock_purge, capsys):
    code, payload = run_json(capsys, "retention", "--dry-run")
    assert code == manage.EXIT_OK
    assert payload["dry_run"] is True
    assert payload["expired"] == 7
    mock_purge.assert_not_called()


@patch("db.purge_expired_events")
def test_retention_run_purges_until_short_batch(mock_purge, capsys):
    mock_purge.side_effect = [[{"id": 1}, {"id": 2}], [{"id": 3}]]
    code, payload = run_json(capsys, "retention", "--run", "--batch-size", "2")
    assert code == manage.EXIT_OK
    assert payload["deleted"] == 3
    assert payload["batches"] == 2
    assert all(c.kwargs == {"batch_size": 2} for c in mock_purge.call_args_list)


def test_retention_requires_a_mode(capsys):
    with pytest.raises(SystemExit) as exc:
        manage.main(["retention"])
    assert exc.value.code == manage.EXIT_USAGE


# --- reconcile -------------------------------------------------------------


def test_reconcile_passes_limit(capsys):
    stub = MagicMock()
    stub.reconcile_pending_registrations.return_value = {
        "ok": True,
        "summary": {"scanned": 1, "confirmed": 1, "updated": 1},
        "minConfirmations": 1,
        "results": [{"txHash": "ab" * 32, "status": "confirmed", "updated": True}],
    }
    with patch.dict(sys.modules, {"registration_reconcile": stub}):
        code, payload = run_json(capsys, "reconcile", "--limit", "5")
    assert code == manage.EXIT_OK
    assert payload["summary"]["confirmed"] == 1
    stub.reconcile_pending_registrations.assert_called_once_with(limit=5)


def test_reconcile_rejects_non_positive_limit(capsys):
    with pytest.raises(SystemExit) as exc:
        manage.main(["reconcile", "--limit", "0"])
    assert exc.value.code == manage.EXIT_USAGE


# --- configuration, errors, and redaction ----------------------------------


def test_missing_database_url_exits_three(monkeypatch, capsys):
    monkeypatch.delenv("DATABASE_URL")
    code, payload = run_json(capsys, "drift")
    assert code == manage.EXIT_NOT_CONFIGURED
    assert payload["ok"] is False


@patch("migration.detect_drift")
def test_unexpected_error_reports_type_only(mock_drift, capsys):
    mock_drift.side_effect = RuntimeError(f"could not connect to {SECRET_URL}")
    code, payload = run_json(capsys, "drift")
    assert code == manage.EXIT_ERROR
    assert payload["error"] == "RuntimeError"


@patch("migration.detect_drift")
def test_text_output_is_redacted(mock_drift, capsys):
    mock_drift.return_value = [
        DriftEntry(table_name="blobs", issue="missing_table",
                   detail=f"seen at {SECRET_URL} password=hunter2"),
    ]
    code, out = run(capsys, "drift")
    assert code == manage.EXIT_PROBLEMS
    assert "missing_table" in out
    assert "hunter2" not in out
    assert manage.REDACTED in out


def test_redact_strips_url_credentials_and_secret_pairs(monkeypatch):
    monkeypatch.delenv("DATABASE_URL")
    text = manage.redact("postgres://u:p@h/db host=h password=x token=y")
    assert "u:p@" not in text
    assert "password=x" not in text
    assert "token=y" not in text
    assert "host=h" in text


# --- against a real test database -------------------------------------------


@pytest.fixture
def test_database(monkeypatch):
    db_url = os.environ.get("TEST_DATABASE_URL") or "postgresql://postgres:password@localhost:5432/postgres"
    monkeypatch.setenv("DATABASE_URL", db_url)
    try:
        from db import check_db
        check_db()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"Database connection failed: {type(exc).__name__}")
    return db_url


@pytest.mark.integration
def test_subcommands_against_test_database(test_database, capsys):
    for argv in (
        ["migrate"],
        ["migrate", "--check"],
        ["drift"],
        ["retention", "--dry-run"],
        ["retention", "--run"],
    ):
        code = manage.main(["--json", *argv])
        out = capsys.readouterr().out
        assert code == manage.EXIT_OK, (argv, out)
        assert json.loads(out)["ok"] is True
        assert test_database not in out


@pytest.mark.integration
def test_reconcile_against_test_database(test_database, capsys):
    try:
        import registration_reconcile as reconcile
    except ImportError as exc:
        pytest.skip(f"registration_reconcile unavailable: {exc}")
    with patch.object(reconcile, "verify_transaction"):
        code = manage.main(["--json", "reconcile", "--limit", "1"])
    out = capsys.readouterr().out
    assert code == manage.EXIT_OK, out
    assert "summary" in json.loads(out)
    assert test_database not in out
