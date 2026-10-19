"""Operator command-line entry point for database maintenance tasks.

Usage (run from ``backend/`` with ``DATABASE_URL`` set)::

    python manage.py [--json] migrate [--check]
    python manage.py [--json] drift
    python manage.py [--json] retention (--dry-run | --run) [--batch-size N]
    python manage.py [--json] reconcile [--limit N]

Exit codes:

    0  success, no problems found
    1  schema drift detected or migration checksum mismatch
    2  invalid command-line usage
    3  DATABASE_URL is not configured
    4  unexpected error (e.g. database unreachable); only the error type is shown

Privacy: output never includes connection strings, credentials, or secrets.
Every line is passed through :func:`redact` before it is written, and
unexpected exceptions are reported by type name only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict
from typing import Any, Callable

EXIT_OK = 0
EXIT_PROBLEMS = 1
EXIT_USAGE = 2
EXIT_NOT_CONFIGURED = 3
EXIT_ERROR = 4

REDACTED = "[REDACTED]"

# ``scheme://user:password@host`` -> ``scheme://[REDACTED]@host``
_URL_CREDENTIALS = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^\s/@]+@")
# libpq keyword/value style secrets, e.g. ``password=hunter2``.
_SECRET_PAIRS = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api_key|apikey|sslpassword)=\S+"
)


def redact(text: str) -> str:
    """Strip connection strings and credential-looking values from *text*."""
    url = os.getenv("DATABASE_URL")
    if url:
        text = text.replace(url, REDACTED)
    text = _URL_CREDENTIALS.sub(rf"\1{REDACTED}@", text)
    return _SECRET_PAIRS.sub(rf"\1={REDACTED}", text)


def _positive_int(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a positive integer") from None
    if value < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


# ---------------------------------------------------------------------------
# Subcommands. Each returns ``(exit_code, payload)``; modules are imported
# lazily so a subcommand only requires the dependencies it actually uses.
# ---------------------------------------------------------------------------


def _cmd_migrate(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    import migration

    if args.check:
        issues = [asdict(issue) for issue in migration.verify_migration_checksums()]
        applied = migration._applied_migrations()
        pending = [
            {"migration_id": m.id, "name": m.name}
            for m in migration.MIGRATIONS
            if m.id not in applied
        ]
        payload = {
            "command": "migrate",
            "check": True,
            "ok": not issues,
            "checksum_issues": issues,
            "pending": pending,
        }
        return (EXIT_PROBLEMS if issues else EXIT_OK), payload

    try:
        results = migration.run_migrations()
    except migration.MigrationChecksumError as exc:
        return EXIT_PROBLEMS, {
            "command": "migrate",
            "ok": False,
            "error": "MigrationChecksumError",
            "checksum_issues": [asdict(issue) for issue in exc.issues],
        }

    mismatched = [r for r in results if r.get("checksum_status") != "verified"]
    payload = {
        "command": "migrate",
        "ok": not mismatched,
        "applied": sum(1 for r in results if r.get("action") == "applied"),
        "migrations": results,
    }
    return (EXIT_PROBLEMS if mismatched else EXIT_OK), payload


def _cmd_drift(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    import migration

    drifts = [asdict(entry) for entry in migration.detect_drift()]
    payload = {"command": "drift", "ok": not drifts, "drift": drifts}
    return (EXIT_PROBLEMS if drifts else EXIT_OK), payload


def _cmd_retention(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    import db

    if args.dry_run:
        return EXIT_OK, {
            "command": "retention",
            "ok": True,
            "dry_run": True,
            "expired": db.count_expired_events(),
        }

    batch_size = args.batch_size
    if batch_size is None:
        from config import load_config

        batch_size = load_config().retention_batch_size

    deleted = 0
    batches = 0
    while True:
        receipts = db.purge_expired_events(batch_size=batch_size)
        batches += 1
        deleted += len(receipts)
        if len(receipts) < batch_size:
            break

    return EXIT_OK, {
        "command": "retention",
        "ok": True,
        "dry_run": False,
        "batch_size": batch_size,
        "batches": batches,
        "deleted": deleted,
    }


def _cmd_reconcile(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    import registration_reconcile

    report = registration_reconcile.reconcile_pending_registrations(limit=args.limit)
    return EXIT_OK, {
        "command": "reconcile",
        "ok": bool(report.get("ok", True)),
        "summary": report.get("summary", {}),
        "min_confirmations": report.get("minConfirmations"),
        "results": report.get("results", []),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="manage.py",
        description="Harpocrates database maintenance commands.",
    )
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    migrate = sub.add_parser("migrate", help="apply pending migrations")
    migrate.add_argument(
        "--check",
        action="store_true",
        help="verify checksums and list pending migrations without applying",
    )
    migrate.set_defaults(handler=_cmd_migrate)

    drift = sub.add_parser("drift", help="compare the live schema with the expected schema")
    drift.set_defaults(handler=_cmd_drift)

    retention = sub.add_parser("retention", help="purge expired proof events")
    mode = retention.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="count expired events only")
    mode.add_argument("--run", action="store_true", help="delete expired events")
    retention.add_argument(
        "--batch-size",
        type=_positive_int,
        default=None,
        help="rows per purge batch (default: HARPOCRATES_RETENTION_BATCH_SIZE)",
    )
    retention.set_defaults(handler=_cmd_retention)

    reconcile = sub.add_parser("reconcile", help="reconcile pending registration txs")
    reconcile.add_argument(
        "--limit",
        type=_positive_int,
        default=50,
        help="maximum pending rows to reconcile (capped at 50)",
    )
    reconcile.set_defaults(handler=_cmd_reconcile)

    return parser


def _format_value(value: Any) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items())
    return str(value)


def _render_text(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    for key, value in payload.items():
        if isinstance(value, list):
            lines.append(f"{key}: {len(value)}")
            lines.extend(f"  - {_format_value(item)}" for item in value)
        else:
            lines.append(f"{key}: {_format_value(value)}")
    return "\n".join(lines)


def _emit(payload: dict[str, Any], as_json: bool, write: Callable[[str], Any]) -> None:
    text = json.dumps(payload, default=str, sort_keys=True) if as_json else _render_text(payload)
    write(redact(text) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)  # exits with EXIT_USAGE (2) on bad usage
    write = sys.stdout.write

    if not os.getenv("DATABASE_URL"):
        _emit(
            {"command": args.command, "ok": False, "error": "DATABASE_URL is not configured"},
            args.json,
            write,
        )
        return EXIT_NOT_CONFIGURED

    try:
        code, payload = args.handler(args)
    except Exception as exc:  # noqa: BLE001 - report type only, never the message
        _emit(
            {"command": args.command, "ok": False, "error": type(exc).__name__},
            args.json,
            write,
        )
        return EXIT_ERROR

    _emit(payload, args.json, write)
    return code


if __name__ == "__main__":
    sys.exit(main())
