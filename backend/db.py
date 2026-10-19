from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from tracing import job_trace_context, span

logger = logging.getLogger(__name__)

# Max page size for GET /api/proofs cursor pagination.
PROOF_EVENTS_MAX_LIMIT = 100
PROOF_EVENTS_DEFAULT_LIMIT = 25
# Default retention page size, used when a caller does not pass one.
RETENTION_BATCH_DEFAULT_SIZE = 100
# Upper bound for a retention page; must match config.RETENTION_BATCH_SIZE_MAX.
RETENTION_BATCH_MAX_SIZE = 5000

# Libpq / Postgres connection-class SQLSTATEs that are typically transient on
# Neon (cold start, compute wake, brief network blips, pooler pressure).
_TRANSIENT_SQLSTATES = frozenset(
    {
        "08000",  # connection_exception
        "08001",  # sqlclient_unable_to_establish_sqlconnection
        "08003",  # connection_does_not_exist
        "08004",  # sqlserver_rejected_establishment_of_sqlconnection
        "08006",  # connection_failure
        "08007",  # transaction_resolution_unknown
        "57P01",  # admin_shutdown
        "57P02",  # crash_shutdown
        "57P03",  # cannot_connect_now (Neon compute starting)
        "53300",  # too_many_connections
        "53400",  # configuration_limit_exceeded
    }
)

_TRANSIENT_MESSAGE_FRAGMENTS = (
    "timeout expired",
    "timed out",
    "connection timed out",
    "connection refused",
    "connection reset",
    "server closed the connection",
    "could not connect",
    "ssl connection has been closed",
    "the database system is starting up",
    "the database system is in recovery mode",
    "remaining connection slots",
    "temporary failure",
    "broken pipe",
    "connection terminated",
    "terminating connection due to administrator command",
    "compute is not active",
    "couldn't connect to compute",
    "error connecting to compute node",
)


def encode_proof_events_cursor(event_id: int) -> str:
    """Return a stable opaque cursor for the given proof_events.id."""
    return base64.urlsafe_b64encode(str(event_id).encode("ascii")).decode("ascii")


def decode_proof_events_cursor(cursor: str) -> int:
    """Decode an opaque proof-events cursor.

    Raises ValueError when the cursor is malformed.
    """
    if not isinstance(cursor, str) or not cursor.strip():
        raise ValueError("invalid cursor")

    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        text = raw.decode("ascii")
        event_id = int(text)
    except (ValueError, UnicodeDecodeError, binascii.Error, TypeError) as exc:
        raise ValueError("invalid cursor") from exc

    if event_id < 1:
        raise ValueError("invalid cursor")
    return event_id


def clamp_proof_events_limit(limit: int) -> int:
    return max(1, min(limit, PROOF_EVENTS_MAX_LIMIT))


def database_url() -> str | None:
    return os.getenv("DATABASE_URL")


def _positive_float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    value = float(raw)
    if value <= 0.0:
        raise RuntimeError(f"{name} must be positive")
    return value


def _positive_int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    value = int(raw)
    if value <= 0:
        raise RuntimeError(f"{name} must be positive")
    return value


def db_connect_timeout_seconds() -> float:
    """Per-attempt libpq connect timeout (seconds)."""
    return _positive_float_env("DB_CONNECT_TIMEOUT_SECONDS", 5.0)


def db_connect_deadline_seconds() -> float:
    """Overall wall-clock budget for connect + retries (seconds)."""
    return _positive_float_env("DB_CONNECT_DEADLINE_SECONDS", 15.0)


def db_connect_max_attempts() -> int:
    """Maximum connect attempts within the deadline."""
    return _positive_int_env("DB_CONNECT_MAX_ATTEMPTS", 4)


def db_connect_retry_base_seconds() -> float:
    """Base backoff before the first retry (doubles each attempt)."""
    return _positive_float_env("DB_CONNECT_RETRY_BASE_SECONDS", 0.05)


def is_transient_neon_connect_error(exc: BaseException) -> bool:
    """Return True when *exc* looks like a transient Neon/Postgres connect failure.

    Classification is intentionally conservative: auth failures, syntax errors,
    and other permanent faults are not retried. Never inspect or return the
    connection string — only error class / SQLSTATE / sanitized message text.
    """
    if isinstance(exc, (TimeoutError, ConnectionError, BrokenPipeError, OSError)):
        # OSError covers many socket-level connect failures; exclude permission
        # errors which are not transient.
        if isinstance(exc, PermissionError):
            return False
        return True

    sqlstate = getattr(exc, "sqlstate", None)
    if isinstance(sqlstate, str) and sqlstate in _TRANSIENT_SQLSTATES:
        return True

    if isinstance(exc, psycopg.OperationalError):
        message = str(exc).lower()
        if any(fragment in message for fragment in _TRANSIENT_MESSAGE_FRAGMENTS):
            return True
        # OperationalError without a permanent marker is treated as transient
        # for the connect path only (Neon wake / pooler flaps).
        permanent_markers = (
            "password authentication failed",
            "authentication failed",
            "no password supplied",
            "certificate verify failed",
            "could not translate host name",
        )
        if any(marker in message for marker in permanent_markers):
            return False
        return True

    return False


def _connect_with_retry(url: str) -> psycopg.Connection:
    """Open a psycopg connection, retrying transient Neon failures until deadline.

    Privacy: never logs ``DATABASE_URL`` or credentials — only attempt counts,
    SQLSTATE, and exception class names.
    """
    deadline_at = time.monotonic() + db_connect_deadline_seconds()
    per_attempt_timeout = db_connect_timeout_seconds()
    max_attempts = db_connect_max_attempts()
    retry_base = db_connect_retry_base_seconds()
    last_exc: BaseException | None = None

    for attempt in range(1, max_attempts + 1):
        remaining = deadline_at - time.monotonic()
        if remaining <= 0:
            break

        connect_timeout = max(1, int(min(per_attempt_timeout, remaining)))
        try:
            return psycopg.connect(
                url,
                row_factory=dict_row,
                connect_timeout=connect_timeout,
            )
        except Exception as exc:  # noqa: BLE001 — classify then re-raise
            last_exc = exc
            transient = is_transient_neon_connect_error(exc)
            sqlstate = getattr(exc, "sqlstate", None)
            logger.warning(
                "neon_connect_attempt_failed attempt=%s/%s transient=%s sqlstate=%s error_type=%s",
                attempt,
                max_attempts,
                transient,
                sqlstate,
                type(exc).__name__,
            )
            if not transient:
                raise

            remaining = deadline_at - time.monotonic()
            if remaining <= 0 or attempt >= max_attempts:
                break

            sleep_for = min(retry_base * (2 ** (attempt - 1)), max(0.0, remaining / 2.0))
            if sleep_for > 0:
                time.sleep(sleep_for)

    message = "database connection deadline exceeded"
    if last_exc is None:
        raise RuntimeError(message)
    raise RuntimeError(message) from last_exc


@contextmanager
def get_connection() -> Iterator[psycopg.Connection]:
    """Yield a Postgres connection with Neon-aware transient connect retries.

    Callers keep the existing interface. Connect attempts honour
    ``DB_CONNECT_TIMEOUT_SECONDS`` per try and ``DB_CONNECT_DEADLINE_SECONDS``
    overall so readiness / request paths stay bounded.
    """
    with span("db.connection", attributes={"db.system.name": "postgresql"}):
        url = database_url()
        if not url:
            raise RuntimeError("DATABASE_URL is not configured")

        connection = _connect_with_retry(url)
        try:
            yield connection
        finally:
            connection.close()


def init_db() -> None:
    """Initialise the database schema via the versioned migration system.

    This replaces the earlier inline ``CREATE TABLE IF NOT EXISTS`` approach
    with an ordered, auditable migration ledger.  Safe to call repeatedly.

    Before any pending migration is applied, the recorded checksum of every
    already-applied migration is replayed against its in-code definition; a
    mismatch raises ``migration.MigrationChecksumError`` so a drifted ledger
    cannot silently start serving traffic.  Set
    ``MIGRATION_CHECKSUM_ENFORCEMENT=warn`` only as a temporary break-glass
    rollback while the ledger is reconciled.
    """
    from migration import run_migrations  # late import to avoid cycles

    run_migrations()


def verify_migration_checksums() -> list[dict[str, object]]:
    """Return applied migrations whose recorded checksum no longer matches.

    Each dict has keys ``migration_id``, ``name``, ``issue``, ``expected`` and
    ``recorded``.  An empty list means every applied migration is intact.
    Read-only; intended for startup diagnostics and operational tooling.
    """
    from migration import verify_migration_checksums as _verify

    return [
        {
            "migration_id": issue.migration_id,
            "name": issue.name,
            "issue": issue.issue,
            "expected": issue.expected,
            "recorded": issue.recorded,
        }
        for issue in _verify()
    ]


def detect_drift() -> list[dict[str, str]]:
    """Check for schema drift and return a list of issues.

    Each dict has keys ``table_name``, ``issue``, ``detail``."""
    from migration import detect_drift as _detect_drift

    return [
        {"table_name": d.table_name, "issue": d.issue, "detail": d.detail}
        for d in _detect_drift()
    ]


def get_migration_report() -> list[dict[str, object]]:
    """Return the list of migrations and their current status.

    Useful for health-check endpoints and operational observability."""
    from migration import run_migrations

    return run_migrations()


def check_db() -> bool:
    if not database_url():
        return False

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("select 1 as ok")
            row = cursor.fetchone()
            return bool(row and row["ok"] == 1)


def insert_lineage_event(
    *,
    manifest_digest: str,
    manifest: dict[str, Any],
    actor_address: str,
    parent_proof_ids: list[str],
) -> dict[str, Any] | None:
    if not database_url():
        return None

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                insert into lineage_events (manifest_digest, manifest, actor_address, parent_proof_ids)
                values (%s, %s, %s, %s)
                on conflict (manifest_digest) do nothing
                returning id, manifest_digest, created_at;
                """,
                (manifest_digest, Jsonb(manifest), actor_address, parent_proof_ids),
            )
            row = cursor.fetchone()
        connection.commit()
        return dict(row) if row else None


def list_lineage_events(limit: int = 25) -> list[dict[str, Any]]:
    if not database_url():
        return []

    limit = max(1, min(limit, 100))
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select id, manifest_digest, manifest, actor_address, parent_proof_ids, created_at
                from lineage_events
                order by id desc
                limit %s;
                """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]


def find_lineage_by_output_digest(output_digest: str) -> dict[str, Any] | None:
    """Find lineage record by the output digest of the derivative.
    
    Args:
        output_digest: The output digest (32-byte hex string)
    
    Returns:
        Lineage record or None if not found
    """
    if not database_url():
        return None

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select id, manifest_digest, manifest, actor_address, parent_proof_ids, created_at
                from lineage_events
                where (manifest ->> 'outputDigest') = %s
                limit 1;
                """,
                (output_digest,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None


def find_lineage_by_actor(actor_address: str, limit: int = 25) -> list[dict[str, Any]]:
    """Find lineage records by actor address with pagination.
    
    Args:
        actor_address: The actor's address
        limit: Maximum number of records to return (bounded to 100)
    
    Returns:
        List of lineage records
    """
    if not database_url():
        return []

    limit = max(1, min(limit, 100))
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select id, manifest_digest, manifest, actor_address, parent_proof_ids, created_at
                from lineage_events
                where actor_address = %s
                order by id desc
                limit %s;
                """,
                (actor_address, limit),
            )
            return [dict(row) for row in cursor.fetchall()]


def insert_proof_event(
    *,
    event_type: str,
    file_name: str | None = None,
    video_hash: str | None = None,
    metadata_hash: str | None = None,
    proof_id: str | None = None,
    tier: str | None = None,
    embedded_hash: str | None = None,
    tx_hash: str | None = None,
    tx_status: str | None = None,
    source_address: str | None = None,
    contract_id: str | None = None,
    retention_class: str | None = None,
    expires_at: datetime | None = None,
    metadata: dict[str, Any] | None = None,
    time_attestation: dict[str, Any] | None = None,
    claimed_capture_time: str | None = None,
) -> dict[str, Any] | None:
    if not database_url():
        return None

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                insert into proof_events (
                    event_type,
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    embedded_hash,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    retention_class,
                    expires_at,
                    metadata,
                    time_attestation,
                    claimed_capture_time
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                returning id, created_at;
                """,
                (
                    event_type,
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    embedded_hash,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    retention_class,
                    expires_at,
                    Jsonb(metadata) if metadata is not None else None,
                    Jsonb(time_attestation) if time_attestation is not None else None,
                    claimed_capture_time,
                ),
            )
            row = cursor.fetchone()
        connection.commit()
        return dict(row) if row else None


def list_proof_events(
    limit: int = PROOF_EVENTS_DEFAULT_LIMIT,
    *,
    cursor_id: int | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """List proof events with stable keyset (cursor) pagination.

    Ordering is deterministic: ``id DESC`` (primary key is the unique tie-breaker).
    Returns ``(events, next_cursor)`` where ``next_cursor`` is an opaque token for
    the next page, or ``None`` when there are no further rows.
    """
    if not database_url():
        return [], None

    page_size = clamp_proof_events_limit(limit)
    fetch_size = page_size + 1

    with get_connection() as connection:
        with connection.cursor() as cursor:
            if cursor_id is None:
                cursor.execute(
                    """
                    select
                        id,
                        event_type,
                        file_name,
                        video_hash,
                        metadata_hash,
                        proof_id,
                        tier,
                        embedded_hash,
                        tx_hash,
                        tx_status,
                        source_address,
                        contract_id,
                        metadata,
                        time_attestation,
                        claimed_capture_time,
                        created_at
                    from proof_events
                    order by id desc
                    limit %s;
                    """,
                    (fetch_size,),
                )
            else:
                cursor.execute(
                    """
                    select
                        id,
                        event_type,
                        file_name,
                        video_hash,
                        metadata_hash,
                        proof_id,
                        tier,
                        embedded_hash,
                        tx_hash,
                        tx_status,
                        source_address,
                        contract_id,
                        metadata,
                        time_attestation,
                        claimed_capture_time,
                        created_at
                    from proof_events
                    where id < %s
                    order by id desc
                    limit %s;
                    """,
                    (cursor_id, fetch_size),
                )
            rows = [dict(row) for row in cursor.fetchall()]

    next_cursor: str | None = None
    if len(rows) > page_size:
        rows = rows[:page_size]
        next_cursor = encode_proof_events_cursor(int(rows[-1]["id"]))
    return rows, next_cursor


def find_proof_events_by_video(
    video_hash: str,
    limit: int = PROOF_EVENTS_DEFAULT_LIMIT,
    *,
    cursor_id: int | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    if not database_url():
        return [], None

    page_size = clamp_proof_events_limit(limit)
    fetch_size = page_size + 1

    with get_connection() as connection:
        with connection.cursor() as cursor:
            if cursor_id is None:
                cursor.execute(
                    """
                    select
                        id,
                        event_type,
                        file_name,
                        video_hash,
                        metadata_hash,
                        proof_id,
                        tier,
                        embedded_hash,
                        tx_hash,
                        tx_status,
                        source_address,
                        contract_id,
                        retention_class,
                        expires_at,
                        legal_hold,
                        metadata,
                        time_attestation,
                        claimed_capture_time,
                        created_at
                    from proof_events
                    where video_hash = %s
                    order by id desc
                    limit %s;
                    """,
                    (video_hash, fetch_size),
                )
            else:
                cursor.execute(
                    """
                    select
                        id,
                        event_type,
                        file_name,
                        video_hash,
                        metadata_hash,
                        proof_id,
                        tier,
                        embedded_hash,
                        tx_hash,
                        tx_status,
                        source_address,
                        contract_id,
                        retention_class,
                        expires_at,
                        legal_hold,
                        metadata,
                        time_attestation,
                        claimed_capture_time,
                        created_at
                    from proof_events
                    where video_hash = %s
                      and id < %s
                    order by id desc
                    limit %s;
                    """,
                    (video_hash, cursor_id, fetch_size),
                )
            rows = [dict(row) for row in cursor.fetchall()]

    next_cursor: str | None = None
    if len(rows) > page_size:
        rows = rows[:page_size]
        next_cursor = encode_proof_events_cursor(int(rows[-1]["id"]))
    return rows, next_cursor


def find_proof_owner(proof_id: str) -> str | None:
    """Return the ``source_address`` that first registered ``proof_id``.

    The earliest register event with a recorded address is authoritative, so a
    later event cannot re-assign ownership. Returns ``None`` when the proof is
    unknown, was registered without an address, or no database is configured
    (the same stub behaviour as :func:`upsert_register_event`). Database errors
    propagate so callers can fail closed instead of guessing.
    """
    if not database_url():
        return None

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select source_address
                from proof_events
                where proof_id = %s
                  and event_type = 'register'
                  and source_address is not null
                order by id asc
                limit 1;
                """,
                (proof_id,),
            )
            row = cursor.fetchone()
    return row["source_address"] if row else None


def make_idempotency_key(video_hash: str, proof_id: str, tx_hash: str | None) -> str:
    """Derive the idempotency key for a register event.

    Key material: ``video_hash:proof_id:tx_hash`` where ``tx_hash`` defaults
    to the empty string when absent.  Using SHA-256 keeps the stored value a
    fixed-length hex string and avoids any length-extension ambiguity.
    """
    raw = f"{video_hash}:{proof_id}:{tx_hash or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()


# Fields compared when deciding whether a retry carries a conflicting payload.
_CONFLICT_FIELDS = ("video_hash", "metadata_hash", "proof_id", "tier", "source_address", "contract_id")


def upsert_register_event(
    *,
    idempotency_key: str,
    file_name: str | None = None,
    video_hash: str | None = None,
    metadata_hash: str | None = None,
    proof_id: str | None = None,
    tier: str | None = None,
    tx_hash: str | None = None,
    tx_status: str | None = None,
    source_address: str | None = None,
    contract_id: str | None = None,
    retention_class: str | None = None,
    expires_at: datetime | None = None,
    metadata: dict[str, Any] | None = None,
    time_attestation: dict[str, Any] | None = None,
    claimed_capture_time: str | None = None,
) -> tuple[dict[str, Any], bool]:
    """Insert a register event idempotently.

    Returns ``(row, created)`` where *created* is ``True`` when a new row was
    written and ``False`` when an existing row was found via the idempotency
    key.

    Raises ``ConflictError`` when the same idempotency key is reused with a
    payload that differs in one of the canonical proof-identity fields.

    The insert is done with ``ON CONFLICT DO NOTHING`` so that concurrent
    requests with the same key race safely: only one writer wins and the
    other falls back to the ``SELECT`` path.
    """
    if not database_url():
        # When no database is configured return a stub so the rest of the app
        # remains functional in minimal dev environments.
        stub: dict[str, Any] = {
            "id": None,
            "created_at": None,
            "video_hash": video_hash,
            "metadata_hash": metadata_hash,
            "proof_id": proof_id,
            "tier": tier,
            "source_address": source_address,
            "contract_id": contract_id,
            "retention_class": retention_class,
            "expires_at": expires_at,
            "legal_hold": False,
        }
        return stub, True

    with get_connection() as connection:
        with connection.cursor() as cursor:
            # Attempt the insert; if the unique key already exists the row is
            # silently skipped and nothing is returned.
            cursor.execute(
                """
                insert into proof_events (
                    event_type,
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    retention_class,
                    expires_at,
                    metadata,
                    time_attestation,
                    claimed_capture_time,
                    idempotency_key
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                on conflict (idempotency_key)
                where idempotency_key is not null
                do nothing
                returning
                    id,
                    event_type,
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    embedded_hash,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    retention_class,
                    expires_at,
                    legal_hold,
                    metadata,
                    time_attestation,
                    claimed_capture_time,
                    created_at;
                """,
                (
                    "register",
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    retention_class,
                    expires_at,
                    Jsonb(metadata) if metadata is not None else None,
                    Jsonb(time_attestation) if time_attestation is not None else None,
                    claimed_capture_time,
                    idempotency_key,
                ),
            )
            row = cursor.fetchone()

            if row is not None:
                # Fresh insert – committed below.
                connection.commit()
                return dict(row), True

            # Key already existed (concurrent insert or retry): fetch the
            # previously stored row.
            cursor.execute(
                """
                select
                    id,
                    event_type,
                    file_name,
                    video_hash,
                    metadata_hash,
                    proof_id,
                    tier,
                    embedded_hash,
                    tx_hash,
                    tx_status,
                    source_address,
                    contract_id,
                    retention_class,
                    expires_at,
                    legal_hold,
                    metadata,
                    time_attestation,
                    claimed_capture_time,
                    created_at
                from proof_events
                where idempotency_key = %s;
                """,
                (idempotency_key,),
            )
            existing = cursor.fetchone()

        # No commit needed for the read-only fallback path; any uncommitted
        # state is just the no-op insert.
        connection.rollback()

    if existing is None:
        # Should not happen – the constraint guarantees the row is visible.
        raise RuntimeError("idempotency key collision but row not found; please retry")

    existing_row = dict(existing)

    # Check whether the caller is re-submitting with a conflicting payload.
    incoming = {
        "video_hash": video_hash,
        "metadata_hash": metadata_hash,
        "proof_id": proof_id,
        "tier": tier,
        "source_address": source_address,
        "contract_id": contract_id,
    }
    for field in _CONFLICT_FIELDS:
        if existing_row.get(field) != incoming.get(field):
            raise ConflictError(
                idempotency_key=idempotency_key,
                field=field,
                existing_value=existing_row.get(field),
                incoming_value=incoming.get(field),
            )

    return existing_row, False


class ConflictError(Exception):
    """Raised when the same idempotency key is reused with a conflicting payload."""

    def __init__(
        self,
        *,
        idempotency_key: str,
        field: str,
        existing_value: object,
        incoming_value: object,
    ) -> None:
        super().__init__(
            f"idempotency key reused with conflicting value for '{field}'"
        )
        self.idempotency_key = idempotency_key
        self.field = field
        self.existing_value = existing_value
        self.incoming_value = incoming_value


def insert_proof_history_event(
    *,
    proof_id: str,
    action: str,
    actor: str | None = None,
    reason_code: int,
    contract_id: str | None = None,
    tx_hash: str | None = None,
    tx_status: str | None = None,
) -> dict[str, Any] | None:
    if not database_url():
        return None

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                insert into proof_history_events (
                    proof_id,
                    action,
                    actor,
                    reason_code,
                    contract_id,
                    tx_hash,
                    tx_status
                )
                values (%s, %s, %s, %s, %s, %s, %s)
                returning id, created_at;
                """,
                (
                    proof_id,
                    action,
                    actor,
                    reason_code,
                    contract_id,
                    tx_hash,
                    tx_status,
                ),
            )
            row = cursor.fetchone()
        connection.commit()
        return dict(row) if row else None


def list_proof_history_events(
    proof_id: str, limit: int = 50, offset: int = 0
) -> list[dict[str, Any]]:
    if not database_url():
        return []

    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select
                    id,
                    proof_id,
                    action,
                    actor,
                    reason_code,
                    contract_id,
                    tx_hash,
                    tx_status,
                    created_at
                from proof_history_events
                where proof_id = %s
                order by id asc
                limit %s offset %s;
                """,
                (proof_id, limit, offset),
            )
            return [dict(row) for row in cursor.fetchall()]

def list_pending_registration_txs(limit: int = 50) -> list[dict[str, Any]]:
    """Return pending registration rows that still need on-chain reconciliation."""
    if not database_url():
        return []
    page_size = max(1, min(int(limit), 50))
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select id, proof_id, tx_hash, tx_status, contract_id, created_at
                from proof_events
                where tx_hash is not null
                  and tx_status = 'pending'
                order by id asc
                limit %s;
                """,
                (page_size,),
            )
            return [dict(row) for row in cursor.fetchall()]


def update_tx_status(tx_hash: str, status: str, *, force: bool = False) -> bool:
    """Persist a reconciled tx status.

    By default only transitions rows that are still ``pending`` so terminal
    confirmations are idempotent and concurrent workers do not clobber each
    other. Pass ``force=True`` to overwrite a terminal status (repair path).

    Returns True when at least one row was updated.
    """
    if not database_url():
        return False
    if not isinstance(tx_hash, str) or not tx_hash.strip():
        return False
    if status not in {"pending", "confirmed", "failed", "missing"}:
        raise ValueError("tx status must be pending, confirmed, failed, or missing")

    with get_connection() as connection:
        with connection.cursor() as cursor:
            if force:
                cursor.execute(
                    """
                    update proof_events
                    set tx_status = %s
                    where tx_hash = %s;
                    """,
                    (status, tx_hash),
                )
            else:
                cursor.execute(
                    """
                    update proof_events
                    set tx_status = %s
                    where tx_hash = %s
                      and (tx_status is null or tx_status = 'pending');
                    """,
                    (status, tx_hash),
                )
            updated = cursor.rowcount > 0
        connection.commit()
    return updated


def set_legal_hold(proof_id: str, hold: bool) -> None:
    """Set or clear the legal-hold flag on a proof event."""
    if not database_url():
        return
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                update proof_events
                set legal_hold = %s
                where proof_id = %s;
                """,
                (hold, proof_id),
            )
        connection.commit()


def count_expired_events() -> int:
    """Return how many proof events ``purge_expired_events`` would delete.

    Read-only; uses the same filter as the purge so retention dry runs match.
    """
    if not database_url():
        return 0
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                select count(*) as expired
                from proof_events
                where expires_at is not null
                  and expires_at <= now()
                  and legal_hold = false;
                """
            )
            row = cursor.fetchone()
    return int(row["expired"]) if row else 0


def purge_expired_events(batch_size: int = RETENTION_BATCH_DEFAULT_SIZE) -> list[dict[str, Any]]:
    """Delete proof events past their expiration that are not on legal hold.

    Returns a list of deletion receipts (proof_id, deleted_at, etc.) for
    each purged event.
    """
    if not database_url():
        return []
    batch_size = max(1, min(batch_size, RETENTION_BATCH_MAX_SIZE))
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                with expired as (
                    select id, proof_id, video_hash, metadata_hash
                    from proof_events
                    where expires_at is not null
                      and expires_at <= now()
                      and legal_hold = false
                    order by id
                    limit %s
                    for update skip locked
                ), deleted as (
                    delete from proof_events
                    using expired
                    where proof_events.id = expired.id
                    returning proof_events.id, proof_events.proof_id,
                              proof_events.video_hash, proof_events.metadata_hash
                )
                insert into deletion_receipts (event_id, proof_id, video_hash, metadata_hash)
                select id, proof_id, video_hash, metadata_hash
                from deleted
                returning id, event_id, proof_id, video_hash, metadata_hash, deleted_at;
                """,
                (batch_size,),
            )
            receipts = [dict(row) for row in cursor.fetchall()]
        connection.commit()
    return receipts


_JOBS: dict[int, dict[str, Any]] = {}
_next_job_id = 1


def enqueue_job(job_type: str, payload: dict[str, Any]) -> int:
    """Enqueue a background job and return its job id."""
    global _next_job_id
    job_id = _next_job_id
    _next_job_id += 1
    _JOBS[job_id] = {
        "id": job_id,
        "type": job_type,
        "payload": payload,
        "_trace_context": job_trace_context(),
        "status": "pending",
        "result": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    return job_id


def get_job(job_id: int) -> dict[str, Any] | None:
    """Return a job by id, or None."""
    return _JOBS.get(job_id)


def cancel_job(job_id: int) -> bool:
    """Cancel a pending job. Returns True on success."""
    job = _JOBS.get(job_id)
    if job and job["status"] == "pending":
        job["status"] = "cancelled"
        return True
    return False


def lease_job(
    worker_id: str,
    job_types: list[str],
    lease_duration: int = 300,
) -> dict[str, Any] | None:
    """Lease the next pending in-memory job matching ``job_types``."""
    del lease_duration  # in-memory queue has no TTL enforcement yet
    for job in _JOBS.values():
        if job.get("status") == "pending" and job.get("type") in job_types:
            job["status"] = "running"
            job["worker_id"] = worker_id
            return dict(job)
    return None


def heartbeat_job(job_id: int, progress: float = 0.0, lease_duration: int = 300) -> None:
    """Record a heartbeat against an in-memory job lease."""
    del lease_duration
    job = _JOBS.get(job_id)
    if job and job.get("status") == "running":
        job["progress"] = progress
        job["heartbeat_at"] = datetime.now(timezone.utc).isoformat()


def complete_job(job_id: int, result: Any = None) -> None:
    """Mark an in-memory job completed."""
    job = _JOBS.get(job_id)
    if not job:
        return
    job["status"] = "completed"
    job["result"] = result
    job["completed_at"] = datetime.now(timezone.utc).isoformat()


def fail_job(job_id: int, error: str, *, is_fatal: bool = False) -> None:
    """Mark an in-memory job failed (fatal) or pending for retry."""
    job = _JOBS.get(job_id)
    if not job:
        return
    job["error"] = error
    job["failed_at"] = datetime.now(timezone.utc).isoformat()
    if is_fatal:
        job["status"] = "failed"
    else:
        job["status"] = "pending"
        job.pop("worker_id", None)


def get_job_queue_metrics() -> dict[str, Any]:
    """Return counts per job type and state plus the age of the oldest queued job.

    Cheap aggregate query grouped by type and status, utilizing the jobs index.
    Skips gracefully (returns empty data) when no database is configured or
    when the database query fails.

    Returns:
        dict with:
            "counts": {(type, state): count, ...}
            "oldest_queued_seconds": {type: seconds, ...}
    """
    if not database_url():
        return {"counts": {}, "oldest_queued_seconds": {}}

    try:
        with get_connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        type,
                        status AS state,
                        COUNT(*) AS count,
                        EXTRACT(EPOCH FROM (NOW() - MIN(created_at))) FILTER (WHERE status = 'pending') AS oldest_queued_seconds
                    FROM jobs
                    GROUP BY type, status;
                    """
                )
                rows = cursor.fetchall()
    except Exception as exc:
        logger.warning("Failed to query job queue metrics: %s", exc)
        return {"counts": {}, "oldest_queued_seconds": {}}

    counts: dict[tuple[str, str], int] = {}
    oldest_queued: dict[str, float] = {}

    for row in rows:
        if isinstance(row, dict):
            j_type = str(row.get("type", ""))
            state = str(row.get("state") or row.get("status", ""))
            cnt = int(row.get("count", 0))
            oldest_sec = row.get("oldest_queued_seconds")
        elif hasattr(row, "__getitem__"):
            try:
                j_type = str(row["type"])
                state = str(row["state"] if "state" in row else row["status"])
                cnt = int(row["count"])
                oldest_sec = row.get("oldest_queued_seconds") if hasattr(row, "get") else row["oldest_queued_seconds"]
            except (KeyError, TypeError):
                j_type = str(row[0])
                state = str(row[1])
                cnt = int(row[2])
                oldest_sec = row[3] if len(row) > 3 else None
        else:
            continue

        if not j_type or not state:
            continue

        counts[(j_type, state)] = cnt
        if oldest_sec is not None:
            oldest_queued[j_type] = max(0.0, float(oldest_sec))

    for j_type, _ in counts:
        if j_type not in oldest_queued:
            oldest_queued[j_type] = 0.0

    return {
        "counts": counts,
        "oldest_queued_seconds": oldest_queued,
    }


get_job_metrics = get_job_queue_metrics
