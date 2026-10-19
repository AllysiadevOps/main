"""Tests for SessionReplayGuard nonce generation and replay protection.

Covers:
- Fresh nonce verifies once and a second use is reported as a duplicate (replay).
- Unknown, malformed, empty, oversized, and non-printable nonces are rejected
  with documented SessionReplayOutcome.
- Nonce expiration after nonce_ttl window.
- Session window tracking, event count limits, and session expiration.
- Capacity limits (max_nonces / storage_full) and pruning behaviour.
- Guard stats tracking (nonce_count, session_count, total_processed) and reset.
- is_valid_outcome check for documented valid outcomes.
- Thread-safety across concurrent verifications.
- Deterministic synthetic timestamps without real-time sleeps.
"""

from __future__ import annotations

import concurrent.futures

from analytics.session_protection import (
    MAX_REPLAY_WINDOW_SECONDS,
    NONCE_TTL_SECONDS,
    REPLAY_PROTECTION_VERSION,
    SessionReplayGuard,
    SessionReplayOutcome,
)


def test_guard_initialization_defaults():
    guard = SessionReplayGuard()
    assert guard.max_replay_window == MAX_REPLAY_WINDOW_SECONDS
    assert guard.nonce_ttl == NONCE_TTL_SECONDS
    assert guard.max_nonces == 16_384
    assert guard.max_session_events == 512
    assert guard.max_nonce_length == 256

    stats = guard.stats()
    assert stats == {
        "nonce_count": 0,
        "session_count": 0,
        "total_processed": 0,
    }


def test_guard_custom_initialization():
    guard = SessionReplayGuard(
        max_replay_window=100.0,
        nonce_ttl=200.0,
        max_nonces=50,
        max_session_events=10,
        max_nonce_length=32,
    )
    assert guard.max_replay_window == 100.0
    assert guard.nonce_ttl == 200.0
    assert guard.max_nonces == 50
    assert guard.max_session_events == 10
    assert guard.max_nonce_length == 32


def test_generate_nonce_format():
    guard = SessionReplayGuard()
    nonce1 = guard.generate_nonce()
    nonce2 = guard.generate_nonce("sess-1")

    assert isinstance(nonce1, str)
    assert isinstance(nonce2, str)
    assert nonce1.startswith("n-v1:")
    assert nonce2.startswith("n-v1:")
    # n-v1: prefix (5 chars) + 16 hex chars = 21 chars
    assert len(nonce1) == 21
    assert len(nonce2) == 21
    assert nonce1 != nonce2


def test_fresh_nonce_verifies_once_and_replay_reported():
    guard = SessionReplayGuard(nonce_ttl=300.0)
    nonce = guard.generate_nonce()
    now = 1_000_000.0

    # First verification is NEW
    outcome1 = guard.verify_and_record(nonce, now_epoch=now)
    assert outcome1 == SessionReplayOutcome.NEW
    assert guard.is_valid_outcome(outcome1) is True

    # Immediate second verification is DUPLICATE (replay)
    outcome2 = guard.verify_and_record(nonce, now_epoch=now + 1.0)
    assert outcome2 == SessionReplayOutcome.DUPLICATE
    assert guard.is_valid_outcome(outcome2) is False

    # Still DUPLICATE within TTL
    outcome3 = guard.verify_and_record(nonce, now_epoch=now + 299.0)
    assert outcome3 == SessionReplayOutcome.DUPLICATE


def test_nonce_expired_after_ttl_when_not_pruned():
    guard = SessionReplayGuard(nonce_ttl=300.0)
    nonce = "n-v1:test-ttl"
    start_time = 1_000_000.0

    res = guard.verify_and_record(nonce, now_epoch=start_time)
    assert res == SessionReplayOutcome.NEW

    # If verify_and_record is called with now >= start_time + nonce_ttl,
    # note that _prune is called with (now), which will delete nonces where now - recorded > ttl.
    # When now - recorded == ttl exactly, (now - recorded > ttl) is False in _prune,
    # but in verify_and_record: age < ttl is False, so it returns EXPIRED.
    res_exact = guard.verify_and_record(nonce, now_epoch=start_time + 300.0)
    assert res_exact == SessionReplayOutcome.EXPIRED
    assert guard.is_valid_outcome(res_exact) is True


def test_nonce_pruned_after_ttl():
    guard = SessionReplayGuard(nonce_ttl=300.0)
    nonce = "n-v1:test-prune"
    start_time = 1_000_000.0

    res = guard.verify_and_record(nonce, now_epoch=start_time)
    assert res == SessionReplayOutcome.NEW

    # Advance time beyond nonce_ttl; _prune will prune the nonce
    later_time = start_time + 301.0
    res_pruned = guard.verify_and_record(nonce, now_epoch=later_time)
    # Since it was pruned, it is treated as a new nonce again
    assert res_pruned == SessionReplayOutcome.NEW


def test_malformed_and_invalid_nonces():
    guard = SessionReplayGuard(max_nonce_length=32)

    # Empty nonce
    assert guard.verify_and_record("") == SessionReplayOutcome.INVALID_NONCE

    # Non-string types
    assert guard.verify_and_record(None) == SessionReplayOutcome.INVALID_NONCE  # type: ignore[arg-type]
    assert guard.verify_and_record(12345) == SessionReplayOutcome.INVALID_NONCE  # type: ignore[arg-type]
    assert guard.verify_and_record(["n-v1:list"]) == SessionReplayOutcome.INVALID_NONCE  # type: ignore[arg-type]

    # Non-printable characters
    assert guard.verify_and_record("nonce\x00withnull") == SessionReplayOutcome.INVALID_NONCE
    assert guard.verify_and_record("nonce\x07bell") == SessionReplayOutcome.INVALID_NONCE
    assert guard.verify_and_record("nonce\x1bescape") == SessionReplayOutcome.INVALID_NONCE
    assert guard.verify_and_record("nonce\u200bzero_width") == SessionReplayOutcome.INVALID_NONCE

    # Oversized nonce
    long_nonce = "a" * 33
    assert guard.verify_and_record(long_nonce) == SessionReplayOutcome.OVERSIZED_NONCE

    # Boundary: exactly max length should pass validation
    exact_nonce = "a" * 32
    assert guard.verify_and_record(exact_nonce, now_epoch=100.0) == SessionReplayOutcome.NEW


def test_session_lifecycle_and_limits():
    guard = SessionReplayGuard(
        max_replay_window=60.0,
        nonce_ttl=300.0,
        max_session_events=3,
        max_nonce_length=32,
    )
    now = 500.0
    session = "session-123"

    # Event 1: NEW
    out1 = guard.verify_and_record("nonce-1", session_tag=session, now_epoch=now)
    assert out1 == SessionReplayOutcome.NEW

    # Event 2: NEW
    out2 = guard.verify_and_record("nonce-2", session_tag=session, now_epoch=now + 10.0)
    assert out2 == SessionReplayOutcome.NEW

    # Event 3: NEW (hits max_session_events = 3)
    out3 = guard.verify_and_record("nonce-3", session_tag=session, now_epoch=now + 20.0)
    assert out3 == SessionReplayOutcome.NEW

    # Event 4: Exceeds max_session_events -> SESSION_TOO_LONG
    out4 = guard.verify_and_record("nonce-4", session_tag=session, now_epoch=now + 30.0)
    assert out4 == SessionReplayOutcome.SESSION_TOO_LONG

    # Stats reflect processed events
    st = guard.stats()
    assert st["session_count"] == 1
    assert st["nonce_count"] == 4
    assert st["total_processed"] == 4


def test_session_tag_oversized():
    guard = SessionReplayGuard(max_nonce_length=10)
    # session_len > max_nonce_length * 2 (20 bytes)
    long_session = "s" * 21
    outcome = guard.verify_and_record("nonce-1", session_tag=long_session, now_epoch=100.0)
    assert outcome == SessionReplayOutcome.SESSION_TOO_LONG


def test_session_expired_replay_window():
    guard = SessionReplayGuard(
        max_replay_window=50.0,
        nonce_ttl=500.0,
        max_session_events=10,
    )
    now = 1000.0
    session = "session-expire"

    out1 = guard.verify_and_record("nonce-1", session_tag=session, now_epoch=now)
    assert out1 == SessionReplayOutcome.NEW

    # Event after replay window (51s > 50s max_replay_window)
    # The session is expired; the nonce itself was recorded in _nonces.
    out2 = guard.verify_and_record("nonce-2", session_tag=session, now_epoch=now + 51.0)
    # Note: _prune prunes session when now - timestamp > max_replay_window.
    # At now + 51.0, prune cleans up the old session timestamp and count,
    # so session becomes fresh if pruned, OR if not pruned age > window returns EXPIRED.
    # Let's verify behavior: _prune runs at start of verify_and_record.
    # Since now + 51.0 - 1000.0 = 51.0 > 50.0, _prune removes session from _session_timestamps!
    # Therefore, session_tag not in _session_timestamps -> re-initialized as fresh.
    assert out2 == SessionReplayOutcome.NEW

    # Now verify when prune does not remove it (e.g. exactly at edge or inside window)
    out3 = guard.verify_and_record("nonce-3", session_tag=session, now_epoch=now + 80.0)
    assert out3 == SessionReplayOutcome.NEW


def test_session_expired_outcome_without_pruning():
    guard = SessionReplayGuard(max_replay_window=100.0, nonce_ttl=500.0)
    now = 1000.0
    session = "session-no-prune"

    guard.verify_and_record("nonce-1", session_tag=session, now_epoch=now)

    # Manually set session timestamp to simulate elapsed time without triggering _prune
    guard._session_timestamps[session] = now - 150.0
    # Now verify a new nonce but bypass prune by patching or direct call
    # Here, let's call verify_and_record: _prune runs with now=now.
    # In _prune: now - _session_timestamps[session] = 1000 - 850 = 150 > 100 -> pruned!
    # To test SessionReplayOutcome.EXPIRED for session directly:
    guard._session_timestamps[session] = now - 100.0001
    # If we check with now=now, but prevent _prune from deleting it by setting max_prune=0:
    original_prune = guard._prune
    guard._prune = lambda *args, **kwargs: None  # disable pruning temporarily
    try:
        outcome = guard.verify_and_record("nonce-subsequent", session_tag=session, now_epoch=now)
        assert outcome == SessionReplayOutcome.EXPIRED
    finally:
        guard._prune = original_prune


def test_prune_max_prune_limit():
    guard = SessionReplayGuard(nonce_ttl=10.0, max_replay_window=10.0)
    now = 100.0

    # Add 5 expired nonces and 5 expired sessions
    for i in range(5):
        guard._nonces[f"nonce-{i}"] = now - 20.0
        guard._session_timestamps[f"sess-{i}"] = now - 20.0
        guard._session_counts[f"sess-{i}"] = 1

    # Prune with max_prune=2 (breaks in nonce loop)
    guard._prune(now, max_prune=2)
    assert len(guard._nonces) == 3

    # Reset and test break in session loop
    guard._nonces.clear()
    guard._session_timestamps.clear()
    guard._session_counts.clear()

    # 1 expired nonce, 3 expired sessions, max_prune=2
    guard._nonces["single-nonce"] = now - 20.0
    for i in range(3):
        guard._session_timestamps[f"sess-{i}"] = now - 20.0
        guard._session_counts[f"sess-{i}"] = 1

    guard._prune(now, max_prune=2)
    # 1 nonce pruned, 1 session pruned, 2 sessions left
    assert len(guard._nonces) == 0
    assert len(guard._session_timestamps) == 2


def test_capacity_limits_storage_full():
    guard = SessionReplayGuard(
        max_nonces=3,
        nonce_ttl=1000.0,
    )
    now = 100.0

    assert guard.verify_and_record("nonce-1", now_epoch=now) == SessionReplayOutcome.NEW
    assert guard.verify_and_record("nonce-2", now_epoch=now) == SessionReplayOutcome.NEW
    assert guard.verify_and_record("nonce-3", now_epoch=now) == SessionReplayOutcome.NEW

    # 4th nonce exceeds max_nonces (3) -> STORAGE_FULL
    assert guard.verify_and_record("nonce-4", now_epoch=now) == SessionReplayOutcome.STORAGE_FULL

    stats = guard.stats()
    assert stats["nonce_count"] == 3


def test_capacity_pruning_frees_space():
    guard = SessionReplayGuard(
        max_nonces=2,
        nonce_ttl=50.0,
    )
    now = 100.0

    assert guard.verify_and_record("nonce-1", now_epoch=now) == SessionReplayOutcome.NEW
    assert guard.verify_and_record("nonce-2", now_epoch=now) == SessionReplayOutcome.NEW
    assert guard.verify_and_record("nonce-3", now_epoch=now) == SessionReplayOutcome.STORAGE_FULL

    # Advance time so nonce-1 and nonce-2 expire and are pruned
    now_later = now + 60.0
    # Next verification triggers prune, freeing capacity
    assert guard.verify_and_record("nonce-3", now_epoch=now_later) == SessionReplayOutcome.NEW
    assert guard.stats()["nonce_count"] == 1


def test_is_valid_outcome():
    guard = SessionReplayGuard()

    # Valid outcomes for permit
    assert guard.is_valid_outcome(SessionReplayOutcome.NEW) is True
    assert guard.is_valid_outcome(SessionReplayOutcome.EXPIRED) is True
    assert guard.is_valid_outcome(SessionReplayOutcome.SESSION_TOO_LONG) is True

    # Invalid outcomes for permit
    assert guard.is_valid_outcome(SessionReplayOutcome.DUPLICATE) is False
    assert guard.is_valid_outcome(SessionReplayOutcome.OVERSIZED_NONCE) is False
    assert guard.is_valid_outcome(SessionReplayOutcome.INVALID_NONCE) is False
    assert guard.is_valid_outcome(SessionReplayOutcome.MAX_BUCKETS_EXCEEDED) is False
    assert guard.is_valid_outcome(SessionReplayOutcome.STORAGE_FULL) is False
    assert guard.is_valid_outcome("unknown_string") is False


def test_stats_and_reset():
    guard = SessionReplayGuard()
    now = 200.0

    guard.verify_and_record("n1", session_tag="sess-A", now_epoch=now)
    guard.verify_and_record("n2", session_tag="sess-A", now_epoch=now)
    guard.verify_and_record("n3", session_tag="sess-B", now_epoch=now)

    st = guard.stats()
    assert st["nonce_count"] == 3
    assert st["session_count"] == 2
    assert st["total_processed"] == 3

    guard.reset()
    st_reset = guard.stats()
    assert st_reset == {
        "nonce_count": 0,
        "session_count": 0,
        "total_processed": 0,
    }

    # Verify that previously used nonces can be re-recorded after reset
    outcome = guard.verify_and_record("n1", session_tag="sess-A", now_epoch=now)
    assert outcome == SessionReplayOutcome.NEW


def test_concurrent_nonce_verifications():
    guard = SessionReplayGuard(max_nonces=5000, nonce_ttl=600.0)
    now = 5000.0
    num_threads = 8
    nonces_per_thread = 50

    all_nonces = [[f"nonce-{t}-{i}" for i in range(nonces_per_thread)] for t in range(num_threads)]

    def worker(nonces: list[str]) -> list[str]:
        results = []
        for n in nonces:
            r = guard.verify_and_record(n, session_tag="concurrent-sess", now_epoch=now)
            results.append(r)
        return results

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, nonces) for nonces in all_nonces]
        for f in concurrent.futures.as_completed(futures):
            results = f.result()
            # Every distinct nonce should verify as NEW
            assert all(r == SessionReplayOutcome.NEW for r in results)

    stats = guard.stats()
    assert stats["nonce_count"] == num_threads * nonces_per_thread
    assert stats["session_count"] == 1
    assert stats["total_processed"] == num_threads * nonces_per_thread

    # Replay of the exact same nonces concurrently must all be DUPLICATE
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, nonces) for nonces in all_nonces]
        for f in concurrent.futures.as_completed(futures):
            results = f.result()
            assert all(r == SessionReplayOutcome.DUPLICATE for r in results)


def test_module_constants_and_error():
    assert REPLAY_PROTECTION_VERSION == "1.0.0"
    from analytics.session_protection import SessionReplayError

    err = SessionReplayError("Replay error occurred", SessionReplayOutcome.DUPLICATE)
    assert str(err) == "Replay error occurred"
    assert err.outcome == SessionReplayOutcome.DUPLICATE
