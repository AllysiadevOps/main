"""Tests for telemetry consent lifecycle in backend/analytics/consent.py.

Covers:
- ConsentDecision validation (valid/invalid status and source)
- ConsentState lifecycle (is_active, requires_scope, to_decision)
- ConsentManager consent checks with injected now_epoch_seconds (grace period, scope checks, expiry)
- ConsentManager grant / set_consent (new, updated, idempotent)
- ConsentManager withdrawal (existing and new accounts)
- ConsentManager invalidation (existing and new accounts)
- ConsentManager prune_expired respecting grace period and max_to_prune
- ConsentManager generate_consent_token stability and account tag redaction
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

backend_dir = str(Path(__file__).resolve().parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import pytest

from analytics.consent import (
    CONSENT_GRACE_PERIOD_SECONDS,
    CONSENT_SCHEMA_VERSION,
    ConsentDecision,
    ConsentManager,
    ConsentSource,
    ConsentStatus,
    ConsentState,
    DEFAULT_CONSENT_STATE,
)


# ===========================================================================
# ConsentDecision tests
# ===========================================================================


class TestConsentDecision:
    """Verifies ConsentDecision instantiation and validation."""

    def test_valid_decision(self) -> None:
        decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry", "error_reporting"],
            expires_at_epoch_seconds=1_800_000_000.0,
            granted_at_epoch_seconds=1_700_000_000.0,
            version=CONSENT_SCHEMA_VERSION,
            consent_token="cst-v1:abcdef1234567890abcdef12",
            withdrawal_epoch_seconds=None,
            reason="user_opt_in",
            stable_account_tag="acct_12345",
        )
        assert decision.status == ConsentStatus.GRANTED
        assert decision.source == ConsentSource.USER_EXPLICIT
        assert decision.scope == ["telemetry", "error_reporting"]
        assert decision.expires_at_epoch_seconds == 1_800_000_000.0
        assert decision.granted_at_epoch_seconds == 1_700_000_000.0
        assert decision.version == CONSENT_SCHEMA_VERSION
        assert decision.consent_token == "cst-v1:abcdef1234567890abcdef12"
        assert decision.withdrawal_epoch_seconds is None
        assert decision.reason == "user_opt_in"
        assert decision.stable_account_tag == "acct_12345"

    def test_invalid_status_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="invalid consent status: invalid_status"):
            ConsentDecision(
                status="invalid_status",
                source=ConsentSource.USER_EXPLICIT,
                scope=[],
                expires_at_epoch_seconds=0.0,
                granted_at_epoch_seconds=0.0,
            )

    def test_invalid_source_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="invalid consent source: invalid_source"):
            ConsentDecision(
                status=ConsentStatus.GRANTED,
                source="invalid_source",
                scope=[],
                expires_at_epoch_seconds=0.0,
                granted_at_epoch_seconds=0.0,
            )


# ===========================================================================
# ConsentState tests
# ===========================================================================


class TestConsentState:
    """Verifies ConsentState behavior: is_active, requires_scope, to_decision."""

    @pytest.mark.parametrize(
        ("status", "expected_active"),
        [
            (ConsentStatus.GRANTED, True),
            (ConsentStatus.GRACE, True),
            (ConsentStatus.EXPIRED, False),
            (ConsentStatus.WITHDRAWN, False),
            (ConsentStatus.INVALID, False),
            (ConsentStatus.DENIED, False),
            (ConsentStatus.UNKNOWN, False),
        ],
    )
    def test_is_active_by_status(self, status: str, expected_active: bool) -> None:
        state = ConsentState(
            account_tag="acct_test",
            status=status,
            source=ConsentSource.USER_EXPLICIT,
        )
        assert state.is_active() is expected_active
        # Injected now_epoch_seconds must also never report expired as active
        assert state.is_active(now_epoch_seconds=1_000_000.0) is expected_active

    def test_default_consent_state_not_active(self) -> None:
        assert DEFAULT_CONSENT_STATE.is_active() is False
        assert DEFAULT_CONSENT_STATE.status == ConsentStatus.UNKNOWN
        assert DEFAULT_CONSENT_STATE.source == ConsentSource.SYSTEM_DEFAULT

    def test_requires_scope_when_granted(self) -> None:
        state = ConsentState(
            account_tag="acct_test",
            status=ConsentStatus.GRANTED,
            granted_scopes=["telemetry", "diagnostics"],
        )
        assert state.requires_scope("telemetry") is True
        assert state.requires_scope("diagnostics") is True
        assert state.requires_scope("profiling") is False

    def test_requires_scope_wildcard(self) -> None:
        state = ConsentState(
            account_tag="acct_test",
            status=ConsentStatus.GRANTED,
            granted_scopes=["*"],
        )
        assert state.requires_scope("telemetry") is True
        assert state.requires_scope("anything") is True

    @pytest.mark.parametrize(
        "status",
        [
            ConsentStatus.GRACE,
            ConsentStatus.DENIED,
            ConsentStatus.EXPIRED,
            ConsentStatus.WITHDRAWN,
            ConsentStatus.INVALID,
            ConsentStatus.UNKNOWN,
        ],
    )
    def test_requires_scope_false_when_not_granted(self, status: str) -> None:
        state = ConsentState(
            account_tag="acct_test",
            status=status,
            granted_scopes=["telemetry", "*"],
        )
        assert state.requires_scope("telemetry") is False

    def test_to_decision(self) -> None:
        state = ConsentState(
            account_tag="acct_123",
            status=ConsentStatus.GRANTED,
            source=ConsentSource.API_REQUEST,
            granted_at_epoch_seconds=1_000.0,
            expires_at_epoch_seconds=2_000.0,
            withdrawal_epoch_seconds=None,
            granted_scopes=["telemetry", "metrics"],
            consent_token="cst-v1:1234567890abcdef12345678",
            version=CONSENT_SCHEMA_VERSION,
        )
        decision = state.to_decision()
        assert decision.status == ConsentStatus.GRANTED
        assert decision.source == ConsentSource.API_REQUEST
        assert decision.scope == ["telemetry", "metrics"]
        assert decision.expires_at_epoch_seconds == 2_000.0
        assert decision.granted_at_epoch_seconds == 1_000.0
        assert decision.version == CONSENT_SCHEMA_VERSION
        assert decision.consent_token == "cst-v1:1234567890abcdef12345678"
        assert decision.withdrawal_epoch_seconds is None
        assert decision.stable_account_tag == "acct_123"


# ===========================================================================
# ConsentManager check_consent tests
# ===========================================================================


class TestConsentManagerCheckConsent:
    """Verifies check_consent with injected now_epoch_seconds without wall-clock time."""

    def test_check_consent_none_account_tag(self) -> None:
        cm = ConsentManager(grace_period_seconds=1200)
        now = 10_000.0
        allowed, state = cm.check_consent(account_tag=None, scope="telemetry", now_epoch_seconds=now)
        assert allowed is True
        assert state.account_tag is None
        assert state.status == ConsentStatus.GRACE
        assert state.source == ConsentSource.SYSTEM_DEFAULT
        assert state.granted_at_epoch_seconds == now
        assert state.expires_at_epoch_seconds == now + 1200.0
        assert state.last_modified_epoch_seconds == now

    def test_check_consent_unseen_account_tag_enters_grace_but_denied(self) -> None:
        cm = ConsentManager(grace_period_seconds=1800)
        now = 20_000.0
        allowed, state = cm.check_consent(account_tag="acct_new", scope="telemetry", now_epoch_seconds=now)
        assert allowed is False
        assert state.account_tag == "acct_new"
        assert state.status == ConsentStatus.GRACE
        assert state.source == ConsentSource.SYSTEM_DEFAULT
        assert state.granted_at_epoch_seconds == now
        assert state.expires_at_epoch_seconds == now + 1800.0
        assert state.last_modified_epoch_seconds == now

    def test_check_consent_granted_with_matching_scope(self) -> None:
        cm = ConsentManager()
        decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry", "diagnostics"],
            expires_at_epoch_seconds=50_000.0,
            granted_at_epoch_seconds=10_000.0,
        )
        cm.set_consent("acct_1", decision)

        allowed, state = cm.check_consent("acct_1", scope="telemetry", now_epoch_seconds=20_000.0)
        assert allowed is True
        assert state.status == ConsentStatus.GRANTED

    def test_check_consent_granted_with_unmatched_scope(self) -> None:
        cm = ConsentManager()
        decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry"],
            expires_at_epoch_seconds=50_000.0,
            granted_at_epoch_seconds=10_000.0,
        )
        cm.set_consent("acct_1", decision)

        allowed, state = cm.check_consent("acct_1", scope="profiling", now_epoch_seconds=20_000.0)
        assert allowed is False
        assert state.status == ConsentStatus.GRANTED

    def test_check_consent_granted_with_wildcard_scope(self) -> None:
        cm = ConsentManager()
        decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["*"],
            expires_at_epoch_seconds=50_000.0,
            granted_at_epoch_seconds=10_000.0,
        )
        cm.set_consent("acct_wild", decision)

        allowed, _ = cm.check_consent("acct_wild", scope="any_arbitrary_scope", now_epoch_seconds=20_000.0)
        assert allowed is True

    def test_check_consent_granted_without_scope_check(self) -> None:
        cm = ConsentManager()
        decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry"],
            expires_at_epoch_seconds=50_000.0,
            granted_at_epoch_seconds=10_000.0,
        )
        cm.set_consent("acct_noscope", decision)

        allowed, _ = cm.check_consent("acct_noscope", scope=None, now_epoch_seconds=20_000.0)
        assert allowed is True

    def test_check_consent_expiry_using_injected_now_epoch_seconds(self) -> None:
        cm = ConsentManager()
        expiry = 30_000.0
        decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry"],
            expires_at_epoch_seconds=expiry,
            granted_at_epoch_seconds=10_000.0,
        )
        cm.set_consent("acct_exp", decision)

        # Before expiry: active & allowed
        allowed, _ = cm.check_consent("acct_exp", scope="telemetry", now_epoch_seconds=expiry - 1.0)
        assert allowed is True

        # At expiry boundary: allowed
        allowed, _ = cm.check_consent("acct_exp", scope="telemetry", now_epoch_seconds=expiry)
        assert allowed is True

        # After expiry: not allowed (expired consent never reports active)
        allowed, state = cm.check_consent("acct_exp", scope="telemetry", now_epoch_seconds=expiry + 0.1)
        assert allowed is False

    @pytest.mark.parametrize("status", [ConsentStatus.WITHDRAWN, ConsentStatus.INVALID, ConsentStatus.EXPIRED])
    def test_check_consent_inactive_statuses_rejected(self, status: str) -> None:
        cm = ConsentManager()
        decision = ConsentDecision(
            status=status,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry"],
            expires_at_epoch_seconds=0.0,
            granted_at_epoch_seconds=10_000.0,
        )
        cm.set_consent("acct_inactive", decision)

        allowed, state = cm.check_consent("acct_inactive", scope="telemetry", now_epoch_seconds=20_000.0)
        assert allowed is False
        assert state.status == status


# ===========================================================================
# ConsentManager set_consent, withdraw_consent, invalidate_consent tests
# ===========================================================================


class TestConsentManagerModifications:
    """Verifies state mutation methods: set_consent, withdraw_consent, invalidate_consent."""

    def test_set_consent_creates_new_state(self) -> None:
        cm = ConsentManager()
        decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["metrics"],
            expires_at_epoch_seconds=40_000.0,
            granted_at_epoch_seconds=10_000.0,
            consent_token="cst-v1:token123",
        )
        state = cm.set_consent("acct_set", decision)

        assert state.account_tag == "acct_set"
        assert state.status == ConsentStatus.GRANTED
        assert state.source == ConsentSource.USER_EXPLICIT
        assert state.granted_scopes == ["metrics"]
        assert state.expires_at_epoch_seconds == 40_000.0
        assert state.granted_at_epoch_seconds == 10_000.0
        assert state.consent_token == "cst-v1:token123"

    def test_set_consent_idempotent_retains_existing(self) -> None:
        cm = ConsentManager()
        decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["metrics"],
            expires_at_epoch_seconds=40_000.0,
            granted_at_epoch_seconds=10_000.0,
            consent_token="cst-v1:token123",
        )
        state1 = cm.set_consent("acct_idem", decision)
        state2 = cm.set_consent("acct_idem", decision)

        assert state1 is state2

    def test_withdraw_consent_for_existing_account(self) -> None:
        cm = ConsentManager()
        decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["metrics"],
            expires_at_epoch_seconds=40_000.0,
            granted_at_epoch_seconds=10_000.0,
        )
        cm.set_consent("acct_withdraw", decision)

        state = cm.withdraw_consent("acct_withdraw", reason="user_requested")
        assert state.status == ConsentStatus.WITHDRAWN
        assert state.withdrawal_epoch_seconds is not None
        assert state.withdrawal_epoch_seconds > 0

        # Verify check_consent reflects withdrawal
        allowed, _ = cm.check_consent("acct_withdraw", scope="metrics", now_epoch_seconds=20_000.0)
        assert allowed is False

    def test_withdraw_consent_for_unknown_account(self) -> None:
        cm = ConsentManager()
        state = cm.withdraw_consent("acct_unseen_withdraw")
        assert state.account_tag == "acct_unseen_withdraw"
        assert state.status == ConsentStatus.WITHDRAWN
        assert state.source == ConsentSource.USER_EXPLICIT

    def test_invalidate_consent_for_existing_account(self) -> None:
        cm = ConsentManager()
        decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["metrics"],
            expires_at_epoch_seconds=40_000.0,
            granted_at_epoch_seconds=10_000.0,
        )
        cm.set_consent("acct_invalid", decision)

        state = cm.invalidate_consent("acct_invalid", reason="policy_change")
        assert state.status == ConsentStatus.INVALID

        allowed, _ = cm.check_consent("acct_invalid", scope="metrics", now_epoch_seconds=20_000.0)
        assert allowed is False

    def test_invalidate_consent_for_unknown_account(self) -> None:
        cm = ConsentManager()
        state = cm.invalidate_consent("acct_unseen_invalid")
        assert state.account_tag == "acct_unseen_invalid"
        assert state.status == ConsentStatus.INVALID
        assert state.source == ConsentSource.SYSTEM_DEFAULT


# ===========================================================================
# ConsentManager prune_expired tests
# ===========================================================================


class TestConsentManagerPruneExpired:
    """Verifies prune_expired logic, grace period enforcement, and max_to_prune limits."""

    def test_prune_expired_removes_aged_terminal_states(self) -> None:
        grace = 1800.0
        cm = ConsentManager(grace_period_seconds=grace)

        now = 100_000.0
        old_time = now - grace - 100.0

        # Populate states with various terminal statuses that are older than grace period
        cm.withdraw_consent("acct_withdrawn")
        cm._consent_states["acct_withdrawn"].last_modified_epoch_seconds = old_time

        cm.invalidate_consent("acct_invalid")
        cm._consent_states["acct_invalid"].last_modified_epoch_seconds = old_time

        expired_decision = ConsentDecision(
            status=ConsentStatus.EXPIRED,
            source=ConsentSource.SYSTEM_DEFAULT,
            scope=[],
            expires_at_epoch_seconds=old_time,
            granted_at_epoch_seconds=old_time - 1000,
        )
        cm.set_consent("acct_expired", expired_decision)
        cm._consent_states["acct_expired"].last_modified_epoch_seconds = old_time

        # Active granted state should NOT be pruned even if old
        granted_decision = ConsentDecision(
            status=ConsentStatus.GRANTED,
            source=ConsentSource.USER_EXPLICIT,
            scope=["telemetry"],
            expires_at_epoch_seconds=now + 10_000,
            granted_at_epoch_seconds=old_time,
        )
        cm.set_consent("acct_granted", granted_decision)
        cm._consent_states["acct_granted"].last_modified_epoch_seconds = old_time

        removed = cm.prune_expired(now_epoch_seconds=now)
        assert removed == 3
        assert "acct_withdrawn" not in cm._consent_states
        assert "acct_invalid" not in cm._consent_states
        assert "acct_expired" not in cm._consent_states
        assert "acct_granted" in cm._consent_states

    def test_prune_expired_keeps_states_within_grace_period(self) -> None:
        grace = 1800.0
        cm = ConsentManager(grace_period_seconds=grace)

        now = 100_000.0
        recent_time = now - grace + 100.0  # within grace period

        cm.withdraw_consent("acct_recent_withdrawn")
        cm._consent_states["acct_recent_withdrawn"].last_modified_epoch_seconds = recent_time

        removed = cm.prune_expired(now_epoch_seconds=now)
        assert removed == 0
        assert "acct_recent_withdrawn" in cm._consent_states

    def test_prune_expired_respects_max_to_prune(self) -> None:
        grace = 1800.0
        cm = ConsentManager(grace_period_seconds=grace)

        now = 100_000.0
        old_time = now - grace - 50.0

        total_records = 15
        max_to_prune = 6

        for i in range(total_records):
            tag = f"acct_{i:03d}"
            cm.withdraw_consent(tag)
            cm._consent_states[tag].last_modified_epoch_seconds = old_time

        assert len(cm._consent_states) == total_records

        removed = cm.prune_expired(now_epoch_seconds=now, max_to_prune=max_to_prune)
        assert removed == max_to_prune
        assert len(cm._consent_states) == total_records - max_to_prune

        # Pruning the remaining states
        second_removed = cm.prune_expired(now_epoch_seconds=now, max_to_prune=total_records)
        assert second_removed == total_records - max_to_prune
        assert len(cm._consent_states) == 0


# ===========================================================================
# ConsentManager generate_consent_token tests
# ===========================================================================


class TestConsentManagerGenerateConsentToken:
    """Verifies token formatting, account tag redaction, and deterministic hashing stability."""

    def test_generate_consent_token_format(self) -> None:
        cm = ConsentManager()
        token = cm.generate_consent_token(
            account_tag="user_account_98765",
            status=ConsentStatus.GRANTED,
            scopes=["telemetry", "diagnostics"],
        )
        assert isinstance(token, str)
        assert token.startswith("cst-v1:")
        hex_part = token.split(":", 1)[1]
        assert len(hex_part) == 24
        # Validate that hex_part consists of valid hex digits
        int(hex_part, 16)

    def test_generate_consent_token_redacts_account_tag(self) -> None:
        cm = ConsentManager()
        sensitive_account = "super_secret_account_id_9999"
        token = cm.generate_consent_token(
            account_tag=sensitive_account,
            status=ConsentStatus.GRANTED,
            scopes=["telemetry"],
        )
        assert sensitive_account not in token

    def test_generate_consent_token_stable_for_same_inputs_with_fixed_entropy(self) -> None:
        cm = ConsentManager()
        fixed_entropy = b"\x01\x02\x03\x04\x05\x06\x07\x08"

        with patch("os.urandom", return_value=fixed_entropy):
            token_a = cm.generate_consent_token(
                account_tag="acct_1",
                status=ConsentStatus.GRANTED,
                scopes=["telemetry", "metrics"],
            )
            # Same scopes in reverse order must produce identical token due to internal sort
            token_b = cm.generate_consent_token(
                account_tag="acct_1",
                status=ConsentStatus.GRANTED,
                scopes=["metrics", "telemetry"],
            )
            assert token_a == token_b

    def test_generate_consent_token_differs_for_different_inputs(self) -> None:
        cm = ConsentManager()
        fixed_entropy = b"\xaa" * 8

        with patch("os.urandom", return_value=fixed_entropy):
            base_token = cm.generate_consent_token(
                account_tag="acct_1",
                status=ConsentStatus.GRANTED,
                scopes=["telemetry"],
            )
            different_account = cm.generate_consent_token(
                account_tag="acct_2",
                status=ConsentStatus.GRANTED,
                scopes=["telemetry"],
            )
            different_status = cm.generate_consent_token(
                account_tag="acct_1",
                status=ConsentStatus.DENIED,
                scopes=["telemetry"],
            )
            different_scope = cm.generate_consent_token(
                account_tag="acct_1",
                status=ConsentStatus.GRANTED,
                scopes=["metrics"],
            )

            assert base_token != different_account
            assert base_token != different_status
            assert base_token != different_scope
