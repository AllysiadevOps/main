"""Tests for size and label caps in backend/analytics/metrics_collector.py."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from typing import Any

backend_dir = str(Path(__file__).resolve().parent)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import pytest

from analytics.metrics_collector import (
    _METRIC_DOMAIN_SET,
    _METRIC_NAME_PATTERN,
    _RECOVERY_SIGNAL_SET,
    _SATURATION_SIGNAL_SET,
    AnalyticsOperationalMetrics,
    MetricDomain,
    RecoverySignal,
    SaturationSignal,
    _cap_str_bytes,
    _clamp_int,
    _top_n,
    _validate_domain,
    _validate_name,
    operational_collector,
)


# ---------------------------------------------------------------------------
# Unit tests for domain validation & cardinality bounding
# ---------------------------------------------------------------------------


class TestValidateDomain:
    """Verifies that metric domains are strictly restricted to the allowlisted set."""

    def test_all_known_domains_accepted(self) -> None:
        for domain in _METRIC_DOMAIN_SET:
            assert _validate_domain(domain) == domain

    @pytest.mark.parametrize(
        "invalid_domain",
        [
            "unknown",
            "custom_domain",
            "PROGRESS",  # uppercase not in domain set
            "analytics_extra",
            "injection;DROP TABLE",
            "",
            "   ",
            "123",
            None,
            12345,
            True,
        ],
    )
    def test_invalid_domains_rejected_and_defaulted(self, invalid_domain: Any) -> None:
        # Invalid domains are rejected from creating unbounded labels
        # and safely coerce to MetricDomain.ANALYTICS.
        assert _validate_domain(invalid_domain) == MetricDomain.ANALYTICS

    @pytest.mark.parametrize("unhashable_domain", [[], ["nested"], {}, {"key": "val"}])
    def test_unhashable_invalid_domain_raises(self, unhashable_domain: Any) -> None:
        with pytest.raises(TypeError):
            _validate_domain(unhashable_domain)



# ---------------------------------------------------------------------------
# Unit tests for name validation & cardinality bounding
# ---------------------------------------------------------------------------


class TestValidateName:
    """Verifies that metric names conform to pattern and are length-capped."""

    @pytest.mark.parametrize(
        "valid_name",
        [
            "request_count",
            "http_200",
            "_internal_metric",
            "a",
            "a" * 48,
            "status_4xx",
        ],
    )
    def test_valid_names_preserved(self, valid_name: str) -> None:
        assert _validate_name(valid_name) == valid_name
        assert _METRIC_NAME_PATTERN.match(_validate_name(valid_name))

    def test_name_length_capped_at_48_chars(self) -> None:
        oversized = "a" * 100
        validated = _validate_name(oversized)
        assert len(validated) == 48
        assert validated == "a" * 48
        assert _METRIC_NAME_PATTERN.match(validated)

    def test_uppercase_converted_to_lowercase(self) -> None:
        assert _validate_name("RequestCount") == "requestcount"
        assert _validate_name("HTTP_STATUS_OK") == "http_status_ok"

    def test_disallowed_characters_replaced_with_underscore(self) -> None:
        assert _validate_name("request-count.total@v1") == "request_count_total_v1"
        assert _validate_name("user:id!status#") == "user_id_status_"

    def test_leading_digit_prefixed_with_m(self) -> None:
        assert _validate_name("500_errors") == "m_500_errors"
        assert _validate_name("1") == "m_1"

    def test_leading_digit_with_oversized_length_capped(self) -> None:
        oversized_numeric = "9" * 100
        validated = _validate_name(oversized_numeric)
        assert len(validated) == 48
        assert validated.startswith("m_")
        assert _METRIC_NAME_PATTERN.match(validated)

    @pytest.mark.parametrize(
        "empty_or_special",
        [
            "",
            "   ",
            "---",
            "!!!",
            "@@@",
        ],
    )
    def test_empty_or_only_symbols_sanitized(self, empty_or_special: str) -> None:
        validated = _validate_name(empty_or_special)
        assert len(validated) <= 48
        assert _METRIC_NAME_PATTERN.match(validated)

    def test_non_string_input_converted_and_sanitized(self) -> None:
        assert _validate_name(500) == "m_500"
        assert _validate_name(None) == "none"
        assert _validate_name(True) == "true"

    def test_unstringable_input_raises(self) -> None:
        class Unstringable:
            def __str__(self) -> str:
                raise TypeError("cannot stringify")

        with pytest.raises(TypeError):
            _validate_name(Unstringable())



# ---------------------------------------------------------------------------
# Unit tests for string byte capping
# ---------------------------------------------------------------------------


class TestCapStrBytes:
    """Verifies byte capping handles ASCII and multi-byte UTF-8 cleanly."""

    def test_under_cap_returned_as_is(self) -> None:
        text = "short text"
        assert _cap_str_bytes(text, 64) == text

    def test_exact_cap_returned_as_is(self) -> None:
        text = "a" * 64
        assert _cap_str_bytes(text, 64) == text

    def test_oversized_ascii_truncated_to_cap(self) -> None:
        oversized = "a" * 200
        capped = _cap_str_bytes(oversized, 64)
        assert len(capped.encode("utf-8")) == 64
        assert capped == "a" * 64

    def test_oversized_multibyte_utf8_truncated_safely(self) -> None:
        # 3-byte UTF-8 character '€' repeated
        euro = "€" * 30  # 90 bytes
        capped = _cap_str_bytes(euro, 10)
        # Cap is 10 bytes: each '€' is 3 bytes, so 3 chars = 9 bytes (10th byte ignored)
        assert len(capped.encode("utf-8")) <= 10
        assert capped == "€" * 3

    def test_non_string_value_converted_and_capped(self) -> None:
        assert _cap_str_bytes(123456789, 4) == "1234"
        assert _cap_str_bytes(None, 2) == "No"


# ---------------------------------------------------------------------------
# Unit tests for integer clamping
# ---------------------------------------------------------------------------


class TestClampInt:
    """Verifies bounds clamping for metric counts and batch sizes."""

    def test_within_range_unchanged(self) -> None:
        assert _clamp_int(50, 0, 100) == 50

    def test_below_minimum_clamped(self) -> None:
        assert _clamp_int(-10, 0, 100) == 0

    def test_above_maximum_clamped(self) -> None:
        assert _clamp_int(500, 0, 100) == 100

    def test_exact_boundaries_preserved(self) -> None:
        assert _clamp_int(0, 0, 100) == 0
        assert _clamp_int(100, 0, 100) == 100


# ---------------------------------------------------------------------------
# Unit tests for top-N ranking & cardinality capping
# ---------------------------------------------------------------------------


class TestTopN:
    """Verifies that _top_n limits cardinality and ranks deterministically."""

    def test_empty_dict(self) -> None:
        assert _top_n({}, 10) == {}

    def test_fewer_than_n_entries(self) -> None:
        data = {"a": 1, "b": 2}
        assert _top_n(data, 10) == {"b": 2, "a": 1}

    def test_more_than_n_entries_truncated_to_n(self) -> None:
        data = {f"k_{i}": i for i in range(100)}
        result = _top_n(data, 10)
        assert len(result) == 10
        # The top 10 items should have the highest counts: 99 down to 90
        assert list(result.values()) == list(range(99, 89, -1))

    def test_deterministic_tie_breaking(self) -> None:
        # With equal values, keys are ordered lexicographically ascending
        data = {"banana": 5, "apple": 5, "cherry": 5, "date": 5}
        result = _top_n(data, 2)
        assert len(result) == 2
        assert list(result.keys()) == ["apple", "banana"]


# ---------------------------------------------------------------------------
# Integration tests for AnalyticsOperationalMetrics
# ---------------------------------------------------------------------------


class TestAnalyticsOperationalMetrics:
    """Tests the state, size caps, cardinality bounding, and reset of metrics collector."""

    @pytest.fixture
    def metrics(self) -> AnalyticsOperationalMetrics:
        m = AnalyticsOperationalMetrics()
        m.reset()
        return m

    def test_increment_counter_valid(self, metrics: AnalyticsOperationalMetrics) -> None:
        val = metrics.increment_counter(MetricDomain.PROGRESS, "job_complete", 1)
        assert val == 1
        val2 = metrics.increment_counter(MetricDomain.PROGRESS, "job_complete", 3)
        assert val2 == 4
        snap = metrics.snapshot()
        assert snap["counters"]["progress:job_complete"] == 4

    def test_increment_counter_rejects_invalid_domain_to_analytics(
        self, metrics: AnalyticsOperationalMetrics
    ) -> None:
        metrics.increment_counter("unauthorized_domain", "hits", 5)
        snap = metrics.snapshot()
        # Invalid domain is rejected into "analytics" domain
        assert "unauthorized_domain:hits" not in snap["counters"]
        assert snap["counters"]["analytics:hits"] == 5

    def test_increment_counter_sanitizes_invalid_name(
        self, metrics: AnalyticsOperationalMetrics
    ) -> None:
        metrics.increment_counter(MetricDomain.SESSION, "User Login (Failed!)", 2)
        snap = metrics.snapshot()
        assert "session:user_login__failed__" in snap["counters"]
        assert snap["counters"]["session:user_login__failed__"] == 2

    def test_increment_counter_clamps_negative_and_oversized(
        self, metrics: AnalyticsOperationalMetrics
    ) -> None:
        # Negative increment clamped to 0
        metrics.increment_counter(MetricDomain.CONSENT, "accepted", -50)
        snap = metrics.snapshot()
        assert snap["counters"]["consent:accepted"] == 0

        # Increment exceeding 1,000,000 clamped to 1,000,000
        metrics.increment_counter(MetricDomain.CONSENT, "accepted", 5_000_000)
        snap = metrics.snapshot()
        assert snap["counters"]["consent:accepted"] == 1_000_000

    def test_increment_counter_handles_malformed_values(
        self, metrics: AnalyticsOperationalMetrics
    ) -> None:
        # Non-numeric value safely defaults to 0
        metrics.increment_counter(MetricDomain.ERROR, "fails", "not_a_number")  # type: ignore[arg-type]
        snap = metrics.snapshot()
        assert snap["counters"]["error:fails"] == 0

    def test_set_gauge_valid_and_sanitized(
        self, metrics: AnalyticsOperationalMetrics
    ) -> None:
        metrics.set_gauge(MetricDomain.SATURATION, "memory_pct", 78.5)
        snap = metrics.snapshot()
        assert snap["gauges"]["saturation:memory_pct"] == 78.5

        # Invalid domain rejected to analytics
        metrics.set_gauge("rogue_domain", "cpu_pct", 92.1)
        snap = metrics.snapshot()
        assert "rogue_domain:cpu_pct" not in snap["gauges"]
        assert snap["gauges"]["analytics:cpu_pct"] == 92.1

        # Non-float value safely defaults to 0.0
        metrics.set_gauge(MetricDomain.ANALYTICS, "invalid_gauge", "not_a_float")  # type: ignore[arg-type]
        snap = metrics.snapshot()
        assert snap["gauges"]["analytics:invalid_gauge"] == 0.0

    def test_record_event_seen_caps_string_at_128_bytes(
        self, metrics: AnalyticsOperationalMetrics
    ) -> None:
        short_event = "user_action"
        metrics.record_event_seen(short_event)
        metrics.record_event_seen(short_event)

        oversized_event = "e" * 200
        metrics.record_event_seen(oversized_event)

        snap = metrics.snapshot()
        assert snap["event_counts"][short_event] == 2
        assert "e" * 200 not in snap["event_counts"]
        assert snap["event_counts"]["e" * 128] == 1

    def test_record_event_seen_handles_none(
        self, metrics: AnalyticsOperationalMetrics
    ) -> None:
        metrics.record_event_seen(None)  # type: ignore[arg-type]
        snap = metrics.snapshot()
        assert snap["event_counts"][""] == 1

    def test_record_saturation_signal_valid_and_invalid(
        self, metrics: AnalyticsOperationalMetrics
    ) -> None:
        # Valid signal
        metrics.record_saturation_signal(SaturationSignal.CPU_HIGH, detail="95% load")
        # Invalid signal rejected to "other"
        metrics.record_saturation_signal("unregistered_saturation_type", detail="custom signal")

        snap = metrics.snapshot()
        assert snap["saturation_signals"][SaturationSignal.CPU_HIGH] == 1
        assert "unregistered_saturation_type" not in snap["saturation_signals"]
        assert snap["saturation_signals"]["other"] == 1

        # Verifies gauge and counter updates
        assert snap["gauges"]["saturation:saturation_signal_count"] == 2.0
        assert snap["counters"]["saturation:signal_total"] == 2
        assert snap["last_saturation_epoch"] > 0

    def test_record_recovery_signal_valid_and_invalid(
        self, metrics: AnalyticsOperationalMetrics
    ) -> None:
        # Valid signal
        metrics.record_recovery_signal(RecoverySignal.CPU_OK, detail="40% load")
        # Invalid signal rejected to "other"
        metrics.record_recovery_signal("rogue_recovery_signal", detail="bad signal")

        snap = metrics.snapshot()
        assert snap["recovery_signals"][RecoverySignal.CPU_OK] == 1
        assert "rogue_recovery_signal" not in snap["recovery_signals"]
        assert snap["recovery_signals"]["other"] == 1

        # Verifies gauge and counter updates
        assert snap["gauges"]["recovery:recovery_signal_count"] == 2.0
        assert snap["counters"]["recovery:recovery_total"] == 2
        assert snap["last_recovery_epoch"] > 0

    def test_record_failure_truncates_error_code_and_category(
        self, metrics: AnalyticsOperationalMetrics
    ) -> None:
        oversized_code = "ERR_" + "x" * 200
        oversized_cat = "CAT_" + "y" * 100
        metrics.record_failure(oversized_code, category=oversized_cat)

        snap = metrics.snapshot()
        expected_code = _cap_str_bytes(oversized_code, 128)
        assert len(expected_code.encode("utf-8")) == 128
        assert snap["failure_errors"][expected_code] == 1
        assert oversized_code not in snap["failure_errors"]

        # Failure counter name err_<category> validated and capped to <= 48
        expected_counter_name = _validate_name(f"err_{_cap_str_bytes(oversized_cat, 64)}")
        assert len(expected_counter_name) <= 48
        assert snap["counters"][f"failure:{expected_counter_name}"] == 1

    def test_progress_tick_truncates_operation_name(
        self, metrics: AnalyticsOperationalMetrics
    ) -> None:
        oversized_op = "op_" + "z" * 100
        metrics.progress_tick("progress", oversized_op)

        snap = metrics.snapshot()
        expected_op = _cap_str_bytes(oversized_op, 64)
        assert len(expected_op.encode("utf-8")) == 64
        # increment_counter passes op_str through _validate_name, bounding the counter label to <= 48 chars
        expected_name = _validate_name(expected_op)
        assert len(expected_name) <= 48
        assert snap["counters"][f"progress:{expected_name}"] == 1
        assert snap["progress_ticks"] == 1


    def test_snapshot_caps_top_64_entries(
        self, metrics: AnalyticsOperationalMetrics
    ) -> None:
        # Record 80 distinct events (> 64)
        for i in range(80):
            metrics.record_event_seen(f"event_{i:03d}")
        # Give event_079 highest count so it ranks first deterministically
        for _ in range(5):
            metrics.record_event_seen("event_079")

        # Record 80 distinct failures (> 64)
        for i in range(80):
            metrics.record_failure(f"err_code_{i:03d}")

        snap = metrics.snapshot()

        # Cardinality caps: top-64 only
        assert len(snap["event_counts"]) == 64
        assert len(snap["failure_errors"]) == 64

        # Top event should be event_079
        top_event = list(snap["event_counts"].keys())[0]
        assert top_event == "event_079"
        assert snap["event_counts"][top_event] == 6

        # Pruned items (the 16 lowest ranked items) should not appear
        # With equal counts (1), _top_n sorts by (-count, key).
        # So event_000 through event_062 are kept (63 items) + event_079 (count 6) = 64 items.
        # event_064 through event_078 have count 1 and higher lexicographical keys, so they are pruned.
        assert "event_078" not in snap["event_counts"]

    def test_reset_clears_all_counters_gauges_and_state(
        self, metrics: AnalyticsOperationalMetrics
    ) -> None:
        # Populate various states
        metrics.increment_counter(MetricDomain.PROGRESS, "step1", 10)
        metrics.set_gauge(MetricDomain.SATURATION, "mem", 50.0)
        metrics.record_event_seen("action")
        metrics.record_saturation_signal(SaturationSignal.MEMORY_HIGH)
        metrics.record_recovery_signal(RecoverySignal.MEMORY_OK)
        metrics.record_failure("ERR_404")
        metrics.progress_tick()

        snap_before = metrics.snapshot()
        assert len(snap_before["counters"]) > 0
        assert len(snap_before["gauges"]) > 0
        assert len(snap_before["event_counts"]) > 0
        assert len(snap_before["saturation_signals"]) > 0
        assert len(snap_before["recovery_signals"]) > 0
        assert len(snap_before["failure_errors"]) > 0
        assert snap_before["progress_ticks"] > 0
        assert snap_before["last_saturation_epoch"] > 0.0
        assert snap_before["last_recovery_epoch"] > 0.0

        # Perform reset
        metrics.reset()

        snap_after = metrics.snapshot()
        assert snap_after["counters"] == {}
        assert snap_after["gauges"] == {}
        assert snap_after["event_counts"] == {}
        assert snap_after["saturation_signals"] == {}
        assert snap_after["recovery_signals"] == {}
        assert snap_after["failure_errors"] == {}
        assert snap_after["progress_ticks"] == 0
        assert snap_after["last_saturation_epoch"] == 0.0
        assert snap_after["last_recovery_epoch"] == 0.0

    def test_operational_collector_singleton(self) -> None:
        assert isinstance(operational_collector, AnalyticsOperationalMetrics)
        # Verify operational_collector has reset and snapshot methods
        operational_collector.reset()
        snap = operational_collector.snapshot()
        assert snap["counters"] == {}

    def test_thread_safety_under_concurrent_updates(
        self, metrics: AnalyticsOperationalMetrics
    ) -> None:
        num_threads = 4
        ops_per_thread = 25

        def worker(thread_id: int) -> None:
            for i in range(ops_per_thread):
                metrics.increment_counter(
                    MetricDomain.PROGRESS, f"worker_thread_{thread_id}", 1
                )
                metrics.record_event_seen(f"event_{thread_id}_{i}")
                if i % 10 == 0:
                    metrics.snapshot()

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        snap = metrics.snapshot()
        for t in range(num_threads):
            assert snap["counters"][f"progress:worker_thread_{t}"] == ops_per_thread

