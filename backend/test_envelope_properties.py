"""Property-based tests for backend/envelope.py using Hypothesis.

Scope
-----
- Property 1: every valid v1/v2 metadata dict round-trips to an equal dict.
- Property 2: arbitrary byte strings never raise from unpack_envelope (they return None).
- Property 3: truncating a valid envelope never yields a different valid metadata dict.
"""

from __future__ import annotations

import os
import unittest
from datetime import datetime, timezone
from typing import Any

from hypothesis import HealthCheck, Phase, given, seed, settings, strategies as st

from envelope import (
    ALLOWED_TIERS,
    MAGIC_V1,
    MAGIC_V2,
    MAX_DECOMPRESSED_BYTES,
    MAX_PAYLOAD_BYTES,
    canonical_metadata_hash,
    pack_envelope,
    unpack_envelope,
    _canonical_json,
)

#: Default deterministic seed shared across property tests for reproducible CI runs.
DEFAULT_SEED = 20260727

#: Bounded example count for CI execution to keep runtime predictable and fast.
CI_MAX_EXAMPLES = int(os.getenv("HYPOTHESIS_MAX_EXAMPLES", "50"))

settings.register_profile(
    "ci",
    max_examples=CI_MAX_EXAMPLES,
    deadline=None,
    phases=[Phase.explicit, Phase.reuse, Phase.generate, Phase.shrink],
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "dev",
    max_examples=25,
    deadline=None,
)

settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "ci"))

# ---------------------------------------------------------------------------
# Strategies for valid metadata generation
# ---------------------------------------------------------------------------

_hex_64_strategy = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)
_tier_strategy = st.sampled_from(sorted(ALLOWED_TIERS))

# Realistic timestamp range: year 2000 to ~2026 UTC
_timestamp_strategy = st.integers(min_value=946684800, max_value=1767225600).map(
    lambda ts: datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
)

_json_primitive_strategy = st.one_of(
    st.text(max_size=64),
    st.integers(min_value=-1_000_000, max_value=1_000_000),
    st.booleans(),
    st.none(),
)

_extra_fields_strategy = st.dictionaries(
    keys=st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=24).filter(
        lambda k: k not in {"protocol", "version", "tier", "sourceHash", "proofId", "timestamp"}
    ),
    values=_json_primitive_strategy,
    max_size=6,
)

valid_v1_metadata_strategy = st.builds(
    lambda tier, source_hash, proof_id, ts: {
        "protocol": "harpocrates",
        "version": 1,
        "tier": tier,
        "sourceHash": source_hash,
        "proofId": proof_id,
        "timestamp": ts,
    },
    tier=_tier_strategy,
    source_hash=_hex_64_strategy,
    proof_id=_hex_64_strategy,
    ts=_timestamp_strategy,
)

valid_v2_metadata_strategy = st.builds(
    lambda version, tier, source_hash, proof_id, ts, extra: {
        "protocol": "harpocrates",
        "version": version,
        "tier": tier,
        "sourceHash": source_hash,
        "proofId": proof_id,
        "timestamp": ts,
        **extra,
    },
    version=st.integers(min_value=2, max_value=100),
    tier=_tier_strategy,
    source_hash=_hex_64_strategy,
    proof_id=_hex_64_strategy,
    ts=_timestamp_strategy,
    extra=_extra_fields_strategy,
).filter(lambda m: len(_canonical_json(m)) <= MAX_DECOMPRESSED_BYTES)


# ---------------------------------------------------------------------------
# Test Suite
# ---------------------------------------------------------------------------


class TestEnvelopeProperties(unittest.TestCase):
    """Property-based test suite verifying envelope invariants."""

    # ── Property 1: Round-trip preservation ─────────────────────────────────

    @seed(DEFAULT_SEED)
    @given(valid_v1_metadata_strategy)
    def test_property_1_v1_metadata_round_trip(self, metadata: dict[str, Any]):
        """Every valid v1 metadata dict round-trips to an equal dict."""
        packed = pack_envelope(metadata, version=1)
        self.assertTrue(packed.startswith(MAGIC_V1))
        unpacked = unpack_envelope(packed)
        self.assertEqual(unpacked, metadata)
        self.assertEqual(canonical_metadata_hash(metadata), canonical_metadata_hash(unpacked))

    @seed(DEFAULT_SEED)
    @given(valid_v2_metadata_strategy)
    def test_property_1_v2_metadata_round_trip(self, metadata: dict[str, Any]):
        """Every valid v2 metadata dict round-trips to an equal dict, preserving extra fields."""
        packed = pack_envelope(metadata, version=2)
        self.assertTrue(packed.startswith(MAGIC_V2))
        unpacked = unpack_envelope(packed)
        self.assertEqual(unpacked, metadata)
        self.assertEqual(canonical_metadata_hash(metadata), canonical_metadata_hash(unpacked))

    @seed(DEFAULT_SEED)
    @given(valid_v1_metadata_strategy)
    def test_property_1_v1_packed_as_v2_auto_migrates_and_round_trips(self, metadata: dict[str, Any]):
        """Packing a valid v1 metadata dict as v2 auto-upgrades the version to 2."""
        packed = pack_envelope(metadata, version=2)
        self.assertTrue(packed.startswith(MAGIC_V2))
        unpacked = unpack_envelope(packed)
        expected = dict(metadata)
        expected["version"] = 2
        self.assertEqual(unpacked, expected)

    # ── Property 2: Total safety on arbitrary inputs ────────────────────────

    @seed(DEFAULT_SEED)
    @given(st.binary(min_size=0, max_size=4096))
    def test_property_2_arbitrary_bytes_never_raise(self, data: bytes):
        """Arbitrary byte strings never raise from unpack_envelope (they return None)."""
        result = unpack_envelope(data)
        self.assertTrue(result is None or isinstance(result, dict))

    @seed(DEFAULT_SEED)
    @given(valid_v2_metadata_strategy, st.data())
    def test_property_2_corrupted_envelopes_never_raise(self, metadata: dict[str, Any], data: st.DataObject):
        """Corrupted envelopes (tampered header, size, checksum, or payload) never raise."""
        valid_packed = pack_envelope(metadata, version=2)
        mutation_kind = data.draw(
            st.sampled_from(["corrupt_magic", "corrupt_size", "corrupt_checksum", "corrupt_body", "bit_flip"])
        )
        mutated = bytearray(valid_packed)

        if mutation_kind == "corrupt_magic":
            mutated[:7] = b"INVALID"
        elif mutation_kind == "corrupt_size":
            # Replace size with a bad length prefix
            mutated[7:11] = data.draw(st.binary(min_size=4, max_size=4))
        elif mutation_kind == "corrupt_checksum":
            # Tamper one byte in the checksum
            mutated[11] ^= 0xFF
        elif mutation_kind == "corrupt_body" and len(mutated) > 43:
            # Tamper one byte in the body
            idx = data.draw(st.integers(min_value=43, max_value=len(mutated) - 1))
            mutated[idx] ^= 0xFF
        elif mutation_kind == "bit_flip" and len(mutated) > 0:
            idx = data.draw(st.integers(min_value=0, max_value=len(mutated) - 1))
            mutated[idx] ^= 0x01

        result = unpack_envelope(bytes(mutated))
        self.assertTrue(result is None or isinstance(result, dict))

    # ── Property 3: Safe rejection of truncated envelopes ───────────────────

    @seed(DEFAULT_SEED)
    @given(valid_v1_metadata_strategy, st.data())
    def test_property_3_truncating_v1_envelope_never_yields_different_metadata(
        self, metadata: dict[str, Any], data: st.DataObject
    ):
        """Truncating a valid v1 envelope never yields a different valid metadata dict."""
        packed = pack_envelope(metadata, version=1)
        cut = data.draw(st.integers(min_value=0, max_value=len(packed) - 1))
        truncated = packed[:cut]
        result = unpack_envelope(truncated)
        # Any strict truncation of a valid envelope cannot satisfy the length/checksum checks.
        self.assertIsNone(result)

    @seed(DEFAULT_SEED)
    @given(valid_v2_metadata_strategy, st.data())
    def test_property_3_truncating_v2_envelope_never_yields_different_metadata(
        self, metadata: dict[str, Any], data: st.DataObject
    ):
        """Truncating a valid v2 envelope never yields a different valid metadata dict."""
        packed = pack_envelope(metadata, version=2)
        cut = data.draw(st.integers(min_value=0, max_value=len(packed) - 1))
        truncated = packed[:cut]
        result = unpack_envelope(truncated)
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
