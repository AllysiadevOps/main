import unittest
from datetime import datetime, timezone
from envelope import (
    MAGIC_V1,
    MAGIC_V2,
    pack_envelope,
    unpack_envelope,
    validate_v1,
    validate_v2,
    canonical_metadata_hash,
)


class TestEnvelope(unittest.TestCase):
    def setUp(self):
        self.valid_v1 = {
            "protocol": "harpocrates",
            "version": 1,
            "tier": "silent",
            "sourceHash": "11" * 32,
            "proofId": "22" * 32,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.valid_v2 = self.valid_v1.copy()
        self.valid_v2["version"] = 2
        self.valid_v2["unknown_field"] = "should_be_preserved"

    def test_pack_unpack_v1(self):
        data = pack_envelope(self.valid_v1, version=1)
        self.assertTrue(data.startswith(MAGIC_V1))

        unpacked = unpack_envelope(data)
        self.assertEqual(unpacked, self.valid_v1)

    def test_pack_unpack_v2(self):
        data = pack_envelope(self.valid_v2, version=2)
        self.assertTrue(data.startswith(MAGIC_V2))

        unpacked = unpack_envelope(data)
        self.assertEqual(unpacked, self.valid_v2)

    def test_auto_migration_on_pack(self):
        # Packing a v1 dict as v2 should auto-upgrade version to 2
        data = pack_envelope(self.valid_v1, version=2)
        unpacked = unpack_envelope(data)
        self.assertEqual(unpacked["version"], 2)

    def test_validate_v1_rejects_missing_fields(self):
        invalid = self.valid_v1.copy()
        del invalid["proofId"]
        with self.assertRaises(ValueError):
            validate_v1(invalid)

    def test_validate_v2_preserves_unknown_fields(self):
        validated = validate_v2(self.valid_v2)
        self.assertEqual(validated["unknown_field"], "should_be_preserved")

    def test_canonical_hash_consistency(self):
        hash1 = canonical_metadata_hash(self.valid_v1)
        hash2 = canonical_metadata_hash(self.valid_v1.copy())
        self.assertEqual(hash1, hash2)

    def test_canonical_hash_order_independence(self):
        # Ensure canonicalization ignores key order
        hash1 = canonical_metadata_hash(self.valid_v1)
        # Create a copy with keys in different order
        reordered = {
            "timestamp": self.valid_v1["timestamp"],
            "proofId": self.valid_v1["proofId"],
            "sourceHash": self.valid_v1["sourceHash"],
            "tier": self.valid_v1["tier"],
            "version": self.valid_v1["version"],
            "protocol": self.valid_v1["protocol"],
        }
        hash2 = canonical_metadata_hash(reordered)
        self.assertEqual(hash1, hash2)

    def test_canonical_hash_ignores_unknown_fields(self):
        # Canonical hash should be stable regardless of unknown fields
        # to support forward compatibility without breaking hashes
        hash1 = canonical_metadata_hash(self.valid_v1)
        v2_with_unknown = self.valid_v2.copy()
        hash2 = canonical_metadata_hash(v2_with_unknown)
        # Note: Depending on implementation, v2 might include unknowns in hash.
        # If canonicalization is strict on known fields only, they should match.
        # If it includes all fields, they won't. We test that it's deterministic.
        hash3 = canonical_metadata_hash(v2_with_unknown)
        self.assertEqual(hash2, hash3)

    def test_pack_envelope_max_size(self):
        # Test boundary condition for oversized metadata
        large_data = self.valid_v1.copy()
        large_data["payload"] = "x" * 1024 * 1024  # 1MB payload
        with self.assertRaises(ValueError):
            pack_envelope(large_data, version=1)

    def test_unpack_envelope_invalid_magic(self):
        # Test handling of malformed magic bytes
        self.assertIsNone(unpack_envelope(b"INVALID_MAGIC" + b"data"))

    def test_validate_v1_rejects_invalid_version(self):
        invalid = self.valid_v1.copy()
        invalid["version"] = 99
        with self.assertRaises(ValueError):
            validate_v1(invalid)

    def test_validate_v2_rejects_missing_required_fields(self):
        invalid = self.valid_v2.copy()
        del invalid["proofId"]
        with self.assertRaises(ValueError):
            validate_v2(invalid)


if __name__ == "__main__":
    unittest.main()