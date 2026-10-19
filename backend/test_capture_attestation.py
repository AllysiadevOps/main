"""
Test vectors for the Harpocrates capture-device attestation profile.

Covers success, failure, and adversarial paths as specified in the
acceptance criteria of the attestation protocol.
"""

import hashlib
import os
import unittest

from capture_attestation import (
    AppIdentity,
    CameraPipeline,
    CaptureAttestation,
    SecureTime,
    canonical_attestation_hash,
    decode_attestation,
    encode_attestation,
    make_device_commitment,
    verify_device_commitment,
    verify_evidence_binding,
)


class TestCanonicalEncoding(unittest.TestCase):
    """Round-trip encoding / decoding produces identical attestation data."""

    def setUp(self):
        self.device_key = os.urandom(32)
        self.nonce = hashlib.sha256(b"test-nonce-1").hexdigest()
        self.evidence = b"fake-video-bytes-for-attestation-test"

        self.attestation = CaptureAttestation(
            version=1,
            trust_level=2,
            capture_nonce=self.nonce,
            app_identity=AppIdentity(
                package_name="com.harpocrates.camera",
                version_code="42",
                build_fingerprint="google/sunfish/sunfish:12/SP1A.210812.016/7671062:user/release-keys",
                signing_digest=hashlib.sha256(b"signing-cert").hexdigest(),
            ),
            device_commitment=make_device_commitment(self.nonce, self.device_key),
            privacy_scope="per_session",
            evidence_digest_binding=hashlib.sha256(self.evidence).hexdigest(),
            secure_time=SecureTime(unix_ms=1721971200000, source="hardware_clock", drift_ms=150),
            camera_pipeline=CameraPipeline(
                sensor_orientation=90,
                has_watermark=False,
                claimed_integrity="raw_sensor",
            ),
        )

    def test_encode_then_decode_is_identity(self):
        encoded = encode_attestation(self.attestation)
        decoded = decode_attestation(encoded)

        self.assertEqual(decoded.version, self.attestation.version)
        self.assertEqual(decoded.trust_level, self.attestation.trust_level)
        self.assertEqual(decoded.capture_nonce, self.attestation.capture_nonce)
        self.assertEqual(decoded.app_identity.package_name, self.attestation.app_identity.package_name)
        self.assertEqual(decoded.device_commitment, self.attestation.device_commitment)
        self.assertEqual(decoded.privacy_scope, self.attestation.privacy_scope)
        self.assertEqual(decoded.evidence_digest_binding, self.attestation.evidence_digest_binding)

    def test_canonical_hash_is_deterministic(self):
        h1 = canonical_attestation_hash(self.attestation)
        h2 = canonical_attestation_hash(self.attestation)
        self.assertEqual(h1, h2)

    def test_canonical_hash_changes_when_trust_level_changes(self):
        h1 = canonical_attestation_hash(self.attestation)
        modified = CaptureAttestation(
            **{**self.attestation.__dict__, "trust_level": 1}
        )
        h2 = canonical_attestation_hash(modified)
        self.assertNotEqual(h1, h2)


class TestEvidenceBinding(unittest.TestCase):
    """The attestation must be cryptographically bound to the evidence."""

    def setUp(self):
        self.evidence = b"original-evidence-payload"
        self.attestation = CaptureAttestation(
            version=1,
            trust_level=2,
            capture_nonce=hashlib.sha256(b"n").hexdigest(),
            app_identity=AppIdentity(package_name="com.example", version_code="1"),
            device_commitment="a" * 64,
            privacy_scope="per_session",
            evidence_digest_binding=hashlib.sha256(self.evidence).hexdigest(),
        )

    def test_matching_evidence_passes(self):
        self.assertTrue(verify_evidence_binding(self.attestation, self.evidence))

    def test_non_matching_evidence_fails(self):
        self.assertFalse(verify_evidence_binding(self.attestation, b"different-evidence"))

    def test_empty_evidence(self):
        attestation = CaptureAttestation(
            version=1,
            trust_level=0,
            capture_nonce=hashlib.sha256(b"n").hexdigest(),
            app_identity=AppIdentity(package_name="com.example", version_code="1"),
            device_commitment="a" * 64,
            privacy_scope="per_session",
            evidence_digest_binding=hashlib.sha256(b"").hexdigest(),
        )
        self.assertTrue(verify_evidence_binding(attestation, b""))


class TestDeviceCommitment(unittest.TestCase):
    """The device commitment must verify with the correct per-session key."""

    def setUp(self):
        self.key = os.urandom(32)
        self.nonce = hashlib.sha256(b"device-nonce").hexdigest()

    def test_commitment_verifies_with_correct_key(self):
        commitment = make_device_commitment(self.nonce, self.key)
        attestation = CaptureAttestation(
            version=1,
            trust_level=2,
            capture_nonce=self.nonce,
            app_identity=AppIdentity(package_name="com.example", version_code="1"),
            device_commitment=commitment,
            privacy_scope="per_session",
            evidence_digest_binding=hashlib.sha256(b"ev").hexdigest(),
        )
        self.assertTrue(verify_device_commitment(attestation, self.key))

    def test_commitment_fails_with_wrong_key(self):
        commitment = make_device_commitment(self.nonce, self.key)
        attestation = CaptureAttestation(
            version=1,
            trust_level=2,
            capture_nonce=self.nonce,
            app_identity=AppIdentity(package_name="com.example", version_code="1"),
            device_commitment=commitment,
            privacy_scope="per_session",
            evidence_digest_binding=hashlib.sha256(b"ev").hexdigest(),
        )
        wrong_key = os.urandom(32)
        self.assertFalse(verify_device_commitment(attestation, wrong_key))


class TestTrustLevels(unittest.TestCase):
    """All trust levels round-trip correctly."""

    def test_every_trust_level_round_trips(self):
        for level in range(5):
            attestation = CaptureAttestation(
                version=1,
                trust_level=level,
                capture_nonce=hashlib.sha256(f"nonce-{level}".encode()).hexdigest(),
                app_identity=AppIdentity(package_name="com.example", version_code="1"),
                device_commitment="a" * 64,
                privacy_scope="per_session",
                evidence_digest_binding=hashlib.sha256(b"ev").hexdigest(),
            )
            encoded = encode_attestation(attestation)
            self.assertEqual(encoded["trustLevel"], level, f"Level {level} not round-tripped")


class TestReplayProtection(unittest.TestCase):
    """Replay attacks must be detectable."""

    def test_different_nonce_produces_different_device_commitment(self):
        key = os.urandom(32)
        c1 = make_device_commitment(hashlib.sha256(b"nonce-1").hexdigest(), key)
        c2 = make_device_commitment(hashlib.sha256(b"nonce-2").hexdigest(), key)
        self.assertNotEqual(c1, c2)

    def test_same_nonce_same_key_produces_same_commitment(self):
        key = os.urandom(32)
        nonce = hashlib.sha256(b"nonce-reuse-test").hexdigest()
        c1 = make_device_commitment(nonce, key)
        c2 = make_device_commitment(nonce, key)
        self.assertEqual(c1, c2)


class TestValidation(unittest.TestCase):
    """Input validation must reject malformed attestation objects."""

    def test_rejects_missing_profile(self):
        with self.assertRaises(ValueError):
            decode_attestation({"version": 1})

    def test_rejects_unsupported_version(self):
        with self.assertRaises(ValueError):
            decode_attestation({
                "version": 99,
                "profile": "harpocrates-capture-attestation/v1",
                "trustLevel": 0,
                "captureNonce": "a" * 64,
                "appIdentity": {"packageName": "x", "versionCode": "1"},
                "deviceCommitment": "a" * 64,
                "privacyScope": "per_session",
                "evidenceDigestBinding": "a" * 64,
            })

    def test_rejects_invalid_trust_level(self):
        with self.assertRaises(ValueError):
            CaptureAttestation(
                version=1,
                trust_level=99,
                capture_nonce="a" * 64,
                app_identity=AppIdentity(package_name="x", version_code="1"),
                device_commitment="a" * 64,
                privacy_scope="per_session",
                evidence_digest_binding="a" * 64,
            )

    def test_rejects_non_hex_nonce(self):
        with self.assertRaises(ValueError):
            CaptureAttestation(
                version=1,
                trust_level=0,
                capture_nonce="not-hex",
                app_identity=AppIdentity(package_name="x", version_code="1"),
                device_commitment="a" * 64,
                privacy_scope="per_session",
                evidence_digest_binding="a" * 64,
            )

    def test_rejects_invalid_privacy_scope(self):
        with self.assertRaises(ValueError):
            CaptureAttestation(
                version=1,
                trust_level=0,
                capture_nonce="a" * 64,
                app_identity=AppIdentity(package_name="x", version_code="1"),
                device_commitment="a" * 64,
                privacy_scope="invalid_scope",
                evidence_digest_binding="a" * 64,
            )

    def test_rejects_invalid_time_source(self):
        with self.assertRaises(ValueError):
            CaptureAttestation(
                version=1,
                trust_level=0,
                capture_nonce="a" * 64,
                app_identity=AppIdentity(package_name="x", version_code="1"),
                device_commitment="a" * 64,
                privacy_scope="per_session",
                evidence_digest_binding="a" * 64,
                secure_time=SecureTime(unix_ms=0, source="bad_source", drift_ms=0),
            )


class TestDowngradeProtection(unittest.TestCase):
    """Stripping or downgrading attestation must be detectable."""

    def test_canonical_hash_differs_when_attestation_removed(self):
        attestation = CaptureAttestation(
            version=1,
            trust_level=2,
            capture_nonce="a" * 64,
            app_identity=AppIdentity(package_name="com.example", version_code="1"),
            device_commitment="a" * 64,
            privacy_scope="per_session",
            evidence_digest_binding="a" * 64,
        )
        h_with = canonical_attestation_hash(attestation)

        unattested = CaptureAttestation(
            version=1,
            trust_level=0,
            capture_nonce="a" * 64,
            app_identity=AppIdentity(package_name="com.example", version_code="1"),
            device_commitment="a" * 64,
            privacy_scope="per_session",
            evidence_digest_binding="a" * 64,
        )
        h_without = canonical_attestation_hash(unattested)

        self.assertNotEqual(h_with, h_without)


class TestMinimalAttestation(unittest.TestCase):
    """The minimal valid attestation passes all checks."""

    def test_minimal_attestation_is_valid(self):
        attestation = CaptureAttestation(
            version=1,
            trust_level=0,
            capture_nonce=hashlib.sha256(b"minimal").hexdigest(),
            app_identity=AppIdentity(package_name="com.example", version_code="1"),
            device_commitment=make_device_commitment(
                hashlib.sha256(b"minimal").hexdigest(), b"x" * 32
            ),
            privacy_scope="per_session",
            evidence_digest_binding=hashlib.sha256(b"").hexdigest(),
        )
        encoded = encode_attestation(attestation)
        self.assertIn("profile", encoded)
        self.assertEqual(encoded["profile"], "harpocrates-capture-attestation/v1")


class TestCaptureAttestationRoute(unittest.TestCase):
    """Route tests for POST /api/capture-attestation/verify."""

    def setUp(self):
        from app import create_app

        self.app = create_app()
        self.client = self.app.test_client()

        self.device_key = os.urandom(32)
        self.nonce = hashlib.sha256(b"route-test-nonce").hexdigest()
        self.evidence = b"route-test-evidence-bytes"
        self.evidence_digest = hashlib.sha256(self.evidence).hexdigest()

        self.attestation = CaptureAttestation(
            version=1,
            trust_level=2,
            capture_nonce=self.nonce,
            app_identity=AppIdentity(
                package_name="com.harpocrates.camera",
                version_code="10",
                build_fingerprint="google/sunfish:12/SP1A",
                signing_digest=hashlib.sha256(b"cert").hexdigest(),
            ),
            device_commitment=make_device_commitment(self.nonce, self.device_key),
            privacy_scope="per_session",
            evidence_digest_binding=self.evidence_digest,
            secure_time=SecureTime(unix_ms=1721971200000, source="hardware_clock", drift_ms=50),
            camera_pipeline=CameraPipeline(
                sensor_orientation=0,
                has_watermark=False,
                claimed_integrity="raw_sensor",
            ),
        )
        self.encoded_attestation = encode_attestation(self.attestation)

    def test_valid_attestation_returns_valid_true_and_canonical_hash(self):
        res = self.client.post(
            "/api/capture-attestation/verify",
            json={
                "attestation": self.encoded_attestation,
                "evidence_digest": self.evidence_digest,
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("ok"))
        self.assertTrue(data.get("valid"))
        self.assertEqual(data.get("attestation_hash"), canonical_attestation_hash(self.attestation))
        self.assertEqual(data.get("checks"), {"evidence_binding": True})
        self.assertIn("request_id", data)

    def test_mismatched_evidence_digest_reports_failing_check(self):
        wrong_digest = hashlib.sha256(b"tampered-evidence").hexdigest()
        res = self.client.post(
            "/api/capture-attestation/verify",
            json={
                "attestation": self.encoded_attestation,
                "evidence_digest": wrong_digest,
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("ok"))
        self.assertFalse(data.get("valid"))
        self.assertEqual(data.get("attestation_hash"), canonical_attestation_hash(self.attestation))
        self.assertEqual(data.get("checks"), {"evidence_binding": False})

    def test_device_commitment_verification_with_matching_device_key(self):
        res = self.client.post(
            "/api/capture-attestation/verify",
            json={
                "attestation": self.encoded_attestation,
                "evidence_digest": self.evidence_digest,
                "device_key": self.device_key.hex(),
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("ok"))
        self.assertTrue(data.get("valid"))
        self.assertEqual(
            data.get("checks"),
            {"evidence_binding": True, "device_commitment": True},
        )

    def test_device_commitment_verification_with_mismatched_device_key(self):
        wrong_key = os.urandom(32).hex()
        res = self.client.post(
            "/api/capture-attestation/verify",
            json={
                "attestation": self.encoded_attestation,
                "evidence_digest": self.evidence_digest,
                "device_key": wrong_key,
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("ok"))
        self.assertFalse(data.get("valid"))
        self.assertEqual(
            data.get("checks"),
            {"evidence_binding": True, "device_commitment": False},
        )

    def test_camel_case_input_fields_accepted(self):
        res = self.client.post(
            "/api/capture-attestation/verify",
            json={
                "attestation": self.encoded_attestation,
                "evidenceDigest": self.evidence_digest,
                "deviceKey": self.device_key.hex(),
            },
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("valid"))
        self.assertTrue(data.get("checks")["evidence_binding"])
        self.assertTrue(data.get("checks")["device_commitment"])

    def test_malformed_missing_attestation_returns_400(self):
        res = self.client.post(
            "/api/capture-attestation/verify",
            json={"evidence_digest": self.evidence_digest},
        )
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get("ok"))
        self.assertEqual(data["error"]["code"], "VALIDATION_ERROR")
        self.assertEqual(data["error"]["message"], "attestation is required")

    def test_malformed_attestation_not_dict_returns_400(self):
        res = self.client.post(
            "/api/capture-attestation/verify",
            json={"attestation": "not-an-object", "evidence_digest": self.evidence_digest},
        )
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get("ok"))
        self.assertEqual(data["error"]["code"], "VALIDATION_ERROR")
        self.assertEqual(data["error"]["message"], "attestation must be a JSON object")

    def test_malformed_missing_evidence_digest_returns_400(self):
        res = self.client.post(
            "/api/capture-attestation/verify",
            json={"attestation": self.encoded_attestation},
        )
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get("ok"))
        self.assertEqual(data["error"]["code"], "VALIDATION_ERROR")
        self.assertEqual(data["error"]["message"], "evidence_digest is required")

    def test_malformed_invalid_hex_evidence_digest_returns_400(self):
        res = self.client.post(
            "/api/capture-attestation/verify",
            json={"attestation": self.encoded_attestation, "evidence_digest": "not-hex-digest"},
        )
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get("ok"))
        self.assertEqual(data["error"]["code"], "VALIDATION_ERROR")
        self.assertEqual(data["error"]["message"], "evidence_digest must be a 32-byte hex string")

    def test_malformed_invalid_hex_device_key_returns_400(self):
        res = self.client.post(
            "/api/capture-attestation/verify",
            json={
                "attestation": self.encoded_attestation,
                "evidence_digest": self.evidence_digest,
                "device_key": "short-key",
            },
        )
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get("ok"))
        self.assertEqual(data["error"]["code"], "VALIDATION_ERROR")
        self.assertEqual(data["error"]["message"], "device_key must be a 32-byte hex string")

    def test_malformed_attestation_fields_returns_400(self):
        bad_attestation = dict(self.encoded_attestation)
        bad_attestation["profile"] = "wrong-profile"
        res = self.client.post(
            "/api/capture-attestation/verify",
            json={"attestation": bad_attestation, "evidence_digest": self.evidence_digest},
        )
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get("ok"))
        self.assertEqual(data["error"]["code"], "VALIDATION_ERROR")
        self.assertEqual(data["error"]["message"], "malformed attestation payload")

    def test_malformed_payload_does_not_echo_input(self):
        sensitive_string = "SENSITIVE_SECRET_12345"
        bad_attestation = dict(self.encoded_attestation)
        bad_attestation["captureNonce"] = sensitive_string
        res = self.client.post(
            "/api/capture-attestation/verify",
            json={"attestation": bad_attestation, "evidence_digest": self.evidence_digest},
        )
        self.assertEqual(res.status_code, 400)
        self.assertNotIn(sensitive_string, res.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()

