import unittest

from lineage import (
    LineageValidationError,
    canonical_lineage_manifest,
    lineage_manifest_digest,
    validate_lineage_graph,
)


class LineageManifestTests(unittest.TestCase):
    def test_canonical_lineage_manifest_is_stable(self) -> None:
        manifest = {
            "parentProofIds": ["a" * 64, "b" * 64],
            "operationType": "crop",
            "parametersDigest": "c" * 64,
            "toolIdentity": "harpocrates-studio",
            "toolVersion": "1.2.3",
            "outputDigest": "d" * 64,
            "network": "testnet",
            "actorAddress": "GAJC123",
        }
        first = canonical_lineage_manifest(manifest)
        second = canonical_lineage_manifest(manifest)
        self.assertEqual(first, second)
        self.assertEqual(lineage_manifest_digest(manifest), lineage_manifest_digest(manifest))

    def test_rejects_unsupported_operation(self) -> None:
        with self.assertRaises(LineageValidationError):
            canonical_lineage_manifest({
                "parentProofIds": ["a" * 64],
                "operationType": "unsupported",
                "parametersDigest": "c" * 64,
                "toolIdentity": "harpocrates-studio",
                "toolVersion": "1.2.3",
                "outputDigest": "d" * 64,
                "network": "testnet",
                "actorAddress": "GAJC123",
            })

    def test_rejects_excessive_fanout(self) -> None:
        with self.assertRaises(LineageValidationError):
            canonical_lineage_manifest({
                "parentProofIds": ["a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64],
                "operationType": "compose",
                "parametersDigest": "c" * 64,
                "toolIdentity": "harpocrates-studio",
                "toolVersion": "1.2.3",
                "outputDigest": "d" * 64,
                "network": "testnet",
                "actorAddress": "GAJC123",
            })

    def test_rejects_direct_cycle(self) -> None:
        output = "a" * 64
        with self.assertRaises(LineageValidationError) as ctx:
            validate_lineage_graph(
                parent_proof_ids=[output],
                depth=1,
                actor_address="GAJC123",
                output_digest=output,
            )
        self.assertIn("cycle", str(ctx.exception).lower())

    def test_rejects_missing_actor_address(self) -> None:
        with self.assertRaises(LineageValidationError):
            validate_lineage_graph(
                parent_proof_ids=["a" * 64],
                depth=1,
                actor_address="",
            )

    def test_accepts_valid_lineage_graph(self) -> None:
        # Should not raise
        validate_lineage_graph(
            parent_proof_ids=["a" * 64, "b" * 64],
            depth=1,
            actor_address="GAJC123",
            output_digest="c" * 64,
        )


class LineageListEndpointErrorEnvelopeTests(unittest.TestCase):
    """Tests for the standard error envelope on lineage list endpoints."""

    def setUp(self) -> None:
        try:
            from app import app
        except Exception as exc:  # noqa: BROEART
            self.skipTest(f"app module unavailable: {exc}")
            return
        self.app = app
        self.client = app.test_client()

    def _assert_validation_envelope(self, response) -> None:
        self.assertEqual(response.status_code, 400)
        payload = response.get_json()
        self.assertIsInstance(payload, dict)
        self.assertIn("error", payload)
        error = payload["error"]
        self.assertIsInstance(error, dict)
        self.assertEqual(error.get("code"), "VALIDATION_ERROR")
        self.assertTruthy(error.get("requestId") or payload.get("requestId"))

    def test_lineage_events_rejects_non_integer_limit(self) -> None:
        response = self.client.get("/api/proofs/lineage?limit=abc")
        self._assert_validation_envelope(response)

    def test_lineage_events_rejects_negative_limit(self) -> None:
        response = self.client.get("/api/proofs/lineage?limit=-1")
        self._assert_validation_envelope(response)

    def test_lineage_by_actor_rejects_non_integer_limit(self) -> None:
        response = self.client.get("/api/proofs/lineage/actor/GAJC123?limit=abc")
        self._assert_validation_envelope(response)

    def test_lineage_by_actor_rejects_negative_limit(self) -> None:
        response = self.client.get("/api/proofs/lineage/actor/GAJC123?limit=-1")
        self._assert_validation_envelope(response)


class LineageByActorApiTests(unittest.TestCase):
    """Tests for GET /api/lineage/by-actor/<actor_address> address validation."""

    VALID_G_ADDRESS = "GCCHDCX2JTLB6FDKHGIAAQPS6JHBDETFXTCQRETJUP5BWBVT6G4LQKOQ"
    VALID_C_CONTRACT = "CBQQWKW6JE6NAFM7HT7R5DNMCPISCVY275LPSUPIRLYTY3ICKYJDIANZ"

    def setUp(self) -> None:
        import sys
        import types
        from unittest.mock import patch

        if "storage" not in sys.modules:
            try:
                import storage  # noqa: F401
            except SyntaxError:
                mock_storage = types.ModuleType("storage")
                mock_storage.get_job_output_path = lambda x: None
                mock_storage.get_job_input_path = lambda x: None
                mock_storage.get_storage_dir = lambda: None
                sys.modules["storage"] = mock_storage

        from app import create_app

        self.app = create_app()
        self.client = self.app.test_client()

    def test_valid_g_address_returns_200_and_expected_shape(self) -> None:
        from unittest.mock import patch

        fake_events = [
            {
                "id": 1,
                "manifest_digest": "a" * 64,
                "actor_address": self.VALID_G_ADDRESS,
            }
        ]
        with patch("app.find_lineage_by_actor", return_value=fake_events) as mock_find:
            response = self.client.get(f"/api/lineage/by-actor/{self.VALID_G_ADDRESS}")
            self.assertEqual(response.status_code, 200)
            mock_find.assert_called_once_with(self.VALID_G_ADDRESS, 25)

            data = response.get_json()
            self.assertTrue(data["ok"])
            self.assertEqual(data["events"], fake_events)

    def test_valid_lowercase_g_address_is_normalized_and_accepted(self) -> None:
        from unittest.mock import patch

        with patch("app.find_lineage_by_actor", return_value=[]) as mock_find:
            response = self.client.get(
                f"/api/lineage/by-actor/{self.VALID_G_ADDRESS.lower()}"
            )
            self.assertEqual(response.status_code, 200)
            mock_find.assert_called_once_with(self.VALID_G_ADDRESS, 25)

            data = response.get_json()
            self.assertTrue(data["ok"])
            self.assertEqual(data["events"], [])

    def test_malformed_address_returns_400_with_standard_error_envelope(self) -> None:
        from unittest.mock import patch

        malformed_candidates = [
            "not-an-address",
            "G12345",
            "GCCHDCX2JTLB6FDKHGIAAQPS6JHBDETFXTCQRETJUP5BWBVT6G4LQKXX",  # invalid checksum
            "G" * 56,  # invalid characters/version
            "00000000000000000000000000000000000000000000000000000000",
        ]

        for malformed in malformed_candidates:
            with self.subTest(actor_address=malformed):
                with patch("app.find_lineage_by_actor") as mock_find:
                    response = self.client.get(f"/api/lineage/by-actor/{malformed}")
                    self.assertEqual(response.status_code, 400)
                    mock_find.assert_not_called()

                    data = response.get_json()
                    self.assertFalse(data["ok"])
                    self.assertIn("error", data)
                    self.assertEqual(data["error"]["code"], "VALIDATION_ERROR")
                    self.assertIn("message", data["error"])
                    # Acceptance criterion: Error message does not echo the address
                    self.assertNotIn(malformed, data["error"]["message"])

    def test_contract_c_address_rejected_with_400_and_standard_error_envelope(self) -> None:
        from unittest.mock import patch

        with patch("app.find_lineage_by_actor") as mock_find:
            response = self.client.get(f"/api/lineage/by-actor/{self.VALID_C_CONTRACT}")
            self.assertEqual(response.status_code, 400)
            mock_find.assert_not_called()

            data = response.get_json()
            self.assertFalse(data["ok"])
            self.assertIn("error", data)
            self.assertEqual(data["error"]["code"], "VALIDATION_ERROR")
            self.assertIn("message", data["error"])
            # Acceptance criterion: Error message does not echo the address
            self.assertNotIn(self.VALID_C_CONTRACT, data["error"]["message"])