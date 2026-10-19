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
            "actorAddress": "GABC123",
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
                "actorAddress": "GABC123",
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
                "actorAddress": "GABC123",
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
            actor_address="GABC123",
            output_digest="c" * 64,
        )

