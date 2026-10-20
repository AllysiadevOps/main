"""Unit tests for devx/retain_proof_artifacts.py.

Verifies proof artifact retention and fail-closed privacy rules:
- Allowed artifacts (.proof, .vk, .json, .sha256, .hex) copied to destination
- Non-allowlisted files safely skipped and counted in manifest
- Denied media, private keys, seeds, prover.toml, and witness files rejected
- Per-file and total size bounds enforced
- Non-empty output directories rejected
- Dry-run mode writes nothing to disk
- All CLI options (--src, --out, --max-file-bytes, --max-total-bytes, --dry-run) exercised
- Exit codes strictly asserted (0 success, 2 violation/argparse error, 3 IO error)
- Output never echoes file contents, secrets, or file names
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Ensure devx is on sys.path regardless of how tests are invoked
DEVX_DIR = Path(__file__).resolve().parent
REPO_ROOT = DEVX_DIR.parent
if str(DEVX_DIR) not in sys.path:
    sys.path.insert(0, str(DEVX_DIR))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

try:
    import retain_proof_artifacts as rpa
except ImportError:
    from devx import retain_proof_artifacts as rpa

# Synthetic test seed matching the Stellar secret pattern: S followed by 55 base32 chars
FAKE_STELLAR_SEED = "S" + "A" * 55
FAKE_PRIVATE_KEY_PEM = "-----BEGIN PRIVATE KEY-----\nMIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQg...\n-----END PRIVATE KEY-----"


def run_cli(args: list[str]) -> tuple[int, str, str]:
    """Execute retain_proof_artifacts.main with args, capturing exit code, stdout, and stderr."""
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stderr_buf):
        try:
            code = rpa.main(args)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 2)
    return code, stdout_buf.getvalue(), stderr_buf.getvalue()


class TestRetainProofArtifacts(unittest.TestCase):
    """Test suite for retain_proof_artifacts using temporary directory paths (tmp_path)."""

    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._temp_dir.name)
        self.src = self.tmp_path / "src"
        self.src.mkdir(parents=True, exist_ok=True)
        self.out = self.tmp_path / "out"

    def tearDown(self) -> None:
        self._temp_dir.cleanup()

    def write_file(self, parent: Path, rel_path: str, data: bytes | str) -> Path:
        """Helper to write content to a relative path inside parent."""
        target = parent / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            target.write_text(data, encoding="utf-8")
        else:
            target.write_bytes(data)
        return target

    def assert_violation(self, expected_code: str, *extra_args: str) -> None:
        """Run CLI and assert exit code 2, expected policy violation, and clean output."""
        code, stdout, stderr = run_cli(["--src", str(self.src), "--out", str(self.out), *extra_args])
        self.assertEqual(code, 2, f"Expected exit code 2 for violation {expected_code}, got {code}")
        self.assertIn(f"policy violation: {expected_code}", stderr)
        self.assertFalse(self.out.exists(), f"Output directory must not be created on violation: {self.out}")

    # =========================================================================
    # 1. Allowed artifacts copied & manifest verification
    # =========================================================================

    def test_allowed_artifacts_copied(self) -> None:
        """All allowlisted file types (.proof, .vk, .json, .sha256, .hex) are retained."""
        tmp_path = self.tmp_path
        src = tmp_path / "src"
        out = tmp_path / "out"

        self.write_file(src, "witness.proof", b"\x01\x02\x03\x04")
        self.write_file(src, "verifier.vk", b"vk-bytes-content")
        self.write_file(src, "metadata.json", json.dumps({"protocol": "harpocrates", "version": 1}))
        self.write_file(src, "checksum.sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n")
        self.write_file(src, "data.hex", "deadbeef01234567\n")

        code, stdout, stderr = run_cli(["--src", str(src), "--out", str(out)])
        self.assertEqual(code, 0, f"Expected 0, stderr: {stderr}")
        self.assertIn("retained 5 files", stdout)

        manifest_path = out / "retention-manifest.json"
        self.assertTrue(manifest_path.exists())
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(manifest["schema"], rpa.SCHEMA)
        self.assertEqual(manifest["skippedNotAllowlisted"], 0)
        self.assertEqual(len(manifest["files"]), 5)

        retained_paths = {f["path"] for f in manifest["files"]}
        expected_paths = {
            "src0/witness.proof",
            "src0/verifier.vk",
            "src0/metadata.json",
            "src0/checksum.sha256",
            "src0/data.hex",
        }
        self.assertEqual(retained_paths, expected_paths)

        # Verify actual copied files
        for rel in expected_paths:
            self.assertTrue((out / rel).exists(), f"Expected {rel} in output directory")

    def test_repeatable_src_cli_option(self) -> None:
        """CLI option --src can be passed multiple times (exercising repeatable --src)."""
        tmp_path = self.tmp_path
        src1 = tmp_path / "src1"
        src2 = tmp_path / "src2"
        out = tmp_path / "out"

        self.write_file(src1, "first.proof", b"first-proof")
        self.write_file(src2, "second.vk", b"second-vk")

        code, stdout, stderr = run_cli([
            "--src", str(src1),
            "--src", str(src2),
            "--out", str(out),
        ])
        self.assertEqual(code, 0, f"Expected 0, stderr: {stderr}")
        self.assertIn("retained 2 files", stdout)

        self.assertTrue((out / "src0" / "first.proof").exists())
        self.assertTrue((out / "src1" / "second.vk").exists())

        manifest = json.loads((out / "retention-manifest.json").read_text(encoding="utf-8"))
        paths = [f["path"] for f in manifest["files"]]
        self.assertIn("src0/first.proof", paths)
        self.assertIn("src1/second.vk", paths)

    def test_nested_source_directories_preserved(self) -> None:
        """Subdirectories within source directory are preserved under src0/."""
        tmp_path = self.tmp_path
        src = tmp_path / "src"
        out = tmp_path / "out"

        self.write_file(src, "sub/deep/circuit.proof", b"deep-circuit")
        code, stdout, stderr = run_cli(["--src", str(src), "--out", str(out)])
        self.assertEqual(code, 0, f"Expected 0, stderr: {stderr}")
        self.assertTrue((out / "src0" / "sub" / "deep" / "circuit.proof").exists())

    def test_manifest_determinism(self) -> None:
        """Manifest JSON output is deterministic and formatted with sort_keys and indent."""
        tmp_path = self.tmp_path
        src = tmp_path / "src"
        out1 = tmp_path / "out1"
        out2 = tmp_path / "out2"

        self.write_file(src, "z_last.proof", b"z")
        self.write_file(src, "a_first.hex", b"a")

        code1, _, _ = run_cli(["--src", str(src), "--out", str(out1)])
        code2, _, _ = run_cli(["--src", str(src), "--out", str(out2)])
        self.assertEqual(code1, 0)
        self.assertEqual(code2, 0)

        content1 = (out1 / "retention-manifest.json").read_text(encoding="utf-8")
        content2 = (out2 / "retention-manifest.json").read_text(encoding="utf-8")
        self.assertEqual(content1, content2)

    # =========================================================================
    # 2. Disallowed / sensitive files skipped or rejected
    # =========================================================================

    def test_disallowed_non_allowlisted_files_are_skipped(self) -> None:
        """Non-allowlisted file types (.md, .txt, .log) are skipped without error."""
        tmp_path = self.tmp_path
        src = tmp_path / "src"
        out = tmp_path / "out"

        self.write_file(src, "valid.proof", b"valid proof")
        self.write_file(src, "README.md", "# Documentation")
        self.write_file(src, "notes.txt", "Some build notes")
        self.write_file(src, "output.log", "Build log")

        code, stdout, stderr = run_cli(["--src", str(src), "--out", str(out)])
        self.assertEqual(code, 0, f"Expected 0, stderr: {stderr}")
        self.assertIn("skipped 3", stdout)

        # Non-allowlisted files must not be copied
        self.assertFalse((out / "src0" / "README.md").exists())
        self.assertFalse((out / "src0" / "notes.txt").exists())
        self.assertFalse((out / "src0" / "output.log").exists())
        self.assertTrue((out / "src0" / "valid.proof").exists())

        manifest = json.loads((out / "retention-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["skippedNotAllowlisted"], 3)
        self.assertEqual(len(manifest["files"]), 1)

    def test_denied_media_types_rejected(self) -> None:
        """Real media suffixes (.mp4, .png, .jpg, .wav, .mp3, etc.) trigger DENIED_TYPE."""
        for ext in [".mp4", ".png", ".jpg", ".wav", ".mp3", ".mov", ".gif"]:
            with self.subTest(ext=ext):
                self._temp_dir.cleanup()
                self.setUp()
                self.write_file(self.src, "valid.proof", b"ok")
                self.write_file(self.src, f"sample{ext}", b"\x00\x01\x02")
                self.assert_violation("DENIED_TYPE")

    def test_denied_keys_and_witnesses_rejected(self) -> None:
        """Cryptographic keys and witness files (.pem, .key, .p12, .pfx, .gz, .wtns) trigger DENIED_TYPE."""
        for ext in [".pem", ".key", ".p12", ".pfx", ".gz", ".wtns"]:
            with self.subTest(ext=ext):
                self._temp_dir.cleanup()
                self.setUp()
                self.write_file(self.src, "valid.proof", b"ok")
                self.write_file(self.src, f"artifact{ext}", b"payload")
                self.assert_violation("DENIED_TYPE")

    def test_denied_name_parts_rejected(self) -> None:
        """Filenames or directory parts with forbidden tokens trigger DENIED_NAME."""
        forbidden_names = [
            "Prover.toml",
            "prover.toml",
            "my_secret_data.proof",
            "seed_phrase.hex",
            "private_config.json",
            "mnemonic_words.json",
            ".env",
            ".env.production",
        ]
        for name in forbidden_names:
            with self.subTest(name=name):
                self._temp_dir.cleanup()
                self.setUp()
                self.write_file(self.src, "valid.proof", b"ok")
                self.write_file(self.src, name, b"test-payload")
                self.assert_violation("DENIED_NAME")

    def test_denied_name_in_parent_directory_rejected(self) -> None:
        """Denied name token appearing in an intermediate directory triggers DENIED_NAME."""
        self.write_file(self.src, "secret_dir/artifact.proof", b"ok")
        self.assert_violation("DENIED_NAME")

    def test_secret_content_private_key_rejected(self) -> None:
        """Content containing 'PRIVATE KEY' in allowlisted files triggers SECRET_CONTENT."""
        self.write_file(self.src, "leak.json", json.dumps({"key": FAKE_PRIVATE_KEY_PEM}))
        self.assert_violation("SECRET_CONTENT")

    def test_secret_content_stellar_seed_rejected(self) -> None:
        """Content containing a Stellar secret seed triggers SECRET_CONTENT."""
        self.write_file(self.src, "config.hex", f"prefix {FAKE_STELLAR_SEED} suffix")
        self.assert_violation("SECRET_CONTENT")

    def test_forbidden_json_key_rejected_nested(self) -> None:
        """Forbidden JSON keys (e.g., witness, secret, private_key, password) trigger FORBIDDEN_JSON_KEY."""
        forbidden_keys = [
            "witness",
            "secret",
            "seed",
            "privateKey",
            "private_key",
            "credential-secret",
            "nullifier_secret",
            "mnemonic",
            "password",
            "apiKey",
            "api_key",
            "token",
        ]
        for key in forbidden_keys:
            with self.subTest(key=key):
                self._temp_dir.cleanup()
                self.setUp()
                payload = {"data": [{"nested": {key: "sensitive_val"}}]}
                self.write_file(self.src, "artifact.json", json.dumps(payload))
                self.assert_violation("FORBIDDEN_JSON_KEY")

    def test_malformed_json_rejected(self) -> None:
        """Invalid JSON syntax in a .json file triggers MALFORMED_JSON."""
        self.write_file(self.src, "bad.json", '{"incomplete": true,')
        self.assert_violation("MALFORMED_JSON")

    def test_symlink_file_rejected(self) -> None:
        """Symlinked files in source directory trigger SYMLINK."""
        target = self.tmp_path / "real.proof"
        target.write_bytes(b"content")
        link = self.src / "link.proof"
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks not supported in current environment")
        self.assert_violation("SYMLINK")

    def test_symlink_directory_rejected(self) -> None:
        """Symlinked directory within source tree triggers SYMLINK."""
        real_dir = self.tmp_path / "real_dir"
        real_dir.mkdir()
        (real_dir / "file.proof").write_bytes(b"content")
        link_dir = self.src / "link_dir"
        try:
            os.symlink(real_dir, link_dir, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Directory symlinks not supported in current environment")
        self.assert_violation("SYMLINK")

    def test_missing_source_rejected(self) -> None:
        """Non-existent source directory triggers MISSING_SOURCE."""
        code, stdout, stderr = run_cli(["--src", str(self.tmp_path / "non_existent"), "--out", str(self.out)])
        self.assertEqual(code, 2)
        self.assertIn("policy violation: MISSING_SOURCE", stderr)
        self.assertFalse(self.out.exists())

    def test_source_is_file_rejected(self) -> None:
        """Source path pointing to a regular file instead of a directory triggers MISSING_SOURCE."""
        src_file = self.tmp_path / "file_src"
        src_file.write_bytes(b"not a directory")
        code, stdout, stderr = run_cli(["--src", str(src_file), "--out", str(self.out)])
        self.assertEqual(code, 2)
        self.assertIn("policy violation: MISSING_SOURCE", stderr)

    def test_nothing_to_retain_rejected(self) -> None:
        """Source containing only skipped non-allowlisted files triggers NOTHING_TO_RETAIN."""
        self.write_file(self.src, "notes.txt", "just plain text")
        self.assert_violation("NOTHING_TO_RETAIN")

    # =========================================================================
    # 3. Per-file and total size limits
    # =========================================================================

    def test_max_file_bytes_boundary(self) -> None:
        """CLI option --max-file-bytes is respected: exact limit succeeds, limit+1 triggers OVERSIZED."""
        limit = 64
        # Exactly at limit succeeds
        self.write_file(self.src, "exact.proof", b"x" * limit)
        code, stdout, stderr = run_cli([
            "--src", str(self.src),
            "--out", str(self.out),
            "--max-file-bytes", str(limit),
        ])
        self.assertEqual(code, 0, f"Expected 0, stderr: {stderr}")
        self.assertTrue((self.out / "src0" / "exact.proof").exists())

        # Cleanup output and test limit + 1
        self._temp_dir.cleanup()
        self.setUp()
        self.write_file(self.src, "oversized.proof", b"x" * (limit + 1))
        self.assert_violation("OVERSIZED", "--max-file-bytes", str(limit))

    def test_max_total_bytes_boundary(self) -> None:
        """CLI option --max-total-bytes is respected: total within limit succeeds, over triggers TOTAL_TOO_LARGE."""
        limit = 100
        # Exactly at limit (50 + 50) succeeds
        self.write_file(self.src, "p1.proof", b"x" * 50)
        self.write_file(self.src, "p2.proof", b"x" * 50)
        code, stdout, stderr = run_cli([
            "--src", str(self.src),
            "--out", str(self.out),
            "--max-total-bytes", str(limit),
        ])
        self.assertEqual(code, 0, f"Expected 0, stderr: {stderr}")

        # Cleanup output and test 51 + 50 = 101 > 100
        self._temp_dir.cleanup()
        self.setUp()
        self.write_file(self.src, "p1.proof", b"x" * 51)
        self.write_file(self.src, "p2.proof", b"x" * 50)
        self.assert_violation("TOTAL_TOO_LARGE", "--max-total-bytes", str(limit))

    def test_default_size_constants(self) -> None:
        """Default per-file and total size limits are 5 MiB and 25 MiB."""
        self.assertEqual(rpa.DEFAULT_MAX_FILE_BYTES, 5 * 1024 * 1024)
        self.assertEqual(rpa.DEFAULT_MAX_TOTAL_BYTES, 25 * 1024 * 1024)

    # =========================================================================
    # 4. Non-empty --out rejected
    # =========================================================================

    def test_non_empty_out_directory_rejected(self) -> None:
        """Non-empty output directory triggers OUT_NOT_EMPTY and writes nothing."""
        self.write_file(self.src, "a.proof", b"proof content")
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "existing_file.txt").write_text("already here", encoding="utf-8")

        code, stdout, stderr = run_cli(["--src", str(self.src), "--out", str(self.out)])
        self.assertEqual(code, 2)
        self.assertIn("policy violation: OUT_NOT_EMPTY", stderr)
        # Verify existing file was not overwritten or augmented
        self.assertFalse((self.out / "retention-manifest.json").exists())

    def test_existing_empty_out_directory_allowed(self) -> None:
        """An existing but empty output directory is accepted."""
        self.write_file(self.src, "a.proof", b"proof content")
        self.out.mkdir(parents=True, exist_ok=True)

        code, stdout, stderr = run_cli(["--src", str(self.src), "--out", str(self.out)])
        self.assertEqual(code, 0, f"Expected 0, stderr: {stderr}")
        self.assertTrue((self.out / "retention-manifest.json").exists())

    def test_out_path_is_existing_file_rejected(self) -> None:
        """Output path pointing to an existing file triggers OUT_NOT_EMPTY."""
        self.write_file(self.src, "a.proof", b"proof content")
        self.out.write_text("regular file", encoding="utf-8")

        code, stdout, stderr = run_cli(["--src", str(self.src), "--out", str(self.out)])
        self.assertEqual(code, 2)
        self.assertIn("policy violation: OUT_NOT_EMPTY", stderr)

    # =========================================================================
    # 5. Dry-run writing nothing
    # =========================================================================

    def test_dry_run_writes_nothing(self) -> None:
        """CLI option --dry-run checks policy and succeeds (0) without creating output dir or files."""
        tmp_path = self.tmp_path
        src = tmp_path / "src"
        out = tmp_path / "out"

        self.write_file(src, "test.proof", b"valid proof data")
        self.write_file(src, "vk.json", json.dumps({"vk": "0x1234"}))

        code, stdout, stderr = run_cli([
            "--src", str(src),
            "--out", str(out),
            "--dry-run",
        ])
        self.assertEqual(code, 0, f"Expected 0, stderr: {stderr}")
        self.assertIn("retained 2 files", stdout)
        self.assertFalse(out.exists(), "Output directory must not be created during --dry-run")

    def test_dry_run_fails_closed_on_violation(self) -> None:
        """--dry-run still enforces all policy violations and fails with code 2."""
        self.write_file(self.src, "secret.proof", b"valid bytes")
        code, stdout, stderr = run_cli([
            "--src", str(self.src),
            "--out", str(self.out),
            "--dry-run",
        ])
        self.assertEqual(code, 2)
        self.assertIn("policy violation: DENIED_NAME", stderr)
        self.assertFalse(self.out.exists())

    # =========================================================================
    # 6. Exit codes and CLI options
    # =========================================================================

    def test_cli_missing_required_arguments(self) -> None:
        """CLI without required --src or --out arguments exits with code 2."""
        code, _, stderr = run_cli([])
        self.assertEqual(code, 2)

        code, _, stderr = run_cli(["--src", str(self.src)])
        self.assertEqual(code, 2)

        code, _, stderr = run_cli(["--out", str(self.out)])
        self.assertEqual(code, 2)

    def test_io_error_handling(self) -> None:
        """OSError during output writing exits with code 3 and 'io error'."""
        self.write_file(self.src, "valid.proof", b"content")
        with mock.patch("retain_proof_artifacts.write_output", side_effect=OSError("Disk full")):
            code, stdout, stderr = run_cli(["--src", str(self.src), "--out", str(self.out)])
            self.assertEqual(code, 3)
            self.assertIn("io error", stderr)

    # =========================================================================
    # 7. Privacy: output never echoes file contents, secrets, or file names
    # =========================================================================

    def test_output_never_echoes_file_contents_or_secrets(self) -> None:
        """Assert stdout and stderr never echo file contents, private keys, seeds, or sensitive names."""
        sensitive_file_name = "highly-confidential-prover.toml"
        sensitive_body = f"secret_key = {FAKE_STELLAR_SEED}"

        self.write_file(self.src, sensitive_file_name, sensitive_body)
        self.write_file(self.src, "leak.hex", FAKE_STELLAR_SEED)
        self.write_file(self.src, "private.json", FAKE_PRIVATE_KEY_PEM)

        code, stdout, stderr = run_cli(["--src", str(self.src), "--out", str(self.out)])
        self.assertEqual(code, 2)

        combined_output = stdout + stderr
        self.assertNotIn(sensitive_file_name, combined_output, "File name must not be echoed in output")
        self.assertNotIn(FAKE_STELLAR_SEED, combined_output, "Secret seed must not be echoed in output")
        self.assertNotIn(FAKE_PRIVATE_KEY_PEM, combined_output, "Private key must not be echoed in output")
        self.assertNotIn("highly-confidential", combined_output)


if __name__ == "__main__":
    unittest.main()
