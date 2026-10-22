# harpocrates:ignore-file
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from devx.secret_scanner import (
    compute_line_hash,
    is_secret_allowlisted,
    load_baseline,
    main,
    save_baseline,
    scan_file,
)

class TestSecretScanner(unittest.TestCase):
    def test_safe_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
            f.write("Just some safe text.")
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = scan_file(path)
        self.assertEqual(len(errors), 0)
        
    def test_stellar_secret_key(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
            f.write("S" + "A"*55)
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = scan_file(path)
        self.assertIn("secrets violation: private key detected", errors)

    def test_rsa_private_key(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
            f.write("-----BEGIN RSA PRIVATE KEY-----\nMIICXAIBAAKBgQC...\n-----END RSA PRIVATE KEY-----")
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = scan_file(path)
        self.assertIn("secrets violation: private key detected", errors)

    def test_media_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".mp4", delete=False) as f:
            f.write("fake video content")
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = scan_file(path)
        self.assertIn("unsupported input: real media files are prohibited", errors)

    def test_witness_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".tr", delete=False) as f:
            f.write("fake witness content")
            path = Path(f.name)
        self.addCleanup(path.unlink)
        errors = scan_file(path)
        self.assertIn("unsupported input: witness values are prohibited", errors)

    def test_allowlisted_test_fixtures(self):
        # Allowlisted test fixtures with dummy RSA key should not produce errors
        self.assertTrue(is_secret_allowlisted(Path("devx/test_c2pa_parser.py")))
        self.assertTrue(is_secret_allowlisted(Path("devx/test_validate_c2pa_fixture.py")))
        self.assertTrue(is_secret_allowlisted(Path("devx/tests/test_retain_proof_artifacts.py")))
        self.assertTrue(is_secret_allowlisted(Path("backend/test_redaction_adversarial.py")))
        self.assertTrue(is_secret_allowlisted(Path("backend/test_trace_fields.py")))
        self.assertTrue(is_secret_allowlisted(Path("devx/fixtures/c2pa/manifest.json")))
        self.assertFalse(is_secret_allowlisted(Path("backend/routes.py")))

    def test_allowlisted_fixture_scan(self):
        tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(tmp_dir.cleanup)
        devx_dir = Path(tmp_dir.name) / "devx"
        devx_dir.mkdir(parents=True, exist_ok=True)
        fixture_path = devx_dir / "test_c2pa_parser.py"
        fixture_path.write_text('dummy = "-----BEGIN RSA PRIVATE KEY-----"', encoding="utf-8")
        
        errors = scan_file(fixture_path, repo_root=Path(tmp_dir.name))
        self.assertEqual(len(errors), 0)

    def test_oversized_file(self):
        # We can simulate by monkeypatching stat or creating a sparse file
        pass

    def test_baseline_match(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".py") as f:
            line = 'DUMMY_KEY = "-----BEGIN RSA PRIVATE KEY-----"\n'
            f.write(line)
            path = Path(f.name)
        self.addCleanup(path.unlink)

        line_hash = compute_line_hash(line)
        baseline = [
            {"path": path.name, "rule": "private_key", "line_hash": line_hash}
        ]
        errors = scan_file(path, baseline=baseline)
        self.assertEqual(len(errors), 0)

    def test_baseline_new_finding(self):
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".py") as f:
            line = 'DUMMY_KEY = "-----BEGIN RSA PRIVATE KEY-----"\n'
            f.write(line)
            path = Path(f.name)
        self.addCleanup(path.unlink)

        # Baseline with different hash should not match new finding
        baseline = [
            {"path": path.name, "rule": "private_key", "line_hash": "different_hash"}
        ]
        errors = scan_file(path, baseline=baseline)
        self.assertIn("secrets violation: private key detected", errors)

    def test_baseline_stale_entry(self):
        tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(tmp_dir.cleanup)
        root = Path(tmp_dir.name)
        safe_file = root / "clean_test.py"
        safe_file.write_text('msg = "nothing secret here"\n', encoding="utf-8")

        baseline_file = root / "secret_baseline.json"
        stale_entries = [
            {"path": "clean_test.py", "rule": "private_key", "line_hash": "stale_hash_value"}
        ]
        baseline_file.write_text(json.dumps(stale_entries), encoding="utf-8")

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = main(["--baseline", str(baseline_file)], repo_root=root)

        self.assertEqual(code, 0)
        self.assertIn("Warning: Stale baseline entry", err.getvalue())
        self.assertIn("clean_test.py", err.getvalue())

    def test_update_baseline(self):
        tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(tmp_dir.cleanup)
        root = Path(tmp_dir.name)
        test_file = root / "test_fixture.py"
        test_line = 'TEST_KEY = "-----BEGIN RSA PRIVATE KEY-----"\n'
        test_file.write_text(test_line, encoding="utf-8")

        baseline_file = root / "custom_baseline.json"
        code = main(["--baseline", str(baseline_file), "--update-baseline"], repo_root=root)
        self.assertEqual(code, 0)
        self.assertTrue(baseline_file.exists())

        raw_content = baseline_file.read_text(encoding="utf-8")
        # Ensure raw secret is NEVER in the baseline file
        self.assertNotIn("BEGIN RSA PRIVATE KEY", raw_content)

        entries = json.loads(raw_content)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["path"], "test_fixture.py")
        self.assertEqual(entries[0]["rule"], "private_key")
        self.assertEqual(entries[0]["line_hash"], compute_line_hash(test_line))

        # Subsequent scan using this baseline succeeds without errors
        scan_code = main(["--baseline", str(baseline_file)], repo_root=root)
        self.assertEqual(scan_code, 0)

if __name__ == "__main__":
    unittest.main()
