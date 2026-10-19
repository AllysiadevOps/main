"""Tests for devx/_io.py: shared bounded reading and sensitive pattern detection.

Covers:
  - File size bounds (inclusive limit, rejection of oversized files)
  - Missing file and OSError handling
  - UTF-8 decoding and rejection of invalid UTF-8 bytes
  - JSON bounded parsing, dict requirement, and sensitive key rejection
  - TOML bounded parsing and decode errors
  - Sensitive text matching across shared credential and secret patterns
  - Recursive sensitive key detection in nested structures
"""
from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from devx._io import (
    DEFAULT_SENSITIVE_KEY_RE,
    DEFAULT_SENSITIVE_TEXT_PATTERNS,
    contains_sensitive_text,
    find_sensitive_match,
    read_json_bounded,
    read_text_bounded,
    read_toml_bounded,
    reject_sensitive_keys,
)


class TestReadTextBounded(unittest.TestCase):
    def test_reads_valid_text(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write("hello world\n")
            path = Path(handle.name)
        self.addCleanup(path.unlink)

        content = read_text_bounded(path, limit=100)
        self.assertEqual(content, "hello world\n")

    def test_limit_is_inclusive(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as handle:
            handle.write(b"a" * 50)
            path = Path(handle.name)
        self.addCleanup(path.unlink)

        content = read_text_bounded(path, limit=50)
        self.assertEqual(len(content), 50)

    def test_rejects_oversized_file(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as handle:
            handle.write(b"a" * 51)
            path = Path(handle.name)
        self.addCleanup(path.unlink)

        with self.assertRaisesRegex(ValueError, "exceeds the 50 byte limit"):
            read_text_bounded(path, limit=50)

    def test_custom_error_factory(self):
        class CustomError(Exception):
            pass

        with tempfile.NamedTemporaryFile("wb", delete=False) as handle:
            handle.write(b"a" * 10)
            path = Path(handle.name)
        self.addCleanup(path.unlink)

        with self.assertRaises(CustomError):
            read_text_bounded(path, limit=5, error_factory=CustomError)

    def test_missing_file_raises_via_error_factory(self):
        path = Path("/nonexistent/file/path/that/does/not/exist.txt")
        with self.assertRaisesRegex(ValueError, "cannot read"):
            read_text_bounded(path, limit=100)

    def test_rejects_invalid_utf8(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as handle:
            handle.write(b"\x80\x81\xff\xfe")
            path = Path(handle.name)
        self.addCleanup(path.unlink)

        with self.assertRaisesRegex(ValueError, "not valid UTF-8"):
            read_text_bounded(path, limit=100)


class TestReadJsonBounded(unittest.TestCase):
    def test_reads_valid_json_dict(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            json.dump({"name": "harpocrates", "count": 42}, handle)
            path = Path(handle.name)
        self.addCleanup(path.unlink)

        data = read_json_bounded(path, limit=1024)
        self.assertEqual(data["name"], "harpocrates")
        self.assertEqual(data["count"], 42)

    def test_rejects_non_dict_when_required(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            json.dump(["item1", "item2"], handle)
            path = Path(handle.name)
        self.addCleanup(path.unlink)

        with self.assertRaisesRegex(ValueError, "must be a JSON object"):
            read_json_bounded(path, limit=1024, require_dict=True)

    def test_allows_non_dict_when_not_required(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            json.dump(["item1", "item2"], handle)
            path = Path(handle.name)
        self.addCleanup(path.unlink)

        data = read_json_bounded(path, limit=1024, require_dict=False, sensitive_pattern=None)
        self.assertEqual(data, ["item1", "item2"])

    def test_rejects_malformed_json(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write('{"key": unclosed')
            path = Path(handle.name)
        self.addCleanup(path.unlink)

        with self.assertRaisesRegex(ValueError, "malformed JSON"):
            read_json_bounded(path, limit=1024)

    def test_rejects_oversized_json(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write('{"x": "' + "a" * 200 + '"}')
            path = Path(handle.name)
        self.addCleanup(path.unlink)

        with self.assertRaisesRegex(ValueError, "exceeds the 100 byte limit"):
            read_json_bounded(path, limit=100)

    def test_rejects_sensitive_keys_in_json(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            json.dump({"config": {"witness": "secret-val"}}, handle)
            path = Path(handle.name)
        self.addCleanup(path.unlink)

        with self.assertRaisesRegex(ValueError, "contains forbidden sensitive field 'witness'"):
            read_json_bounded(path, limit=1024)


class TestReadTomlBounded(unittest.TestCase):
    def test_reads_valid_toml(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write('[package]\nname = "demo"\nversion = "1.0.0"\n')
            path = Path(handle.name)
        self.addCleanup(path.unlink)

        data = read_toml_bounded(path, limit=1024)
        self.assertEqual(data["package"]["name"], "demo")
        self.assertEqual(data["package"]["version"], "1.0.0")

    def test_rejects_malformed_toml(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write('[package\nname = ')
            path = Path(handle.name)
        self.addCleanup(path.unlink)

        with self.assertRaisesRegex(ValueError, "malformed TOML"):
            read_toml_bounded(path, limit=1024)

    def test_rejects_oversized_toml(self):
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
            handle.write('key = "' + "x" * 200 + '"\n')
            path = Path(handle.name)
        self.addCleanup(path.unlink)

        with self.assertRaisesRegex(ValueError, "exceeds the 100 byte limit"):
            read_toml_bounded(path, limit=100)


class TestSensitiveDetection(unittest.TestCase):
    def test_reject_sensitive_keys_nested_dict(self):
        payload = {"outer": {"middle": {"private_key": "some-key"}}}
        with self.assertRaisesRegex(ValueError, "outer.middle contains forbidden sensitive field 'private_key'"):
            reject_sensitive_keys(payload, "root")

    def test_reject_sensitive_keys_list(self):
        payload = {"items": [{"secret": "supersecret"}]}
        with self.assertRaisesRegex(ValueError, "root.items\\[0\\] contains forbidden sensitive field 'secret'"):
            reject_sensitive_keys(payload, "root")

    def test_reject_sensitive_keys_passes_safe_payload(self):
        payload = {
            "name": "harpocrates",
            "version": "1.0.0",
            "metadata": {"includes_private_material": False},
        }
        # Should not raise
        reject_sensitive_keys(payload, "root")

    def test_contains_sensitive_text(self):
        self.assertTrue(contains_sensitive_text("ghp_12345678901234567890"))
        self.assertTrue(contains_sensitive_text("-----BEGIN PRIVATE KEY-----"))
        self.assertTrue(contains_sensitive_text("password: secretpassword123"))
        self.assertTrue(contains_sensitive_text("Contains nullifier_value for proof"))
        self.assertFalse(contains_sensitive_text("public_version = 1.0.0"))

    def test_find_sensitive_match(self):
        text = "token: supersecrettoken123"
        result = find_sensitive_match(text)
        self.assertIsNotNone(result)
        pat, match = result
        self.assertIn("supersecrettoken", match.group(0))

    def test_find_sensitive_match_none(self):
        self.assertIsNone(find_sensitive_match("clean normal source line"))


if __name__ == "__main__":
    unittest.main()
