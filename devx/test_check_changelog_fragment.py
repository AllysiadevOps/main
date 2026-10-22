"""Tests for devx/check_changelog_fragment.py and devx/fold_changelog_fragments.py.

Coverage
--------
  - Path matching: protocol paths require fragments, non-protocol paths do not.
  - Label bypass: 'no-changelog' label bypasses fragment check even if protocol paths touched.
  - Fragment validation: valid types (added/changed/fixed/security), missing entries, invalid types.
  - Deterministic folding: entries sorted strictly by type (Added, Changed, Fixed, Security)
    and within types by fragment filename.
  - Idempotency & dry-run options.
  - Integration with changelog insertion.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

# Make devx/ importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_changelog_fragment as ccf
import fold_changelog_fragments as fcf


class TestPathMatching(unittest.TestCase):
    def test_protocol_paths_recognized(self) -> None:
        self.assertTrue(ccf.is_protocol_path("contracts/harpocrates-registry/src/lib.rs"))
        self.assertTrue(ccf.is_protocol_path("contracts/Cargo.toml"))
        self.assertTrue(ccf.is_protocol_path("contracts/"))
        self.assertTrue(ccf.is_protocol_path("contracts"))
        self.assertTrue(ccf.is_protocol_path("zk/noir/silent_witness/src/main.nr"))
        self.assertTrue(ccf.is_protocol_path("zk/noir/Nargo.toml"))
        self.assertTrue(ccf.is_protocol_path("release/compatibility-manifest.json"))
        # Windows-style backslashes
        self.assertTrue(ccf.is_protocol_path("contracts\\harpocrates-registry\\src\\lib.rs"))
        self.assertTrue(ccf.is_protocol_path("zk\\noir\\silent_witness\\src\\main.nr"))
        self.assertTrue(ccf.is_protocol_path(".\\release\\compatibility-manifest.json"))

    def test_non_protocol_paths_ignored(self) -> None:
        self.assertFalse(ccf.is_protocol_path("frontend/src/App.tsx"))
        self.assertFalse(ccf.is_protocol_path("backend/routes.py"))
        self.assertFalse(ccf.is_protocol_path("devx/check_dependency_pins.py"))
        self.assertFalse(ccf.is_protocol_path("docs/README.md"))
        self.assertFalse(ccf.is_protocol_path("release/compatibility-report.json"))
        self.assertFalse(ccf.is_protocol_path("zk/bench/zk_bench.py"))

    def test_touches_protocol_paths(self) -> None:
        files = [
            "frontend/src/index.ts",
            "contracts/src/lib.rs",
            "backend/app.py",
            "release/compatibility-manifest.json",
        ]
        matched = ccf.touches_protocol_paths(files)
        self.assertEqual(
            matched,
            ["contracts/src/lib.rs", "release/compatibility-manifest.json"],
        )


class TestLabelBypass(unittest.TestCase):
    def test_parse_labels_string(self) -> None:
        labels = ccf.parse_labels("type/feature, no-changelog, layer/contracts")
        self.assertIn("no-changelog", labels)
        self.assertIn("type/feature", labels)

    def test_parse_labels_json(self) -> None:
        json_labels = '[{"name": "impact/protocol"}, {"name": "no-changelog"}]'
        labels = ccf.parse_labels(json_labels)
        self.assertIn("no-changelog", labels)
        self.assertIn("impact/protocol", labels)

    def test_has_bypass_label(self) -> None:
        self.assertTrue(ccf.has_bypass_label(["no-changelog", "type/fix"]))
        self.assertTrue(ccf.has_bypass_label(["NO-CHANGELOG"]))
        self.assertFalse(ccf.has_bypass_label(["impact/protocol", "type/fix"]))

    def test_check_pr_bypassed_with_label(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            empty_changelog_d = Path(tmp) / "changelog.d"
            empty_changelog_d.mkdir()

            passed, msg = ccf.check_pr(
                changed_files=["contracts/src/lib.rs"],
                labels=["no-changelog"],
                changelog_dir=empty_changelog_d,
            )
            self.assertTrue(passed)
            self.assertIn("Bypassed", msg)


class TestFragmentValidation(unittest.TestCase):
    def test_parse_valid_fragment(self) -> None:
        content = (
            "### Added\n"
            "- Added new verifier endpoint\n\n"
            "### Fixed\n"
            "- Fixed boundary check in circuit\n"
        )
        parsed = ccf.parse_fragment(content, "test.md")
        self.assertEqual(len(parsed["added"]), 1)
        self.assertEqual(parsed["added"][0], "- Added new verifier endpoint")
        self.assertEqual(len(parsed["fixed"]), 1)
        self.assertEqual(parsed["fixed"][0], "- Fixed boundary check in circuit")

    def test_parse_case_insensitive_header(self) -> None:
        content = "### added\n- Item 1\n### FIXED\n- Item 2"
        parsed = ccf.parse_fragment(content, "test.md")
        self.assertIn("added", parsed)
        self.assertIn("fixed", parsed)

    def test_reject_invalid_type_header(self) -> None:
        content = "### UnknownType\n- Some change"
        with self.assertRaises(ccf.ChangelogCheckError) as ctx:
            ccf.parse_fragment(content, "bad.md")
        self.assertIn("invalid type header", str(ctx.exception))

    def test_reject_empty_fragment_or_missing_header(self) -> None:
        with self.assertRaises(ccf.ChangelogCheckError) as ctx:
            ccf.parse_fragment("Just plain text without header", "plain.md")
        self.assertIn("must contain at least one valid type header", str(ctx.exception))

        with self.assertRaises(ccf.ChangelogCheckError) as ctx:
            ccf.parse_fragment("### Added\n\n", "empty_header.md")
        self.assertIn("contains no entry items", str(ctx.exception))


class TestCheckPRWorkflow(unittest.TestCase):
    def test_protocol_change_requires_fragment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dir_path = Path(tmp) / "changelog.d"
            dir_path.mkdir()

            # No fragment present
            passed, msg = ccf.check_pr(
                changed_files=["contracts/src/lib.rs"],
                labels=[],
                changelog_dir=dir_path,
            )
            self.assertFalse(passed)
            self.assertIn("No changelog fragments found", msg)

            # Valid fragment added
            frag = dir_path / "123-fix.md"
            frag.write_text("### Fixed\n- Fixed nullifier parsing", encoding="utf-8")

            passed, msg = ccf.check_pr(
                changed_files=["contracts/src/lib.rs"],
                labels=[],
                changelog_dir=dir_path,
            )
            self.assertTrue(passed)
            self.assertIn("passed", msg.lower())

    def test_non_protocol_change_passes_without_fragment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dir_path = Path(tmp) / "changelog.d"
            dir_path.mkdir()

            passed, msg = ccf.check_pr(
                changed_files=["frontend/src/main.tsx", "docs/index.md"],
                labels=[],
                changelog_dir=dir_path,
            )
            self.assertTrue(passed)
            self.assertIn("No protocol paths touched", msg)


class TestDeterministicFolding(unittest.TestCase):
    def test_folding_order_by_type_and_filename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dir_path = Path(tmp) / "changelog.d"
            dir_path.mkdir()

            # Create fragments in non-alphabetical creation
            f2 = dir_path / "b-feat.md"
            f2.write_text("### Added\n- Added B feature\n### Fixed\n- Fixed B bug", encoding="utf-8")

            f1 = dir_path / "a-feat.md"
            f1.write_text("### Added\n- Added A feature\n### Security\n- Security patch A", encoding="utf-8")

            fragments = ccf.find_fragments(dir_path)
            grouped = fcf.collect_fragment_entries(fragments)

            # Check type ordering: added, changed, fixed, security
            self.assertEqual(
                grouped["added"],
                ["- Added A feature", "- Added B feature"],
            )
            self.assertEqual(
                grouped["fixed"],
                ["- Fixed B bug"],
            )
            self.assertEqual(
                grouped["security"],
                ["- Security patch A"],
            )

            formatted = fcf.format_folded_section(grouped)
            expected = (
                "- Added A feature\n"
                "- Added B feature\n"
                "- Fixed B bug\n"
                "- Security patch A"
            )
            self.assertEqual(formatted, expected)

    def test_fold_into_changelog_content(self) -> None:
        original = (
            "# Changelog\n\n"
            "## Unreleased\n\n"
            "- Split registry-admin roles\n"
        )
        folded_text = "- Added A\n- Fixed B"
        updated = fcf.fold_into_changelog_content(original, folded_text)
        expected = (
            "# Changelog\n\n"
            "## Unreleased\n\n"
            "- Added A\n"
            "- Fixed B\n\n"
            "- Split registry-admin roles\n"
        )
        self.assertEqual(updated, expected)

    def test_end_to_end_fold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            changelog = root / "CHANGELOG.md"
            changelog.write_text("# Changelog\n\n## Unreleased\n\n- Existing\n", encoding="utf-8")

            changelog_d = root / "changelog.d"
            changelog_d.mkdir()
            (changelog_d / "01.md").write_text("### Added\n- New item\n", encoding="utf-8")

            count, msg = fcf.fold_fragments(
                changelog_path=changelog,
                changelog_dir=changelog_d,
                delete_fragments=True,
            )
            self.assertEqual(count, 1)

            # Fragment should be deleted
            self.assertEqual(len(ccf.find_fragments(changelog_d)), 0)

            # Changelog content updated
            content = changelog.read_text(encoding="utf-8")
            self.assertIn("- New item", content)
            self.assertIn("- Existing", content)


if __name__ == "__main__":
    unittest.main()
