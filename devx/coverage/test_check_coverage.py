#!/usr/bin/env python3
"""Tests for devx/coverage/check_coverage.py.

Run with either:
    python3 -m pytest devx/coverage/test_check_coverage.py -v
    python3 -m unittest devx.coverage.test_check_coverage -v
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_coverage as cc  # noqa: E402


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


class ThresholdsFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def test_missing_thresholds_file_fails_closed(self) -> None:
        with self.assertRaises(cc.CoverageCheckError):
            cc.load_thresholds("nonexistent", self.dir)

    def test_malformed_json_thresholds_file_fails_closed(self) -> None:
        (self.dir / "backend.json").write_text("{not json", encoding="utf-8")
        with self.assertRaises(cc.CoverageCheckError):
            cc.load_thresholds("backend", self.dir)

    def test_thresholds_not_an_object_fails_closed(self) -> None:
        write_json(self.dir / "backend.json", [1, 2, 3])
        with self.assertRaises(cc.CoverageCheckError):
            cc.load_thresholds("backend", self.dir)

    def test_workspace_name_mismatch_fails_closed(self) -> None:
        write_json(
            self.dir / "backend.json",
            {"workspace": "frontend", "report_format": "coverage_py", "thresholds": {"line_rate": 50}},
        )
        with self.assertRaises(cc.CoverageCheckError):
            cc.load_thresholds("backend", self.dir)

    def test_unknown_report_format_fails_closed(self) -> None:
        write_json(
            self.dir / "backend.json",
            {"workspace": "backend", "report_format": "xml_v9", "thresholds": {"line_rate": 50}},
        )
        with self.assertRaises(cc.CoverageCheckError):
            cc.load_thresholds("backend", self.dir)

    def test_empty_thresholds_object_fails_closed(self) -> None:
        write_json(
            self.dir / "backend.json",
            {"workspace": "backend", "report_format": "coverage_py", "thresholds": {}},
        )
        with self.assertRaises(cc.CoverageCheckError):
            cc.load_thresholds("backend", self.dir)

    def test_out_of_range_metric_fails_closed(self) -> None:
        write_json(
            self.dir / "backend.json",
            {"workspace": "backend", "report_format": "coverage_py", "thresholds": {"line_rate": 150}},
        )
        with self.assertRaises(cc.CoverageCheckError):
            cc.load_thresholds("backend", self.dir)

    def test_non_numeric_metric_fails_closed(self) -> None:
        write_json(
            self.dir / "backend.json",
            {"workspace": "backend", "report_format": "coverage_py", "thresholds": {"line_rate": "high"}},
        )
        with self.assertRaises(cc.CoverageCheckError):
            cc.load_thresholds("backend", self.dir)

    def test_valid_thresholds_file_loads(self) -> None:
        write_json(
            self.dir / "backend.json",
            {"workspace": "backend", "report_format": "coverage_py", "thresholds": {"line_rate": 70}},
        )
        data = cc.load_thresholds("backend", self.dir)
        self.assertEqual(data["thresholds"]["line_rate"], 70)


class CheckReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        write_json(
            self.dir / "backend.json",
            {
                "workspace": "backend",
                "report_format": "coverage_py",
                "thresholds": {"line_rate": 70, "branch_rate": 55},
            },
        )
        write_json(
            self.dir / "frontend.json",
            {
                "workspace": "frontend",
                "report_format": "istanbul_summary",
                "thresholds": {"lines": 55, "branches": 45},
            },
        )

    def test_missing_report_file_fails_closed(self) -> None:
        with self.assertRaises(cc.CoverageCheckError):
            cc.check("backend", self.dir / "does-not-exist.json", self.dir)

    def test_malformed_json_report_fails_closed(self) -> None:
        report = self.dir / "coverage.json"
        report.write_text("{ this is not json", encoding="utf-8")
        with self.assertRaises(cc.CoverageCheckError):
            cc.check("backend", report, self.dir)

    def test_report_not_an_object_fails_closed(self) -> None:
        report = self.dir / "coverage.json"
        write_json(report, [1, 2, 3])
        with self.assertRaises(cc.CoverageCheckError):
            cc.check("backend", report, self.dir)

    def test_coverage_py_report_missing_totals_fails_closed(self) -> None:
        report = self.dir / "coverage.json"
        write_json(report, {"files": {}})
        with self.assertRaises(cc.CoverageCheckError):
            cc.check("backend", report, self.dir)

    def test_coverage_py_report_passes_above_threshold(self) -> None:
        report = self.dir / "coverage.json"
        write_json(
            report,
            {"totals": {"percent_covered": 80.5, "num_branches": 40, "covered_branches": 30}},
        )
        self.assertEqual(cc.check("backend", report, self.dir), [])

    def test_coverage_py_report_fails_below_threshold(self) -> None:
        report = self.dir / "coverage.json"
        write_json(
            report,
            {"totals": {"percent_covered": 50.0, "num_branches": 40, "covered_branches": 10}},
        )
        failures = cc.check("backend", report, self.dir)
        self.assertEqual(len(failures), 2)

    def test_boundary_exact_threshold_passes(self) -> None:
        report = self.dir / "coverage.json"
        write_json(
            report,
            {"totals": {"percent_covered": 70.0, "num_branches": 100, "covered_branches": 55}},
        )
        self.assertEqual(cc.check("backend", report, self.dir), [])

    def test_coverage_py_no_branches_defaults_to_full_branch_rate(self) -> None:
        report = self.dir / "coverage.json"
        write_json(report, {"totals": {"percent_covered": 90.0, "num_branches": 0, "covered_branches": 0}})
        self.assertEqual(cc.check("backend", report, self.dir), [])

    def test_istanbul_summary_report_passes(self) -> None:
        report = self.dir / "coverage-summary.json"
        write_json(
            report,
            {
                "total": {
                    "lines": {"pct": 60},
                    "statements": {"pct": 60},
                    "functions": {"pct": 60},
                    "branches": {"pct": 50},
                }
            },
        )
        self.assertEqual(cc.check("frontend", report, self.dir), [])

    def test_istanbul_summary_report_fails_below_threshold(self) -> None:
        report = self.dir / "coverage-summary.json"
        write_json(
            report,
            {
                "total": {
                    "lines": {"pct": 10},
                    "statements": {"pct": 10},
                    "functions": {"pct": 10},
                    "branches": {"pct": 10},
                }
            },
        )
        failures = cc.check("frontend", report, self.dir)
        self.assertEqual(len(failures), 2)

    def test_istanbul_summary_missing_total_key_fails_closed(self) -> None:
        report = self.dir / "coverage-summary.json"
        write_json(report, {"src/foo.ts": {"lines": {"pct": 90}}})
        with self.assertRaises(cc.CoverageCheckError):
            cc.check("frontend", report, self.dir)

    def test_istanbul_summary_unknown_pct_fails_closed(self) -> None:
        # istanbul reports "Unknown" (a string) for pct when a project has no files.
        report = self.dir / "coverage-summary.json"
        write_json(
            report,
            {"total": {"lines": {"pct": "Unknown"}, "branches": {"pct": "Unknown"}}},
        )
        with self.assertRaises(cc.CoverageCheckError):
            cc.check("frontend", report, self.dir)

    def test_report_missing_metric_required_by_thresholds_fails_closed(self) -> None:
        write_json(
            self.dir / "backend.json",
            {
                "workspace": "backend",
                "report_format": "coverage_py",
                "thresholds": {"line_rate": 70, "made_up_metric": 10},
            },
        )
        report = self.dir / "coverage.json"
        write_json(report, {"totals": {"percent_covered": 90.0}})
        with self.assertRaises(cc.CoverageCheckError):
            cc.check("backend", report, self.dir)

    def test_llvm_cov_json_report_passes(self) -> None:
        write_json(
            self.dir / "contracts.json",
            {
                "workspace": "contracts",
                "report_format": "llvm_cov_json",
                "thresholds": {"lines": 70, "regions": 65},
            },
        )
        report = self.dir / "coverage.json"
        write_json(
            report,
            {
                "data": [
                    {
                        "totals": {
                            "lines": {"count": 100, "covered": 85, "percent": 85.0},
                            "regions": {"count": 100, "covered": 75, "percent": 75.0},
                            "functions": {"count": 20, "covered": 18, "percent": 90.0},
                        }
                    }
                ]
            },
        )
        self.assertEqual(cc.check("contracts", report, self.dir), [])

    def test_llvm_cov_json_report_fails_below_threshold(self) -> None:
        write_json(
            self.dir / "contracts.json",
            {
                "workspace": "contracts",
                "report_format": "llvm_cov_json",
                "thresholds": {"lines": 70, "regions": 65},
            },
        )
        report = self.dir / "coverage.json"
        write_json(
            report,
            {
                "data": [
                    {
                        "totals": {
                            "lines": {"count": 100, "covered": 50, "percent": 50.0},
                            "regions": {"count": 100, "covered": 40, "percent": 40.0},
                        }
                    }
                ]
            },
        )
        failures = cc.check("contracts", report, self.dir)
        self.assertEqual(len(failures), 2)

    def test_llvm_cov_json_missing_data_fails_closed(self) -> None:
        write_json(
            self.dir / "contracts.json",
            {
                "workspace": "contracts",
                "report_format": "llvm_cov_json",
                "thresholds": {"lines": 70},
            },
        )
        report = self.dir / "coverage.json"
        write_json(report, {"data": []})
        with self.assertRaises(cc.CoverageCheckError):
            cc.check("contracts", report, self.dir)

    def test_llvm_cov_json_missing_totals_fails_closed(self) -> None:
        write_json(
            self.dir / "contracts.json",
            {
                "workspace": "contracts",
                "report_format": "llvm_cov_json",
                "thresholds": {"lines": 70},
            },
        )
        report = self.dir / "coverage.json"
        write_json(report, {"data": [{}]})
        with self.assertRaises(cc.CoverageCheckError):
            cc.check("contracts", report, self.dir)


class LintThresholdsTests(unittest.TestCase):
    def test_lint_empty_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(cc.lint_thresholds(Path(tmp)))

    def test_lint_missing_directory_fails_closed(self) -> None:
        problems = cc.lint_thresholds(Path("/nonexistent/thresholds/dir"))
        self.assertTrue(problems)

    def test_lint_published_thresholds_are_well_formed(self) -> None:
        # Regression test: the thresholds files actually shipped in this repo
        # must stay valid as workspaces edit them.
        self.assertEqual(cc.lint_thresholds(), [])

    def test_published_thresholds_cover_backend_frontend_cli(self) -> None:
        names = {path.stem for path in cc.THRESHOLDS_DIR.glob("*.json")}
        self.assertEqual(names, {"backend", "frontend", "cli", "contracts"})


class MainCliTests(unittest.TestCase):
    def test_lint_thresholds_flag_returns_zero(self) -> None:
        self.assertEqual(cc.main(["--lint-thresholds"]), 0)

    def test_missing_arguments_is_an_error(self) -> None:
        with self.assertRaises(SystemExit):
            cc.main([])

    def test_main_fails_closed_on_missing_report(self) -> None:
        self.assertEqual(cc.main(["--workspace", "backend", "--report", "/nonexistent/report.json"]), 1)


if __name__ == "__main__":
    unittest.main()
