#!/usr/bin/env python3
"""Fail-closed coverage-threshold checker for Harpocrates workspaces.

Each workspace (backend, frontend, cli, ...) publishes its minimum coverage
bar as a small JSON file under devx/coverage/thresholds/<workspace>.json.
This script compares a workspace's coverage report against that file and
exits non-zero -- with no partial credit -- when the report is missing,
malformed, or falls short of any published metric.

Supported report formats:
  * "coverage_py"      -- `coverage json` output (Python / pytest-cov)
  * "istanbul_summary" -- vitest/istanbul `coverage-summary.json` output
  * "llvm_cov_json"    -- `cargo llvm-cov --json` output (LLVM coverage JSON)

Usage:
    python3 devx/coverage/check_coverage.py --workspace backend --report backend/coverage.json
    python3 devx/coverage/check_coverage.py --workspace frontend --report frontend/coverage/coverage-summary.json
    python3 devx/coverage/check_coverage.py --workspace contracts --report contracts/coverage.json
    python3 devx/coverage/check_coverage.py --lint-thresholds
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

THRESHOLDS_DIR = Path(__file__).resolve().parent / "thresholds"
KNOWN_FORMATS = {"coverage_py", "istanbul_summary", "llvm_cov_json"}
METRIC_MIN, METRIC_MAX = 0, 100


class CoverageCheckError(ValueError):
    """Raised for any fail-closed condition: a missing or malformed input."""


def load_thresholds(workspace: str, thresholds_dir: Path = THRESHOLDS_DIR) -> dict[str, Any]:
    path = thresholds_dir / f"{workspace}.json"
    if not path.is_file():
        raise CoverageCheckError(f"no thresholds file for workspace {workspace!r}: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CoverageCheckError(f"thresholds file {path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise CoverageCheckError(f"thresholds file {path} must contain a JSON object")
    if data.get("workspace") != workspace:
        raise CoverageCheckError(
            f"thresholds file {path} declares workspace {data.get('workspace')!r}, expected {workspace!r}"
        )
    report_format = data.get("report_format")
    if report_format not in KNOWN_FORMATS:
        raise CoverageCheckError(
            f"thresholds file {path} has unknown report_format {report_format!r}; "
            f"expected one of {sorted(KNOWN_FORMATS)}"
        )
    thresholds = data.get("thresholds")
    if not isinstance(thresholds, dict) or not thresholds:
        raise CoverageCheckError(f"thresholds file {path} must have a non-empty 'thresholds' object")
    for metric, value in thresholds.items():
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise CoverageCheckError(f"thresholds file {path}: metric {metric!r} must be a number")
        if not (METRIC_MIN <= value <= METRIC_MAX):
            raise CoverageCheckError(
                f"thresholds file {path}: metric {metric!r}={value} must be between {METRIC_MIN} and {METRIC_MAX}"
            )
    return data


def _coverage_py_metrics(report: dict[str, Any]) -> dict[str, float]:
    try:
        totals = report["totals"]
        line_rate = float(totals["percent_covered"])
        num_branches = float(totals.get("num_branches", 0) or 0)
        covered_branches = float(totals.get("covered_branches", 0) or 0)
    except (KeyError, TypeError, ValueError) as exc:
        raise CoverageCheckError(f"coverage_py report is missing expected totals: {exc}") from exc
    branch_rate = (covered_branches / num_branches * 100.0) if num_branches > 0 else 100.0
    return {"line_rate": line_rate, "branch_rate": branch_rate}


def _istanbul_summary_metrics(report: dict[str, Any]) -> dict[str, float]:
    try:
        total = report["total"]
        metrics = {key: float(total[key]["pct"]) for key in ("lines", "statements", "functions", "branches")}
    except (KeyError, TypeError, ValueError) as exc:
        raise CoverageCheckError(f"istanbul_summary report is missing expected totals: {exc}") from exc
    return metrics


def _llvm_cov_json_metrics(report: dict[str, Any]) -> dict[str, float]:
    try:
        data = report["data"]
        if not isinstance(data, list) or not data:
            raise CoverageCheckError("llvm_cov_json report data array is missing or empty")
        totals = data[0]["totals"]
        metrics = {}
        for key in ("lines", "regions", "functions", "branches", "instantiations"):
            if key in totals and isinstance(totals[key], dict) and "percent" in totals[key]:
                metrics[key] = float(totals[key]["percent"])
        if not metrics:
            raise CoverageCheckError("llvm_cov_json report totals object has no recognized metrics")
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise CoverageCheckError(f"llvm_cov_json report is missing expected totals: {exc}") from exc
    return metrics


_PARSERS = {
    "coverage_py": _coverage_py_metrics,
    "istanbul_summary": _istanbul_summary_metrics,
    "llvm_cov_json": _llvm_cov_json_metrics,
}


def load_report(report_format: str, report_path: Path) -> dict[str, float]:
    if not report_path.is_file():
        raise CoverageCheckError(f"coverage report not found: {report_path}")
    try:
        raw = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CoverageCheckError(f"coverage report {report_path} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise CoverageCheckError(f"coverage report {report_path} must contain a JSON object")
    return _PARSERS[report_format](raw)


def check(workspace: str, report_path: Path, thresholds_dir: Path = THRESHOLDS_DIR) -> list[str]:
    """Returns human-readable failures. An empty list means the workspace passed."""
    config = load_thresholds(workspace, thresholds_dir)
    metrics = load_report(config["report_format"], report_path)
    failures = []
    for metric, minimum in config["thresholds"].items():
        if metric not in metrics:
            raise CoverageCheckError(
                f"coverage report {report_path} does not include metric {metric!r} "
                f"required by the {workspace} thresholds"
            )
        actual = metrics[metric]
        if actual + 1e-9 < minimum:
            failures.append(f"{metric}: {actual:.2f}% < required {minimum}%")
    return failures


def lint_thresholds(thresholds_dir: Path = THRESHOLDS_DIR) -> list[str]:
    """Validates every published thresholds file without needing a coverage report."""
    if not thresholds_dir.is_dir():
        return [f"thresholds directory missing: {thresholds_dir}"]
    files = sorted(thresholds_dir.glob("*.json"))
    if not files:
        return [f"no thresholds files found in {thresholds_dir}"]
    problems = []
    for path in files:
        try:
            load_thresholds(path.stem, thresholds_dir)
        except CoverageCheckError as exc:
            problems.append(str(exc))
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--workspace", help="workspace name, e.g. backend, frontend, cli")
    parser.add_argument("--report", help="path to the workspace's coverage report JSON")
    parser.add_argument(
        "--lint-thresholds",
        action="store_true",
        help="validate all thresholds files under devx/coverage/thresholds and exit",
    )
    args = parser.parse_args(argv)

    if args.lint_thresholds:
        problems = lint_thresholds()
        for problem in problems:
            print(f"FAIL {problem}", file=sys.stderr)
        if problems:
            return 1
        print("OK all thresholds files are well-formed")
        return 0

    if not args.workspace or not args.report:
        parser.error("--workspace and --report are required unless --lint-thresholds is given")

    try:
        failures = check(args.workspace, Path(args.report))
    except CoverageCheckError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1

    if failures:
        print(f"FAIL {args.workspace} coverage is below its published thresholds:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(f"OK {args.workspace} meets its published coverage thresholds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
