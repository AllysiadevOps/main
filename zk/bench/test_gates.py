"""Unit tests for ZK circuit gate and opcode count regression checking.

Exercises:
- Output parsing for `nargo info` across JSON and tabular fixture variations.
- Output parsing for `bb gates` across JSON and raw integer fixture variations.
- Comparison logic, growth calculations, and threshold enforcement (>5% failure).
- Table generation (Markdown for job summary, ASCII for console).
- Lock file persistence and toolchain metadata extraction from zk/toolchain.lock.json.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

import gates  # noqa: E402


# ── Fixtures for nargo info ─────────────────────────────────────────────────

FIXTURE_NARGO_INFO_JSON_PROGRAMS = """
{
  "programs": [
    {
      "name": "silent_witness",
      "acir_opcodes": 142,
      "circuit_size": 3143
    }
  ],
  "contracts": []
}
"""

FIXTURE_NARGO_INFO_JSON_FUNCTIONS = """
{
  "programs": [
    {
      "package": "silent_witness_aggregator",
      "functions": [
        {
          "name": "main",
          "acir_opcodes": 2150
        }
      ]
    }
  ]
}
"""

FIXTURE_NARGO_INFO_JSON_ROOT_FUNCTIONS = """
{
  "functions": [
    {
      "name": "main",
      "acir_opcodes": 89
    }
  ]
}
"""

FIXTURE_NARGO_INFO_TABLE = """
+----------------+----------+--------------+-----------------+
| Package        | Function | ACIR Opcodes | Brillig Opcodes |
+----------------+----------+--------------+-----------------+
| silent_witness | main     | 142          | 0               |
+----------------+----------+--------------+-----------------+
"""

FIXTURE_NARGO_INFO_TABLE_ALT = """
| Package | ACIR Opcodes |
| test_pkg | 320 |
"""


# ── Fixtures for bb gates ───────────────────────────────────────────────────

FIXTURE_BB_GATES_JSON_FUNCTIONS = """
{
  "functions": [
    {
      "circuit_size": 3143,
      "sub_gates": {}
    }
  ]
}
"""

FIXTURE_BB_GATES_JSON_ROOT = """
{
  "circuit_size": 45120
}
"""

FIXTURE_BB_GATES_JSON_GATES_KEY = """
{
  "gates": 1820
}
"""

FIXTURE_BB_GATES_RAW_INT = "  3143  \n"

FIXTURE_BB_GATES_TEXT = "circuit_size: 3143"


# ── Tests: Parsing ──────────────────────────────────────────────────────────


def test_parse_nargo_info_json_programs():
    assert gates.parse_nargo_info(FIXTURE_NARGO_INFO_JSON_PROGRAMS) == 142


def test_parse_nargo_info_json_functions():
    assert gates.parse_nargo_info(FIXTURE_NARGO_INFO_JSON_FUNCTIONS) == 2150


def test_parse_nargo_info_json_root_functions():
    assert gates.parse_nargo_info(FIXTURE_NARGO_INFO_JSON_ROOT_FUNCTIONS) == 89


def test_parse_nargo_info_table():
    assert gates.parse_nargo_info(FIXTURE_NARGO_INFO_TABLE) == 142


def test_parse_nargo_info_table_alt():
    assert gates.parse_nargo_info(FIXTURE_NARGO_INFO_TABLE_ALT) == 320


def test_parse_nargo_info_invalid():
    with pytest.raises(gates.GatesError, match="could not parse"):
        gates.parse_nargo_info("unexpected text without numbers")


def test_parse_nargo_info_empty():
    with pytest.raises(gates.GatesError, match="empty output"):
        gates.parse_nargo_info("   \n")


def test_parse_bb_gates_json_functions():
    assert gates.parse_bb_gates(FIXTURE_BB_GATES_JSON_FUNCTIONS) == 3143


def test_parse_bb_gates_json_root():
    assert gates.parse_bb_gates(FIXTURE_BB_GATES_JSON_ROOT) == 45120


def test_parse_bb_gates_json_gates_key():
    assert gates.parse_bb_gates(FIXTURE_BB_GATES_JSON_GATES_KEY) == 1820


def test_parse_bb_gates_raw_int():
    assert gates.parse_bb_gates(FIXTURE_BB_GATES_RAW_INT) == 3143


def test_parse_bb_gates_text():
    assert gates.parse_bb_gates(FIXTURE_BB_GATES_TEXT) == 3143


def test_parse_bb_gates_invalid():
    with pytest.raises(gates.GatesError, match="could not parse"):
        gates.parse_bb_gates("invalid output without numbers")


def test_parse_bb_gates_empty():
    with pytest.raises(gates.GatesError, match="empty output"):
        gates.parse_bb_gates("")


# ── Tests: Growth Calculation ───────────────────────────────────────────────


def test_calculate_growth_percent():
    assert gates.calculate_growth_percent(100, 100) == pytest.approx(0.0)
    assert gates.calculate_growth_percent(100, 105) == pytest.approx(5.0)
    assert gates.calculate_growth_percent(100, 106) == pytest.approx(6.0)
    assert gates.calculate_growth_percent(100, 95) == pytest.approx(-5.0)
    assert gates.calculate_growth_percent(0, 0) == pytest.approx(0.0)
    assert gates.calculate_growth_percent(0, 50) == pytest.approx(100.0)


# ── Tests: Comparison Logic ─────────────────────────────────────────────────


def test_compare_counts_exact_match():
    locked = {
        "c1": gates.CircuitCounts(acir_opcodes=100, backend_gates=1000),
        "c2": gates.CircuitCounts(acir_opcodes=200, backend_gates=2000),
    }
    current = {
        "c1": gates.CircuitCounts(acir_opcodes=100, backend_gates=1000),
        "c2": gates.CircuitCounts(acir_opcodes=200, backend_gates=2000),
    }
    result = gates.compare_counts(locked, current, threshold_percent=5.0)
    assert result.passed
    assert not result.has_regression
    assert len(result.diffs) == 2
    assert all(d.status == "OK" for d in result.diffs)
    assert all(d.opcode_growth_pct == 0.0 for d in result.diffs)
    assert all(d.gate_growth_pct == 0.0 for d in result.diffs)


def test_compare_counts_within_threshold():
    locked = {
        "c1": gates.CircuitCounts(acir_opcodes=100, backend_gates=1000),
    }
    # 4.0% opcode growth, 5.0% gate growth -> both <= 5.0%
    current = {
        "c1": gates.CircuitCounts(acir_opcodes=104, backend_gates=1050),
    }
    result = gates.compare_counts(locked, current, threshold_percent=5.0)
    assert result.passed
    assert result.diffs[0].status == "OK"


def test_compare_counts_fails_on_opcode_growth():
    locked = {
        "c1": gates.CircuitCounts(acir_opcodes=100, backend_gates=1000),
    }
    # 6.0% opcode growth (> 5.0%), gates ok
    current = {
        "c1": gates.CircuitCounts(acir_opcodes=106, backend_gates=1020),
    }
    result = gates.compare_counts(locked, current, threshold_percent=5.0)
    assert not result.passed
    assert result.has_regression
    assert result.diffs[0].status == "REGRESSION"
    assert "ACIR opcodes +6.0%" in result.diffs[0].details


def test_compare_counts_fails_on_gate_growth():
    locked = {
        "c1": gates.CircuitCounts(acir_opcodes=100, backend_gates=1000),
    }
    # opcodes ok, 5.5% gate growth (> 5.0%)
    current = {
        "c1": gates.CircuitCounts(acir_opcodes=101, backend_gates=1055),
    }
    result = gates.compare_counts(locked, current, threshold_percent=5.0)
    assert not result.passed
    assert result.has_regression
    assert result.diffs[0].status == "REGRESSION"
    assert "Backend gates +5.5%" in result.diffs[0].details


def test_compare_counts_decreases_always_pass():
    locked = {
        "c1": gates.CircuitCounts(acir_opcodes=100, backend_gates=1000),
    }
    # Optimization: counts shrunk
    current = {
        "c1": gates.CircuitCounts(acir_opcodes=80, backend_gates=850),
    }
    result = gates.compare_counts(locked, current, threshold_percent=5.0)
    assert result.passed
    assert result.diffs[0].status == "OK"
    assert result.diffs[0].opcode_growth_pct == -20.0
    assert result.diffs[0].gate_growth_pct == -15.0


def test_compare_counts_custom_threshold():
    locked = {
        "c1": gates.CircuitCounts(acir_opcodes=100, backend_gates=1000),
    }
    current = {
        "c1": gates.CircuitCounts(acir_opcodes=107, backend_gates=1000),
    }
    # 7.0% growth passes with 10.0% threshold
    assert gates.compare_counts(locked, current, threshold_percent=10.0).passed
    # 7.0% growth fails with 5.0% threshold
    assert not gates.compare_counts(locked, current, threshold_percent=5.0).passed


def test_compare_counts_detects_untracked_and_missing():
    locked = {
        "old_circuit": gates.CircuitCounts(acir_opcodes=100, backend_gates=1000),
    }
    current = {
        "new_circuit": gates.CircuitCounts(acir_opcodes=120, backend_gates=1200),
    }
    result = gates.compare_counts(locked, current, threshold_percent=5.0)
    assert not result.passed
    assert result.has_regression

    statuses = {d.name: d.status for d in result.diffs}
    assert statuses["old_circuit"] == "MISSING"
    assert statuses["new_circuit"] == "NEW"


# ── Tests: Toolchain Metadata & Discovery ───────────────────────────────────


def test_load_toolchain_info_from_repo():
    tc = gates.load_toolchain_info(gates.DEFAULT_TOOLCHAIN_LOCK)
    assert tc["nargo"] == "1.0.0-beta.9"
    assert tc["barretenberg"] == "0.87.0"
    assert tc["proving_scheme"] == "ultra_honk"
    assert tc["oracle_hash"] == "keccak"


def test_discover_circuits_from_repo():
    circuits = gates.discover_circuits(gates.CIRCUIT_ROOT)
    assert "silent_witness" in circuits
    assert "silent_witness_aggregator" in circuits
    assert "harpocrates_common" not in circuits  # Library crate excluded
    assert len(circuits) == 9


# ── Tests: Table Formatting ─────────────────────────────────────────────────


def test_format_markdown_table_passed():
    diffs = [
        gates.CircuitDiff(
            name="silent_witness",
            locked_opcodes=142,
            actual_opcodes=142,
            opcode_growth_pct=0.0,
            locked_gates=3143,
            actual_gates=3143,
            gate_growth_pct=0.0,
            status="OK",
        )
    ]
    res = gates.ComparisonResult(diffs=diffs, has_regression=False, threshold_percent=5.0)
    md = gates.format_markdown_table(res)
    assert "### ZK Circuit Gate & Opcode Counts" in md
    assert "[!NOTE]" in md
    assert "| `silent_witness` | 142 | 142 | `+0.0%` | 3,143 | 3,143 | `+0.0%` | ✅ OK |" in md


def test_format_markdown_table_regression():
    diffs = [
        gates.CircuitDiff(
            name="silent_witness",
            locked_opcodes=100,
            actual_opcodes=106,
            opcode_growth_pct=6.0,
            locked_gates=1000,
            actual_gates=1000,
            gate_growth_pct=0.0,
            status="REGRESSION",
            details="ACIR opcodes +6.0% > 5.0%",
        )
    ]
    res = gates.ComparisonResult(diffs=diffs, has_regression=True, threshold_percent=5.0)
    md = gates.format_markdown_table(res)
    assert "[!CAUTION]" in md
    assert "❌ **REGRESSION**" in md
    assert "ACIR opcodes +6.0% > 5.0%" in md


def test_format_ascii_table():
    diffs = [
        gates.CircuitDiff(
            name="silent_witness",
            locked_opcodes=142,
            actual_opcodes=142,
            opcode_growth_pct=0.0,
            locked_gates=3143,
            actual_gates=3143,
            gate_growth_pct=0.0,
            status="OK",
        )
    ]
    res = gates.ComparisonResult(diffs=diffs, has_regression=False, threshold_percent=5.0)
    ascii_out = gates.format_ascii_table(res)
    assert "silent_witness" in ascii_out
    assert "OK" in ascii_out


# ── Tests: Lock Persistence & CLI Roundtrip ─────────────────────────────────


def test_save_and_load_gates_lock(tmp_path: Path):
    lock_file = tmp_path / "gates.lock.json"
    counts = {
        "silent_witness": gates.CircuitCounts(acir_opcodes=142, backend_gates=3143),
        "silent_witness_helper": gates.CircuitCounts(acir_opcodes=90, backend_gates=1800),
    }

    gates.save_gates_lock(counts, path=lock_file, threshold_percent=5.0)
    loaded = gates.load_gates_lock(lock_file)

    assert loaded["format"] == gates.GATES_LOCK_FORMAT
    assert loaded["version"] == gates.GATES_LOCK_VERSION
    assert loaded["threshold_percent"] == 5.0
    assert loaded["toolchain"]["nargo"] == "1.0.0-beta.9"
    assert loaded["circuits"]["silent_witness"]["acir_opcodes"] == 142
    assert loaded["circuits"]["silent_witness"]["backend_gates"] == 3143


def test_command_check_cli_mock(tmp_path: Path):
    lock_file = tmp_path / "gates.lock.json"
    summary_file = tmp_path / "summary.md"
    counts = {
        "silent_witness": gates.CircuitCounts(acir_opcodes=100, backend_gates=1000),
    }
    gates.save_gates_lock(counts, path=lock_file, threshold_percent=5.0)

    # Within threshold -> exit 0
    ok_counts = {"silent_witness": gates.CircuitCounts(acir_opcodes=102, backend_gates=1020)}
    ret = gates.command_check(
        gates_lock_path=lock_file,
        summary_path=summary_file,
        current_counts_override=ok_counts,
    )
    assert ret == gates.EXIT_OK
    assert summary_file.is_file()
    assert "✅ OK" in summary_file.read_text(encoding="utf-8")

    # Exceeding threshold -> exit 1
    regressed_counts = {"silent_witness": gates.CircuitCounts(acir_opcodes=110, backend_gates=1000)}
    ret_fail = gates.command_check(
        gates_lock_path=lock_file,
        summary_path=summary_file,
        current_counts_override=regressed_counts,
    )
    assert ret_fail == gates.EXIT_REGRESSION
