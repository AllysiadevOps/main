"""Cross-layer bound constant synchronization tests.

Verifies that circuit (Noir globals), host (Python constants), and contract
(Soroban lib.rs constants) bounds stay in strict lockstep.

Run from the repository root:

    python -m pytest zk/tools -q
"""

from __future__ import annotations

import difflib
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import aggregation_bound as ab  # noqa: E402
import revocation_depth as rd  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
LIB_RS_PATH = (
    REPO_ROOT
    / "contracts"
    / "contracts"
    / "harpocrates-registry"
    / "src"
    / "lib.rs"
)
NOIR_DIR = REPO_ROOT / "zk" / "noir"

NOIR_GLOBAL_RE = re.compile(
    r"^\s*global\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*[^=]+=\s*([0-9][0-9_]*|0x[0-9a-fA-F][0-9a-fA-F_]*)\s*;",
    re.MULTILINE,
)

RUST_PUB_CONST_RE = re.compile(
    r"^\s*pub\s+const\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*[^=]+=\s*([0-9][0-9_]*|0x[0-9a-fA-F][0-9a-fA-F_]*)\s*;",
    re.MULTILINE,
)

# Canonical Python bounds
PYTHON_BOUND_CONSTANTS: dict[str, int] = {
    "MAX_AGGREGATION_SIZE": ab.MAX_AGGREGATION_SIZE,
    "MIN_AGGREGATION_SIZE": ab.MIN_AGGREGATION_SIZE,
    "MAX_REVOCATION_WITNESS_DEPTH": rd.MAX_REVOCATION_WITNESS_DEPTH,
    "MAX_REVOCATION_LEAVES": rd.MAX_REVOCATION_LEAVES,
}


def parse_noir_globals(path: Path) -> dict[str, int]:
    """Parse integer `global NAME: Type = value;` declarations from a Noir file."""
    content = path.read_text(encoding="utf-8")
    return {
        name: int(val.replace("_", ""), 0)
        for name, val in NOIR_GLOBAL_RE.findall(content)
    }


def parse_rust_pub_consts(path: Path) -> dict[str, int]:
    """Parse integer `pub const NAME: Type = value;` lines from a Rust source file."""
    content = path.read_text(encoding="utf-8")
    return {
        name: int(val.replace("_", ""), 0)
        for name, val in RUST_PUB_CONST_RE.findall(content)
    }


def format_diff(
    expected_label: str,
    actual_label: str,
    expected: dict[str, int | None],
    actual: dict[str, int | None],
) -> str:
    """Produce a unified diff of expected vs actual constants."""
    keys = sorted(set(expected.keys()) | set(actual.keys()))
    expected_lines = [f"{k} = {expected.get(k)}\n" for k in keys if k in expected]
    actual_lines = [f"{k} = {actual.get(k)}\n" for k in keys if k in actual]
    diff = list(
        difflib.unified_diff(
            expected_lines,
            actual_lines,
            fromfile=expected_label,
            tofile=actual_label,
        )
    )
    return "".join(diff)


def assert_constants_sync(
    actual_all: dict[str, int],
    expected: dict[str, int],
    source_label: str,
) -> None:
    """Assert actual constants match expected, failing with a readable diff on mismatch."""
    actual_subset: dict[str, int | None] = {k: actual_all.get(k) for k in expected}
    if actual_subset != expected:
        diff = format_diff("expected (python)", source_label, expected, actual_subset)
        mismatches = []
        for k, exp_val in sorted(expected.items()):
            act_val = actual_subset.get(k)
            if act_val != exp_val:
                mismatches.append(f"  {k}: expected {exp_val}, got {act_val}")
        mismatch_summary = "\n".join(mismatches)
        pytest.fail(
            f"Constant drift detected in {source_label}:\n"
            f"{mismatch_summary}\n\n"
            f"Diff:\n{diff}"
        )


def test_lib_rs_constants_sync():
    """Verify lib.rs pub const lines match host Python constants."""
    assert LIB_RS_PATH.is_file(), f"lib.rs not found at {LIB_RS_PATH}"
    actual = parse_rust_pub_consts(LIB_RS_PATH)
    expected = {
        "MAX_REVOCATION_WITNESS_DEPTH": rd.MAX_REVOCATION_WITNESS_DEPTH,
        "MAX_REVOCATION_LEAVES": rd.MAX_REVOCATION_LEAVES,
        "MIN_AGGREGATION_SIZE": ab.MIN_AGGREGATION_SIZE,
        "MAX_AGGREGATION_SIZE": ab.MAX_AGGREGATION_SIZE,
    }
    rel_path = str(LIB_RS_PATH.relative_to(REPO_ROOT)).replace("\\", "/")
    assert_constants_sync(actual, expected, rel_path)


@pytest.mark.parametrize(
    "rel_path",
    [
        "zk/noir/revocation_witness/src/main.nr",
        "zk/noir/revocation_witness_helper/src/main.nr",
    ],
)
def test_revocation_circuits_constants_sync(rel_path: str):
    """Verify revocation circuit Noir globals match host Python constants."""
    target_path = REPO_ROOT / rel_path
    assert target_path.is_file(), f"Circuit file not found at {target_path}"
    actual = parse_noir_globals(target_path)
    expected = {
        "MAX_REVOCATION_WITNESS_DEPTH": rd.MAX_REVOCATION_WITNESS_DEPTH,
        "MAX_REVOCATION_LEAVES": rd.MAX_REVOCATION_LEAVES,
    }
    assert_constants_sync(actual, expected, rel_path)


@pytest.mark.parametrize(
    "rel_path",
    [
        "zk/noir/silent_witness_aggregator/src/main.nr",
        "zk/noir/silent_witness_aggregator_helper/src/main.nr",
    ],
)
def test_silent_witness_aggregator_circuits_constants_sync(rel_path: str):
    """Verify aggregation circuit Noir globals match host Python constants."""
    target_path = REPO_ROOT / rel_path
    assert target_path.is_file(), f"Circuit file not found at {target_path}"
    actual = parse_noir_globals(target_path)
    expected = {
        "MAX_AGGREGATION_SIZE": ab.MAX_AGGREGATION_SIZE,
    }
    assert_constants_sync(actual, expected, rel_path)


def test_all_circuits_no_tracked_constant_drift():
    """Ensure no Noir circuit in zk/noir/*/src/main.nr drifts on any tracked bound."""
    circuit_files = sorted(NOIR_DIR.glob("*/src/main.nr"))
    assert circuit_files, "No Noir circuit main.nr files found"

    for circuit in circuit_files:
        globals_found = parse_noir_globals(circuit)
        intersecting_keys = set(globals_found.keys()) & set(PYTHON_BOUND_CONSTANTS.keys())
        if intersecting_keys:
            expected = {k: PYTHON_BOUND_CONSTANTS[k] for k in intersecting_keys}
            rel_path = str(circuit.relative_to(REPO_ROOT)).replace("\\", "/")
            assert_constants_sync(globals_found, expected, rel_path)


def test_diff_on_mismatch_formatting():
    """Verify format_diff and assert_constants_sync produce a readable diff on mismatch."""
    expected = {"MAX_AGGREGATION_SIZE": 8, "MIN_AGGREGATION_SIZE": 1}
    actual = {"MAX_AGGREGATION_SIZE": 16, "MIN_AGGREGATION_SIZE": 1}
    diff = format_diff("expected (python)", "test_circuit", expected, actual)
    assert "--- expected (python)" in diff
    assert "+++ test_circuit" in diff
    assert "-MAX_AGGREGATION_SIZE = 8" in diff
    assert "+MAX_AGGREGATION_SIZE = 16" in diff

    with pytest.raises(pytest.fail.Exception) as exc_info:
        assert_constants_sync(actual, expected, "test_circuit")
    err_msg = str(exc_info.value)
    assert "Constant drift detected in test_circuit" in err_msg
    assert "MAX_AGGREGATION_SIZE: expected 8, got 16" in err_msg
    assert "-MAX_AGGREGATION_SIZE = 8" in err_msg
    assert "+MAX_AGGREGATION_SIZE = 16" in err_msg
