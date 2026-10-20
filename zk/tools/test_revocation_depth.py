"""Unit tests for bounded revocation witness depth (#357).

Run from the repository root:

    python -m pytest zk/tools -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import revocation_depth as rd  # noqa: E402

FIXTURES = (
    Path(__file__).resolve().parents[1]
    / "noir"
    / "fixtures"
    / "revocation_vectors.json"
)


def test_protocol_constants():
    assert rd.MAX_REVOCATION_WITNESS_DEPTH == 3
    assert rd.MAX_REVOCATION_LEAVES == 8
    assert rd.MAX_REVOCATION_LEAVES == 1 << rd.MAX_REVOCATION_WITNESS_DEPTH


def test_accepts_bound_depths():
    for depth in range(1, rd.MAX_REVOCATION_WITNESS_DEPTH + 1):
        assert rd.check_revocation_depth(depth) == depth
        assert rd.check_revocation_leaf_count(1 << depth, depth) == 1 << depth


def test_rejects_oversized_depth():
    with pytest.raises(rd.DepthBoundError) as exc:
        rd.check_revocation_depth(rd.MAX_REVOCATION_WITNESS_DEPTH + 1)
    assert exc.value.code == "depth_oversize"
    assert exc.value.signal() == {"rejectCode": "depth_oversize", "field": "depth"}


def test_rejects_undersized_and_malformed():
    with pytest.raises(rd.DepthBoundError) as exc:
        rd.check_revocation_depth(0)
    assert exc.value.code == "depth_undersize"
    with pytest.raises(rd.DepthBoundError) as exc:
        rd.check_revocation_depth(True)  # type: ignore[arg-type]
    assert exc.value.code == "malformed_depth"
    with pytest.raises(rd.DepthBoundError) as exc:
        rd.check_revocation_depth("3")  # type: ignore[arg-type]
    assert exc.value.code == "malformed_depth"


def test_rejects_oversized_leaf_count():
    with pytest.raises(rd.DepthBoundError) as exc:
        rd.check_revocation_leaf_count(rd.MAX_REVOCATION_LEAVES + 1)
    assert exc.value.code == "depth_oversize"
    assert exc.value.signal() == {"rejectCode": "depth_oversize", "field": "depth"}

    with pytest.raises(rd.DepthBoundError) as exc_with_depth:
        rd.check_revocation_leaf_count(
            rd.MAX_REVOCATION_LEAVES + 1, rd.MAX_REVOCATION_WITNESS_DEPTH
        )
    assert exc_with_depth.value.code == "depth_oversize"
    assert exc_with_depth.value.signal() == {
        "rejectCode": "depth_oversize",
        "field": "depth",
    }


def test_rejects_leaf_count_mismatch_smaller_than_expected():
    for depth, smaller_count in [(2, 2), (2, 3), (3, 4), (3, 7)]:
        with pytest.raises(rd.DepthBoundError) as exc:
            rd.check_revocation_leaf_count(smaller_count, depth)
        assert exc.value.code == "leaf_count_mismatch"
        signal = exc.value.signal()
        assert signal == {"rejectCode": "leaf_count_mismatch", "field": "depth"}
        assert str(smaller_count) not in str(signal)
        assert "leaves" not in signal


def test_rejects_leaf_count_mismatch_larger_than_expected():
    for depth, larger_count in [(1, 4), (2, 6)]:
        with pytest.raises(rd.DepthBoundError) as exc:
            rd.check_revocation_leaf_count(larger_count, depth)
        assert exc.value.code == "leaf_count_mismatch"
        signal = exc.value.signal()
        assert signal == {"rejectCode": "leaf_count_mismatch", "field": "depth"}
        assert str(larger_count) not in str(signal)
        assert "leaves" not in signal


def test_fixtures_declare_bound():
    data = json.loads(FIXTURES.read_text())
    assert data["_max_revocation_witness_depth"] == rd.MAX_REVOCATION_WITNESS_DEPTH
    assert data["_max_revocation_leaves"] == rd.MAX_REVOCATION_LEAVES
    tree = data["revocation_tree"]
    assert tree["depth"] == rd.MAX_REVOCATION_WITNESS_DEPTH
    assert tree["max_depth"] == rd.MAX_REVOCATION_WITNESS_DEPTH
    assert tree["leaf_count"] == rd.MAX_REVOCATION_LEAVES
    assert tree["max_leaves"] == rd.MAX_REVOCATION_LEAVES
    rd.check_revocation_depth(tree["depth"])
    rd.check_revocation_leaf_count(tree["leaf_count"], tree["depth"])

    names = {case["name"] for case in data["negative_cases"]}
    assert "oversized_revocation_depth" in names
    assert "undersized_revocation_depth" in names
