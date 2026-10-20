"""Bounded revocation-witness Merkle depth (#357).

Host-side guard that mirrors the Noir globals:

    MAX_REVOCATION_WITNESS_DEPTH = 3
    MAX_REVOCATION_LEAVES = 8  # 2**depth

Oversized or malformed depth values are rejected with a stable machine code
and never echo leaves, secrets, or witness material.

Reject codes:
    * ``depth_oversize``: depth > MAX_REVOCATION_WITNESS_DEPTH or leaf_count > MAX_REVOCATION_LEAVES
    * ``depth_undersize``: depth < 1 or leaf_count < 1
    * ``malformed_depth``: non-integer or boolean input
    * ``leaf_count_mismatch``: leaf_count != 2**depth for a bounded depth
"""

from __future__ import annotations

from typing import Final

MAX_REVOCATION_WITNESS_DEPTH: Final[int] = 3
MAX_REVOCATION_LEAVES: Final[int] = 1 << MAX_REVOCATION_WITNESS_DEPTH  # 8


class DepthBoundError(ValueError):
    """Privacy-safe depth rejection."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)

    def signal(self) -> dict[str, str]:
        return {"rejectCode": self.code, "field": "depth"}


def check_revocation_depth(depth: object) -> int:
    """Return ``depth`` when it is within ``[1, MAX_REVOCATION_WITNESS_DEPTH]``."""
    if isinstance(depth, bool) or not isinstance(depth, int):
        raise DepthBoundError("malformed_depth")
    if depth < 1:
        raise DepthBoundError("depth_undersize")
    if depth > MAX_REVOCATION_WITNESS_DEPTH:
        raise DepthBoundError("depth_oversize")
    return depth


def check_revocation_leaf_count(leaf_count: object, depth: int | None = None) -> int:
    """Reject leaf counts that exceed the depth bound or disagree with ``2**depth``."""
    if isinstance(leaf_count, bool) or not isinstance(leaf_count, int):
        raise DepthBoundError("malformed_depth")
    if leaf_count < 1:
        raise DepthBoundError("depth_undersize")
    if leaf_count > MAX_REVOCATION_LEAVES:
        raise DepthBoundError("depth_oversize")
    if depth is not None:
        bound_depth = check_revocation_depth(depth)
        expected = 1 << bound_depth
        if leaf_count != expected:
            raise DepthBoundError("leaf_count_mismatch")
    return leaf_count
