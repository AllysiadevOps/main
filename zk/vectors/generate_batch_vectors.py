#!/usr/bin/env python3
"""Generate cross-layer test vectors for Tier 2 source batch Merkle inclusion.

Merkle tree construction:
  Leaf hash:          SHA-256(0x00 || leaf)
  Internal node hash: SHA-256(0x01 || left || right)

Emits zk/vectors/source_batch_inclusion_v1.json.
"""

import hashlib
import json
from pathlib import Path

OUT_PATH = Path(__file__).resolve().parent / "source_batch_inclusion_v1.json"


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def leaf_hash(leaf: bytes) -> bytes:
    assert len(leaf) == 32
    return sha256(b"\x00" + leaf)


def node_hash(left: bytes, right: bytes) -> bytes:
    assert len(left) == 32 and len(right) == 32
    return sha256(b"\x01" + left + right)


def build_tree(leaves: list[bytes]) -> tuple[bytes, list[list[bytes]]]:
    """Build a Merkle tree over leaves. Assumes len(leaves) is a power of 2."""
    assert len(leaves) > 0
    # Level 0 is leaf hashes
    current_level = [leaf_hash(l) for l in leaves]
    levels = [current_level]

    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1]
            next_level.append(node_hash(left, right))
        current_level = next_level
        levels.append(current_level)

    root = current_level[0]
    return root, levels


def get_proof(levels: list[list[bytes]], index: int) -> list[bytes]:
    proof = []
    idx = index
    for level in levels[:-1]:
        sibling_idx = idx ^ 1
        proof.append(level[sibling_idx])
        idx //= 2
    return proof


def make_leaf(val: int) -> bytes:
    # 32-byte leaf digest: sha256("harpocrates:batch-leaf:v1" || val_bytes)
    prefix = b"harpocrates:batch-leaf:v1"
    payload = val.to_bytes(32, "big")
    return sha256(prefix + payload)


def main():
    cases = []

    # 1. Single-leaf tree (depth 0)
    leaf0 = make_leaf(1)
    root0 = leaf_hash(leaf0)
    cases.append({
        "id": "single-leaf-valid",
        "description": "Tree with single leaf, proof length 0",
        "root": root0.hex(),
        "leaf": leaf0.hex(),
        "proof": [],
        "index": 0,
        "valid": True,
        "error": None
    })

    # 2. 2-leaf tree (depth 1)
    leaves2 = [make_leaf(i) for i in range(1, 3)]
    root2, levels2 = build_tree(leaves2)
    for i in range(2):
        proof = get_proof(levels2, i)
        cases.append({
            "id": f"two-leaves-leaf-{i}",
            "description": f"2-leaf tree inclusion for leaf index {i}",
            "root": root2.hex(),
            "leaf": leaves2[i].hex(),
            "proof": [p.hex() for p in proof],
            "index": i,
            "valid": True,
            "error": None
        })

    # 3. 4-leaf tree (depth 2)
    leaves4 = [make_leaf(i) for i in range(10, 14)]
    root4, levels4 = build_tree(leaves4)
    for i in range(4):
        proof = get_proof(levels4, i)
        cases.append({
            "id": f"four-leaves-leaf-{i}",
            "description": f"4-leaf tree inclusion for leaf index {i}",
            "root": root4.hex(),
            "leaf": leaves4[i].hex(),
            "proof": [p.hex() for p in proof],
            "index": i,
            "valid": True,
            "error": None
        })

    # 4. 8-leaf tree (depth 3)
    leaves8 = [make_leaf(i) for i in range(100, 108)]
    root8, levels8 = build_tree(leaves8)
    for i in range(8):
        proof = get_proof(levels8, i)
        cases.append({
            "id": f"eight-leaves-leaf-{i}",
            "description": f"8-leaf tree inclusion for leaf index {i}",
            "root": root8.hex(),
            "leaf": leaves8[i].hex(),
            "proof": [p.hex() for p in proof],
            "index": i,
            "valid": True,
            "error": None
        })

    # 5. Deep tree (depth 32 - maximum allowed proof length)
    # We construct a synthetic path of depth 32
    deep_leaf = make_leaf(999)
    deep_index = 0x55555555  # alternating bits
    deep_proof = [make_leaf(2000 + d) for d in range(32)]
    # calculate root
    cur = leaf_hash(deep_leaf)
    for d in range(32):
        sibling = deep_proof[d]
        if (deep_index >> d) & 1 == 0:
            cur = node_hash(cur, sibling)
        else:
            cur = node_hash(sibling, cur)
    deep_root = cur

    cases.append({
        "id": "max-depth-32-valid",
        "description": "Maximum allowed proof length (depth 32) with valid proof",
        "root": deep_root.hex(),
        "leaf": deep_leaf.hex(),
        "proof": [p.hex() for p in deep_proof],
        "index": deep_index,
        "valid": True,
        "error": None
    })

    # Negative Cases
    # Neg 1: Tampered leaf in 4-leaf tree
    cases.append({
        "id": "neg-tampered-leaf",
        "description": "4-leaf tree with tampered leaf digest",
        "root": root4.hex(),
        "leaf": make_leaf(9999).hex(),
        "proof": [p.hex() for p in get_proof(levels4, 0)],
        "index": 0,
        "valid": False,
        "error": "InvalidInclusionProof"
    })

    # Neg 2: Tampered proof sibling
    tampered_proof = [p.hex() for p in get_proof(levels4, 1)]
    tampered_proof[0] = make_leaf(8888).hex()
    cases.append({
        "id": "neg-tampered-sibling",
        "description": "4-leaf tree with tampered sibling in proof",
        "root": root4.hex(),
        "leaf": leaves4[1].hex(),
        "proof": tampered_proof,
        "index": 1,
        "valid": False,
        "error": "InvalidInclusionProof"
    })

    # Neg 3: Wrong index (swapped position)
    cases.append({
        "id": "neg-wrong-index",
        "description": "4-leaf tree with wrong index",
        "root": root4.hex(),
        "leaf": leaves4[2].hex(),
        "proof": [p.hex() for p in get_proof(levels4, 2)],
        "index": 3,
        "valid": False,
        "error": "InvalidInclusionProof"
    })

    # Neg 4: Index out of range for depth (index >= 2^depth)
    cases.append({
        "id": "neg-index-out-of-range",
        "description": "Depth 2 tree with index 4 (>= 2^2)",
        "root": root4.hex(),
        "leaf": leaves4[0].hex(),
        "proof": [p.hex() for p in get_proof(levels4, 0)],
        "index": 4,
        "valid": False,
        "error": "InvalidInclusionProof"
    })

    # Neg 5: Proof length exceeds maximum (33 > 32)
    proof_33 = [p.hex() for p in deep_proof] + [make_leaf(3000).hex()]
    cases.append({
        "id": "neg-proof-too-long",
        "description": "Proof length 33 exceeds maximum bound 32",
        "root": deep_root.hex(),
        "leaf": deep_leaf.hex(),
        "proof": proof_33,
        "index": 0,
        "valid": False,
        "error": "InvalidInclusionProof"
    })

    # Neg 6: Second-preimage attack attempt:
    # Attacker tries to pass an internal node (left || right) or similar as a leaf
    # In a naive Merkle tree without domain separation, a node = H(left || right)
    # could be verified as a leaf = H(node_preimage).
    # With domain separation, leaf is H(0x00 || leaf) while node is H(0x01 || left || right).
    cases.append({
        "id": "neg-second-preimage-node-as-leaf",
        "description": "Attempt to verify an internal node as a leaf",
        "root": root4.hex(),
        "leaf": levels4[1][0].hex(),  # left internal node
        "proof": [levels4[1][1].hex()], # right internal node
        "index": 0,
        "valid": False,
        "error": "InvalidInclusionProof"
    })

    doc = {
        "format": "harpocrates.source-batch-inclusion",
        "version": 1,
        "description": "Cross-layer conformance vectors for Tier 2 Source Batch Merkle inclusion proofs.",
        "generator": "python zk/vectors/generate_batch_vectors.py",
        "constants": {
            "max_batch_count": 1048576,
            "min_batch_count": 1,
            "max_proof_len": 32,
            "leaf_domain_tag_hex": "00",
            "node_domain_tag_hex": "01"
        },
        "cases": cases
    }

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    print(f"Wrote {len(cases)} vectors to {OUT_PATH}")


if __name__ == "__main__":
    main()
