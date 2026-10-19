#!/usr/bin/env python3
"""Regenerate the cross-layer verifier conformance vectors.

The emitted file (``verifier_conformance_v1.json``) is the single source of
truth consumed by every verifier boundary in the repository:

    backend   backend/test_conformance_vectors.py   (Python codec)
    frontend  frontend/src/verifierInputs.conformance.test.ts (TypeScript codec)
    contract  contracts/contracts/harpocrates-registry/src/test_conformance.rs

Run this script only when the vector corpus changes; the JSON file is checked
in so the runners never depend on Python being available.

    python zk/vectors/generate_vectors.py

The vector file is versioned. Adding cases is a minor change; changing the
meaning of an existing case id, the codec id, or the reject-code set requires
bumping ``version`` and shipping a migration note in
docs/zk-conformance-vectors.md.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import difflib
import hashlib
import json
from pathlib import Path
import sys

OUT_PATH = Path(__file__).resolve().parent / "verifier_conformance_v1.json"
OUT_PATH_V2 = Path(__file__).resolve().parent / "verifier_conformance_v2.json"

CODEC_ID = "hpx-vi/1"
CODEC_ID_V2 = "hpx-vi/2"
VECTOR_VERSION = 1
VECTOR_VERSION_V2 = 2

FIELD_LEN = 32
PUBLIC_INPUTS_LEN = 160
SILENT_WITNESS_V2_FIELD_COUNT = 8
SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN = FIELD_LEN * SILENT_WITNESS_V2_FIELD_COUNT  # 256
MIN_PROOF_BYTES = 64
MAX_PROOF_BYTES = 65536

# Circuit version bound into the `silent_witness/v2` envelope (#368). Must
# match EXPECTED_CIRCUIT_VERSION in verifier_inputs.rs and
# CURRENT_CIRCUIT_VERSION in zk/noir/silent_witness/src/main.nr.
EXPECTED_CIRCUIT_VERSION = 2

# BN254 scalar field modulus, big-endian. A field element encoding is canonical
# only when it is strictly below this value.
BN254_R_HEX = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"

# Must byte-for-byte match REVOCATION_DOMAIN_SEPARATOR in
# contracts/contracts/harpocrates-registry/src/lib.rs:
# 7 zero bytes of BN254 padding followed by the 25 ASCII bytes of
# "HARPOCRATES_REVOCATION_V1".
DOMAIN_HEX = ("00" * 7) + b"HARPOCRATES_REVOCATION_V1".hex()

# Silent-witness domain tag: SHA-256(protocol || circuit-version || network).
# The three component fields are byte-for-byte counterparts of
# backend/verifier_inputs.py (DOMAIN_*_FIELD), so a proof is bound to exactly
# this (protocol, circuit version, network) tuple.
DOMAIN_PROTOCOL_FIELD = bytes.fromhex(
    "261e9f6e39e3c1ae6aca9f29e84c10d59c82d5f4b40c21c1b7e3c01ad571c201"
)
DOMAIN_VERSION_FIELD = bytes.fromhex(
    "0c89eff4ec8e39a01e9f19547a0cc9dd7fd2a97d79ba4d94fd32e97a1f5ac623"
)
DOMAIN_NETWORK_FIELD = bytes.fromhex(
    "2a2c3f48ce2e3c2f1e6c89b18d64b5f5c1f88a59a0d9bc82cb61a1e8cb77a50f"
)


def _domain_tag(protocol: bytes, version: bytes, network: bytes) -> str:
    return hashlib.sha256(protocol + version + network).hexdigest()


def _bump_last_byte(field: bytes) -> bytes:
    return field[:-1] + bytes([(field[-1] + 1) % 256])


DOMAIN_TAG_HEX = _domain_tag(DOMAIN_PROTOCOL_FIELD, DOMAIN_VERSION_FIELD, DOMAIN_NETWORK_FIELD)

# Single-component mutations: each tag is recomputed with exactly one domain
# component changed, modelling cross-protocol / cross-version / cross-network
# proof replay. They stay canonical, non-zero 32-byte values, so the expected
# failure is a domain *mismatch* rather than a framing/canonicity error.
DOMAIN_TAG_WRONG_PROTOCOL_HEX = _domain_tag(
    _bump_last_byte(DOMAIN_PROTOCOL_FIELD), DOMAIN_VERSION_FIELD, DOMAIN_NETWORK_FIELD
)
DOMAIN_TAG_WRONG_VERSION_HEX = _domain_tag(
    DOMAIN_PROTOCOL_FIELD, _bump_last_byte(DOMAIN_VERSION_FIELD), DOMAIN_NETWORK_FIELD
)
DOMAIN_TAG_WRONG_NETWORK_HEX = _domain_tag(
    DOMAIN_PROTOCOL_FIELD, DOMAIN_VERSION_FIELD, _bump_last_byte(DOMAIN_NETWORK_FIELD)
)

ZERO = "00" * FIELD_LEN
ONES = "ff" * FIELD_LEN

# Circuit version 2 encoded as a u32 in the low 4 bytes of a field element.
VERSION_2 = "00" * 28 + "00000002"
VERSION_1 = "00" * 28 + "00000001"
VERSION_3 = "00" * 28 + "00000003"
VERSION_DIRTY_UPPER = "00" * 27 + "01" + "00000002"

VIDEO_HASH = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
PAD16 = "00" * 16
VIDEO_HI = PAD16 + VIDEO_HASH[:32]
VIDEO_LO = PAD16 + VIDEO_HASH[32:]

CREDENTIAL_ROOT = "01" * FIELD_LEN
NULLIFIER = "02" * FIELD_LEN
REVOCATION_ROOT = "03" * FIELD_LEN
VERIFIER_SCOPE = "04" * FIELD_LEN
# Epoch 5 as a u64 in the low 8 bytes of a field element.
EPOCH = "00" * 24 + "0000000000000005"
EPOCH_ZERO = "00" * FIELD_LEN

PROOF_MIN = "ab" * MIN_PROOF_BYTES
PROOF_TYPICAL = "cd" * 512


def silent(hi: str, lo: str, root: str, nullifier: str, domain: str = DOMAIN_TAG_HEX) -> str:
    return hi + lo + root + nullifier + domain


def silent_v2(
    hi: str,
    lo: str,
    root: str,
    nullifier: str,
    scope: str = VERIFIER_SCOPE,
    epoch: str = EPOCH,
    domain: str = DOMAIN_TAG_HEX,
    version: str | None = None,
) -> str:
    """silent_witness/v2 frame: the scoped frame followed by the circuit version."""
    if version is None:
        version = VERSION_2
    return hi + lo + root + nullifier + scope + epoch + domain + version


def revocation(root: str, nullifier: str, domain: str, credential: str) -> str:
    return root + nullifier + domain + credential


SILENT_VALID = silent(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER)
SILENT_V2_VALID = silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER)
REVOCATION_VALID = revocation(REVOCATION_ROOT, NULLIFIER, DOMAIN_HEX, CREDENTIAL_ROOT)


def case(
    case_id: str,
    schema: str,
    description: str,
    public_inputs_hex: str,
    reject_code: str | None,
    proof_hex: str = PROOF_MIN,
) -> dict[str, object]:
    return {
        "id": case_id,
        "schema": schema,
        "description": description,
        "public_inputs_hex": public_inputs_hex,
        "proof_hex": proof_hex,
        "expect": {
            "accept": reject_code is None,
            "reject_code": reject_code,
        },
    }


def build_cases() -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []

    # ---- positive corpus ------------------------------------------------
    cases.append(
        case(
            "sw-pos-001-canonical",
            "silent_witness/v1",
            "Canonical silent-witness inputs with a minimum-length proof.",
            SILENT_VALID,
            None,
        )
    )
    cases.append(
        case(
            "sw-pos-002-typical-proof-size",
            "silent_witness/v1",
            "Same inputs with a realistically sized proof blob.",
            SILENT_VALID,
            None,
            PROOF_TYPICAL,
        )
    )
    cases.append(
        case(
            "sw-pos-003-zero-video-hash",
            "silent_witness/v1",
            "A zero video hash is structurally legal; only identity fields must be non-zero.",
            silent(PAD16 + "00" * 16, PAD16 + "00" * 16, CREDENTIAL_ROOT, NULLIFIER),
            None,
        )
    )
    cases.append(
        case(
            "sw-pos-004-max-canonical-field",
            "silent_witness/v1",
            "Identity fields one below the BN254 modulus remain canonical.",
            silent(VIDEO_HI, VIDEO_LO, _decrement_hex(BN254_R_HEX), NULLIFIER),
            None,
        )
    )
    cases.append(
        case(
            "rv-pos-001-canonical",
            "revocation_witness/v1",
            "Canonical revocation inputs carrying the v1 domain separator.",
            REVOCATION_VALID,
            None,
        )
    )
    cases.append(
        case(
            "rv-pos-002-max-proof-size",
            "revocation_witness/v1",
            "Proof blob exactly at the accepted upper bound.",
            REVOCATION_VALID,
            None,
            "ee" * MAX_PROOF_BYTES,
        )
    )

    # ---- length / framing -----------------------------------------------
    cases.append(
        case(
            "sw-neg-001-empty",
            "silent_witness/v1",
            "Empty public inputs.",
            "",
            "length",
        )
    )
    cases.append(
        case(
            "sw-neg-002-truncated-one-byte",
            "silent_witness/v1",
            "127 bytes: one byte short of a full frame.",
            SILENT_VALID[:-2],
            "length",
        )
    )
    cases.append(
        case(
            "sw-neg-003-truncated-one-field",
            "silent_witness/v1",
            "96 bytes: a whole field element missing.",
            SILENT_VALID[: 96 * 2],
            "length",
        )
    )
    cases.append(
        case(
            "sw-neg-004-oversized-one-byte",
            "silent_witness/v1",
            "129 bytes: one trailing byte past the frame.",
            SILENT_VALID + "00",
            "length",
        )
    )
    cases.append(
        case(
            "sw-neg-005-doubled-frame",
            "silent_witness/v1",
            "Two concatenated valid frames must not be accepted as one.",
            SILENT_VALID + SILENT_VALID,
            "length",
        )
    )

    # ---- padding invariants ---------------------------------------------
    cases.append(
        case(
            "sw-neg-010-hi-padding-dirty",
            "silent_witness/v1",
            "High half of video_hash_hi must be zero padding.",
            silent("01" + PAD16[2:] + VIDEO_HASH[:32], VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER),
            "padding",
        )
    )
    cases.append(
        case(
            "sw-neg-011-lo-padding-dirty",
            "silent_witness/v1",
            "High half of video_hash_lo must be zero padding.",
            silent(VIDEO_HI, PAD16[:30] + "01" + VIDEO_HASH[32:], CREDENTIAL_ROOT, NULLIFIER),
            "padding",
        )
    )

    # ---- field canonicity ------------------------------------------------
    cases.append(
        case(
            "sw-neg-020-credential-root-equals-modulus",
            "silent_witness/v1",
            "A field element equal to the modulus is a non-canonical encoding.",
            silent(VIDEO_HI, VIDEO_LO, BN254_R_HEX, NULLIFIER),
            "non_canonical_field",
        )
    )
    cases.append(
        case(
            "sw-neg-021-nullifier-all-ones",
            "silent_witness/v1",
            "0xff..ff is far above the modulus.",
            silent(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, ONES),
            "non_canonical_field",
        )
    )
    cases.append(
        case(
            "rv-neg-020-revocation-root-non-canonical",
            "revocation_witness/v1",
            "Non-canonical revocation root.",
            revocation(ONES, NULLIFIER, DOMAIN_HEX, CREDENTIAL_ROOT),
            "non_canonical_field",
        )
    )

    # ---- zero identity fields -------------------------------------------
    cases.append(
        case(
            "sw-neg-030-zero-nullifier",
            "silent_witness/v1",
            "A zero nullifier would disable replay protection.",
            silent(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, ZERO),
            "zero_field",
        )
    )
    cases.append(
        case(
            "sw-neg-031-zero-credential-root",
            "silent_witness/v1",
            "A zero credential root can never be registered on-chain.",
            silent(VIDEO_HI, VIDEO_LO, ZERO, NULLIFIER),
            "zero_field",
        )
    )
    cases.append(
        case(
            "rv-neg-030-zero-revocation-root",
            "revocation_witness/v1",
            "A zero revocation root is not a valid published root.",
            revocation(ZERO, NULLIFIER, DOMAIN_HEX, CREDENTIAL_ROOT),
            "zero_field",
        )
    )

    # ---- domain binding --------------------------------------------------
    cases.append(
        case(
            "rv-neg-040-zero-domain",
            "revocation_witness/v1",
            "Missing domain separator.",
            revocation(REVOCATION_ROOT, NULLIFIER, ZERO, CREDENTIAL_ROOT),
            "domain_mismatch",
        )
    )
    cases.append(
        case(
            "rv-neg-041-domain-off-by-one",
            "revocation_witness/v1",
            "Domain separator differing in the final version byte (V1 -> V2).",
            revocation(
                REVOCATION_ROOT,
                NULLIFIER,
                DOMAIN_HEX[:-2] + "32",
                CREDENTIAL_ROOT,
            ),
            "domain_mismatch",
        )
    )
    cases.append(
        case(
            "rv-neg-042-domain-case-folded",
            "revocation_witness/v1",
            "Lowercased domain ASCII: the separator is compared byte-wise, not case-insensitively.",
            revocation(
                REVOCATION_ROOT,
                NULLIFIER,
                ("00" * 7) + b"harpocrates_revocation_v1".hex(),
                CREDENTIAL_ROOT,
            ),
            "domain_mismatch",
        )
    )
    cases.append(
        case(
            "rv-neg-043-fields-rotated",
            "revocation_witness/v1",
            "Field order rotated by one element; caught by the domain check.",
            revocation(NULLIFIER, DOMAIN_HEX, CREDENTIAL_ROOT, REVOCATION_ROOT),
            "domain_mismatch",
        )
    )
    cases.append(
        case(
            "sw-neg-044-domain-mismatch",
            "silent_witness/v1",
            "Silent-witness domain tag must match the protocol binding.",
            silent(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, ONES),
            "domain_mismatch",
        )
    )
    # Cross-component rejection vectors: the domain tag binds
    # SHA-256(protocol || circuit-version || network), so a proof carrying a tag
    # computed for a *different* protocol, circuit version, or network must be
    # rejected even though it is otherwise canonical and non-zero.
    cases.append(
        case(
            "sw-neg-045-domain-wrong-protocol",
            "silent_witness/v1",
            "Domain tag recomputed with a different protocol component (cross-protocol replay).",
            silent(
                VIDEO_HI,
                VIDEO_LO,
                CREDENTIAL_ROOT,
                NULLIFIER,
                DOMAIN_TAG_WRONG_PROTOCOL_HEX,
            ),
            "domain_mismatch",
        )
    )
    cases.append(
        case(
            "sw-neg-046-domain-wrong-circuit-version",
            "silent_witness/v1",
            "Domain tag recomputed with a different circuit version (cross-version replay).",
            silent(
                VIDEO_HI,
                VIDEO_LO,
                CREDENTIAL_ROOT,
                NULLIFIER,
                DOMAIN_TAG_WRONG_VERSION_HEX,
            ),
            "domain_mismatch",
        )
    )
    cases.append(
        case(
            "sw-neg-047-domain-wrong-network",
            "silent_witness/v1",
            "Domain tag recomputed with a different network component (cross-network replay).",
            silent(
                VIDEO_HI,
                VIDEO_LO,
                CREDENTIAL_ROOT,
                NULLIFIER,
                DOMAIN_TAG_WRONG_NETWORK_HEX,
            ),
            "domain_mismatch",
        )
    )

    # ---- proof blob bounds ------------------------------------------------
    cases.append(
        case(
            "sw-neg-050-empty-proof",
            "silent_witness/v1",
            "Empty proof blob.",
            SILENT_VALID,
            "proof_undersize",
            "",
        )
    )
    cases.append(
        case(
            "sw-neg-051-proof-one-byte-short",
            "silent_witness/v1",
            "Proof blob one byte below the accepted floor.",
            SILENT_VALID,
            "proof_undersize",
            "ab" * (MIN_PROOF_BYTES - 1),
        )
    )
    cases.append(
        case(
            "sw-neg-052-proof-one-byte-long",
            "silent_witness/v1",
            "Proof blob one byte past the accepted ceiling.",
            SILENT_VALID,
            "proof_oversize",
            "ab" * (MAX_PROOF_BYTES + 1),
        )
    )

    # ---- boundary: proof exactly at limits (regression) -----------------
    cases.append(
        case(
            "sw-pos-010-proof-exactly-min",
            "silent_witness/v1",
            "Proof blob exactly at the accepted floor (MIN_PROOF_BYTES=64).",
            SILENT_VALID,
            None,
            "ab" * MIN_PROOF_BYTES,
        )
    )
    cases.append(
        case(
            "sw-pos-011-proof-exactly-max",
            "silent_witness/v1",
            "Proof blob exactly at the accepted ceiling (MAX_PROOF_BYTES=65536).",
            SILENT_VALID,
            None,
            "cd" * MAX_PROOF_BYTES,
        )
    )

    # ---- field canonicity boundary: one below vs at modulus -------------
    cases.append(
        case(
            "sw-neg-022-credential-root-above-modulus-by-one",
            "silent_witness/v1",
            "Field element one above the BN254 modulus is non-canonical.",
            silent(VIDEO_HI, VIDEO_LO, _increment_hex(BN254_R_HEX), NULLIFIER),
            "non_canonical_field",
        )
    )
    cases.append(
        case(
            "rv-neg-021-nullifier-equals-modulus",
            "revocation_witness/v1",
            "Nullifier equal to the BN254 modulus is non-canonical.",
            revocation(REVOCATION_ROOT, BN254_R_HEX, DOMAIN_HEX, CREDENTIAL_ROOT),
            "non_canonical_field",
        )
    )
    cases.append(
        case(
            "rv-neg-022-credential-root-all-ones",
            "revocation_witness/v1",
            "0xff..ff credential root is far above the modulus.",
            revocation(REVOCATION_ROOT, NULLIFIER, DOMAIN_HEX, ONES),
            "non_canonical_field",
        )
    )

    # ---- zero identity fields: revocation witness -----------------------
    cases.append(
        case(
            "rv-neg-031-zero-nullifier",
            "revocation_witness/v1",
            "A zero nullifier in a revocation frame disables replay protection.",
            revocation(REVOCATION_ROOT, ZERO, DOMAIN_HEX, CREDENTIAL_ROOT),
            "zero_field",
        )
    )
    cases.append(
        case(
            "rv-neg-032-zero-credential-root",
            "revocation_witness/v1",
            "A zero credential root in a revocation frame is invalid.",
            revocation(REVOCATION_ROOT, NULLIFIER, DOMAIN_HEX, ZERO),
            "zero_field",
        )
    )

    # ---- padding: silent witness lo field dirty high half ---------------
    cases.append(
        case(
            "sw-neg-012-hi-padding-all-ones",
            "silent_witness/v1",
            "All-ones high half in video_hash_hi field must be rejected as dirty padding.",
            silent(ONES[:32] + VIDEO_HASH[:32], VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER),
            "padding",
        )
    )

    # ---- domain binding: domain mismatch --------------------------------
    cases.append(
        case(
            "rv-neg-044-domain-mismatch",
            "revocation_witness/v1",
            "All-ones domain separator is non-canonical (canonical check precedes domain match).",
            revocation(REVOCATION_ROOT, NULLIFIER, ONES, CREDENTIAL_ROOT),
            "non_canonical_field",
        )
    )

    # ---- check-order regression: length beats padding -------------------
    cases.append(
        case(
            "sw-neg-060-length-before-padding",
            "silent_witness/v1",
            "A frame that is both dirty-padded and wrong length must be rejected for length, not padding (check order).",
            "01" + SILENT_VALID[:-4],  # 159 bytes with dirty first byte — length wins
            "length",
        )
    )

    # ---- revocation length / framing (malformed public-input shapes) ----
    cases.append(
        case(
            "rv-neg-001-empty",
            "revocation_witness/v1",
            "Empty revocation public inputs.",
            "",
            "length",
        )
    )
    cases.append(
        case(
            "rv-neg-002-truncated-one-byte",
            "revocation_witness/v1",
            "127 bytes: one byte short of a revocation frame.",
            REVOCATION_VALID[:-2],
            "length",
        )
    )
    cases.append(
        case(
            "rv-neg-003-truncated-one-field",
            "revocation_witness/v1",
            "96 bytes: a whole field element missing from a revocation frame.",
            REVOCATION_VALID[: 96 * 2],
            "length",
        )
    )
    cases.append(
        case(
            "rv-neg-004-oversized-one-byte",
            "revocation_witness/v1",
            "129 bytes: one trailing byte past the revocation frame.",
            REVOCATION_VALID + "00",
            "length",
        )
    )
    cases.append(
        case(
            "rv-neg-005-doubled-frame",
            "revocation_witness/v1",
            "Two concatenated valid revocation frames must not be accepted as one.",
            REVOCATION_VALID + REVOCATION_VALID,
            "length",
        )
    )
    cases.append(
        case(
            "rv-neg-006-silent-length-as-revocation",
            "revocation_witness/v1",
            "A silent-witness-length (160-byte) frame must not be accepted under the revocation schema.",
            SILENT_VALID,
            "length",
        )
    )
    cases.append(
        case(
            "sw-neg-006-revocation-length-as-silent",
            "silent_witness/v1",
            "A revocation-length (128-byte) frame must not be accepted under the silent-witness schema.",
            REVOCATION_VALID,
            "length",
        )
    )

    # ---- revocation proof blob bounds -----------------------------------
    cases.append(
        case(
            "rv-neg-050-empty-proof",
            "revocation_witness/v1",
            "Empty proof blob for a revocation frame.",
            REVOCATION_VALID,
            "proof_undersize",
            "",
        )
    )
    cases.append(
        case(
            "rv-neg-051-proof-one-byte-short",
            "revocation_witness/v1",
            "Revocation proof one byte below the accepted floor.",
            REVOCATION_VALID,
            "proof_undersize",
            "ab" * (MIN_PROOF_BYTES - 1),
        )
    )

    return cases


def build_cases_v2() -> list[dict[str, object]]:
    """silent_witness/v2 cases: the v2-envelope interpretation of the v1 silent
    corpus, plus version-field-specific rejections (#368)."""
    cases: list[dict[str, object]] = []

    # ---- positive corpus --------------------------------------------------
    cases.append(
        case(
            "sw2-pos-001-canonical",
            "silent_witness/v2",
            "Canonical v2 inputs (version 2) with a minimum-length proof.",
            SILENT_V2_VALID,
            None,
        )
    )
    cases.append(
        case(
            "sw2-pos-002-typical-proof-size",
            "silent_witness/v2",
            "Same inputs with a realistically sized proof blob.",
            SILENT_V2_VALID,
            None,
            PROOF_TYPICAL,
        )
    )
    cases.append(
        case(
            "sw2-pos-003-zero-video-hash",
            "silent_witness/v2",
            "A zero video hash is structurally legal; only identity fields must be non-zero.",
            silent_v2(PAD16 + "00" * 16, PAD16 + "00" * 16, CREDENTIAL_ROOT, NULLIFIER),
            None,
        )
    )
    cases.append(
        case(
            "sw2-pos-004-max-canonical-field",
            "silent_witness/v2",
            "Identity fields one below the BN254 modulus remain canonical.",
            silent_v2(VIDEO_HI, VIDEO_LO, _decrement_hex(BN254_R_HEX), NULLIFIER),
            None,
        )
    )
    cases.append(
        case(
            "sw2-pos-010-proof-exactly-min",
            "silent_witness/v2",
            "Proof blob exactly at the accepted floor.",
            SILENT_V2_VALID,
            None,
            "ab" * MIN_PROOF_BYTES,
        )
    )

    # ---- length / framing -------------------------------------------------
    cases.append(case("sw2-neg-001-empty", "silent_witness/v2", "Empty public inputs.", "", "length"))
    cases.append(
        case(
            "sw2-neg-002-truncated-one-byte",
            "silent_witness/v2",
            "255 bytes: one byte short of a v2 frame.",
            SILENT_V2_VALID[:-2],
            "length",
        )
    )
    cases.append(
        case(
            "sw2-neg-003-truncated-one-field",
            "silent_witness/v2",
            "224 bytes: the scoped frame without its committed version field.",
            SILENT_V2_VALID[:-2 * FIELD_LEN],
            "length",
        )
    )
    cases.append(
        case(
            "sw2-neg-004-v1-len-as-v2",
            "silent_witness/v2",
            "A 160-byte v1 silent frame must not be accepted under the v2 schema.",
            SILENT_VALID,
            "length",
        )
    )
    cases.append(
        case(
            "sw2-neg-005-doubled-frame",
            "silent_witness/v2",
            "Two concatenated v2 frames must not be accepted as one.",
            SILENT_V2_VALID + SILENT_V2_VALID,
            "length",
        )
    )

    # ---- padding invariants ----------------------------------------------
    cases.append(
        case(
            "sw2-neg-010-hi-padding-dirty",
            "silent_witness/v2",
            "High half of video_hash_hi must be zero padding.",
            silent_v2("01" + PAD16[2:] + VIDEO_HASH[:32], VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER),
            "padding",
        )
    )
    cases.append(
        case(
            "sw2-neg-011-lo-padding-dirty",
            "silent_witness/v2",
            "High half of video_hash_lo must be zero padding.",
            silent_v2(VIDEO_HI, PAD16[:30] + "01" + VIDEO_HASH[32:], CREDENTIAL_ROOT, NULLIFIER),
            "padding",
        )
    )

    # ---- scope / epoch bindings ------------------------------------------
    cases.append(
        case(
            "sw2-pos-005-zero-epoch",
            "silent_witness/v2",
            "Epoch 0 is a legal epoch; only identity fields must be non-zero.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, epoch=EPOCH_ZERO),
            None,
        )
    )
    cases.append(
        case(
            "sw2-pos-006-zero-scope",
            "silent_witness/v2",
            "The default (zero) verifier scope is legal; scope is a binding, not an identity.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, scope=EPOCH_ZERO),
            None,
        )
    )
    cases.append(
        case(
            "sw2-neg-012-epoch-non-canonical",
            "silent_witness/v2",
            "An epoch above the BN254 modulus is not a field element.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, epoch=ONES),
            "non_canonical_field",
        )
    )
    cases.append(
        case(
            "sw2-neg-013-scope-non-canonical",
            "silent_witness/v2",
            "A verifier scope above the BN254 modulus is not a field element.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, scope=ONES),
            "non_canonical_field",
        )
    )

    # ---- circuit version (#368) ------------------------------------------
    cases.append(
        case(
            "sw2-neg-020-version-zero",
            "silent_witness/v2",
            "A zero version field is not the accepted circuit version.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, version=ZERO),
            "version_mismatch",
        )
    )
    cases.append(
        case(
            "sw2-neg-021-version-one",
            "silent_witness/v2",
            "Declaring legacy circuit version 1 inside a v2 envelope is a mismatch.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, version=VERSION_1),
            "version_mismatch",
        )
    )
    cases.append(
        case(
            "sw2-neg-022-version-three",
            "silent_witness/v2",
            "A future circuit version is rejected until the codec is promoted.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, version=VERSION_3),
            "version_mismatch",
        )
    )
    cases.append(
        case(
            "sw2-neg-023-version-all-ones",
            "silent_witness/v2",
            "An all-ones version field is not a valid u32 encoding (upper bytes dirty).",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, version=ONES),
            "version_mismatch",
        )
    )
    cases.append(
        case(
            "sw2-neg-024-version-dirty-upper",
            "silent_witness/v2",
            "Version 2 with a non-zero upper byte is a malformed u32 encoding.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, version=VERSION_DIRTY_UPPER),
            "version_mismatch",
        )
    )

    # ---- field canonicity ------------------------------------------------
    cases.append(
        case(
            "sw2-neg-030-credential-root-equals-modulus",
            "silent_witness/v2",
            "A field element equal to the modulus is a non-canonical encoding.",
            silent_v2(VIDEO_HI, VIDEO_LO, BN254_R_HEX, NULLIFIER),
            "non_canonical_field",
        )
    )
    cases.append(
        case(
            "sw2-neg-031-nullifier-all-ones",
            "silent_witness/v2",
            "0xff..ff is far above the modulus.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, ONES),
            "non_canonical_field",
        )
    )

    # ---- zero identity fields --------------------------------------------
    cases.append(
        case(
            "sw2-neg-040-zero-nullifier",
            "silent_witness/v2",
            "A zero nullifier would disable replay protection.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, ZERO),
            "zero_field",
        )
    )
    cases.append(
        case(
            "sw2-neg-041-zero-credential-root",
            "silent_witness/v2",
            "A zero credential root can never be registered on-chain.",
            silent_v2(VIDEO_HI, VIDEO_LO, ZERO, NULLIFIER),
            "zero_field",
        )
    )

    # ---- domain binding ---------------------------------------------------
    cases.append(
        case(
            "sw2-neg-050-domain-mismatch",
            "silent_witness/v2",
            "Silent-witness domain tag must match the protocol binding.",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, domain=ONES),
            "domain_mismatch",
        )
    )
    cases.append(
        case(
            "sw2-neg-051-domain-all-ones",
            "silent_witness/v2",
            "An all-ones domain tag is not the protocol binding (the silent domain is compared byte-for-byte, not canonicalised).",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, domain=DOMAIN_HEX),
            "domain_mismatch",
        )
    )

    # ---- proof blob bounds ------------------------------------------------
    cases.append(
        case(
            "sw2-neg-060-empty-proof",
            "silent_witness/v2",
            "Empty proof blob.",
            SILENT_V2_VALID,
            "proof_undersize",
            "",
        )
    )
    cases.append(
        case(
            "sw2-neg-061-proof-one-byte-long",
            "silent_witness/v2",
            "Proof blob one byte past the accepted ceiling.",
            SILENT_V2_VALID,
            "proof_oversize",
            "ab" * (MAX_PROOF_BYTES + 1),
        )
    )

    # ---- check-order regressions -----------------------------------------
    cases.append(
        case(
            "sw2-neg-070-length-before-version",
            "silent_witness/v2",
            "255 bytes with a wrong version field: length wins (check order).",
            silent_v2(VIDEO_HI, VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, version=VERSION_1)[:-2],
            "length",
        )
    )
    cases.append(
        case(
            "sw2-neg-071-padding-before-version",
            "silent_witness/v2",
            "Dirty padding with a wrong version field: padding wins.",
            silent_v2("01" + PAD16[2:] + VIDEO_HASH[:32], VIDEO_LO, CREDENTIAL_ROOT, NULLIFIER, version=VERSION_1),
            "padding",
        )
    )
    cases.append(
        case(
            "sw2-neg-072-version-before-canonical",
            "silent_witness/v2",
            "Wrong version with a non-canonical root: version wins.",
            silent_v2(VIDEO_HI, VIDEO_LO, BN254_R_HEX, NULLIFIER, version=VERSION_1),
            "version_mismatch",
        )
    )

    return cases


def _decrement_hex(value: str) -> str:
    return format(int(value, 16) - 1, "064x")


def _increment_hex(value: str) -> str:
    return format(int(value, 16) + 1, "064x")


def build_document() -> dict[str, object]:
    return {
        "format": "harpocrates.verifier-conformance",
        "version": VECTOR_VERSION,
        "codec": CODEC_ID,
        "description": (
            "Cross-layer conformance vectors for the Harpocrates verifier input "
            "boundary. Every layer (Noir-facing backend, browser, Soroban "
            "registry) must classify each case identically."
        ),
        "regenerate_with": "python zk/vectors/generate_vectors.py",
        "constants": {
            "field_len": FIELD_LEN,
            "public_inputs_len": PUBLIC_INPUTS_LEN,
            "min_proof_bytes": MIN_PROOF_BYTES,
            "max_proof_bytes": MAX_PROOF_BYTES,
            "bn254_scalar_field_modulus_hex": BN254_R_HEX,
            "revocation_domain_separator_hex": DOMAIN_HEX,
        },
        "schemas": {
            "silent_witness/v1": [
                "video_hash_hi",
            "video_hash_lo",
            "credential_root",
            "nullifier",
            "domain_tag",
            ],
            "revocation_witness/v1": [
                "revocation_root",
                "nullifier",
                "domain_separator",
                "credential_root",
            ],
        },
        "reject_codes": [
            "length",
            "padding",
            "non_canonical_field",
            "zero_field",
            "domain_mismatch",
            "proof_undersize",
            "proof_oversize",
            "malformed_hex",
        ],
        "cases": build_cases(),
    }


def build_document_v2() -> dict[str, object]:
    """Circuit-versioned silent-witness envelope corpus (#368)."""
    return {
        "format": "harpocrates.verifier-conformance",
        "version": VECTOR_VERSION_V2,
        "codec": CODEC_ID_V2,
        "description": (
            "Cross-layer conformance vectors for the circuit-versioned "
            "silent-witness envelope. `silent_witness/v2` is the scoped frame "
            "with the circuit version committed as its trailing field, so the "
            "wire format names the exact circuit that produced the proof. "
            "Every layer must classify each case identically."
        ),
        "regenerate_with": "python zk/vectors/generate_vectors.py",
        "constants": {
            "field_len": FIELD_LEN,
            "public_inputs_len": PUBLIC_INPUTS_LEN,
            "silent_witness_v2_field_count": SILENT_WITNESS_V2_FIELD_COUNT,
            "silent_witness_v2_public_inputs_len": SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN,
            "min_proof_bytes": MIN_PROOF_BYTES,
            "max_proof_bytes": MAX_PROOF_BYTES,
            "bn254_scalar_field_modulus_hex": BN254_R_HEX,
            "revocation_domain_separator_hex": DOMAIN_HEX,
            "silent_witness_domain_tag_hex": DOMAIN_TAG_HEX,
            "expected_circuit_version": EXPECTED_CIRCUIT_VERSION,
        },
        "schemas": {
            "silent_witness/v2": [
                "video_hash_hi",
                "video_hash_lo",
                "credential_root",
                "nullifier",
                "verifier_scope",
                "epoch",
                "domain_tag",
                "circuit_version",
            ],
        },
        "reject_codes": [
            "length",
            "padding",
            "non_canonical_field",
            "zero_field",
            "domain_mismatch",
            "proof_undersize",
            "proof_oversize",
            "malformed_hex",
            "version_mismatch",
        ],
        "cases": build_cases_v2(),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify committed vector files match generated output without writing",
    )
    if argv is None:
        argv = sys.argv[1:] if Path(sys.argv[0]).name == Path(__file__).name else []
    args = parser.parse_args(list(argv))

    documents = [build_document(), build_document_v2()]
    outputs = [OUT_PATH, OUT_PATH_V2]
    seen: set[str] = set()
    mismatched = False
    for document, output in zip(documents, outputs):
        seen.clear()
        for entry in document["cases"]:  # type: ignore[index]
            case_id = entry["id"]  # type: ignore[index]
            if case_id in seen:
                raise SystemExit(f"duplicate case id: {case_id}")
            seen.add(case_id)

        rendered = json.dumps(document, indent=2, sort_keys=False) + "\n"
        if args.check:
            if not output.is_file():
                print(f"missing vector file: {output}", file=sys.stderr)
                mismatched = True
                continue
            committed = output.read_text(encoding="utf-8")
            if committed != rendered:
                diff = "".join(
                    difflib.unified_diff(
                        committed.splitlines(keepends=True),
                        rendered.splitlines(keepends=True),
                        fromfile=f"{output.name} (committed)",
                        tofile=f"{output.name} (generated)",
                    )
                )
                print(
                    f"{output} is out of date; regenerate with `{document['regenerate_with']}`:",
                    file=sys.stderr,
                )
                print(diff, end="", file=sys.stderr)
                mismatched = True
            else:
                print(f"verified {len(document['cases'])} cases in {output}")  # type: ignore[arg-type]
        else:
            output.write_text(
                rendered,
                encoding="utf-8",
            )
            print(f"wrote {len(document['cases'])} cases to {output}")  # type: ignore[arg-type]

    if mismatched:
        raise SystemExit(1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
