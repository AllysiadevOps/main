"""Canonical verifier-input codec for Harpocrates (codec ``hpx-vi/1``).

This module is the Python side of a three-way codec that must agree byte for
byte with:

    frontend/src/verifierInputs.ts                       (browser / TypeScript)
    contracts/contracts/harpocrates-registry/src/lib.rs  (Soroban / Rust)

Agreement is enforced by the shared corpus in
``zk/vectors/verifier_conformance_v1.json``; see docs/zk-conformance-vectors.md.

Design rules
------------
* **Bounded.** Every entry point rejects oversized material *before* allocating
  a decoded buffer, so hostile inputs cannot drive memory use.
* **Deterministic.** Validation runs in a fixed order and returns the first
  failing :class:`RejectCode`. The same bytes always produce the same code on
  every layer.
* **Silent.** Errors carry a stable machine code and a field *name* only. No
  witness material, proof bytes, or public-input bytes ever reach the message,
  so the error is safe to log and safe to return to a caller.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import Enum
from collections.abc import Sequence
from typing import Final

CODEC_ID: Final[str] = "hpx-vi/1"

#: Circuit-versioned codec id for the ``silent_witness/v2`` envelope (#368).
CODEC_ID_V2: Final[str] = "hpx-vi/2"

FIELD_LEN: Final[int] = 32
SILENT_WITNESS_FIELD_COUNT: Final[int] = 5
REVOCATION_FIELD_COUNT: Final[int] = 4
SILENT_WITNESS_PUBLIC_INPUTS_LEN: Final[int] = FIELD_LEN * SILENT_WITNESS_FIELD_COUNT  # 160
REVOCATION_PUBLIC_INPUTS_LEN: Final[int] = FIELD_LEN * REVOCATION_FIELD_COUNT          # 128
PUBLIC_INPUTS_LEN: Final[int] = SILENT_WITNESS_PUBLIC_INPUTS_LEN  # default (largest schema)

#: ``silent_witness/v2`` is the scoped frame (7 fields) plus a trailing 8th
#: field that commits the circuit version (#368).
SILENT_WITNESS_V2_FIELD_COUNT: Final[int] = 8
SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN: Final[int] = FIELD_LEN * SILENT_WITNESS_V2_FIELD_COUNT  # 256

#: The only circuit version accepted by the ``silent_witness/v2`` codec. Must
#: match ``CURRENT_CIRCUIT_VERSION`` in zk/noir/silent_witness/src/main.nr.
EXPECTED_CIRCUIT_VERSION: Final[int] = 2

MIN_PROOF_BYTES: Final[int] = 64
MAX_PROOF_BYTES: Final[int] = 65_536

MIN_AGGREGATION_SIZE: Final[int] = 1
MAX_AGGREGATION_SIZE: Final[int] = 8

#: Hard ceiling on accepted hex input length. Anything longer is rejected on the
#: string itself, before any decoding, so a hostile caller cannot force a large
#: allocation just to be told the value is too big.
MAX_HEX_CHARS: Final[int] = 2 * (MAX_PROOF_BYTES + 1_024)

#: BN254 scalar field modulus. A 32-byte big-endian encoding is canonical only
#: when the value it denotes is strictly below this.
BN254_SCALAR_FIELD_MODULUS: Final[int] = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)

#: Byte-for-byte identical to ``REVOCATION_DOMAIN_SEPARATOR`` in the Soroban
#: registry: seven bytes of BN254 padding followed by 25 ASCII bytes.
REVOCATION_DOMAIN_SEPARATOR: Final[bytes] = (b"\x00" * 7) + b"HARPOCRATES_REVOCATION_V1"

# Domain constants that must be byte-identical to the Noir circuit globals.
DOMAIN_PROTOCOL_FIELD: Final[bytes] = bytes.fromhex(
    "261e9f6e39e3c1ae6aca9f29e84c10d59c82d5f4b40c21c1b7e3c01ad571c201"
)
DOMAIN_VERSION_FIELD: Final[bytes] = bytes.fromhex(
    "0c89eff4ec8e39a01e9f19547a0cc9dd7fd2a97d79ba4d94fd32e97a1f5ac623"
)
DOMAIN_NETWORK_FIELD: Final[bytes] = bytes.fromhex(
    "2a2c3f48ce2e3c2f1e6c89b18d64b5f5c1f88a59a0d9bc82cb61a1e8cb77a50f"
)

#: SHA-256(DOMAIN_PROTOCOL_FIELD || DOMAIN_VERSION_FIELD || DOMAIN_NETWORK_FIELD)
#: Mirrors the Soroban contract's expected_domain_tag() implementation.
SILENT_WITNESS_DOMAIN_TAG: Final[bytes] = hashlib.sha256(
    DOMAIN_PROTOCOL_FIELD + DOMAIN_VERSION_FIELD + DOMAIN_NETWORK_FIELD
).digest()

SCHEMA_SILENT_WITNESS: Final[str] = "silent_witness/v1"
SCHEMA_REVOCATION_WITNESS: Final[str] = "revocation_witness/v1"
SCHEMA_SILENT_WITNESS_V2: Final[str] = "silent_witness/v2"

#: Protocol Merkle-depth bound for ``revocation_witness/v1`` (#357).
#: Must match the Noir globals and the Soroban registry constants.
MAX_REVOCATION_WITNESS_DEPTH: Final[int] = 3
#: Leaf capacity implied by ``MAX_REVOCATION_WITNESS_DEPTH`` (``2**depth``).
MAX_REVOCATION_LEAVES: Final[int] = 8

_ZERO_FIELD: Final[bytes] = b"\x00" * FIELD_LEN

_HEX_DIGITS: Final[frozenset[str]] = frozenset("0123456789abcdefABCDEF")


class RejectCode(str, Enum):
    """Stable rejection codes shared across circuit, backend, browser, chain."""

    MALFORMED_HEX = "malformed_hex"
    LENGTH = "length"
    PADDING = "padding"
    NON_CANONICAL_FIELD = "non_canonical_field"
    ZERO_FIELD = "zero_field"
    DOMAIN_MISMATCH = "domain_mismatch"
    PROOF_UNDERSIZE = "proof_undersize"
    PROOF_OVERSIZE = "proof_oversize"
    UNKNOWN_SCHEMA = "unknown_schema"
    VERSION_MISMATCH = "version_mismatch"


class VerifierInputError(ValueError):
    """Raised for any rejected verifier input.

    Carries the machine-readable :class:`RejectCode` and, where meaningful, the
    *name* of the offending field. Never carries field contents.
    """

    def __init__(self, code: RejectCode, field: str | None = None) -> None:
        self.code = code
        self.field = field
        super().__init__(f"{code.value}" if field is None else f"{code.value}:{field}")

    def signal(self) -> dict[str, str]:
        """Privacy-safe structured payload for logs and metrics."""
        payload = {"codec": CODEC_ID, "reject_code": self.code.value}
        if self.field is not None:
            payload["field"] = self.field
        return payload


@dataclass(frozen=True)
class SilentWitnessInputs:
    """Parsed ``silent_witness/v1`` public inputs."""

    video_hash: bytes
    credential_root: bytes
    nullifier: bytes
    domain_tag: bytes
    #: Verifier scope of the ``silent_witness/v2`` scoped frame; ``None`` for v1.
    verifier_scope: bytes | None = None
    #: Raw 32-byte epoch field element of a v2 frame; ``None`` for v1.
    epoch: bytes | None = None
    #: Circuit version committed to the rightmost trailing field (``hpx-vi/2``).
    circuit_version: int | None = None


@dataclass(frozen=True)
class RevocationWitnessInputs:
    """Parsed ``revocation_witness/v1`` public inputs."""

    revocation_root: bytes
    nullifier: bytes
    domain_separator: bytes
    credential_root: bytes


# ── Primitives ──────────────────────────────────────────────────────────────


def constant_time_equals(left: bytes, right: bytes) -> bool:
    """Compare two byte strings without an early exit on the first difference.

    Protocol bindings (domain tags, separators, zero sentinels) are compared
    through this helper on every layer so that the time taken to reject a
    tampered value does not reveal how many leading bytes matched. Inputs of
    different lengths compare unequal; length is public.
    """
    return hmac.compare_digest(left, right)


def decode_hex(
    value: str,
    *,
    field: str = "value",
    oversize_code: RejectCode = RejectCode.PROOF_OVERSIZE,
) -> bytes:
    """Decode an even-length, bounded hex string.

    Rejects odd lengths, non-hex characters, and anything past
    :data:`MAX_HEX_CHARS` without decoding it.
    """
    if not isinstance(value, str):
        raise VerifierInputError(RejectCode.MALFORMED_HEX, field)
    if len(value) > MAX_HEX_CHARS:
        raise VerifierInputError(oversize_code, field)
    if len(value) % 2 != 0:
        raise VerifierInputError(RejectCode.MALFORMED_HEX, field)
    if any(character not in _HEX_DIGITS for character in value):
        raise VerifierInputError(RejectCode.MALFORMED_HEX, field)
    try:
        return bytes.fromhex(value)
    except ValueError as exc:  # pragma: no cover - guarded above
        raise VerifierInputError(RejectCode.MALFORMED_HEX, field) from exc


def _parse_field_value(value: int | str, field: str) -> int:
    """Parse a decimal or ``0x``-prefixed field without reducing it."""
    if isinstance(value, bool):
        raise VerifierInputError(RejectCode.MALFORMED_HEX, field)
    if isinstance(value, int):
        return value
    if not isinstance(value, str) or not value:
        raise VerifierInputError(RejectCode.MALFORMED_HEX, field)
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value, 10)
    except ValueError as exc:
        raise VerifierInputError(RejectCode.MALFORMED_HEX, field) from exc


def encode_field_to_bytes32_hex(value: int | str, field: str = "field") -> str:
    """Encode one canonical BN254 field as a lowercase 32-byte hex string.

    This is the backend counterpart to the browser's
    ``encodeFieldToBytes32Hex``. Values are validated, never reduced modulo the
    field, and rejection messages contain only the stable code and field name.
    """
    element = _parse_field_value(value, field)
    if element < 0 or element >= BN254_SCALAR_FIELD_MODULUS:
        raise VerifierInputError(RejectCode.NON_CANONICAL_FIELD, field)
    return f"{element:064x}"


def encode_public_inputs(
    values: Sequence[int | str], fields: Sequence[str] = ()
) -> str:
    """Encode an ordered public-input vector using the canonical field codec."""
    return "".join(
        encode_field_to_bytes32_hex(value, fields[index] if index < len(fields) else f"field_{index}")
        for index, value in enumerate(values)
    )


def is_canonical_field(element: bytes) -> bool:
    """Is this 32-byte big-endian encoding strictly below the BN254 modulus?"""
    return (
        len(element) == FIELD_LEN
        and int.from_bytes(element, "big") < BN254_SCALAR_FIELD_MODULUS
    )


def check_proof_bounds(proof: bytes) -> None:
    """Enforce the accepted proof-blob size window."""
    if len(proof) < MIN_PROOF_BYTES:
        raise VerifierInputError(RejectCode.PROOF_UNDERSIZE, "proof")
    if len(proof) > MAX_PROOF_BYTES:
        raise VerifierInputError(RejectCode.PROOF_OVERSIZE, "proof")


def _split_fields(public_inputs: bytes, expected_len: int, count: int) -> list[bytes]:
    if len(public_inputs) != expected_len:
        raise VerifierInputError(RejectCode.LENGTH, "public_inputs")
    return [
        public_inputs[index * FIELD_LEN : (index + 1) * FIELD_LEN]
        for index in range(count)
    ]


def _require_canonical(fields: list[bytes], names: tuple[str, ...]) -> None:
    for element, name in zip(fields, names):
        if not is_canonical_field(element):
            raise VerifierInputError(RejectCode.NON_CANONICAL_FIELD, name)


def _require_non_zero(field_value: bytes, name: str) -> None:
    if constant_time_equals(field_value, _ZERO_FIELD):
        raise VerifierInputError(RejectCode.ZERO_FIELD, name)


def _require_half_padding(field_value: bytes, name: str) -> bytes:
    """A 128-bit half is carried in the low 16 bytes; the high 16 must be zero."""
    if not constant_time_equals(field_value[:16], _ZERO_FIELD[:16]):
        raise VerifierInputError(RejectCode.PADDING, name)
    return field_value[16:]


def _version_of(field_value: bytes) -> int:
    """Read a 32-byte circuit-version field as a big-endian u32.

    The upper 28 bytes must be zero; otherwise a sentinel is returned so the
    caller's equality check fails, mirroring the Rust ``circuit_version_of``.
    """
    if field_value[:28] != b"\x00" * 28:
        return 0xFFFFFFFF
    return int.from_bytes(field_value[28:32], "big")


# ── Schema parsers ──────────────────────────────────────────────────────────

_SILENT_WITNESS_FIELDS: Final[tuple[str, ...]] = (
    "video_hash_hi",
    "video_hash_lo",
    "credential_root",
    "nullifier",
    "domain_tag",
)

_SILENT_WITNESS_V2_FIELDS: Final[tuple[str, ...]] = (
    "video_hash_hi",
    "video_hash_lo",
    "credential_root",
    "nullifier",
    "verifier_scope",
    "epoch",
    "domain_tag",
    "circuit_version",
)

_REVOCATION_FIELDS: Final[tuple[str, ...]] = (
    "revocation_root",
    "nullifier",
    "domain_separator",
    "credential_root",
)


def parse_silent_witness_inputs(public_inputs: bytes) -> SilentWitnessInputs:
    """Parse ``silent_witness/v1`` public inputs in canonical check order.

    Layout (5 × 32 bytes = 160 bytes):
      [0] video_hash_hi  — 128-bit half (low 16 bytes only)
      [1] video_hash_lo  — 128-bit half (low 16 bytes only)
      [2] credential_root
      [3] nullifier
      [4] domain_tag     — SHA-256(DOMAIN_PROTOCOL_FIELD || DOMAIN_VERSION_FIELD || DOMAIN_NETWORK_FIELD)
    """
    fields = _split_fields(
        public_inputs, SILENT_WITNESS_PUBLIC_INPUTS_LEN, SILENT_WITNESS_FIELD_COUNT
    )

    high = _require_half_padding(fields[0], "video_hash_hi")
    low = _require_half_padding(fields[1], "video_hash_lo")

    # The digest is an opaque protocol binding; compare it byte-for-byte below
    # instead of treating arbitrary SHA-256 output as a BN254 scalar.
    _require_canonical(fields[:4], _SILENT_WITNESS_FIELDS[:4])

    _require_non_zero(fields[2], "credential_root")
    _require_non_zero(fields[3], "nullifier")
    _require_non_zero(fields[4], "domain_tag")

    if not constant_time_equals(fields[4], SILENT_WITNESS_DOMAIN_TAG):
        raise VerifierInputError(RejectCode.DOMAIN_MISMATCH, "domain_tag")

    return SilentWitnessInputs(
        video_hash=high + low,
        credential_root=fields[2],
        nullifier=fields[3],
        domain_tag=fields[4],
    )


def parse_silent_witness_v2_inputs(public_inputs: bytes) -> SilentWitnessInputs:
    """Parse ``silent_witness/v2`` public inputs in canonical check order (#368).

    Layout (8 × 32 bytes = 256 bytes):
      [0] video_hash_hi     — 128-bit half (low 16 bytes only)
      [1] video_hash_lo     — 128-bit half (low 16 bytes only)
      [2] credential_root
      [3] nullifier
      [4] verifier_scope
      [5] epoch
      [6] domain_tag        — Pedersen hash of the DOMAIN_*_FIELD constants
      [7] circuit_version   — u32 in the low 4 bytes; upper 28 bytes must be zero

    The check order is the codec contract: length → half padding → circuit
    version → canonicity → zero → domain. The domain tag and circuit version
    are protocol bindings rather than user scalars, so they are compared
    byte-for-byte and never reduced modulo BN254.
    """
    fields = _split_fields(
        public_inputs, SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN, SILENT_WITNESS_V2_FIELD_COUNT
    )

    high = _require_half_padding(fields[0], "video_hash_hi")
    low = _require_half_padding(fields[1], "video_hash_lo")

    # Checked before the identity fields so a frame from another circuit reads
    # as a version problem, never as a malformed-identity problem.
    if _version_of(fields[7]) != EXPECTED_CIRCUIT_VERSION:
        raise VerifierInputError(RejectCode.VERSION_MISMATCH, "circuit_version")

    _require_canonical(fields[:6], _SILENT_WITNESS_V2_FIELDS[:6])

    _require_non_zero(fields[2], "credential_root")
    _require_non_zero(fields[3], "nullifier")
    _require_non_zero(fields[6], "domain_tag")

    if not constant_time_equals(fields[6], SILENT_WITNESS_DOMAIN_TAG):
        raise VerifierInputError(RejectCode.DOMAIN_MISMATCH, "domain_tag")

    return SilentWitnessInputs(
        video_hash=high + low,
        credential_root=fields[2],
        nullifier=fields[3],
        domain_tag=fields[6],
        verifier_scope=fields[4],
        epoch=fields[5],
        circuit_version=EXPECTED_CIRCUIT_VERSION,
    )


def parse_revocation_witness_inputs(public_inputs: bytes) -> RevocationWitnessInputs:
    """Parse ``revocation_witness/v1`` public inputs in canonical check order."""
    fields = _split_fields(
        public_inputs, REVOCATION_PUBLIC_INPUTS_LEN, REVOCATION_FIELD_COUNT
    )

    _require_canonical(fields, _REVOCATION_FIELDS)

    _require_non_zero(fields[0], "revocation_root")
    _require_non_zero(fields[1], "nullifier")
    _require_non_zero(fields[3], "credential_root")

    if not constant_time_equals(fields[2], REVOCATION_DOMAIN_SEPARATOR):
        raise VerifierInputError(RejectCode.DOMAIN_MISMATCH, "domain_separator")

    return RevocationWitnessInputs(
        revocation_root=fields[0],
        nullifier=fields[1],
        domain_separator=fields[2],
        credential_root=fields[3],
    )


def parse_public_inputs(
    schema: str, public_inputs: bytes
) -> SilentWitnessInputs | RevocationWitnessInputs:
    """Dispatch to the parser for ``schema``."""
    if schema == SCHEMA_SILENT_WITNESS:
        return parse_silent_witness_inputs(public_inputs)
    if schema == SCHEMA_SILENT_WITNESS_V2:
        return parse_silent_witness_v2_inputs(public_inputs)
    if schema == SCHEMA_REVOCATION_WITNESS:
        return parse_revocation_witness_inputs(public_inputs)
    raise VerifierInputError(RejectCode.UNKNOWN_SCHEMA, "schema")


# ── Conformance entry point ─────────────────────────────────────────────────


def classify(schema: str, public_inputs_hex: str, proof_hex: str) -> str | None:
    """Classify one conformance case.

    Returns ``None`` when the material is accepted, otherwise the stable
    reject-code string. The check order — public inputs first, then the proof
    blob — is part of the codec contract and is mirrored by every layer.
    """
    try:
        public_inputs = decode_hex(
            public_inputs_hex,
            field="public_inputs",
            oversize_code=RejectCode.LENGTH,
        )
        parse_public_inputs(schema, public_inputs)
        proof = decode_hex(proof_hex, field="proof")
        check_proof_bounds(proof)
    except VerifierInputError as error:
        return error.code.value
    return None


def check_revocation_witness_depth(depth: object) -> None:
    """Reject a Merkle depth outside the protocol bound.

    Privacy-safe: raises :class:`VerifierInputError` with a stable code and the
    field name ``depth`` only — never leaves, secrets, or witness material.
    """
    if isinstance(depth, bool) or not isinstance(depth, int):
        raise VerifierInputError(RejectCode.MALFORMED_HEX, "depth")
    if depth < 1:
        raise VerifierInputError(RejectCode.LENGTH, "depth")
    if depth > MAX_REVOCATION_WITNESS_DEPTH:
        raise VerifierInputError(RejectCode.PROOF_OVERSIZE, "depth")


def check_aggregation_batch_size(batch_size: object) -> int:
    """Reject an aggregation proof count outside the protocol bound (#497).

    Privacy-safe: raises :class:`VerifierInputError` with a stable code and the
    field name ``batch_size`` only — never video hashes, secrets, or witness material.
    """
    if isinstance(batch_size, bool) or not isinstance(batch_size, int):
        raise VerifierInputError(RejectCode.MALFORMED_HEX, "batch_size")
    if batch_size < MIN_AGGREGATION_SIZE:
        raise VerifierInputError(RejectCode.LENGTH, "batch_size")
    if batch_size > MAX_AGGREGATION_SIZE:
        raise VerifierInputError(RejectCode.PROOF_OVERSIZE, "batch_size")
    return batch_size

