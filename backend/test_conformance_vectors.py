"""Cross-layer verifier conformance runner (Python side, codecs ``hpx-vi/1``
and ``hpx-vi/2``).

Drives the shared corpora in ``zk/vectors/verifier_conformance_v1.json`` and
``zk/vectors/verifier_conformance_v2.json`` through ``backend.verifier_inputs``.
The Rust runner (``contracts/contracts/harpocrates-registry/src/test_conformance.rs``)
and the TypeScript runner (``frontend/src/verifierInputs.conformance.test.ts``)
drive the same files, so a divergence in any layer fails exactly one of the
three suites and names the offending case id.

See docs/zk-conformance-vectors.md.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

VECTORS_DIR = Path(__file__).resolve().parents[1] / "zk" / "vectors"
if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

import generate_malformed_public_inputs  # noqa: E402
import generate_vectors  # noqa: E402

from verifier_inputs import (
    BN254_SCALAR_FIELD_MODULUS,
    CODEC_ID,
    CODEC_ID_V2,
    EXPECTED_CIRCUIT_VERSION,
    MAX_PROOF_BYTES,
    MIN_PROOF_BYTES,
    PUBLIC_INPUTS_LEN,
    REVOCATION_DOMAIN_SEPARATOR,
    SCHEMA_SILENT_WITNESS_V2,
    SILENT_WITNESS_DOMAIN_TAG,
    SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN,
    RejectCode,
    VerifierInputError,
    classify,
    decode_hex,
    parse_public_inputs,
)

CORPUS_PATH = (
    Path(__file__).resolve().parents[1] / "zk" / "vectors" / "verifier_conformance_v1.json"
)
CORPUS_V2_PATH = (
    Path(__file__).resolve().parents[1] / "zk" / "vectors" / "verifier_conformance_v2.json"
)
MALFORMED_PATH = (
    Path(__file__).resolve().parents[1]
    / "zk"
    / "vectors"
    / "malformed_public_inputs_v1.json"
)

CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
CASES = CORPUS["cases"]
CORPUS_V2 = json.loads(CORPUS_V2_PATH.read_text(encoding="utf-8"))
CASES_V2 = CORPUS_V2["cases"]
MALFORMED_CORPUS = json.loads(MALFORMED_PATH.read_text(encoding="utf-8"))
MALFORMED_CASES = MALFORMED_CORPUS["cases"]


def case_id(case: dict) -> str:
    return case["id"]


# ── Corpus integrity ────────────────────────────────────────────────────────


def test_corpus_is_versioned_and_matches_this_codec():
    assert CORPUS["format"] == "harpocrates.verifier-conformance"
    assert CORPUS["version"] == 1
    assert CORPUS["codec"] == CODEC_ID


def test_corpus_constants_match_implementation_constants():
    constants = CORPUS["constants"]
    assert constants["public_inputs_len"] == PUBLIC_INPUTS_LEN
    assert constants["min_proof_bytes"] == MIN_PROOF_BYTES
    assert constants["max_proof_bytes"] == MAX_PROOF_BYTES
    assert int(constants["bn254_scalar_field_modulus_hex"], 16) == BN254_SCALAR_FIELD_MODULUS
    assert (
        bytes.fromhex(constants["revocation_domain_separator_hex"])
        == REVOCATION_DOMAIN_SEPARATOR
    )


def test_corpus_has_positive_and_negative_cases():
    assert len(CASES) >= 20
    assert any(case["expect"]["accept"] for case in CASES)
    assert any(not case["expect"]["accept"] for case in CASES)


def test_case_ids_are_unique():
    identifiers = [case["id"] for case in CASES]
    assert len(identifiers) == len(set(identifiers))


def test_every_reject_code_is_declared():
    declared = set(CORPUS["reject_codes"])
    assert declared <= {code.value for code in RejectCode}
    for case in CASES:
        code = case["expect"]["reject_code"]
        if code is not None:
            assert code in declared, f"{case['id']} uses an undeclared reject code"


def test_every_declared_reject_code_is_reachable_or_layer_specific():
    """Codes with no structural case must be justified.

    ``malformed_hex`` is exercised by the companion corpus
    ``malformed_public_inputs_v1.json`` (hex decoding is string-layer only).
    ``unknown_schema`` remains outside both corpora (schema dispatch is not a
    wire input).
    """
    exercised = {
        case["expect"]["reject_code"] for case in CASES if case["expect"]["reject_code"]
    }
    malformed_exercised = {
        case["expect"]["reject_code"] for case in MALFORMED_CASES
    }
    unexercised = set(CORPUS["reject_codes"]) - exercised - malformed_exercised
    assert unexercised <= set()


# ── The corpus itself ───────────────────────────────────────────────────────


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_conformance_case(case: dict):
    expected = case["expect"]["reject_code"] if not case["expect"]["accept"] else None
    actual = classify(case["schema"], case["public_inputs_hex"], case["proof_hex"])
    assert actual == expected, (
        f"{case['id']}: expected {expected!r}, got {actual!r} — "
        f"{case['description']}"
    )


@pytest.mark.parametrize("case", CASES, ids=case_id)
def test_conformance_case_is_deterministic(case: dict):
    """The same bytes must classify identically on repeat evaluation."""
    first = classify(case["schema"], case["public_inputs_hex"], case["proof_hex"])
    second = classify(case["schema"], case["public_inputs_hex"], case["proof_hex"])
    assert first == second


# ── v2 (circuit-versioned envelope, #368) ───────────────────────────────────


def test_v2_corpus_is_versioned_and_matches_this_codec():
    assert CORPUS_V2["format"] == "harpocrates.verifier-conformance"
    assert CORPUS_V2["version"] == 2
    assert CORPUS_V2["codec"] == CODEC_ID_V2
    assert "version_mismatch" in CORPUS_V2["reject_codes"]


def test_v2_corpus_constants_match_implementation_constants():
    constants = CORPUS_V2["constants"]
    assert constants["silent_witness_v2_public_inputs_len"] == SILENT_WITNESS_V2_PUBLIC_INPUTS_LEN
    assert constants["expected_circuit_version"] == EXPECTED_CIRCUIT_VERSION
    assert bytes.fromhex(constants["silent_witness_domain_tag_hex"]) == SILENT_WITNESS_DOMAIN_TAG


def test_v2_corpus_has_positive_and_negative_and_version_mismatch_cases():
    assert len(CASES_V2) >= 10
    assert any(case["expect"]["accept"] for case in CASES_V2)
    assert any(not case["expect"]["accept"] for case in CASES_V2)
    assert any(
        case["expect"]["reject_code"] == "version_mismatch" for case in CASES_V2
    )
    for case in CASES_V2:
        assert case["schema"] == SCHEMA_SILENT_WITNESS_V2


def test_v2_case_ids_are_unique():
    identifiers = [case["id"] for case in CASES_V2]
    assert len(identifiers) == len(set(identifiers))


def test_v2_reject_codes_are_reachable_or_layer_specific():
    """``malformed_hex`` is still the string-layer only code, covered by the
    companion malformed corpus; every other declared v2 code must have a case."""
    exercised = {
        case["expect"]["reject_code"] for case in CASES_V2 if case["expect"]["reject_code"]
    }
    unexercised = set(CORPUS_V2["reject_codes"]) - exercised - {"malformed_hex"}
    assert unexercised <= set()


@pytest.mark.parametrize("case", CASES_V2, ids=case_id)
def test_v2_conformance_case(case: dict):
    expected = case["expect"]["reject_code"] if not case["expect"]["accept"] else None
    actual = classify(case["schema"], case["public_inputs_hex"], case["proof_hex"])
    assert actual == expected, (
        f"{case['id']}: expected {expected!r}, got {actual!r} — "
        f"{case['description']}"
    )


@pytest.mark.parametrize("case", CASES_V2, ids=case_id)
def test_v2_conformance_case_is_deterministic(case: dict):
    first = classify(case["schema"], case["public_inputs_hex"], case["proof_hex"])
    second = classify(case["schema"], case["public_inputs_hex"], case["proof_hex"])
    assert first == second


# ── Boundary behaviour not expressible as a corpus case ─────────────────────


def test_unknown_schema_is_rejected():
    valid = next(case for case in CASES if case["expect"]["accept"])
    assert (
        classify("silent_witness/v9", valid["public_inputs_hex"], valid["proof_hex"])
        == "unknown_schema"
    )


def malformed_case_id(case: dict) -> str:
    return case["id"]


def test_malformed_corpus_is_versioned_and_matches_this_codec():
    assert MALFORMED_CORPUS["format"] == "harpocrates.malformed-public-inputs"
    assert MALFORMED_CORPUS["version"] == 1
    assert MALFORMED_CORPUS["codec"] == CODEC_ID
    assert MALFORMED_CORPUS["reject_codes"] == ["malformed_hex"]


def test_malformed_case_ids_are_unique():
    identifiers = [case["id"] for case in MALFORMED_CASES]
    assert len(identifiers) == len(set(identifiers))
    assert len(MALFORMED_CASES) >= 10


@pytest.mark.parametrize("case", MALFORMED_CASES, ids=malformed_case_id)
def test_malformed_public_input_hex_is_rejected(case: dict):
    """Shared malformed public-input hex vectors (issue #353)."""
    with pytest.raises(VerifierInputError) as excinfo:
        decode_hex(case["value"], field=case.get("field", "public_inputs"))
    assert excinfo.value.code.value == case["expect"]["reject_code"]
    assert excinfo.value.field == case.get("field", "public_inputs")
    # Privacy: rejection signal must never echo the malformed presentation.
    signal = excinfo.value.signal()
    rendered = json.dumps(signal)
    assert case["value"] not in rendered
    assert set(signal) <= {"codec", "reject_code", "field"}


@pytest.mark.parametrize("case", MALFORMED_CASES, ids=malformed_case_id)
def test_malformed_public_input_hex_is_deterministic(case: dict):
    first = second = None
    for _ in range(2):
        try:
            decode_hex(case["value"], field=case.get("field", "public_inputs"))
        except VerifierInputError as exc:
            outcome = (exc.code.value, exc.field)
        else:
            outcome = ("accepted", None)
        if first is None:
            first = outcome
        else:
            second = outcome
    assert first == second


def test_error_signal_never_carries_input_material():
    """Rejections are safe to log: the payload names a field, never bytes."""
    valid = next(case for case in CASES if case["expect"]["accept"])
    tampered = "ff" * 32 + valid["public_inputs_hex"][64:]

    with pytest.raises(VerifierInputError) as excinfo:
        parse_public_inputs(valid["schema"], decode_hex(tampered))

    signal = excinfo.value.signal()
    rendered = json.dumps(signal)
    assert signal["codec"] == CODEC_ID
    assert tampered not in rendered
    assert "ff" * 8 not in rendered
    assert set(signal) <= {"codec", "reject_code", "field"}


# ── Generator --check and write mode ────────────────────────────────────────


def test_generators_check_passes_on_committed_vectors():
    assert generate_vectors.main(["--check"]) == 0
    assert generate_malformed_public_inputs.main(["--check"]) == 0


def test_generate_vectors_check_fails_on_tampered_temp_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    temp_v1 = tmp_path / "verifier_conformance_v1.json"
    temp_v2 = tmp_path / "verifier_conformance_v2.json"
    tampered_v1_text = CORPUS_PATH.read_text(encoding="utf-8").replace(
        '"sw-pos-001-canonical"', '"sw-pos-001-tampered"', 1
    )
    temp_v1.write_text(tampered_v1_text, encoding="utf-8")
    temp_v2.write_text(CORPUS_V2_PATH.read_text(encoding="utf-8"), encoding="utf-8")

    monkeypatch.setattr(generate_vectors, "OUT_PATH", temp_v1)
    monkeypatch.setattr(generate_vectors, "OUT_PATH_V2", temp_v2)

    with pytest.raises(SystemExit) as excinfo:
        generate_vectors.main(["--check"])

    assert excinfo.value.code == 1
    assert temp_v1.read_text(encoding="utf-8") == tampered_v1_text
    captured = capsys.readouterr()
    output = captured.err + captured.out
    assert "out of date" in output
    assert "--- verifier_conformance_v1.json (committed)" in output
    assert "+++ verifier_conformance_v1.json (generated)" in output
    assert '-      "id": "sw-pos-001-tampered",' in output
    assert '+      "id": "sw-pos-001-canonical",' in output


def test_generate_vectors_check_fails_on_tampered_v2_temp_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    temp_v1 = tmp_path / "verifier_conformance_v1.json"
    temp_v2 = tmp_path / "verifier_conformance_v2.json"
    tampered_v2_text = CORPUS_V2_PATH.read_text(encoding="utf-8").replace(
        '"sw2-pos-001-canonical"', '"sw2-pos-001-tampered"', 1
    )
    temp_v1.write_text(CORPUS_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    temp_v2.write_text(tampered_v2_text, encoding="utf-8")

    monkeypatch.setattr(generate_vectors, "OUT_PATH", temp_v1)
    monkeypatch.setattr(generate_vectors, "OUT_PATH_V2", temp_v2)

    with pytest.raises(SystemExit) as excinfo:
        generate_vectors.main(["--check"])

    assert excinfo.value.code == 1
    assert temp_v2.read_text(encoding="utf-8") == tampered_v2_text
    captured = capsys.readouterr()
    output = captured.err + captured.out
    assert "out of date" in output
    assert "--- verifier_conformance_v2.json (committed)" in output
    assert "+++ verifier_conformance_v2.json (generated)" in output
    assert '-      "id": "sw2-pos-001-tampered",' in output
    assert '+      "id": "sw2-pos-001-canonical",' in output


def test_generate_malformed_public_inputs_check_fails_on_tampered_temp_copy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    temp_malformed = tmp_path / "malformed_public_inputs_v1.json"
    tampered_text = MALFORMED_PATH.read_text(encoding="utf-8").replace(
        '"mh-neg-001-single-nibble"', '"mh-neg-001-tampered"', 1
    )
    temp_malformed.write_text(tampered_text, encoding="utf-8")

    monkeypatch.setattr(generate_malformed_public_inputs, "OUT_PATH", temp_malformed)

    with pytest.raises(SystemExit) as excinfo:
        generate_malformed_public_inputs.main(["--check"])

    assert excinfo.value.code == 1
    assert temp_malformed.read_text(encoding="utf-8") == tampered_text
    captured = capsys.readouterr()
    output = captured.err + captured.out
    assert "out of date" in output
    assert "--- malformed_public_inputs_v1.json (committed)" in output
    assert "+++ malformed_public_inputs_v1.json (generated)" in output
    assert '-      "id": "mh-neg-001-tampered",' in output
    assert '+      "id": "mh-neg-001-single-nibble",' in output


def test_generators_write_mode_output_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    temp_v1 = tmp_path / "verifier_conformance_v1.json"
    temp_v2 = tmp_path / "verifier_conformance_v2.json"
    temp_malformed = tmp_path / "malformed_public_inputs_v1.json"

    monkeypatch.setattr(generate_vectors, "OUT_PATH", temp_v1)
    monkeypatch.setattr(generate_vectors, "OUT_PATH_V2", temp_v2)
    monkeypatch.setattr(generate_malformed_public_inputs, "OUT_PATH", temp_malformed)

    assert generate_vectors.main([]) == 0
    assert generate_malformed_public_inputs.main([]) == 0

    assert temp_v1.read_text(encoding="utf-8") == CORPUS_PATH.read_text(encoding="utf-8")
    assert temp_v2.read_text(encoding="utf-8") == CORPUS_V2_PATH.read_text(encoding="utf-8")
    assert temp_malformed.read_text(encoding="utf-8") == MALFORMED_PATH.read_text(
        encoding="utf-8"
    )
    assert generate_vectors.main(["--check"]) == 0
    assert generate_malformed_public_inputs.main(["--check"]) == 0

