"""Unit tests for the reproducible-artifact manifest tool.

Covers the normalization rules, the bounded WASM walker, the artifact state
machine, drift detection, and the privacy property that no artifact content
ever reaches a signal, a manifest, or a drift finding.

Run from the repository root:

    python -m pytest zk/tools -q
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import artifact_manifest as am  # noqa: E402


LOCK_PATH = Path(__file__).resolve().parents[1] / "toolchain.lock.json"


@pytest.fixture()
def lock() -> am.Lock:
    return am.load_lock(LOCK_PATH)


# ── Lock file ───────────────────────────────────────────────────────────────


def test_repo_lock_loads_and_declares_required_artifacts(lock: am.Lock):
    assert lock.toolchain["nargo"]["version"]
    assert lock.toolchain["barretenberg"]["version"]
    assert any(entry.get("required") for entry in lock.artifacts)
    assert lock.limits.max_artifact_bytes > 0


def test_lock_rejects_unknown_version(tmp_path: Path):
    raw = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    raw["version"] = 99
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(am.BuildError, match="unsupported toolchain lock version"):
        am.load_lock(path)


def test_lock_rejects_foreign_format(tmp_path: Path):
    path = tmp_path / "lock.json"
    path.write_text(json.dumps({"format": "something-else", "version": 1}), encoding="utf-8")

    with pytest.raises(am.BuildError, match="unexpected format identifier"):
        am.load_lock(path)


def test_missing_lock_is_a_typed_failure(tmp_path: Path):
    with pytest.raises(am.BuildError, match="toolchain lock not found"):
        am.load_lock(tmp_path / "absent.json")


# ── JSON normalization ──────────────────────────────────────────────────────


def test_json_normalization_is_key_order_independent(lock: am.Lock):
    first = b'{"a":1,"b":{"c":2,"d":3}}'
    second = b'{"b":{"d":3,"c":2},"a":1}'

    assert am.normalize_json(first, lock.volatile_json_keys) == am.normalize_json(
        second, lock.volatile_json_keys
    )


def test_json_normalization_is_whitespace_independent(lock: am.Lock):
    compact = b'{"a":[1,2,3]}'
    spaced = b'{\n  "a": [\n    1,\n    2,\n    3\n  ]\n}\n'

    assert am.normalize_json(compact, lock.volatile_json_keys) == am.normalize_json(
        spaced, lock.volatile_json_keys
    )


def test_json_normalization_drops_declared_volatile_keys(lock: am.Lock):
    with_debug = json.dumps(
        {
            "bytecode": "AAA",
            "debug_symbols": "host-specific",
            "file_map": {"1": "/home/runner/work/x.nr"},
            "nested": {"names": ["main"], "keep": 1},
        }
    ).encode("utf-8")
    without_debug = json.dumps({"bytecode": "AAA", "nested": {"keep": 1}}).encode("utf-8")

    assert am.normalize_json(with_debug, lock.volatile_json_keys) == am.normalize_json(
        without_debug, lock.volatile_json_keys
    )


def test_json_normalization_still_detects_a_semantic_change(lock: am.Lock):
    """Normalization must never mask a real circuit change."""
    original = b'{"bytecode":"AAA","debug_symbols":"x"}'
    changed = b'{"bytecode":"AAB","debug_symbols":"x"}'

    assert am.normalize_json(original, lock.volatile_json_keys) != am.normalize_json(
        changed, lock.volatile_json_keys
    )


def test_json_normalization_rejects_non_json(lock: am.Lock):
    with pytest.raises(am.BuildError, match="not valid UTF-8 JSON"):
        am.normalize_json(b"\xff\xfe not json", lock.volatile_json_keys)


# ── WASM normalization ──────────────────────────────────────────────────────


def _uleb128(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _custom_section(name: str, body: bytes = b"") -> bytes:
    encoded_name = name.encode("utf-8")
    payload = _uleb128(len(encoded_name)) + encoded_name + body
    return b"\x00" + _uleb128(len(payload)) + payload


def _typed_section(section_id: int, body: bytes) -> bytes:
    return bytes([section_id]) + _uleb128(len(body)) + body


WASM_HEADER = b"\x00asm\x01\x00\x00\x00"


def test_wasm_normalization_strips_declared_custom_sections(lock: am.Lock):
    keep = _typed_section(1, b"\x01\x02\x03")
    module = (
        WASM_HEADER
        + _custom_section("producers", b"clang-17")
        + keep
        + _custom_section("name", b"symbols")
    )

    assert am.normalize_wasm(module, lock.strip_custom_sections) == WASM_HEADER + keep


def test_wasm_normalization_preserves_unlisted_custom_sections(lock: am.Lock):
    kept_custom = _custom_section("harpocrates.provenance", b"v1")
    module = WASM_HEADER + kept_custom + _custom_section("producers", b"x")

    assert am.normalize_wasm(module, lock.strip_custom_sections) == WASM_HEADER + kept_custom


def test_wasm_normalization_preserves_section_order(lock: am.Lock):
    first = _typed_section(1, b"\xaa")
    second = _typed_section(3, b"\xbb")
    module = WASM_HEADER + first + _custom_section("producers") + second

    assert am.normalize_wasm(module, lock.strip_custom_sections) == WASM_HEADER + first + second


def test_wasm_normalization_is_idempotent(lock: am.Lock):
    module = WASM_HEADER + _custom_section("producers", b"x") + _typed_section(1, b"\x01")
    once = am.normalize_wasm(module, lock.strip_custom_sections)

    assert am.normalize_wasm(once, lock.strip_custom_sections) == once


@pytest.mark.parametrize(
    "module",
    [
        b"",
        b"\x00asm",
        b"notawasmmodule!!",
        b"\x00asm\x01\x00\x00",
    ],
)
def test_wasm_normalization_rejects_a_bad_header(module: bytes, lock: am.Lock):
    with pytest.raises(am.BuildError):
        am.normalize_wasm(module, lock.strip_custom_sections)


def test_wasm_normalization_rejects_a_truncated_section(lock: am.Lock):
    module = WASM_HEADER + b"\x01" + _uleb128(1000) + b"\x01\x02"

    with pytest.raises(am.BuildError, match="section length exceeds file size"):
        am.normalize_wasm(module, lock.strip_custom_sections)


def test_wasm_normalization_rejects_an_over_long_leb128(lock: am.Lock):
    module = WASM_HEADER + b"\x01" + b"\x80\x80\x80\x80\x80\x80"

    with pytest.raises(am.BuildError, match="over-long LEB128"):
        am.normalize_wasm(module, lock.strip_custom_sections)


def test_wasm_normalization_rejects_a_name_past_its_section(lock: am.Lock):
    payload = _uleb128(200) + b"short"
    module = WASM_HEADER + b"\x00" + _uleb128(len(payload)) + payload

    with pytest.raises(am.BuildError, match="custom section name exceeds section"):
        am.normalize_wasm(module, lock.strip_custom_sections)


# ── Artifact state machine ──────────────────────────────────────────────────


def _lock_for(tmp_path: Path, artifacts: list[dict], **overrides) -> am.Lock:
    raw = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    raw["artifacts"] = artifacts
    raw["limits"].update(overrides)
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return am.load_lock(path)


def test_optional_missing_artifact_is_skipped_not_fatal(tmp_path: Path):
    lock = _lock_for(tmp_path, [{"path": "absent.bin", "kind": "binary", "required": False}])
    result = am.digest_artifact(lock.artifacts[0], lock, tmp_path)

    assert result.state == am.ArtifactState.SKIPPED
    assert result.state not in am.FATAL_STATES


def test_required_missing_artifact_is_missing(tmp_path: Path):
    lock = _lock_for(tmp_path, [{"path": "absent.bin", "kind": "binary", "required": True}])
    result = am.digest_artifact(lock.artifacts[0], lock, tmp_path)

    assert result.state == am.ArtifactState.MISSING


def test_oversized_artifact_is_rejected_before_reading(tmp_path: Path):
    target = tmp_path / "big.bin"
    target.write_bytes(b"\x00" * 4096)
    lock = _lock_for(
        tmp_path,
        [{"path": "big.bin", "kind": "binary", "required": True}],
        max_artifact_bytes=16,
    )

    result = am.digest_artifact(lock.artifacts[0], lock, tmp_path)

    assert result.state == am.ArtifactState.OVERSIZE
    assert result.state in am.FATAL_STATES
    assert result.normalized_sha256 is None


def test_digested_artifact_records_both_digests(tmp_path: Path):
    target = tmp_path / "acir.json"
    target.write_text('{"b":2,"a":1,"debug_symbols":"host"}', encoding="utf-8")
    lock = _lock_for(tmp_path, [{"path": "acir.json", "kind": "json", "required": True}])

    result = am.digest_artifact(lock.artifacts[0], lock, tmp_path)

    assert result.state == am.ArtifactState.DIGESTED
    assert result.raw_sha256 != result.normalized_sha256
    assert len(result.normalized_sha256) == 64


def test_lock_rejects_more_artifacts_than_the_cap(tmp_path: Path):
    entries = [
        {"path": f"a{index}.bin", "kind": "binary", "required": False} for index in range(70)
    ]
    with pytest.raises(am.BuildError, match="above the cap"):
        _lock_for(tmp_path, entries)


def test_unknown_kind_is_a_typed_failure(tmp_path: Path, lock: am.Lock):
    with pytest.raises(am.BuildError, match="unknown artifact kind"):
        am.normalize(b"{}", "exotic", lock)


# ── Manifest and drift ──────────────────────────────────────────────────────


def _manifest(artifacts: list[dict], provenance: dict[str, str] | None = None) -> dict:
    return {
        "format": am.MANIFEST_FORMAT,
        "version": am.MANIFEST_VERSION,
        "toolchain": {"nargo": "1.0.0-beta.9", "barretenberg": "0.87.0"},
        "normalization_policy_sha256": "a" * 64,
        "provenance": provenance or {"zk/noir/silent_witness/src/main.nr": "b" * 64},
        "artifacts": artifacts,
        "skipped": [],
    }


def _artifact(path: str, normalized: str, raw: str | None = None) -> dict:
    return {
        "path": path,
        "kind": "json",
        "role": "acir",
        "raw_bytes": 10,
        "normalized_bytes": 8,
        "raw_sha256": raw or normalized,
        "normalized_sha256": normalized,
    }


def test_identical_manifests_report_no_drift():
    manifest = _manifest([_artifact("x.json", "c" * 64)])
    assert am.compare_manifests(manifest, manifest) == []


def test_changed_artifact_digest_is_reported():
    before = _manifest([_artifact("x.json", "c" * 64)])
    after = _manifest([_artifact("x.json", "d" * 64)])

    findings = am.compare_manifests(before, after)

    assert len(findings) == 1
    assert "x.json" in findings[0]
    assert "normalized digest" in findings[0]


def test_host_only_difference_is_reported_as_non_semantic():
    before = _manifest([_artifact("x.json", "c" * 64, raw="1" * 64)])
    after = _manifest([_artifact("x.json", "c" * 64, raw="2" * 64)])

    findings = am.compare_manifests(before, after)

    assert len(findings) == 1
    assert "not a semantic change" in findings[0]


def test_toolchain_drift_is_reported():
    before = _manifest([])
    after = _manifest([])
    after["toolchain"]["barretenberg"] = "0.88.0"

    findings = am.compare_manifests(before, after)

    assert any("toolchain.barretenberg" in finding for finding in findings)


def test_source_drift_is_reported():
    before = _manifest([], provenance={"zk/noir/silent_witness/src/main.nr": "b" * 64})
    after = _manifest([], provenance={"zk/noir/silent_witness/src/main.nr": "e" * 64})

    findings = am.compare_manifests(before, after)

    assert any("main.nr" in finding for finding in findings)


def test_added_and_removed_artifacts_are_both_reported():
    before = _manifest([_artifact("x.json", "c" * 64)])
    after = _manifest([_artifact("y.json", "c" * 64)])

    findings = am.compare_manifests(before, after)

    assert any("missing from the rebuilt tree" in finding for finding in findings)
    assert any("unexpected" in finding for finding in findings)


def test_normalization_policy_change_is_reported():
    before = _manifest([])
    after = _manifest([])
    after["normalization_policy_sha256"] = "f" * 64

    findings = am.compare_manifests(before, after)

    assert any("normalization policy changed" in finding for finding in findings)


def test_findings_are_deterministically_ordered():
    before = _manifest(
        [_artifact("b.json", "1" * 64), _artifact("a.json", "2" * 64)],
        provenance={"z.nr": "1" * 64, "a.nr": "2" * 64},
    )
    after = _manifest(
        [_artifact("b.json", "3" * 64), _artifact("a.json", "4" * 64)],
        provenance={"z.nr": "5" * 64, "a.nr": "6" * 64},
    )

    assert am.compare_manifests(before, after) == am.compare_manifests(before, after)


# ── Privacy ─────────────────────────────────────────────────────────────────


def test_drift_findings_never_contain_artifact_content():
    """A digest mismatch reports two digests, never the differing bytes."""
    secret = "WITNESS-MATERIAL-DO-NOT-LOG"
    before = _manifest([_artifact("x.json", "c" * 64)])
    after = _manifest([_artifact("x.json", "d" * 64)])

    rendered = " ".join(am.compare_manifests(before, after))

    assert secret not in rendered
    assert "c" * 64 not in rendered  # digests are truncated, not echoed in full


def test_manifest_never_embeds_artifact_bytes(tmp_path: Path):
    secret = b'{"bytecode":"SECRET-WITNESS-BYTES"}'
    target = tmp_path / "acir.json"
    target.write_bytes(secret)
    lock = _lock_for(tmp_path, [{"path": "acir.json", "kind": "json", "required": True}])

    result = am.digest_artifact(lock.artifacts[0], lock, tmp_path)
    rendered = json.dumps(result.to_entry())

    assert "SECRET-WITNESS-BYTES" not in rendered
    assert result.normalized_sha256 in rendered


def test_signals_are_single_line_json(capsys):
    am.signal("artifact.state", path="zk/noir/x.json", state="digested", bytes=10)
    captured = capsys.readouterr().err.strip()

    assert "\n" not in captured
    parsed = json.loads(captured)
    assert parsed["event"] == "artifact.state"
    assert set(parsed) == {"event", "path", "state", "bytes"}


# ── Serialization ───────────────────────────────────────────────────────────


def test_manifest_serialization_is_stable_and_newline_terminated():
    manifest = _manifest([_artifact("x.json", "c" * 64)])
    first = am.serialize_manifest(manifest)

    assert first.endswith("\n")
    assert first == am.serialize_manifest(json.loads(first))


def test_cli_rejects_an_unknown_command():
    with pytest.raises(SystemExit) as excinfo:
        am.main(["nonsense"])
    assert excinfo.value.code == am.EXIT_USAGE


def test_compare_command_exits_with_drift_code(tmp_path: Path):
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    first.write_text(am.serialize_manifest(_manifest([_artifact("x.json", "c" * 64)])))
    second.write_text(am.serialize_manifest(_manifest([_artifact("x.json", "d" * 64)])))

    assert am.main(["compare", str(first), str(second)]) == am.EXIT_DRIFT
    assert am.main(["compare", str(first), str(first)]) == am.EXIT_OK


def test_verify_reports_a_missing_manifest_as_fatal(tmp_path: Path):
    assert am.main(["verify", "--manifest", str(tmp_path / "absent.json")]) == am.EXIT_FATAL



# ── Browser published ACIR ──────────────────────────────────────────────────


def test_published_to_build_target_pairs_by_stem():
    assert (
        am.published_to_build_target("frontend/public/noir/silent_witness.json")
        == "zk/noir/silent_witness/target/silent_witness.json"
    )


@pytest.mark.parametrize(
    "published_path",
    [
        "frontend/public/noir/../secret.json",
        "frontend/public/noir/foo/bar.json",
        "zk/noir/silent_witness/target/silent_witness.json",
        "frontend/public/noir/bad-name.json",
        "frontend/public/noir/.json",
    ],
)
def test_published_to_build_target_rejects_path_injection(published_path: str):
    with pytest.raises(am.BuildError, match="refusing"):
        am.published_to_build_target(published_path)


def test_build_browser_manifest_digests_only_published_acir(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(am, "REPO_ROOT", tmp_path)
    (tmp_path / "frontend/public/noir").mkdir(parents=True)
    payload = b'{"bytecode":"AAA","debug_symbols":"host"}'
    (tmp_path / "frontend/public/noir/silent_witness.json").write_bytes(payload)
    (tmp_path / "frontend/public/noir/silent_witness_helper.json").write_bytes(payload)

    lock = _lock_for(
        tmp_path,
        [
            {
                "path": "frontend/public/noir/silent_witness.json",
                "kind": "json",
                "role": "published_acir",
                "required": False,
            },
            {
                "path": "frontend/public/noir/silent_witness_helper.json",
                "kind": "json",
                "role": "published_acir",
                "required": False,
            },
            {
                "path": "frontend/public/noir/silent_witness_aggregator.json",
                "kind": "json",
                "role": "published_acir",
                "required": False,
            },
            {
                "path": "zk/noir/silent_witness/target/silent_witness.json",
                "kind": "json",
                "role": "acir",
                "required": True,
            },
        ],
    )

    manifest, run = am.build_browser_manifest(lock, tmp_path)

    assert manifest["format"] == am.BROWSER_MANIFEST_FORMAT
    assert len(manifest["artifacts"]) == 2
    assert "frontend/public/noir/silent_witness_aggregator.json" in manifest["skipped"]
    assert all(entry.state != am.ArtifactState.DIGESTED or "SECRET" not in str(entry)
               for entry in run.entries)
    rendered = am.serialize_manifest(manifest)
    assert "host" not in rendered  # volatile key stripped before digest; content never embedded
    assert "AAA" not in rendered


def test_compare_published_to_targets_detects_mismatch(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(am, "REPO_ROOT", tmp_path)
    pub = tmp_path / "frontend/public/noir"
    tgt = tmp_path / "zk/noir/silent_witness/target"
    pub.mkdir(parents=True)
    tgt.mkdir(parents=True)
    pub.joinpath("silent_witness.json").write_bytes(b'{"bytecode":"PUB"}')
    tgt.joinpath("silent_witness.json").write_bytes(b'{"bytecode":"TGT"}')

    lock = _lock_for(
        tmp_path,
        [
            {
                "path": "frontend/public/noir/silent_witness.json",
                "kind": "json",
                "role": "published_acir",
                "required": False,
            }
        ],
    )

    findings = am.compare_published_to_targets(lock, tmp_path)

    assert len(findings) == 1
    assert "disagrees with build target" in findings[0]
    assert "PUB" not in findings[0]
    assert "TGT" not in findings[0]


def test_compare_published_to_targets_matches_when_equal(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(am, "REPO_ROOT", tmp_path)
    pub = tmp_path / "frontend/public/noir"
    tgt = tmp_path / "zk/noir/silent_witness/target"
    pub.mkdir(parents=True)
    tgt.mkdir(parents=True)
    body = b'{"bytecode":"SAME","debug_symbols":"a"}'
    pub.joinpath("silent_witness.json").write_bytes(body)
    tgt.joinpath("silent_witness.json").write_bytes(
        b'{"debug_symbols":"b","bytecode":"SAME"}'
    )

    lock = _lock_for(
        tmp_path,
        [
            {
                "path": "frontend/public/noir/silent_witness.json",
                "kind": "json",
                "role": "published_acir",
                "required": False,
            }
        ],
    )

    assert am.compare_published_to_targets(lock, tmp_path) == []


def test_compare_browser_manifests_reports_digest_drift():
    before = {
        "format": am.BROWSER_MANIFEST_FORMAT,
        "version": am.MANIFEST_VERSION,
        "toolchain": {"nargo": "1.0.0-beta.9", "barretenberg": "0.87.0"},
        "normalization_policy_sha256": "a" * 64,
        "artifacts": [_artifact("frontend/public/noir/x.json", "c" * 64)],
        "skipped": [],
    }
    after = {
        **before,
        "artifacts": [_artifact("frontend/public/noir/x.json", "d" * 64)],
    }

    findings = am.compare_browser_manifests(before, after)

    assert len(findings) == 1
    assert "normalized digest" in findings[0]
    assert "c" * 64 not in findings[0]


def test_compare_browser_manifests_reports_missing_and_unexpected():
    before = {
        "format": am.BROWSER_MANIFEST_FORMAT,
        "version": am.MANIFEST_VERSION,
        "toolchain": {"nargo": "1.0.0-beta.9"},
        "normalization_policy_sha256": "a" * 64,
        "artifacts": [_artifact("frontend/public/noir/a.json", "c" * 64)],
        "skipped": [],
    }
    after = {
        **before,
        "artifacts": [_artifact("frontend/public/noir/b.json", "c" * 64)],
    }

    findings = am.compare_browser_manifests(before, after)
    assert any("missing from frontend/public/noir" in f for f in findings)
    assert any("unexpected publish" in f for f in findings)


def test_write_and_verify_browser_round_trip(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(am, "REPO_ROOT", tmp_path)
    # Minimal lock file on disk for CLI --lock
    artifacts = [
        {
            "path": "frontend/public/noir/silent_witness.json",
            "kind": "json",
            "role": "published_acir",
            "required": False,
        }
    ]
    _lock_for(tmp_path, artifacts)
    lock_path = tmp_path / "lock.json"
    pub = tmp_path / "frontend/public/noir"
    pub.mkdir(parents=True)
    pub.joinpath("silent_witness.json").write_bytes(
        b'{"bytecode":"BROWSER","debug_symbols":"x"}'
    )
    manifest_path = tmp_path / "zk" / "browser.artifacts.manifest.json"

    assert (
        am.main(
            [
                "--lock",
                str(lock_path),
                "write-browser",
                "--output",
                str(manifest_path),
            ]
        )
        == am.EXIT_OK
    )
    assert manifest_path.is_file()
    loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert loaded["format"] == am.BROWSER_MANIFEST_FORMAT
    assert len(loaded["artifacts"]) == 1
    assert "BROWSER" not in manifest_path.read_text(encoding="utf-8")

    assert (
        am.main(
            [
                "--lock",
                str(lock_path),
                "verify-browser",
                "--manifest",
                str(manifest_path),
            ]
        )
        == am.EXIT_OK
    )

    # Tamper with published bytes — verify must fail with drift, not leak content.
    pub.joinpath("silent_witness.json").write_bytes(
        b'{"bytecode":"TAMPERED-SECRET-WITNESS"}'
    )
    assert (
        am.main(
            [
                "--lock",
                str(lock_path),
                "verify-browser",
                "--manifest",
                str(manifest_path),
            ]
        )
        == am.EXIT_DRIFT
    )


def test_verify_browser_missing_manifest_is_fatal(tmp_path: Path):
    assert (
        am.main(["verify-browser", "--manifest", str(tmp_path / "absent.json")])
        == am.EXIT_FATAL
    )


def test_oversized_browser_artifact_is_fatal_for_write(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(am, "REPO_ROOT", tmp_path)
    pub = tmp_path / "frontend/public/noir"
    pub.mkdir(parents=True)
    pub.joinpath("silent_witness.json").write_bytes(b"{" + b"x" * 100 + b"}")
    lock = _lock_for(
        tmp_path,
        [
            {
                "path": "frontend/public/noir/silent_witness.json",
                "kind": "json",
                "role": "published_acir",
                "required": False,
            }
        ],
        max_artifact_bytes=16,
    )
    lock_path = tmp_path / "lock.json"
    manifest_path = tmp_path / "browser.manifest.json"

    assert (
        am.main(
            [
                "--lock",
                str(lock_path),
                "write-browser",
                "--output",
                str(manifest_path),
            ]
        )
        == am.EXIT_FATAL
    )
    assert not manifest_path.exists()


# ── Published circuit provenance ─────────────────────────────────────────────


def test_build_provenance_records_sources_and_declared_artifacts(tmp_path: Path, monkeypatch):
    lock_raw = {
        "format": "harpocrates.zk-toolchain-lock",
        "version": 1,
        "toolchain": {
            "nargo": {"version": "1.0.0-beta.9"},
            "barretenberg": {"version": "0.87.0"},
            "proving_scheme": "ultra_honk",
            "oracle_hash": "keccak",
        },
        "environment": {"SOURCE_DATE_EPOCH": "0", "TZ": "UTC"},
        "normalization": {
            "json": {"volatile_keys": ["debug_symbols"]},
            "wasm": {"strip_custom_sections": ["name"]},
        },
        "limits": {
            "max_artifact_bytes": 1024 * 1024,
            "max_artifacts": 64,
            "max_provenance_files": 512,
            "max_circuits": 64,
        },
        "artifacts": [
            {
                "path": "zk/noir/demo/target/demo.json",
                "kind": "json",
                "role": "acir",
                "required": True,
            }
        ],
        "provenance_sources": {"globs": ["zk/noir/*/src/*.nr", "zk/noir/*/Nargo.toml"]},
    }
    lock_path = tmp_path / "toolchain.lock.json"
    lock_path.write_text(json.dumps(lock_raw), encoding="utf-8")
    (tmp_path / "zk/noir/demo/src").mkdir(parents=True)
    (tmp_path / "zk/noir/demo/src/main.nr").write_text("fn main() {}", encoding="utf-8")
    (tmp_path / "zk/noir/demo/Nargo.toml").write_text("[package]\nname=\"demo\"\n", encoding="utf-8")

    monkeypatch.setattr(am, "REPO_ROOT", tmp_path)
    lock = am.load_lock(lock_path)
    document = am.build_provenance(lock, tmp_path)

    assert document["format"] == am.PROVENANCE_FORMAT
    assert document["version"] == 1
    assert "zk/noir/demo/src/main.nr" in document["provenance"]
    assert "zk/noir/demo/Nargo.toml" in document["provenance"]
    assert document["declared_artifacts"] == [
        {
            "path": "zk/noir/demo/target/demo.json",
            "kind": "json",
            "role": "acir",
            "required": True,
        }
    ]
    # Privacy: digests only — never source bytes.
    serialized = am.serialize_manifest(document)
    assert "fn main()" not in serialized


def test_build_provenance_rejects_empty_source_set(tmp_path: Path, monkeypatch):
    lock_raw = {
        "format": "harpocrates.zk-toolchain-lock",
        "version": 1,
        "toolchain": {
            "nargo": {"version": "1.0.0-beta.9"},
            "barretenberg": {"version": "0.87.0"},
            "proving_scheme": "ultra_honk",
            "oracle_hash": "keccak",
        },
        "environment": {"SOURCE_DATE_EPOCH": "0"},
        "normalization": {
            "json": {"volatile_keys": []},
            "wasm": {"strip_custom_sections": []},
        },
        "limits": {
            "max_artifact_bytes": 1024,
            "max_artifacts": 64,
            "max_provenance_files": 512,
            "max_circuits": 64,
        },
        "artifacts": [
            {
                "path": "zk/noir/demo/target/demo.json",
                "kind": "json",
                "role": "acir",
                "required": False,
            }
        ],
        "provenance_sources": {"globs": ["zk/noir/*/src/*.nr"]},
    }
    lock_path = tmp_path / "lock.json"
    lock_path.write_text(json.dumps(lock_raw), encoding="utf-8")
    monkeypatch.setattr(am, "REPO_ROOT", tmp_path)
    lock = am.load_lock(lock_path)
    with pytest.raises(am.BuildError, match="matched no circuit sources"):
        am.build_provenance(lock, tmp_path)


def test_compare_provenance_reports_source_and_declared_drift():
    base = {
        "format": am.PROVENANCE_FORMAT,
        "version": 1,
        "toolchain": {"nargo": "1.0.0-beta.9", "barretenberg": "0.87.0"},
        "normalization_policy_sha256": "aa" * 32,
        "provenance_globs": ["zk/noir/*/src/*.nr"],
        "provenance": {"zk/noir/demo/src/main.nr": "11" * 32},
        "declared_artifacts": [
            {"path": "a.json", "kind": "json", "role": "acir", "required": True}
        ],
    }
    drifted = dict(base)
    drifted["provenance"] = {"zk/noir/demo/src/main.nr": "22" * 32}
    findings = am.compare_provenance(base, drifted)
    assert any(f.startswith("source zk/noir/demo/src/main.nr:") for f in findings)

    role_drift = dict(base)
    role_drift["declared_artifacts"] = [
        {"path": "a.json", "kind": "json", "role": "published_acir", "required": True}
    ]
    findings = am.compare_provenance(base, role_drift)
    assert any("declared artifact a.json.role:" in f for f in findings)


def test_write_and_verify_provenance_round_trip(tmp_path: Path, monkeypatch, capsys):
    lock_raw = {
        "format": "harpocrates.zk-toolchain-lock",
        "version": 1,
        "toolchain": {
            "nargo": {"version": "1.0.0-beta.9"},
            "barretenberg": {"version": "0.87.0"},
            "proving_scheme": "ultra_honk",
            "oracle_hash": "keccak",
        },
        "environment": {"SOURCE_DATE_EPOCH": "0", "TZ": "UTC"},
        "normalization": {
            "json": {"volatile_keys": ["debug_symbols"]},
            "wasm": {"strip_custom_sections": ["name"]},
        },
        "limits": {
            "max_artifact_bytes": 1024 * 1024,
            "max_artifacts": 64,
            "max_provenance_files": 512,
            "max_circuits": 64,
        },
        "artifacts": [
            {
                "path": "zk/noir/demo/target/demo.json",
                "kind": "json",
                "role": "acir",
                "required": True,
            }
        ],
        "provenance_sources": {"globs": ["zk/noir/*/src/*.nr", "zk/noir/*/Nargo.toml"]},
    }
    lock_path = tmp_path / "toolchain.lock.json"
    lock_path.write_text(json.dumps(lock_raw), encoding="utf-8")
    (tmp_path / "zk/noir/demo/src").mkdir(parents=True)
    (tmp_path / "zk/noir/demo/src/main.nr").write_text("fn main() {}", encoding="utf-8")
    (tmp_path / "zk/noir/demo/Nargo.toml").write_text("[package]\nname=\"demo\"\n", encoding="utf-8")

    monkeypatch.setattr(am, "REPO_ROOT", tmp_path)
    out = tmp_path / "zk" / "circuit.provenance.json"
    assert (
        am.main(
            [
                "--lock",
                str(lock_path),
                "write-provenance",
                "--output",
                str(out),
            ]
        )
        == am.EXIT_OK
    )
    assert out.is_file()
    assert (
        am.main(
            [
                "--lock",
                str(lock_path),
                "verify-provenance",
                "--manifest",
                str(out),
            ]
        )
        == am.EXIT_OK
    )

    # Negative: mutate a source and expect drift without logging source bytes.
    (tmp_path / "zk/noir/demo/src/main.nr").write_text("fn main() { assert(1 == 1); }", encoding="utf-8")
    assert (
        am.main(
            [
                "--lock",
                str(lock_path),
                "verify-provenance",
                "--manifest",
                str(out),
            ]
        )
        == am.EXIT_DRIFT
    )
    err = capsys.readouterr().err
    assert "assert(1 == 1)" not in err
    assert "fn main()" not in err


def test_verify_provenance_missing_document_is_fatal(tmp_path: Path):
    missing = tmp_path / "missing.provenance.json"
    code = am.main(["verify-provenance", "--manifest", str(missing)])
    assert code == am.EXIT_FATAL


def test_provenance_findings_never_contain_source_bytes():
    secret = "WITNESS_SECRET_VALUE_SHOULD_NEVER_APPEAR"
    expected = {
        "format": am.PROVENANCE_FORMAT,
        "version": 1,
        "toolchain": {"nargo": "1.0.0-beta.9"},
        "normalization_policy_sha256": "aa" * 32,
        "provenance_globs": ["zk/noir/*/src/*.nr"],
        "provenance": {"zk/noir/demo/src/main.nr": "11" * 32},
        "declared_artifacts": [],
    }
    actual = dict(expected)
    actual["provenance"] = {"zk/noir/demo/src/main.nr": "22" * 32}
    findings = am.compare_provenance(expected, actual)
    blob = "\n".join(findings)
    assert secret not in blob
    assert "11" * 32 not in blob  # full digests truncated via _short
# ── Circuit coverage ────────────────────────────────────────────────────────


def _package(root: Path, name: str) -> Path:
    """Create a minimal Noir package directory (Nargo.toml is what marks it)."""
    circuit_dir = root / "zk" / "noir" / name
    circuit_dir.mkdir(parents=True, exist_ok=True)
    circuit_dir.joinpath("Nargo.toml").write_text(
        f'[package]\nname = "{name}"\ntype = "bin"\n', encoding="utf-8"
    )
    return circuit_dir


def _acir_entry(name: str) -> dict:
    return {
        "path": f"zk/noir/{name}/target/{name}.json",
        "kind": "json",
        "role": "acir",
        "required": True,
    }


def test_repo_lock_pins_every_noir_package_on_disk(lock: am.Lock):
    """Regression: a circuit in the tree that the lock does not pin would be an
    unpinned second truth at a public boundary. `selective_disclosure` is
    fetched by the browser and verified on chain, so it must be covered."""
    on_disk = am.discover_circuit_packages(lock, am.REPO_ROOT)
    declared = am.declared_circuit_names(lock)

    assert on_disk, "no Noir packages discovered"
    assert set(on_disk) == declared
    assert "selective_disclosure" in declared
    assert am.check_coverage(lock, am.REPO_ROOT) == []


def test_build_script_compiles_every_declared_circuit():
    """The build driver iterates its own name list, so a circuit pinned in the
    lock but absent from the script would never be built or digested."""
    script = (am.REPO_ROOT / "zk" / "noir" / "scripts" / "reproducible-build.sh").read_text(
        encoding="utf-8"
    )
    block = script.split("CIRCUITS=(", 1)[1].split(")", 1)[0]
    built = {line.strip().strip('"') for line in block.splitlines() if line.strip()}

    lock = am.load_lock(am.DEFAULT_LOCK)
    assert built == am.declared_circuit_names(lock)
    assert "selective_disclosure" in built


def test_undeclared_package_is_reported_as_unpinned(tmp_path: Path):
    _package(tmp_path, "pinned_circuit")
    _package(tmp_path, "brand_new_circuit")
    lock = _lock_for(tmp_path, [_acir_entry("pinned_circuit")])

    findings = am.check_coverage(lock, tmp_path)

    assert len(findings) == 1
    assert "brand_new_circuit" in findings[0]
    assert "nothing" in findings[0]


def test_declared_pin_without_a_package_is_reported(tmp_path: Path):
    _package(tmp_path, "pinned_circuit")
    lock = _lock_for(
        tmp_path, [_acir_entry("pinned_circuit"), _acir_entry("renamed_circuit")]
    )

    findings = am.check_coverage(lock, tmp_path)

    assert len(findings) == 1
    assert "renamed_circuit" in findings[0]
    assert "never be rebuilt" in findings[0]


def test_findings_are_deterministically_ordered(tmp_path: Path):
    for name in ("zulu", "alpha", "mike"):
        _package(tmp_path, name)

    lock = _lock_for(tmp_path, [])

    findings = am.check_coverage(lock, tmp_path)

    assert [finding.split()[1].rstrip(":") for finding in findings] == [
        "alpha",
        "mike",
        "zulu",
    ]


def test_directories_without_a_package_file_are_not_circuits(tmp_path: Path):
    _package(tmp_path, "real_circuit")
    # `zk/noir/scripts` and `zk/noir/tools` hold tooling, not circuits.
    (tmp_path / "zk" / "noir" / "scripts").mkdir(parents=True)
    (tmp_path / "zk" / "noir" / "tools" / "jq").parent.mkdir(parents=True)
    lock = _lock_for(tmp_path, [_acir_entry("real_circuit")])

    assert am.discover_circuit_packages(lock, tmp_path) == ["real_circuit"]
    assert am.check_coverage(lock, tmp_path) == []


def test_library_packages_are_not_treated_as_unpinned_circuits(tmp_path: Path):
    _package(tmp_path, "real_circuit")
    lib_dir = tmp_path / "zk" / "noir" / "harpocrates_common"
    lib_dir.mkdir(parents=True, exist_ok=True)
    lib_dir.joinpath("Nargo.toml").write_text(
        '[package]\nname = "harpocrates_common"\ntype = "lib"\n', encoding="utf-8"
    )
    lock = _lock_for(tmp_path, [_acir_entry("real_circuit")])

    assert am.discover_circuit_packages(lock, tmp_path) == ["real_circuit"]
    assert am.check_coverage(lock, tmp_path) == []


def test_an_empty_circuit_root_is_not_a_coverage_failure(tmp_path: Path):
    """A repo with no Noir packages is not misreported as a gap."""
    lock = _lock_for(tmp_path, [])

    assert am.discover_circuit_packages(lock, tmp_path) == []
    assert am.check_coverage(lock, tmp_path) == []


def test_only_the_canonical_acir_path_counts_as_a_pin(tmp_path: Path):
    """A verification key or a differently-shaped path is not evidence that a
    circuit is built and digested."""
    _package(tmp_path, "real_circuit")
    lock = _lock_for(
        tmp_path,
        [
            {
                "path": "zk/noir/real_circuit/target/vk",
                "kind": "binary",
                "role": "verification_key",
            },
            {"path": "zk/noir/real_circuit/target/other.json", "kind": "json", "role": "acir"},
        ],
    )

    assert am.declared_circuit_names(lock) == set()
    assert len(am.check_coverage(lock, tmp_path)) == 1


def test_browser_publish_is_not_a_substitute_for_a_build_pin(tmp_path: Path):
    """`published_acir` is a copy of a build target. Treating it as coverage
    would let a circuit ship to the browser with nothing building it."""
    _package(tmp_path, "real_circuit")
    lock = _lock_for(
        tmp_path,
        [
            {
                "path": "frontend/public/noir/real_circuit.json",
                "kind": "json",
                "role": "published_acir",
                "required": False,
            }
        ],
    )

    assert am.declared_circuit_names(lock) == set()
    assert len(am.check_coverage(lock, tmp_path)) == 1


def test_coverage_walk_is_bounded(tmp_path: Path):
    for index in range(5):
        _package(tmp_path, f"circuit_{index}")
    lock = _lock_for(tmp_path, [], max_circuits=3)

    with pytest.raises(am.BuildError, match="circuit count exceeds"):
        am.discover_circuit_packages(lock, tmp_path)


def test_lock_rejects_an_unusable_coverage_path(tmp_path: Path):
    raw = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    raw["coverage"]["circuit_root"] = "../elsewhere"
    path = tmp_path / "lock.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(am.BuildError, match="unusable coverage circuit_root"):
        am.load_lock(path)


def test_check_coverage_command_passes_on_the_repo_lock(capsys):
    assert am.main(["check-coverage"]) == am.EXIT_OK

    signal_event = json.loads(capsys.readouterr().err.strip())
    assert signal_event["event"] == "coverage.ok"
    assert signal_event["circuits"] >= 7


def test_check_coverage_command_reports_drift(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr(am, "REPO_ROOT", tmp_path)
    _package(tmp_path, "unpinned_circuit")
    # A lock that pins no circuit, so the single finding is the package on disk
    # that the lock does not declare.
    _lock_for(tmp_path, [])
    lock_path = tmp_path / "lock.json"

    assert am.main(["--lock", str(lock_path), "check-coverage"]) == am.EXIT_DRIFT

    events = [json.loads(line) for line in capsys.readouterr().err.strip().splitlines()]
    assert events[0]["event"] == "drift.finding"
    assert events[-1] == {"event": "coverage.failed", "findings": 1}


def test_coverage_findings_never_contain_artifact_content(tmp_path: Path, monkeypatch, capsys):
    """The gate must not read artifacts, so it cannot leak bytecode, witnesses,
    or keys through a finding or a signal."""
    monkeypatch.setattr(am, "REPO_ROOT", tmp_path)
    circuit_dir = _package(tmp_path, "unpinned_circuit")
    secret = "0xdeadbeefcredentialsecret"
    circuit_dir.joinpath("Prover.toml").write_text(
        f'credential_secret = "{secret}"\n', encoding="utf-8"
    )
    target = circuit_dir / "target"
    target.mkdir()
    target.joinpath("unpinned_circuit.json").write_bytes(b'{"bytecode":"AAA"}')
    # Same drift setup as above: a lock that pins no circuit, so the gate has
    # to report the unpinned package rather than fail on a missing lock file.
    _lock_for(tmp_path, [])

    assert am.main(["--lock", str(tmp_path / "lock.json"), "check-coverage"]) == am.EXIT_DRIFT

    captured = capsys.readouterr().err
    assert secret not in captured
    assert "AAA" not in captured
    assert "bytecode" not in captured
    assert "unpinned_circuit" in captured
