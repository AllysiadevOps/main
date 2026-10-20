"""Determinism and reproducibility guards for generate_malformed_public_inputs.py.

Ensures that generate_malformed_public_inputs.py produces byte-identical output
on every run, that the output matches the committed malformed_public_inputs_v1.json,
and that any drift in output content or ordering fails with a hint to regenerate.

Runs without nargo.
"""

from __future__ import annotations

import copy
import difflib
import json
import subprocess
import sys
from pathlib import Path

import pytest

VECTORS_DIR = Path(__file__).resolve().parent
GENERATOR_SCRIPT = VECTORS_DIR / "generate_malformed_public_inputs.py"
COMMITTED_FILE = VECTORS_DIR / "malformed_public_inputs_v1.json"

if str(VECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(VECTORS_DIR))

import generate_malformed_public_inputs


def _run_generator_to_path(out_path: Path) -> subprocess.CompletedProcess[str]:
    """Run generate_malformed_public_inputs.py via subprocess to a specified destination."""
    return subprocess.run(
        [sys.executable, str(GENERATOR_SCRIPT), "--out", str(out_path)],
        capture_output=True,
        text=True,
        check=True,
    )


def test_generator_runs_twice_identical_bytes(tmp_path: Path) -> None:
    """Run the generator twice into temp paths and ensure byte-identical outputs."""
    out_1 = tmp_path / "run_1.json"
    out_2 = tmp_path / "run_2.json"

    proc1 = _run_generator_to_path(out_1)
    proc2 = _run_generator_to_path(out_2)

    assert proc1.returncode == 0
    assert proc2.returncode == 0
    assert out_1.is_file()
    assert out_2.is_file()

    bytes_1 = out_1.read_bytes()
    bytes_2 = out_2.read_bytes()

    assert len(bytes_1) > 0, "generator produced empty output"
    assert bytes_1 == bytes_2, "generator output differs between subsequent runs"


def test_generator_output_matches_committed_file(tmp_path: Path) -> None:
    """Compare generator output against the committed file and fail with a hint to regenerate."""
    out_path = tmp_path / "generated.json"
    _run_generator_to_path(out_path)

    assert COMMITTED_FILE.is_file(), f"missing committed file: {COMMITTED_FILE}"

    generated_bytes = out_path.read_bytes()
    committed_bytes = COMMITTED_FILE.read_bytes()

    hint = (
        f"{COMMITTED_FILE.name} is out of date or differs from generator output; "
        f"regenerate with `python zk/vectors/generate_malformed_public_inputs.py`"
    )

    if generated_bytes != committed_bytes:
        diff = "".join(
            difflib.unified_diff(
                committed_bytes.decode("utf-8").splitlines(keepends=True),
                generated_bytes.decode("utf-8").splitlines(keepends=True),
                fromfile=f"{COMMITTED_FILE.name} (committed)",
                tofile=f"{COMMITTED_FILE.name} (generated)",
            )
        )
        pytest.fail(f"{hint}:\n{diff}")


def test_generator_check_mode_passes() -> None:
    """Ensure the generator's built-in --check flag passes against the committed file."""
    res = subprocess.run(
        [sys.executable, str(GENERATOR_SCRIPT), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, f"--check failed: {res.stderr}\n{res.stdout}"
    assert "verified" in res.stdout


def test_generator_check_fails_with_hint_on_tampered_content(tmp_path: Path) -> None:
    """Ensure --check fails with a diff and regenerate hint when file content changes."""
    tampered_path = tmp_path / "malformed_public_inputs_v1.json"
    committed_text = COMMITTED_FILE.read_text(encoding="utf-8")
    tampered_text = committed_text.replace('"mh-neg-001-single-nibble"', '"mh-neg-001-tampered"', 1)
    assert tampered_text != committed_text, "tampering failed to modify text"
    tampered_path.write_text(tampered_text, encoding="utf-8")

    res = subprocess.run(
        [sys.executable, str(GENERATOR_SCRIPT), "--check", "--out", str(tampered_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 1
    output = res.stderr + res.stdout
    assert "is out of date; regenerate with `python zk/vectors/generate_malformed_public_inputs.py`:" in output
    assert "--- malformed_public_inputs_v1.json (committed)" in output
    assert "+++ malformed_public_inputs_v1.json (generated)" in output


def test_generator_check_fails_with_hint_on_reordered_cases(tmp_path: Path) -> None:
    """Ensure --check fails with a diff and regenerate hint when case order changes."""
    reordered_path = tmp_path / "malformed_public_inputs_v1.json"
    doc = json.loads(COMMITTED_FILE.read_text(encoding="utf-8"))
    doc["cases"].reverse()
    reordered_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    res = subprocess.run(
        [sys.executable, str(GENERATOR_SCRIPT), "--check", "--out", str(reordered_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 1
    output = res.stderr + res.stdout
    assert "is out of date; regenerate with `python zk/vectors/generate_malformed_public_inputs.py`:" in output


def test_determinism_comparison_fails_if_order_or_content_changes(tmp_path: Path) -> None:
    """Acceptance criterion: verify comparison fails if output order or content changes between runs."""
    out_1 = tmp_path / "run_1.json"
    _run_generator_to_path(out_1)
    original_bytes = out_1.read_bytes()
    doc = json.loads(original_bytes.decode("utf-8"))

    # Case 1: Reordered cases
    reordered_doc = copy.deepcopy(doc)
    reordered_doc["cases"].reverse()
    reordered_bytes = json.dumps(reordered_doc, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    assert original_bytes != reordered_bytes, "reordering cases must change byte output"

    # Case 2: Modified case content
    modified_content_doc = copy.deepcopy(doc)
    modified_content_doc["cases"][0]["description"] = "Altered description text"
    modified_bytes = json.dumps(modified_content_doc, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    assert original_bytes != modified_bytes, "altering content must change byte output"

    # Case 3: Altered top-level key order
    reordered_keys_doc = {k: doc[k] for k in reversed(list(doc.keys()))}
    reordered_keys_bytes = json.dumps(reordered_keys_doc, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
    assert original_bytes != reordered_keys_bytes, "altering top-level key order must change byte output"


def test_in_process_main_write_and_check(tmp_path: Path) -> None:
    """Verify that in-process execution via main() also works into temp paths and matches committed."""
    out_1 = tmp_path / "in_process_1.json"
    out_2 = tmp_path / "in_process_2.json"

    assert generate_malformed_public_inputs.main(["--out", str(out_1)]) == 0
    assert generate_malformed_public_inputs.main(["--out", str(out_2)]) == 0

    assert out_1.read_bytes() == out_2.read_bytes()
    assert out_1.read_bytes() == COMMITTED_FILE.read_bytes()
    assert generate_malformed_public_inputs.main(["--check", "--out", str(out_1)]) == 0
