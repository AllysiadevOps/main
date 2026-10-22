#!/usr/bin/env python3
"""Generate and drift-check the typed TypeScript client for the registry contract.

The bindings under `frontend/src/generated/registry-bindings` are produced by
`stellar contract bindings typescript` from the compiled registry Wasm, so
function names, argument order and return shapes come from the contract spec
instead of being hand-encoded in the clients.

Modes:
    python3 devx/contract_bindings.py --generate   # regenerate in place
    python3 devx/contract_bindings.py --check      # CI: fail if committed bindings drift

`--check` regenerates into a temporary directory and compares it, file by
file, with the committed package. It never modifies the committed tree.
Line endings are normalised before comparing so Windows checkouts do not
produce false drift.

Privacy: diagnostics carry relative file paths and counts only.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WASM = ROOT / "contracts" / "target" / "wasm32v1-none" / "release" / "harpocrates_registry.wasm"
DEFAULT_OUTPUT = ROOT / "frontend" / "src" / "generated" / "registry-bindings"

# Build/install by-products that are not part of the committed package.
IGNORED_PARTS = {"node_modules", "dist", "package-lock.json"}

Generator = Callable[[Path, Path], None]


class BindingsError(RuntimeError):
    """Raised for any fail-closed condition (missing wasm/CLI, generation failure)."""


def stellar_generator(wasm: Path, out_dir: Path) -> None:
    """Run the Stellar CLI to generate bindings for `wasm` into `out_dir`."""
    if not wasm.is_file():
        raise BindingsError(f"registry Wasm not found: {wasm} -- run `stellar contract build` first")
    cli = shutil.which("stellar")
    if cli is None:
        raise BindingsError("`stellar` CLI not found on PATH")
    result = subprocess.run(
        [cli, "contract", "bindings", "typescript", "--wasm", str(wasm),
         "--output-dir", str(out_dir), "--overwrite"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise BindingsError(f"stellar bindings generation failed: {result.stderr.strip()}")


def _snapshot(root: Path) -> dict[str, bytes]:
    """Map relative posix path -> newline-normalised bytes for every tracked file."""
    files: dict[str, bytes] = {}
    if not root.is_dir():
        return files
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if IGNORED_PARTS & set(rel.parts):
            continue
        files[rel.as_posix()] = path.read_bytes().replace(b"\r\n", b"\n")
    return files


def diff_trees(committed: Path, fresh: Path) -> list[str]:
    """Return human-readable drift lines; empty means identical."""
    have, want = _snapshot(committed), _snapshot(fresh)
    drift = [f"missing from committed bindings: {name}" for name in sorted(want.keys() - have.keys())]
    drift += [f"stale file not in fresh generation: {name}" for name in sorted(have.keys() - want.keys())]
    drift += [f"content differs: {name}" for name in sorted(have.keys() & want.keys()) if have[name] != want[name]]
    return drift


def generate(output: Path, wasm: Path, generator: Generator = stellar_generator) -> None:
    """Regenerate the committed package in place (clean directory first)."""
    with tempfile.TemporaryDirectory() as tmp:
        fresh = Path(tmp) / "bindings"
        generator(wasm, fresh)
        if output.exists():
            shutil.rmtree(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(fresh, output, ignore=shutil.ignore_patterns(*IGNORED_PARTS))


def check(output: Path, wasm: Path, generator: Generator = stellar_generator) -> list[str]:
    """Regenerate into a temp dir and return drift against `output`."""
    with tempfile.TemporaryDirectory() as tmp:
        fresh = Path(tmp) / "bindings"
        generator(wasm, fresh)
        return diff_trees(output, fresh)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--generate", action="store_true", help="regenerate bindings in place")
    mode.add_argument("--check", action="store_true", help="fail if committed bindings differ from a fresh generation")
    parser.add_argument("--wasm", type=Path, default=DEFAULT_WASM, help="compiled registry Wasm")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="bindings package directory")
    args = parser.parse_args(argv)

    try:
        if args.generate:
            generate(args.output, args.wasm)
            print(f"OK generated bindings in {args.output}")
            return 0
        drift = check(args.output, args.wasm)
    except BindingsError as exc:
        print(f"FAIL {exc}", file=sys.stderr)
        return 1

    if drift:
        print("FAIL committed contract bindings drifted from the compiled contract spec:", file=sys.stderr)
        for line in drift:
            print(f"  - {line}", file=sys.stderr)
        print("run `python3 devx/contract_bindings.py --generate` and commit the result", file=sys.stderr)
        return 1
    print("OK contract bindings match the compiled contract spec")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
