#!/usr/bin/env python3
"""Unified circuit build, generation, export, and Soroban artifact preparation tool.

Provides a single tested entry point for building Noir circuits, generating
UltraHonk proofs, exporting proof hex artifacts, and preparing Soroban verifier keys.
All actions enforce toolchain versions pinned in ``zk/toolchain.lock.json``.

Subcommands:
    build           Compile circuits, generate verification keys, and optionally prove/verify.
                    Supports single-circuit builds or double-build reproducibility checks across all circuits.
    generate        Generate witness and proof for a specific circuit (e.g. silent_witness or aggregator).
    export          Export proof, public inputs, and verification key as hex JSON for any circuit.
    prepare-soroban Convert bb UltraHonk verification key into Soroban big-endian verifier format.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOCK = REPO_ROOT / "zk" / "toolchain.lock.json"
DEFAULT_MANIFEST = REPO_ROOT / "zk" / "artifacts.manifest.json"
TOOL_MANIFEST = REPO_ROOT / "zk" / "tools" / "artifact_manifest.py"

DEFAULT_CIRCUITS: tuple[str, ...] = (
    "silent_witness",
    "silent_witness_helper",
    "silent_witness_aggregator",
    "silent_witness_aggregator_helper",
    "revocation_witness",
    "revocation_witness_helper",
    "selective_disclosure",
    "redacted_ancestry",
    "redacted_ancestry_helper",
)

BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617

EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_USAGE = 2
EXIT_FATAL = 3

HERMETIC_ENV = {
    "SOURCE_DATE_EPOCH": "0",
    "TZ": "UTC",
    "LC_ALL": "C",
    "LANG": "C",
    "NARGO_BACKEND_PATH": "",
    "RUST_BACKTRACE": "0",
    "PYTHONHASHSEED": "0",
}


class BuildError(RuntimeError):
    """Fatal build error; carries no private material."""

    def __init__(self, message: str, exit_code: int = EXIT_FATAL) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def signal(event: str, detail: str = "", **fields: Any) -> None:
    """Emit one privacy-safe structured signal on stderr."""
    payload = {"event": event, "detail": detail, **fields} if detail else {"event": event, **fields}
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")), file=sys.stderr)


def get_hermetic_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(HERMETIC_ENV)
    return env


def apply_umask() -> None:
    if hasattr(os, "umask"):
        try:
            os.umask(0o022)
        except OSError:
            pass


@dataclass(frozen=True)
class ToolchainInfo:
    expected_nargo: str
    expected_bb: str
    actual_nargo: str
    actual_bb: str
    proving_scheme: str
    oracle_hash: str


def load_toolchain_lock(lock_path: Path) -> dict[str, Any]:
    if not lock_path.is_file():
        raise BuildError(f"toolchain lock missing: {lock_path}")
    try:
        return json.loads(lock_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise BuildError(f"unreadable toolchain lock: {exc}") from exc


def extract_semver(text: str) -> str:
    match = re.search(r"(\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?)|(\d+\.\d+\.\d+)", text)
    return match.group(0) if match else ""


def check_toolchain(
    lock_path: Path | None = None,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> ToolchainInfo:
    lock_path = lock_path or DEFAULT_LOCK
    lock = load_toolchain_lock(lock_path)
    toolchain = lock.get("toolchain", {})
    expected_nargo = toolchain.get("nargo", {}).get("version", "")
    expected_bb = toolchain.get("barretenberg", {}).get("version", "")
    proving_scheme = toolchain.get("proving_scheme", "ultra_honk")
    oracle_hash = toolchain.get("oracle_hash", "keccak")

    # Verify nargo
    try:
        proc_nargo = runner(
            ["nargo", "--version"],
            capture_output=True,
            text=True,
            check=False,
            env=get_hermetic_env(),
        )
    except FileNotFoundError as exc:
        raise BuildError("nargo not on PATH; see zk/noir/README.md") from exc

    if proc_nargo.returncode != 0:
        raise BuildError("nargo not on PATH; see zk/noir/README.md")

    actual_nargo = extract_semver((proc_nargo.stdout or "") + (proc_nargo.stderr or ""))
    if actual_nargo != expected_nargo:
        raise BuildError(
            f"nargo version drift: expected {expected_nargo}, found {actual_nargo or 'unknown'}"
        )

    # Verify bb
    try:
        proc_bb = runner(
            ["bb", "--version"],
            capture_output=True,
            text=True,
            check=False,
            env=get_hermetic_env(),
        )
    except FileNotFoundError as exc:
        raise BuildError("bb not on PATH; see zk/noir/README.md") from exc

    if proc_bb.returncode != 0:
        raise BuildError("bb not on PATH; see zk/noir/README.md")

    actual_bb = extract_semver((proc_bb.stdout or "") + (proc_bb.stderr or ""))
    if actual_bb != expected_bb:
        raise BuildError(
            f"bb version drift: expected {expected_bb}, found {actual_bb or 'unknown'}"
        )

    signal("toolchain.pinned", detail=f"nargo={actual_nargo} bb={actual_bb}")
    return ToolchainInfo(
        expected_nargo=expected_nargo,
        expected_bb=expected_bb,
        actual_nargo=actual_nargo,
        actual_bb=actual_bb,
        proving_scheme=proving_scheme,
        oracle_hash=oracle_hash,
    )


def run_command(
    cmd: Sequence[str],
    cwd: Path,
    err_msg: str,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> subprocess.CompletedProcess[str]:
    try:
        proc = runner(
            list(cmd),
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
            env=get_hermetic_env(),
        )
    except FileNotFoundError as exc:
        raise BuildError(f"{err_msg}: command {cmd[0]} not found") from exc

    if proc.returncode != 0:
        err_detail = proc.stderr.strip() or proc.stdout.strip()
        msg = f"{err_msg}: {err_detail}" if err_detail else err_msg
        raise BuildError(msg)
    return proc


def normalize_vk_layout(target_dir: Path) -> None:
    for name in ("vk", "vk_fields.json"):
        dir_path = target_dir / name
        nested_file = dir_path / name
        if dir_path.is_dir() and nested_file.is_file():
            tmp_file = target_dir / f"{name}.tmp"
            nested_file.rename(tmp_file)
            shutil.rmtree(dir_path)
            tmp_file.rename(dir_path)


def compile_circuit(
    circuit: str,
    toolchain: ToolchainInfo,
    repo_root: Path = REPO_ROOT,
    clean: bool = True,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    write_vk_flag: bool | None = None,
    prove: bool = False,
) -> None:
    circuit_dir = repo_root / "zk" / "noir" / circuit
    if not circuit_dir.is_dir():
        signal("circuit.skipped", detail=circuit)
        return

    target_dir = circuit_dir / "target"
    if clean and target_dir.exists():
        shutil.rmtree(target_dir, ignore_errors=True)

    target_dir.mkdir(parents=True, exist_ok=True)

    run_command(["nargo", "check"], circuit_dir, f"nargo check failed for {circuit}", runner=runner)
    run_command(["nargo", "compile"], circuit_dir, f"nargo compile failed for {circuit}", runner=runner)
    signal("circuit.compiled", detail=circuit)

    should_write_vk = write_vk_flag
    if should_write_vk is None:
        should_write_vk = circuit in ("silent_witness", "silent_witness_aggregator")

    bytecode_path = target_dir / f"{circuit}.json"
    if should_write_vk and bytecode_path.is_file():
        run_command(
            [
                "bb",
                "write_vk",
                "--scheme",
                toolchain.proving_scheme,
                "--oracle_hash",
                toolchain.oracle_hash,
                "--bytecode_path",
                f"./target/{circuit}.json",
                "--output_path",
                "./target",
                "--output_format",
                "bytes_and_fields",
            ],
            circuit_dir,
            f"bb write_vk failed for {circuit}",
            runner=runner,
        )
        normalize_vk_layout(target_dir)
        signal("vk.written", detail=circuit)

    if prove:
        run_command(
            ["nargo", "execute", "witness"],
            circuit_dir,
            f"nargo execute witness failed for {circuit}",
            runner=runner,
        )
        run_command(
            [
                "bb",
                "prove",
                "--scheme",
                toolchain.proving_scheme,
                "--oracle_hash",
                toolchain.oracle_hash,
                "--bytecode_path",
                f"./target/{circuit}.json",
                "--witness_path",
                "./target/witness.gz",
                "--output_path",
                "./target",
                "--output_format",
                "bytes_and_fields",
            ],
            circuit_dir,
            f"bb prove failed for {circuit}",
            runner=runner,
        )
        run_command(
            [
                "bb",
                "verify",
                "--scheme",
                toolchain.proving_scheme,
                "--oracle_hash",
                toolchain.oracle_hash,
                "--vk_path",
                "./target/vk",
                "--proof_path",
                "./target/proof",
                "--public_inputs_path",
                "./target/public_inputs",
            ],
            circuit_dir,
            f"bb verify failed for {circuit}",
            runner=runner,
        )
        signal("proof.verified", detail=circuit)


def build_all_circuits(
    label: str,
    toolchain: ToolchainInfo,
    repo_root: Path = REPO_ROOT,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> None:
    signal("build.start", detail=label)
    for circuit in DEFAULT_CIRCUITS:
        compile_circuit(circuit, toolchain, repo_root=repo_root, runner=runner)
    signal("build.done", detail=label)


def run_manifest_tool(
    args: Sequence[str],
    repo_root: Path = REPO_ROOT,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> int:
    cmd = [sys.executable, str(TOOL_MANIFEST), *args]
    proc = runner(
        cmd,
        cwd=str(repo_root),
        check=False,
        env=get_hermetic_env(),
    )
    return proc.returncode


def cmd_build(
    args: argparse.Namespace,
    repo_root: Path = REPO_ROOT,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> int:
    apply_umask()
    lock_path = Path(args.lock) if args.lock else (repo_root / "zk" / "toolchain.lock.json")
    manifest_path = Path(args.manifest) if args.manifest else (repo_root / "zk" / "artifacts.manifest.json")

    # If check-coverage requested
    if args.check_coverage:
        return run_manifest_tool(["--lock", str(lock_path), "check-coverage"], repo_root=repo_root, runner=runner)

    circuit = args.circuit or "all"
    if args.all:
        circuit = "all"

    # For builds, check coverage gate first when building all
    if circuit == "all":
        cov_status = run_manifest_tool(["--lock", str(lock_path), "check-coverage"], repo_root=repo_root, runner=runner)
        if cov_status != 0:
            raise BuildError("circuit coverage check failed; see drift.finding above", exit_code=cov_status)

    toolchain = check_toolchain(lock_path=lock_path, runner=runner)

    if circuit != "all":
        compile_circuit(
            circuit,
            toolchain,
            repo_root=repo_root,
            clean=args.clean,
            runner=runner,
            write_vk_flag=args.vk if args.vk else None,
            prove=args.prove,
        )
        signal("circuit.done", detail=circuit)
        return EXIT_OK

    # Building all circuits under specified mode
    mode = "double"
    if args.single:
        mode = "single"
    elif args.verify:
        mode = "verify"

    if mode == "single":
        build_all_circuits("single", toolchain, repo_root=repo_root, runner=runner)
        status = run_manifest_tool(
            ["--lock", str(lock_path), "write", "--output", str(manifest_path)],
            repo_root=repo_root,
            runner=runner,
        )
        if status != 0:
            raise BuildError("manifest write failed", exit_code=status)
        signal("run.ok", detail="manifest written")
        return EXIT_OK

    if mode == "verify":
        build_all_circuits("verify", toolchain, repo_root=repo_root, runner=runner)
        status = run_manifest_tool(
            ["--lock", str(lock_path), "verify", "--manifest", str(manifest_path)],
            repo_root=repo_root,
            runner=runner,
        )
        return status

    # Double build
    with tempfile.TemporaryDirectory() as work_dir:
        work = Path(work_dir)
        first_manifest = work / "first.json"
        second_manifest = work / "second.json"

        build_all_circuits("first", toolchain, repo_root=repo_root, runner=runner)
        status = run_manifest_tool(
            ["--lock", str(lock_path), "write", "--output", str(first_manifest)],
            repo_root=repo_root,
            runner=runner,
        )
        if status != 0:
            raise BuildError("manifest write failed on first build", exit_code=status)

        build_all_circuits("second", toolchain, repo_root=repo_root, runner=runner)
        status = run_manifest_tool(
            ["--lock", str(lock_path), "write", "--output", str(second_manifest)],
            repo_root=repo_root,
            runner=runner,
        )
        if status != 0:
            raise BuildError("manifest write failed on second build", exit_code=status)

        compare_status = run_manifest_tool(
            ["--lock", str(lock_path), "compare", str(first_manifest), str(second_manifest)],
            repo_root=repo_root,
            runner=runner,
        )
        if compare_status != 0:
            signal("run.failed", detail="builds are not reproducible")
            return compare_status

        shutil.copyfile(second_manifest, manifest_path)
        signal("run.ok", detail="reproducible; manifest written")
        return EXIT_OK


def cmd_export(args: argparse.Namespace, repo_root: Path = REPO_ROOT) -> int:
    circuit = args.circuit or "silent_witness"
    target_dir = Path(args.target_dir) if args.target_dir else (repo_root / "zk" / "noir" / circuit / "target")

    files = {
        "proof": target_dir / "proof",
        "publicInputs": target_dir / "public_inputs",
        "verificationKey": target_dir / "vk",
    }

    for key, path in files.items():
        if not path.is_file():
            raise BuildError(f"Missing {key} artifact at {path}. Run build first.")

    result = {
        "proof": files["proof"].read_bytes().hex(),
        "publicInputs": files["publicInputs"].read_bytes().hex(),
        "verificationKey": files["verificationKey"].read_bytes().hex(),
    }

    output_str = json.dumps(result, indent=2)
    print(output_str)

    if args.output:
        Path(args.output).write_text(output_str, encoding="utf-8")

    return EXIT_OK


def cmd_prepare_soroban(args: argparse.Namespace, repo_root: Path = REPO_ROOT) -> int:
    circuit = args.circuit or "silent_witness"
    target_dir = Path(args.target_dir) if args.target_dir else (repo_root / "zk" / "noir" / circuit / "target")
    vk_path = target_dir / "vk"
    soroban_vk_path = target_dir / "vk_soroban"

    if not vk_path.is_file():
        raise BuildError(f"Missing VK artifact at {vk_path}. Run build first.")

    vk = vk_path.read_bytes()
    if len(vk) == 1764:
        stripped = bytearray(vk[4:])
        for offset in range(0, 32, 8):
            first = stripped[offset : offset + 4]
            second = stripped[offset + 4 : offset + 8]
            stripped[offset : offset + 4] = second
            stripped[offset + 4 : offset + 8] = first
        soroban_vk_path.write_bytes(bytes(stripped))
    elif len(vk) == 1760:
        soroban_vk_path.write_bytes(vk)
    else:
        raise BuildError(
            f"Unexpected VK length {len(vk)}. Expected 1764 from bb or 1760 for Soroban verifier."
        )

    result = {
        "vk": str(vk_path),
        "vkBytes": len(vk),
        "sorobanVk": str(soroban_vk_path),
        "sorobanVkBytes": len(soroban_vk_path.read_bytes()),
        "proof": str(target_dir / "proof"),
        "publicInputs": str(target_dir / "public_inputs"),
    }

    output_str = json.dumps(result, indent=2)
    print(output_str)

    if args.output:
        Path(args.output).write_text(output_str, encoding="utf-8")

    return EXIT_OK


def _generate_silent_witness(
    video_hash: str,
    credential_secret: str,
    nullifier_secret: str,
    output_dir: str | None,
    toolchain: ToolchainInfo,
    repo_root: Path = REPO_ROOT,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> int:
    if not re.match(r"^[0-9a-fA-F]{64}$", video_hash):
        raise BuildError("video hash must be a 32-byte hex string", exit_code=EXIT_USAGE)

    hi_hex = video_hash[:32]
    lo_hex = video_hash[32:]
    hi_dec = str(int(hi_hex, 16))
    lo_dec = str(int(lo_hex, 16))

    helper_dir = repo_root / "zk" / "noir" / "silent_witness_helper"
    circuit_dir = repo_root / "zk" / "noir" / "silent_witness"
    helper_toml = helper_dir / "Prover.toml"
    circuit_toml = circuit_dir / "Prover.toml"

    helper_backup = helper_toml.read_text(encoding="utf-8") if helper_toml.is_file() else None
    circuit_backup = circuit_toml.read_text(encoding="utf-8") if circuit_toml.is_file() else None

    try:
        helper_toml.write_text(
            f'credential_secret = "{credential_secret}"\n'
            f'nullifier_secret = "{nullifier_secret}"\n'
            f'video_hash_hi = "{hi_dec}"\n'
            f'video_hash_lo = "{lo_dec}"\n',
            encoding="utf-8",
        )

        proc_helper = run_command(
            ["nargo", "execute", "generated_helper"],
            helper_dir,
            "silent_witness_helper execution failed",
            runner=runner,
        )
        combined_out = proc_helper.stdout + proc_helper.stderr
        raw_fields = re.findall(r"Field\((-?\d+)\)", combined_out)
        values = [int(v) % BN254_MODULUS for v in raw_fields]
        if len(values) != 2:
            raise BuildError(f"Expected 2 Field values from helper, got {len(values)}: {values}")

        credential_root = f"0x{values[0]:064x}"
        nullifier = f"0x{values[1]:064x}"

        circuit_toml.write_text(
            f'credential_secret = "{credential_secret}"\n'
            f'nullifier_secret = "{nullifier_secret}"\n'
            f'video_hash_hi = "{hi_dec}"\n'
            f'video_hash_lo = "{lo_dec}"\n'
            f'credential_root = "{credential_root}"\n'
            f'nullifier = "{nullifier}"\n',
            encoding="utf-8",
        )

        run_command(["nargo", "check"], circuit_dir, "nargo check failed", runner=runner)
        run_command(["nargo", "execute", "witness"], circuit_dir, "witness execution failed", runner=runner)
        run_command(
            [
                "bb",
                "prove",
                "--scheme",
                toolchain.proving_scheme,
                "--oracle_hash",
                toolchain.oracle_hash,
                "--bytecode_path",
                "./target/silent_witness.json",
                "--witness_path",
                "./target/witness.gz",
                "--output_path",
                "./target",
                "--output_format",
                "bytes_and_fields",
            ],
            circuit_dir,
            "bb prove failed",
            runner=runner,
        )
        run_command(
            [
                "bb",
                "verify",
                "--scheme",
                toolchain.proving_scheme,
                "--oracle_hash",
                toolchain.oracle_hash,
                "--vk_path",
                "./target/vk",
                "--proof_path",
                "./target/proof",
                "--public_inputs_path",
                "./target/public_inputs",
            ],
            circuit_dir,
            "bb verify failed",
            runner=runner,
        )

        out_path = Path(output_dir) if output_dir else (circuit_dir / "target" / "generated" / video_hash.lower())
        out_path.mkdir(parents=True, exist_ok=True)

        proof_file = circuit_dir / "target" / "proof"
        public_inputs_file = circuit_dir / "target" / "public_inputs"

        dst_proof = out_path / "proof"
        dst_public_inputs = out_path / "public_inputs"

        shutil.copyfile(proof_file, dst_proof)
        shutil.copyfile(public_inputs_file, dst_public_inputs)

        proof_bytes = dst_proof.read_bytes()
        public_inputs_bytes = dst_public_inputs.read_bytes()

        manifest = {
            "videoHash": video_hash.lower(),
            "credentialRoot": credential_root.removeprefix("0x"),
            "nullifier": nullifier.removeprefix("0x"),
            "proof": proof_bytes.hex(),
            "publicInputs": public_inputs_bytes.hex(),
            "proofBytes": len(proof_bytes),
            "publicInputBytes": len(public_inputs_bytes),
            "proofPath": str(dst_proof),
            "publicInputsPath": str(dst_public_inputs),
        }
        print(json.dumps(manifest))
        return EXIT_OK
    finally:
        if helper_backup is not None:
            helper_toml.write_text(helper_backup, encoding="utf-8")
        if circuit_backup is not None:
            circuit_toml.write_text(circuit_backup, encoding="utf-8")


def _generate_aggregator(
    video_hashes: list[str],
    credential_secret: str,
    nullifier_secret: str,
    output_dir: str | None,
    toolchain: ToolchainInfo,
    repo_root: Path = REPO_ROOT,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> int:
    batch_count = len(video_hashes)
    if batch_count < 1 or batch_count > 8:
        err = {
            "protocol": "harpocrates",
            "version": 1,
            "type": "error",
            "reasonCode": "oversized",
            "detail": f"batch size must be between 1 and 8 (got {batch_count})",
        }
        print(json.dumps(err))
        return EXIT_OK

    for i, vh in enumerate(video_hashes):
        if not re.match(r"^[0-9a-fA-F]{64}$", vh):
            err = {
                "protocol": "harpocrates",
                "version": 1,
                "type": "error",
                "reasonCode": "malformed",
                "detail": f"video hash {i} must be a 32-byte hex string",
            }
            print(json.dumps(err))
            return EXIT_OK

    helper_dir = repo_root / "zk" / "noir" / "silent_witness_aggregator_helper"
    circuit_dir = repo_root / "zk" / "noir" / "silent_witness_aggregator"
    helper_toml = helper_dir / "Prover.toml"
    circuit_toml = circuit_dir / "Prover.toml"

    helper_backup = helper_toml.read_text(encoding="utf-8") if helper_toml.is_file() else None
    circuit_backup = circuit_toml.read_text(encoding="utf-8") if circuit_toml.is_file() else None

    try:
        helper_content = [
            f'credential_secret = "{credential_secret}"',
            f'nullifier_secret = "{nullifier_secret}"',
        ]
        for i in range(batch_count):
            vh = video_hashes[i]
            hi_dec = str(int(vh[:32], 16))
            lo_dec = str(int(vh[32:], 16))
            helper_content.append(f'video_hash_hi_{i} = "{hi_dec}"')
            helper_content.append(f'video_hash_lo_{i} = "{lo_dec}"')
        for i in range(batch_count, 8):
            helper_content.append(f'video_hash_hi_{i} = "0"')
            helper_content.append(f'video_hash_lo_{i} = "0"')

        helper_toml.write_text("\n".join(helper_content) + "\n", encoding="utf-8")

        proc_helper = run_command(
            ["nargo", "execute", "generated_helper"],
            helper_dir,
            "silent_witness_aggregator_helper execution failed",
            runner=runner,
        )
        combined_out = proc_helper.stdout + proc_helper.stderr
        raw_fields = re.findall(r"Field\((-?\d+)\)", combined_out)
        values = [int(v) % BN254_MODULUS for v in raw_fields]
        if len(values) != 16:
            err = {
                "protocol": "harpocrates",
                "version": 1,
                "type": "error",
                "reasonCode": "dependency-failure",
                "detail": f"Expected 16 field values from aggregator helper, got {len(values)}",
            }
            print(json.dumps(err))
            return EXIT_OK

        pairs = [f"0x{v:064x}" for v in values]

        circuit_content = [
            f'credential_secret = "{credential_secret}"',
            f'nullifier_secret = "{nullifier_secret}"',
        ]
        for i in range(8):
            cr_root = pairs[i * 2]
            nullifier = pairs[i * 2 + 1]
            if i < batch_count:
                vh = video_hashes[i]
                hi_dec = str(int(vh[:32], 16))
                lo_dec = str(int(vh[32:], 16))
            else:
                hi_dec = "0"
                lo_dec = "0"
            circuit_content.append(f'video_hash_hi_{i} = "{hi_dec}"')
            circuit_content.append(f'video_hash_lo_{i} = "{lo_dec}"')
            circuit_content.append(f'credential_root_{i} = "{cr_root}"')
            circuit_content.append(f'nullifier_{i} = "{nullifier}"')

        circuit_toml.write_text("\n".join(circuit_content) + "\n", encoding="utf-8")

        run_command(["nargo", "check"], circuit_dir, "nargo check failed", runner=runner)
        run_command(["nargo", "execute", "witness"], circuit_dir, "witness execution failed", runner=runner)
        run_command(
            [
                "bb",
                "prove",
                "--scheme",
                toolchain.proving_scheme,
                "--oracle_hash",
                toolchain.oracle_hash,
                "--bytecode_path",
                "./target/silent_witness_aggregator.json",
                "--witness_path",
                "./target/witness.gz",
                "--output_path",
                "./target",
                "--output_format",
                "bytes_and_fields",
            ],
            circuit_dir,
            "bb prove failed",
            runner=runner,
        )
        run_command(
            [
                "bb",
                "verify",
                "--scheme",
                toolchain.proving_scheme,
                "--oracle_hash",
                toolchain.oracle_hash,
                "--vk_path",
                "./target/vk",
                "--proof_path",
                "./target/proof",
                "--public_inputs_path",
                "./target/public_inputs",
            ],
            circuit_dir,
            "bb verify failed",
            runner=runner,
        )

        all_args_str = " ".join([*video_hashes, credential_secret, nullifier_secret])
        batch_id = hashlib.sha256(all_args_str.encode("utf-8")).hexdigest()

        out_path = Path(output_dir) if output_dir else (circuit_dir / "target" / "generated" / f"batch-{batch_id}")
        out_path.mkdir(parents=True, exist_ok=True)

        proof_file = circuit_dir / "target" / "proof"
        public_inputs_file = circuit_dir / "target" / "public_inputs"

        dst_proof = out_path / "proof"
        dst_public_inputs = out_path / "public_inputs"

        shutil.copyfile(proof_file, dst_proof)
        shutil.copyfile(public_inputs_file, dst_public_inputs)

        proof_bytes = dst_proof.read_bytes()
        public_inputs_bytes = dst_public_inputs.read_bytes()

        manifest = {
            "protocol": "harpocrates",
            "version": 1,
            "type": "aggregated_batch",
            "batchId": batch_id,
            "batchSize": batch_count,
            "maxBatchSize": 8,
            "videoHashes": [vh.lower() for vh in video_hashes],
            "proof": proof_bytes.hex(),
            "publicInputs": public_inputs_bytes.hex(),
            "proofBytes": len(proof_bytes),
            "publicInputBytes": len(public_inputs_bytes),
            "proofPath": str(dst_proof),
            "publicInputsPath": str(dst_public_inputs),
        }
        print(json.dumps(manifest))
        return EXIT_OK
    except Exception as exc:
        err = {
            "protocol": "harpocrates",
            "version": 1,
            "type": "error",
            "reasonCode": "dependency-failure",
            "detail": f"Aggregator script failed unexpectedly: {exc}",
        }
        print(json.dumps(err))
        return EXIT_OK
    finally:
        if helper_backup is not None:
            helper_toml.write_text(helper_backup, encoding="utf-8")
        if circuit_backup is not None:
            circuit_toml.write_text(circuit_backup, encoding="utf-8")


def _generate_generic_circuit(
    circuit: str,
    output_dir: str | None,
    toolchain: ToolchainInfo,
    repo_root: Path = REPO_ROOT,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> int:
    circuit_dir = repo_root / "zk" / "noir" / circuit
    if not circuit_dir.is_dir():
        raise BuildError(f"Circuit directory does not exist: {circuit_dir}")

    run_command(["nargo", "check"], circuit_dir, f"nargo check failed for {circuit}", runner=runner)
    run_command(["nargo", "execute", "witness"], circuit_dir, f"witness execution failed for {circuit}", runner=runner)
    run_command(
        [
            "bb",
            "prove",
            "--scheme",
            toolchain.proving_scheme,
            "--oracle_hash",
            toolchain.oracle_hash,
            "--bytecode_path",
            f"./target/{circuit}.json",
            "--witness_path",
            "./target/witness.gz",
            "--output_path",
            "./target",
            "--output_format",
            "bytes_and_fields",
        ],
        circuit_dir,
        f"bb prove failed for {circuit}",
        runner=runner,
    )

    out_path = Path(output_dir) if output_dir else (circuit_dir / "target" / "generated")
    out_path.mkdir(parents=True, exist_ok=True)

    proof_file = circuit_dir / "target" / "proof"
    public_inputs_file = circuit_dir / "target" / "public_inputs"

    dst_proof = out_path / "proof"
    dst_public_inputs = out_path / "public_inputs"

    shutil.copyfile(proof_file, dst_proof)
    shutil.copyfile(public_inputs_file, dst_public_inputs)

    proof_bytes = dst_proof.read_bytes()
    public_inputs_bytes = dst_public_inputs.read_bytes()

    manifest = {
        "circuit": circuit,
        "proof": proof_bytes.hex(),
        "publicInputs": public_inputs_bytes.hex(),
        "proofBytes": len(proof_bytes),
        "publicInputBytes": len(public_inputs_bytes),
        "proofPath": str(dst_proof),
        "publicInputsPath": str(dst_public_inputs),
    }
    print(json.dumps(manifest))
    return EXIT_OK


def cmd_generate(
    args: argparse.Namespace,
    repo_root: Path = REPO_ROOT,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> int:
    apply_umask()
    toolchain = check_toolchain(runner=runner)
    circuit = args.circuit

    # Dissect positional args and optional flags
    pos_args: list[str] = list(args.args or [])

    if circuit == "silent_witness":
        video_hash = args.video_hash or (pos_args[0] if len(pos_args) > 0 else "")
        credential_secret = args.credential_secret or (pos_args[1] if len(pos_args) > 1 else "")
        nullifier_secret = args.nullifier_secret or (pos_args[2] if len(pos_args) > 2 else "")
        output_dir = args.output_dir or (pos_args[3] if len(pos_args) > 3 else None)

        if not video_hash or not credential_secret or not nullifier_secret:
            raise BuildError(
                "usage: generate silent_witness <video-hash-hex> <credential-secret-field> <nullifier-secret-field> [output-dir]",
                exit_code=EXIT_USAGE,
            )

        return _generate_silent_witness(
            video_hash=video_hash,
            credential_secret=credential_secret,
            nullifier_secret=nullifier_secret,
            output_dir=output_dir,
            toolchain=toolchain,
            repo_root=repo_root,
            runner=runner,
        )

    if circuit == "silent_witness_aggregator":
        video_hashes = list(args.video_hashes or [])
        credential_secret = args.credential_secret or ""
        nullifier_secret = args.nullifier_secret or ""
        output_dir = args.output_dir

        if pos_args:
            # Parse like generate-silent-witness-aggregator.sh
            # Last 2 or 3 args are secrets and optional output_dir
            if len(pos_args) >= 4:
                second_last = pos_args[-2]
                last_arg = pos_args[-1]
                if second_last.isdigit() and last_arg.isdigit():
                    credential_secret = second_last
                    nullifier_secret = last_arg
                    video_hashes = pos_args[:-2]
                elif second_last.isdigit():
                    credential_secret = pos_args[-3]
                    nullifier_secret = second_last
                    output_dir = last_arg
                    video_hashes = pos_args[:-3]
                else:
                    err = {
                        "protocol": "harpocrates",
                        "version": 1,
                        "type": "error",
                        "reasonCode": "malformed",
                        "detail": "invalid arguments. Provide field decimal secrets.",
                    }
                    print(json.dumps(err))
                    return EXIT_OK
            else:
                err = {
                    "protocol": "harpocrates",
                    "version": 1,
                    "type": "error",
                    "reasonCode": "malformed",
                    "detail": "usage: generate silent_witness_aggregator <hash0> [<hash1>...] <cred_secret> <null_secret> [output-dir]",
                }
                print(json.dumps(err))
                return EXIT_OK

        if not video_hashes or not credential_secret or not nullifier_secret:
            err = {
                "protocol": "harpocrates",
                "version": 1,
                "type": "error",
                "reasonCode": "malformed",
                "detail": "Missing required arguments for aggregator",
            }
            print(json.dumps(err))
            return EXIT_OK

        return _generate_aggregator(
            video_hashes=video_hashes,
            credential_secret=credential_secret,
            nullifier_secret=nullifier_secret,
            output_dir=output_dir,
            toolchain=toolchain,
            repo_root=repo_root,
            runner=runner,
        )

    # Any other circuit
    return _generate_generic_circuit(
        circuit=circuit,
        output_dir=args.output_dir or (pos_args[0] if pos_args else None),
        toolchain=toolchain,
        repo_root=repo_root,
        runner=runner,
    )


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="build_circuits.py",
        description="Unified driver for Noir circuit building, proof generation, and artifact export.",
    )
    parser.add_argument(
        "--check-toolchain",
        action="store_true",
        help="Check toolchain versions against zk/toolchain.lock.json and exit.",
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommand to execute")

    # --- build ---
    p_build = subparsers.add_parser("build", help="Build circuit(s)")
    p_build.add_argument("circuit", nargs="?", default="all", help="Circuit name or 'all'")
    p_build.add_argument("--circuit", dest="circuit_opt", default=None, help="Explicit circuit name")
    p_build.add_argument("--all", action="store_true", help="Build all declared circuits")
    p_build.add_argument("--single", action="store_true", help="Build once and write manifest")
    p_build.add_argument("--verify", action="store_true", help="Build once and verify against manifest")
    p_build.add_argument("--check-coverage", action="store_true", help="Coverage gate check only")
    p_build.add_argument("--double", action="store_true", help="Double build and compare (default for all)")
    p_build.add_argument("--prove", action="store_true", help="Execute witness and generate proof")
    p_build.add_argument("--vk", action="store_true", help="Force writing verification key")
    p_build.add_argument("--clean", action="store_true", default=True, help="Clean target before build")
    p_build.add_argument("--manifest", default=None, help="Path to manifest file")
    p_build.add_argument("--lock", default=None, help="Path to toolchain lock file")

    # --- generate ---
    p_gen = subparsers.add_parser("generate", help="Generate proof and public inputs for a circuit")
    p_gen.add_argument("circuit", help="Circuit name to generate proof for")
    p_gen.add_argument("args", nargs="*", help="Positional arguments for generation")
    p_gen.add_argument("--video-hash", default=None, help="Video hash (32-byte hex string)")
    p_gen.add_argument("--video-hashes", nargs="+", default=None, help="List of video hashes")
    p_gen.add_argument("--credential-secret", default=None, help="Credential secret field decimal")
    p_gen.add_argument("--nullifier-secret", default=None, help="Nullifier secret field decimal")
    p_gen.add_argument("--output-dir", default=None, help="Output directory for generated artifacts")
    p_gen.add_argument("--verifier-scope", default="0", help="Verifier scope (optional)")
    p_gen.add_argument("--epoch", type=int, default=0, help="Epoch (optional)")

    # --- export ---
    p_exp = subparsers.add_parser("export", help="Export proof, public inputs, and VK as hex JSON")
    p_exp.add_argument("circuit", nargs="?", default="silent_witness", help="Circuit name")
    p_exp.add_argument("--circuit", dest="circuit_opt", default=None, help="Explicit circuit name")
    p_exp.add_argument("--target-dir", default=None, help="Circuit target directory")
    p_exp.add_argument("--output", default=None, help="Output JSON file path")

    # --- prepare-soroban ---
    p_soroban = subparsers.add_parser("prepare-soroban", help="Prepare VK artifact for Soroban verifier")
    p_soroban.add_argument("circuit", nargs="?", default="silent_witness", help="Circuit name")
    p_soroban.add_argument("--circuit", dest="circuit_opt", default=None, help="Explicit circuit name")
    p_soroban.add_argument("--target-dir", default=None, help="Circuit target directory")
    p_soroban.add_argument("--output", default=None, help="Output JSON file path")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    if args.check_toolchain:
        try:
            check_toolchain()
            return EXIT_OK
        except BuildError as exc:
            signal("build.error", detail=str(exc))
            return exc.exit_code

    if not args.subcommand:
        parser.print_help()
        return EXIT_USAGE

    try:
        # Reconcile explicit circuit flags
        if hasattr(args, "circuit_opt") and args.circuit_opt:
            args.circuit = args.circuit_opt

        if args.subcommand == "build":
            return cmd_build(args)
        if args.subcommand == "export":
            return cmd_export(args)
        if args.subcommand == "prepare-soroban":
            return cmd_prepare_soroban(args)
        if args.subcommand == "generate":
            return cmd_generate(args)

        parser.print_help()
        return EXIT_USAGE
    except BuildError as exc:
        signal("build.error", detail=str(exc))
        return exc.exit_code


if __name__ == "__main__":
    sys.exit(main())
