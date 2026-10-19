#!/usr/bin/env python3
"""Cross-platform deployment, rollback, and end-to-end smoke testing for Harpocrates.

Provides CLI subcommands:
  - deploy: Deploy contracts to Stellar, initialize admin/verifier/issuer, and update frontend .env.local
  - rollback: Roll back active deployment safely using a release compatibility manifest
  - e2e: Execute end-to-end smoke tests (steganography embed/extract, Noir proof, Stellar registration, NeonDB lookup)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("deploy")

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS_DIR = ROOT / "contracts"
FRONTEND_DIR = ROOT / "frontend"
FRONTEND_ENV_LOCAL = FRONTEND_DIR / ".env.local"
MAX_MANIFEST_BYTES = 256 * 1024
HEX_256 = re.compile(r"^[0-9a-fA-F]{64}$")
CONTRACT_ID_REGEX = re.compile(r"C[A-Z0-9]{55}")


class DeployError(Exception):
    """Base exception for deploy / rollback / e2e failures."""

    def __init__(self, message: str, exit_code: int = 1):
        super().__init__(message)
        self.exit_code = exit_code


def write_step(prefix: str, message: str) -> None:
    print(f"[{prefix}] {message}")


def run_command(
    cmd: List[str],
    cwd: Optional[Path] = None,
    env: Optional[Dict[str, str]] = None,
    capture_output: bool = True,
    timeout: Optional[int] = None,
) -> subprocess.CompletedProcess:
    """Execute external command with error handling."""
    resolved_cwd = str(cwd) if cwd else str(ROOT)
    resolved_env = os.environ.copy()
    if env:
        resolved_env.update(env)

    try:
        proc = subprocess.run(
            cmd,
            cwd=resolved_cwd,
            env=resolved_env,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
        )
        return proc
    except subprocess.TimeoutExpired as exc:
        raise DeployError(f"Command {' '.join(cmd)} timed out after {timeout} seconds", exit_code=1) from exc
    except FileNotFoundError as exc:
        raise DeployError(f"Command not found: {cmd[0]}", exit_code=2) from exc


def get_first_contract_id(output: str) -> str:
    match = CONTRACT_ID_REGEX.search(output)
    if not match:
        raise DeployError("Could not find a contract id in deploy output")
    return match.group(0)


def set_env_value(path: Path, name: str, value: str) -> None:
    """Update or append an environment variable to an env file."""
    lines: List[str] = []
    if path.is_file():
        lines = path.read_text(encoding="utf-8").splitlines()

    found = False
    new_lines: List[str] = []
    prefix = f"{name}="
    for line in lines:
        if line.startswith(prefix):
            found = True
            new_lines.append(f"{name}={value}")
        else:
            new_lines.append(line)

    if not found:
        new_lines.append(f"{name}={value}")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


def get_stellar_address(account_or_alias: str) -> str:
    """Fetch public address using stellar CLI or environment lookup."""
    res = run_command(["stellar", "keys", "address", account_or_alias])
    if res.returncode != 0:
        raise DeployError(f"Failed to get address for {account_or_alias}: {res.stderr.strip() or res.stdout.strip()}")
    return res.stdout.strip()


def validate_manifest(manifest_path: Path) -> Dict[str, Any]:
    """Validate rollback compatibility manifest safely with size & release guard validation."""
    if not manifest_path.is_file():
        raise DeployError("Manifest not found or not specified.", exit_code=3)

    if manifest_path.stat().st_size > MAX_MANIFEST_BYTES:
        raise DeployError("Oversized input: manifest exceeds 256 KiB limit.", exit_code=4)

    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        raise DeployError("Malformed input: manifest is not valid JSON.", exit_code=5)

    if not isinstance(data, dict):
        raise DeployError("Malformed input: manifest is not valid JSON.", exit_code=5)

    # Use release_guard validation if present
    write_step("harpocrates-rollback", "INFO  Verifying compatibility manifest via release_guard.py...")
    guard_script = ROOT / "devx" / "release_guard.py"
    if guard_script.is_file():
        proc = run_command([sys.executable, str(guard_script), "--manifest", str(manifest_path)])
        if proc.returncode != 0:
            raise DeployError("Manifest verification failed. Input is malformed, unsupported, or invalid.", exit_code=6)

    rollout = data.get("rollout", {})
    if not isinstance(rollout, dict) or rollout.get("state") != "rollback":
        state_str = rollout.get("state") if isinstance(rollout, dict) else "unknown"
        raise DeployError(f"Unsupported rollout state: '{state_str}'. Expected 'rollback'.", exit_code=7)

    return data


def run_deploy(args: argparse.Namespace) -> Dict[str, Any]:
    """Deploy command logic."""
    step_prefix = "harpocrates-deploy"
    admin = args.admin
    issuer = args.issuer
    network = args.network
    verifier = args.verifier
    rpc_url = args.rpc_url
    skip_build = args.skip_build
    skip_issuer = args.skip_issuer
    skip_e2e = args.skip_e2e
    stellar_timeout = args.stellar_timeout_seconds

    deploy_id = uuid.uuid4().hex
    out_dir = ROOT / "tmp" / f"deploy-{deploy_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    admin_address = get_stellar_address(admin)
    issuer_address = get_stellar_address(issuer)

    if not skip_build:
        write_step(step_prefix, "running Soroban contract tests")
        res = run_command(["cargo", "test"], cwd=CONTRACTS_DIR)
        if res.returncode != 0:
            raise DeployError(f"cargo test failed: {res.stderr or res.stdout}")

        write_step(step_prefix, "building registry WASM")
        res = run_command(["stellar", "contract", "build"], cwd=CONTRACTS_DIR)
        if res.returncode != 0:
            raise DeployError(f"stellar contract build failed: {res.stderr or res.stdout}")

    wasm_path = CONTRACTS_DIR / "target" / "wasm32v1-none" / "release" / "harpocrates_registry.wasm"
    write_step(step_prefix, f"deploying HarpocratesRegistry to {network}")
    deploy_res = run_command(
        [
            "stellar",
            "contract",
            "deploy",
            "--wasm",
            str(wasm_path),
            "--source",
            admin,
            "--network",
            network,
        ],
        cwd=CONTRACTS_DIR,
    )
    if deploy_res.returncode != 0:
        raise DeployError(f"stellar contract deploy failed: {deploy_res.stderr or deploy_res.stdout}")

    contract_id = get_first_contract_id(deploy_res.stdout + "\n" + deploy_res.stderr)

    write_step(step_prefix, "initializing registry admin")
    init_res = run_command(
        [
            "stellar",
            "contract",
            "invoke",
            "--id",
            contract_id,
            "--source",
            admin,
            "--network",
            network,
            "--",
            "init",
            "--admin",
            admin,
        ],
        cwd=CONTRACTS_DIR,
    )
    if init_res.returncode != 0:
        raise DeployError(f"initializing registry admin failed: {init_res.stderr or init_res.stdout}")

    write_step(step_prefix, "attaching Silent Witness verifier")
    set_verifier_res = run_command(
        [
            "stellar",
            "contract",
            "invoke",
            "--id",
            contract_id,
            "--source",
            admin,
            "--network",
            network,
            "--",
            "set_verifier",
            "--admin",
            admin,
            "--verifier",
            verifier,
        ],
        cwd=CONTRACTS_DIR,
    )
    if set_verifier_res.returncode != 0:
        raise DeployError(f"attaching Silent Witness verifier failed: {set_verifier_res.stderr or set_verifier_res.stdout}")

    if not skip_issuer:
        issuer_metadata_hash = hashlib.sha256(f"harpocrates:issuer:{issuer_address}".encode("utf-8")).hexdigest()
        temp_issuer_meta = out_dir / "issuer_meta.bin"
        temp_issuer_meta.write_bytes(bytes.fromhex(issuer_metadata_hash))
        write_step(step_prefix, "adding public seal issuer")
        add_issuer_res = run_command(
            [
                "stellar",
                "contract",
                "invoke",
                "--id",
                contract_id,
                "--source",
                admin,
                "--network",
                network,
                "--",
                "add_issuer",
                "--admin",
                admin,
                "--issuer",
                issuer,
                "--metadata_hash-file-path",
                str(temp_issuer_meta),
            ],
            cwd=CONTRACTS_DIR,
        )
        if add_issuer_res.returncode != 0:
            raise DeployError(f"adding public seal issuer failed: {add_issuer_res.stderr or add_issuer_res.stdout}")

    write_step(step_prefix, "updating frontend environment")
    set_env_value(FRONTEND_ENV_LOCAL, "VITE_API_BASE", "http://127.0.0.1:5050")
    set_env_value(FRONTEND_ENV_LOCAL, "VITE_STELLAR_RPC_URL", rpc_url)
    set_env_value(FRONTEND_ENV_LOCAL, "VITE_STELLAR_READONLY_SOURCE", admin_address)
    set_env_value(FRONTEND_ENV_LOCAL, "VITE_HARPOCRATES_REGISTRY_ID", contract_id)

    e2e_summary = None
    if not skip_e2e:
        write_step(step_prefix, "running on-chain E2E smoke test")
        e2e_args = argparse.Namespace(
            backend_url="http://127.0.0.1:5050",
            contract_id=contract_id,
            source=admin,
            network=network,
            credential_secret=os.environ.get("HARPOCRATES_CREDENTIAL_SECRET"),
            nullifier_secret=os.environ.get("HARPOCRATES_NULLIFIER_SECRET"),
            stellar_timeout_seconds=stellar_timeout,
            ensure_credential_root=True,
            register_on_chain=True,
        )
        e2e_summary = run_e2e(e2e_args)

    summary = {
        "ok": True,
        "deployId": deploy_id,
        "network": network,
        "contractId": contract_id,
        "verifier": verifier,
        "admin": admin_address,
        "issuer": None if skip_issuer else issuer_address,
        "frontendEnv": str(FRONTEND_ENV_LOCAL),
        "e2e": e2e_summary,
        "outputDir": str(out_dir),
    }

    summary_path = out_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    write_step(step_prefix, f"summary written to {summary_path}")
    print(json.dumps(summary, indent=2))
    return summary


def run_rollback(args: argparse.Namespace) -> int:
    """Rollback command logic reproducing scripts/rollback.ps1 behavior."""
    step_prefix = "harpocrates-rollback"
    manifest_path = Path(args.manifest_file).resolve()
    skip_docker = args.skip_docker

    write_step(step_prefix, "INFO  Starting privacy-safe deployment rollback...")

    # Check dependencies
    if not shutil.which("python") and not shutil.which(sys.executable):
        raise DeployError("Dependency failure: missing python", exit_code=2)

    manifest = validate_manifest(manifest_path)
    rollout = manifest.get("rollout", {})
    previous_release = rollout.get("previous_release")
    if not previous_release or previous_release == "null" or not str(previous_release).strip():
        raise DeployError("Rollback requires previous_release in manifest.", exit_code=8)

    write_step(step_prefix, f"INFO  Initiating rollback to release: {previous_release}")

    compose_file = ROOT / "docker-compose.yml"
    if not skip_docker and compose_file.is_file():
        write_step(step_prefix, "INFO  Stopping current containers safely...")
        try:
            down_res = run_command(["docker", "compose", "-f", str(compose_file), "down"])
            if down_res.returncode != 0:
                write_step(step_prefix, "WARN  Failed to stop containers cleanly.")
        except Exception as exc:
            write_step(step_prefix, f"WARN  Failed to execute docker compose down: {exc}")

    os.environ["HARPOCRATES_RELEASE_TARGET"] = previous_release
    write_step(step_prefix, f"INFO  Deployment boundaries reverted to {previous_release}.")

    if not skip_docker and compose_file.is_file():
        write_step(step_prefix, f"INFO  Bringing containers back up with pinned images for {previous_release}...")
        env = {
            "BACKEND_IMAGE_TAG": previous_release,
            "FRONTEND_IMAGE_TAG": previous_release,
        }
        try:
            up_res = run_command(["docker", "compose", "-f", str(compose_file), "up", "-d"], env=env)
            if up_res.returncode != 0:
                raise DeployError(
                    f"Restore failed: docker compose up exited {up_res.returncode}. Release {previous_release} was NOT restored.",
                    exit_code=9,
                )
        except DeployError:
            raise
        except Exception as exc:
            raise DeployError(f"Restore failed: unable to execute docker compose up: {exc}", exit_code=10)
    elif not skip_docker:
        write_step(step_prefix, "WARN  No docker-compose.yml found; skipping container restore step.")

    write_step(step_prefix, f"INFO  Rollback complete: {previous_release} is now active.")
    return 0


def post_multipart(
    url: str,
    file_path: Path,
    file_field: str,
    file_name: str,
    metadata_json: Optional[str] = None,
    output_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Helper to post multipart form data without external heavy dependencies."""
    boundary = uuid.uuid4().hex
    crlf = b"\r\n"
    body = bytearray()

    # File part
    body.extend(f"--{boundary}".encode("ascii") + crlf)
    body.extend(
        f'Content-Disposition: form-data; name="{file_field}"; filename="{file_name}"'.encode("utf-8") + crlf
    )
    body.extend(b"Content-Type: video/mp4" + crlf + crlf)
    body.extend(file_path.read_bytes())
    body.extend(crlf)

    # Metadata part
    if metadata_json is not None:
        body.extend(f"--{boundary}".encode("ascii") + crlf)
        body.extend(b'Content-Disposition: form-data; name="metadata"' + crlf + crlf)
        body.extend(metadata_json.encode("utf-8"))
        body.extend(crlf)

    body.extend(f"--{boundary}--".encode("ascii") + crlf)

    req = Request(url, data=bytes(body), method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")

    try:
        with urlopen(req) as resp:
            data = resp.read()
            headers = dict(resp.headers)
            if output_path:
                output_path.write_bytes(data)
            return {"status": resp.status, "headers": headers, "body": data}
    except HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        raise DeployError(f"multipart request failed with status {exc.code}: {err_body}") from exc
    except URLError as exc:
        raise DeployError(f"Request failed: {exc.reason}") from exc


def run_e2e(args: argparse.Namespace) -> Dict[str, Any]:
    """E2E smoke test logic reproducing scripts/e2e-harpocrates.ps1."""
    step_prefix = "harpocrates-e2e"
    backend_url = args.backend_url
    contract_id = args.contract_id
    source = args.source
    network = args.network
    # Read secrets strictly from environment variables when not passed as explicit env or flag
    credential_secret = args.credential_secret or os.environ.get("HARPOCRATES_CREDENTIAL_SECRET", "123456789")
    nullifier_secret = args.nullifier_secret or os.environ.get("HARPOCRATES_NULLIFIER_SECRET", "987654321")
    stellar_timeout = args.stellar_timeout_seconds
    ensure_credential_root = args.ensure_credential_root
    register_on_chain = args.register_on_chain

    run_id = uuid.uuid4().hex
    out_dir = ROOT / "tmp" / f"e2e-{run_id}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Health check
    write_step(step_prefix, f"checking backend health at {backend_url}")
    try:
        with urlopen(f"{backend_url}/health", timeout=15) as resp:
            health_data = json.loads(resp.read().decode("utf-8"))
            if not health_data.get("ok"):
                raise DeployError("backend health check did not return ok")
    except Exception as exc:
        raise DeployError(f"backend health check failed: {exc}") from exc

    # 2. Synthetic video
    write_step(step_prefix, "creating synthetic source video")
    source_video = out_dir / "source.mp4"
    ffmpeg_res = run_command([
        "ffmpeg",
        "-y",
        "-v",
        "error",
        "-f",
        "lavfi",
        "-i",
        "testsrc=size=320x240:rate=30",
        "-t",
        "3",
        "-pix_fmt",
        "yuv420p",
        str(source_video),
    ])
    if ffmpeg_res.returncode != 0:
        raise DeployError("ffmpeg failed while creating the source video")

    source_hash = hashlib.sha256(source_video.read_bytes()).hexdigest().lower()
    proof_id = hashlib.sha256(f"{source_hash}:{run_id}".encode("utf-8")).hexdigest().lower()
    timestamp = datetime.now(timezone.utc).isoformat()
    metadata = {
        "protocol": "harpocrates",
        "version": 1,
        "tier": "silent",
        "sourceHash": source_hash,
        "proofId": proof_id,
        "timestamp": timestamp,
        "fileName": "source.mp4",
        "testRun": run_id,
    }
    metadata_json = json.dumps(metadata, separators=(",", ":"))

    # 3. Embedding
    write_step(step_prefix, "embedding metadata through Flask steganography endpoint")
    embedded_video = out_dir / "embedded.mp4"
    embed_resp = post_multipart(
        f"{backend_url}/api/stego/embed",
        source_video,
        "video",
        "source.mp4",
        metadata_json=metadata_json,
        output_path=embedded_video,
    )
    embedded_hash = hashlib.sha256(embedded_video.read_bytes()).hexdigest().lower()

    headers = embed_resp["headers"]
    header_embedded_hash = headers.get("X-Harpocrates-Embedded-Hash") or headers.get("x-harpocrates-embedded-hash")
    metadata_hash = headers.get("X-Harpocrates-Metadata-Hash") or headers.get("x-harpocrates-metadata-hash")

    if not HEX_256.fullmatch(embedded_hash):
        raise DeployError(f"embedded hash must be a 32-byte hex string, got: {embedded_hash}")
    if not metadata_hash or not HEX_256.fullmatch(metadata_hash):
        raise DeployError(f"metadata hash must be a 32-byte hex string, got: {metadata_hash}")
    if header_embedded_hash and header_embedded_hash != embedded_hash:
        raise DeployError("embedded hash header does not match downloaded video hash")

    # 4. Extraction
    write_step(step_prefix, "extracting metadata from embedded video")
    extract_resp = post_multipart(
        f"{backend_url}/api/stego/extract",
        embedded_video,
        "video",
        "embedded.mp4",
    )
    extract_data = json.loads(extract_resp["body"].decode("utf-8"))
    if extract_data.get("metadata", {}).get("protocol") != "harpocrates":
        raise DeployError("extract endpoint did not recover Harpocrates metadata")
    if extract_data.get("metadata", {}).get("proofId") != proof_id:
        raise DeployError("extracted proof id does not match")

    # 5. Noir proof generation
    write_step(step_prefix, "generating browser-compatible Noir UltraHonk proof")
    proof_dir = out_dir / "proof"
    noir_cmd = [
        "npm",
        "run",
        "--silent",
        "proof:noir-client",
        "--",
        "--videoHash",
        embedded_hash,
        "--credentialSecret",
        credential_secret,
        "--nullifierSecret",
        nullifier_secret,
        "--outDir",
        str(proof_dir),
    ]
    noir_res = run_command(noir_cmd, cwd=FRONTEND_DIR)
    if noir_res.returncode != 0:
        raise DeployError("Noir client proof generation failed")

    lines = [line.strip() for line in (noir_res.stdout.strip().splitlines()) if line.strip()]
    proof_json = json.loads(lines[-1]) if lines else {}
    if not proof_json.get("verified"):
        raise DeployError("Noir proof did not verify locally")

    tx_hash = None
    tx_status = "LOCAL_ONLY"
    chain_record = None

    if register_on_chain:
        if ensure_credential_root:
            write_step(step_prefix, f"ensuring Silent Witness credential root is active on Stellar {network}")
            cred_root = proof_json["credentialRoot"]
            cred_root_meta_hash = hashlib.sha256(f"credential-root:{cred_root}".encode("utf-8")).hexdigest().lower()
            cred_root_bin = out_dir / "credential_root.bin"
            meta_hash_bin = out_dir / "metadata_hash.bin"
            cred_root_bin.write_bytes(bytes.fromhex(cred_root))
            meta_hash_bin.write_bytes(bytes.fromhex(cred_root_meta_hash))

            add_root_res = run_command(
                [
                    "stellar",
                    "contract",
                    "invoke",
                    "--id",
                    contract_id,
                    "--source",
                    source,
                    "--network",
                    network,
                    "--",
                    "add_credential_root",
                    "--admin",
                    source,
                    "--credential_root-file-path",
                    str(cred_root_bin),
                    "--metadata_hash-file-path",
                    str(meta_hash_bin),
                ],
                cwd=CONTRACTS_DIR,
            )
            if add_root_res.returncode != 0:
                raise DeployError(f"add_credential_root failed: {add_root_res.stderr or add_root_res.stdout}")

        write_step(step_prefix, f"registering Silent Witness proof on Stellar {network}")
        video_bin = out_dir / "video_hash.bin"
        proof_id_bin = out_dir / "proof_id.bin"
        meta_bin = out_dir / "meta_hash.bin"
        video_bin.write_bytes(bytes.fromhex(embedded_hash))
        meta_bin.write_bytes(bytes.fromhex(metadata_hash))
        proof_id_bin.write_bytes(bytes.fromhex(proof_id))

        register_res = run_command(
            [
                "stellar",
                "contract",
                "invoke",
                "--id",
                contract_id,
                "--source",
                source,
                "--network",
                network,
                "--",
                "register_anonymous_verified",
                "--video_hash-file-path",
                str(video_bin),
                "--metadata_hash-file-path",
                str(meta_bin),
                "--proof_id-file-path",
                str(proof_id_bin),
                "--public_inputs-file-path",
                str(proof_json["publicInputsPath"]),
                "--proof-file-path",
                str(proof_json["proofPath"]),
            ],
            cwd=CONTRACTS_DIR,
            timeout=stellar_timeout,
        )

        reg_output = register_res.stdout
        reg_error = register_res.stderr
        looks_successful = '"video_hash"' in reg_output and "Success" in reg_error
        if register_res.returncode != 0 or not looks_successful:
            raise DeployError(f"Stellar registration failed with exit code {register_res.returncode}. stdout: {reg_output} stderr: {reg_error}")

        tx_status = "SUBMITTED"
        match = re.search(r"Signing transaction:\s+([0-9a-fA-F]{64})", reg_error)
        if match:
            tx_hash = match.group(1)
        else:
            match = re.search(r"[0-9a-fA-F]{64}", reg_output)
            if match:
                tx_hash = match.group(0)

        chain_record = json.loads(reg_output)
        if chain_record.get("video_hash") != embedded_hash:
            raise DeployError(f"Stellar contract returned a different video hash: {chain_record.get('video_hash')}")

    # 6. NeonDB registration event
    write_step(step_prefix, "persisting E2E registration event in NeonDB through backend")
    register_body = {
        "fileName": "embedded.mp4",
        "videoHash": embedded_hash,
        "metadataHash": metadata_hash,
        "proofId": proof_id,
        "tier": "silent",
        "txHash": tx_hash,
        "txStatus": tx_status,
        "sourceAddress": source,
        "contractId": contract_id,
        "silentWitness": {
            "credentialRoot": proof_json.get("credentialRoot"),
            "nullifier": proof_json.get("nullifier"),
            "proofBytes": proof_json.get("proofBytes"),
            "publicInputBytes": proof_json.get("publicInputBytes"),
        },
        "e2e": {
            "runId": run_id,
            "registerOnChain": bool(register_on_chain),
        },
    }

    req = Request(
        f"{backend_url}/api/proofs/register",
        data=json.dumps(register_body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(req, timeout=30) as resp:
        reg_event_res = json.loads(resp.read().decode("utf-8"))
        if not reg_event_res.get("ok"):
            raise DeployError("backend register event did not return ok")

    # 7. NeonDB lookup check
    write_step(step_prefix, "checking NeonDB lookup by embedded video hash")
    with urlopen(f"{backend_url}/api/proofs/by-video/{embedded_hash}", timeout=30) as resp:
        lookup = json.loads(resp.read().decode("utf-8"))
        if len(lookup.get("events", [])) < 1:
            raise DeployError("NeonDB lookup returned no events for embedded video hash")

    summary = {
        "ok": True,
        "runId": run_id,
        "sourceHash": source_hash,
        "embeddedHash": embedded_hash,
        "metadataHash": metadata_hash,
        "proofId": proof_id,
        "credentialRoot": proof_json.get("credentialRoot"),
        "nullifier": proof_json.get("nullifier"),
        "proofBytes": proof_json.get("proofBytes"),
        "publicInputBytes": proof_json.get("publicInputBytes"),
        "txStatus": tx_status,
        "txHash": tx_hash,
        "chainRecord": chain_record,
        "outputDir": str(out_dir),
    }

    summary_path = out_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    write_step(step_prefix, f"summary written to {summary_path}")
    print(json.dumps(summary, indent=2))
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Harpocrates cross-platform deploy, rollback, and E2E CLI")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # Subcommand: deploy
    deploy_parser = subparsers.add_parser("deploy", help="Deploy contracts and update environment")
    deploy_parser.add_argument("--admin", default="harpocrates-admin", help="Admin key or address")
    deploy_parser.add_argument("--issuer", default="harpocrates-issuer", help="Issuer key or address")
    deploy_parser.add_argument("--network", default="testnet", help="Stellar network")
    deploy_parser.add_argument(
        "--verifier",
        default="CCP2EQPKT5XAYTOARX3LGHNMJ37A6W2WY3H54MRIHEZVTVAZZPUSGZQJ",
        help="Verifier contract address",
    )
    deploy_parser.add_argument("--rpc-url", default="https://soroban-testnet.stellar.org", help="Stellar RPC URL")
    deploy_parser.add_argument("--skip-build", action="store_true", help="Skip contract build & tests")
    deploy_parser.add_argument("--skip-issuer", action="store_true", help="Skip adding issuer")
    deploy_parser.add_argument("--skip-e2e", action="store_true", help="Skip running E2E smoke tests")
    deploy_parser.add_argument("--stellar-timeout-seconds", type=int, default=180, help="Stellar registration timeout")

    # Subcommand: rollback
    rollback_parser = subparsers.add_parser("rollback", help="Roll back active deployment safely")
    rollback_parser.add_argument("--manifest-file", required=True, help="Path to compatibility manifest JSON")
    rollback_parser.add_argument("--skip-docker", action="store_true", help="Skip stopping/starting docker containers")

    # Subcommand: e2e
    e2e_parser = subparsers.add_parser("e2e", help="Run end-to-end smoke tests")
    e2e_parser.add_argument("--backend-url", default="http://127.0.0.1:5050", help="Backend service URL")
    e2e_parser.add_argument(
        "--contract-id",
        default="CCKTQNMBLXZXMWVR2WG4HDDUI3QGJU5LV5NTLFPCB72UITWE5TEDK7BT",
        help="Contract ID",
    )
    e2e_parser.add_argument("--source", default="harpocrates-admin", help="Source account or identity")
    e2e_parser.add_argument("--network", default="testnet", help="Stellar network")
    e2e_parser.add_argument("--credential-secret", default=None, help="Credential secret (prefer env var)")
    e2e_parser.add_argument("--nullifier-secret", default=None, help="Nullifier secret (prefer env var)")
    e2e_parser.add_argument("--stellar-timeout-seconds", type=int, default=180, help="Stellar timeout in seconds")
    e2e_parser.add_argument("--ensure-credential-root", action="store_true", help="Ensure credential root on chain")
    e2e_parser.add_argument("--register-on-chain", action="store_true", help="Register proof on Stellar")

    return parser


def main(args_list: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(args_list)

    try:
        if args.subcommand == "deploy":
            run_deploy(args)
            return 0
        elif args.subcommand == "rollback":
            return run_rollback(args)
        elif args.subcommand == "e2e":
            run_e2e(args)
            return 0
        else:
            parser.print_help(sys.stderr)
            return 1
    except DeployError as exc:
        write_step(f"harpocrates-{args.subcommand}", f"ERROR {exc}")
        return exc.exit_code
    except Exception as exc:
        write_step(f"harpocrates-{args.subcommand}", f"ERROR Unexpected failure: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
