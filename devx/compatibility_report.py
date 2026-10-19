#!/usr/bin/env python3
"""Publish a cross-layer compatibility report for Harpocrates.

Reuses the canonical release compatibility manifest as the single protocol
truth. The report records public version, interface, and digest alignment
across frontend, backend, circuit, verifier, and registry — never media,
witnesses, credentials, proofs, transaction blobs, or deployment secrets.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "release" / "compatibility-manifest.json"
DEFAULT_BINDING = ROOT / "release" / "verifier-binding.json"
DEFAULT_REPORT = ROOT / "release" / "compatibility-report.json"
FORMAT = "harpocrates.cross-layer-compatibility-report"
SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 256 * 1024
MAX_REPORT_BYTES = 256 * 1024
MAX_SOURCE_BYTES = 8 * 1024 * 1024
LAYERS = ("frontend", "backend", "circuit", "verifier", "registry")
PROOF_SYSTEM_ALIASES = {
    "ultrahonk-v1": {"ultrahonk-v1", "ultra_honk", "ultrahonk"},
}
# Match concrete secret-bearing field names only (avoid flagging
# privacy metadata such as ``includes_private_material``).
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from devx._io import (
    DEFAULT_SENSITIVE_KEY_RE as SENSITIVE_KEY_RE,
    read_json_bounded as _io_read_json_bounded,
    read_text_bounded as _io_read_text_bounded,
    reject_sensitive_keys as _reject_sensitive_keys,
)


class ReportError(ValueError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def read_text_bounded(path: Path, limit: int = MAX_SOURCE_BYTES) -> str:
    return _io_read_text_bounded(
        path,
        limit=limit,
        error_factory=ReportError,
        display_name=_display_path(path),
    )


def read_json_bounded(path: Path, limit: int = MAX_MANIFEST_BYTES) -> dict[str, Any]:
    return _io_read_json_bounded(
        path,
        limit=limit,
        error_factory=ReportError,
        display_name=_display_path(path),
        sensitive_pattern=SENSITIVE_KEY_RE,
        require_dict=True,
    )


def _check(check_id: str, ok: bool, detail: str = "") -> dict[str, Any]:
    item: dict[str, Any] = {"id": check_id, "status": "pass" if ok else "fail"}
    if detail:
        item["detail"] = detail
    return item


def _extract_ts_const(source: str, name: str) -> str | None:
    match = re.search(
        rf"export\s+const\s+{re.escape(name)}\s*=\s*['\"]([^'\"]+)['\"]",
        source,
    )
    return match.group(1) if match else None


def _extract_python_default(source: str, env_name: str) -> str | None:
    match = re.search(
        rf'os\.getenv\(\s*["\']{re.escape(env_name)}["\']\s*,\s*["\']([^"\']+)["\']\s*\)',
        source,
    )
    return match.group(1) if match else None


def _extract_cargo_version(source: str) -> str | None:
    match = re.search(r'^version\s*=\s*"([^"]+)"', source, re.MULTILINE)
    return match.group(1) if match else None


def _proof_systems_compatible(left: str, right: str) -> bool:
    left_n = left.strip().lower().replace("-", "_")
    right_n = right.strip().lower().replace("-", "_")
    if left_n == right_n:
        return True
    for aliases in PROOF_SYSTEM_ALIASES.values():
        normalized = {a.replace("-", "_") for a in aliases}
        if left_n in normalized and right_n in normalized:
            return True
    return False


def _layer_sources(name: str) -> list[str]:
    mapping = {
        "frontend": [
            "release/compatibility-manifest.json",
            "frontend/package.json",
            "frontend/src/releaseCompatibility.ts",
        ],
        "backend": [
            "release/compatibility-manifest.json",
            "backend/config.py",
        ],
        "circuit": [
            "release/compatibility-manifest.json",
            "zk/toolchain.lock.json",
            "zk/noir/silent_witness/Nargo.toml",
        ],
        "verifier": [
            "release/compatibility-manifest.json",
            "release/verifier-binding.json",
        ],
        "registry": [
            "release/compatibility-manifest.json",
            "contracts/contracts/harpocrates-registry/Cargo.toml",
        ],
    }
    return mapping[name]


def evaluate_layers(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    components = manifest["components"]
    layers: list[dict[str, Any]] = []

    # frontend
    frontend_pkg = read_json_bounded(ROOT / "frontend" / "package.json")
    frontend_ts = read_text_bounded(ROOT / "frontend" / "src" / "releaseCompatibility.ts")
    release_id_const = _extract_ts_const(frontend_ts, "COMPATIBILITY_RELEASE_ID")
    network_const = _extract_ts_const(frontend_ts, "COMPATIBILITY_NETWORK")
    frontend_checks = [
        _check(
            "package_version_matches_manifest",
            frontend_pkg.get("version") == components["frontend"]["version"],
            f"package={frontend_pkg.get('version')} manifest={components['frontend']['version']}",
        ),
        _check(
            "release_id_binding",
            release_id_const == manifest["release_id"],
            f"const={release_id_const} manifest={manifest['release_id']}",
        ),
        _check(
            "network_binding",
            network_const == manifest["network"],
            f"const={network_const} manifest={manifest['network']}",
        ),
        _check(
            "api_version",
            components["frontend"].get("api_version") == 1,
            str(components["frontend"].get("api_version")),
        ),
        _check(
            "contract_interface_version",
            components["frontend"].get("contract_interface_version") == 1,
            str(components["frontend"].get("contract_interface_version")),
        ),
    ]
    layers.append(
        {
            "name": "frontend",
            "version": components["frontend"]["version"],
            "api_version": components["frontend"].get("api_version"),
            "sources": _layer_sources("frontend"),
            "checks": frontend_checks,
            "status": "compatible" if all(c["status"] == "pass" for c in frontend_checks) else "incompatible",
        }
    )

    # backend
    backend_cfg = read_text_bounded(ROOT / "backend" / "config.py")
    backend_release = _extract_python_default(backend_cfg, "HARPOCRATES_RELEASE_ID")
    backend_network = _extract_python_default(backend_cfg, "HARPOCRATES_RELEASE_NETWORK")
    backend_checks = [
        _check(
            "release_id_default",
            backend_release == manifest["release_id"],
            f"default={backend_release} manifest={manifest['release_id']}",
        ),
        _check(
            "network_default",
            backend_network == manifest["network"],
            f"default={backend_network} manifest={manifest['network']}",
        ),
        _check(
            "api_version",
            components["backend"].get("api_version") == 1,
            str(components["backend"].get("api_version")),
        ),
        _check(
            "version_declared",
            bool(re.fullmatch(r"\d+\.\d+\.\d+", str(components["backend"].get("version", "")))),
            str(components["backend"].get("version")),
        ),
    ]
    layers.append(
        {
            "name": "backend",
            "version": components["backend"]["version"],
            "api_version": components["backend"].get("api_version"),
            "sources": _layer_sources("backend"),
            "checks": backend_checks,
            "status": "compatible" if all(c["status"] == "pass" for c in backend_checks) else "incompatible",
        }
    )

    # circuit
    toolchain = read_json_bounded(ROOT / "zk" / "toolchain.lock.json")
    proving_scheme = str((toolchain.get("toolchain") or {}).get("proving_scheme") or "")
    circuit_proof = str(components["circuit"].get("proof_system") or "")
    nargo = read_text_bounded(ROOT / "zk" / "noir" / "silent_witness" / "Nargo.toml")
    circuit_checks = [
        _check(
            "proof_system_aligned_with_toolchain",
            _proof_systems_compatible(circuit_proof, proving_scheme),
            f"manifest={circuit_proof} toolchain={proving_scheme}",
        ),
        _check(
            "api_version",
            components["circuit"].get("api_version") == 1,
            str(components["circuit"].get("api_version")),
        ),
        _check(
            "nargo_package_present",
            'name = "silent_witness"' in nargo,
            "zk/noir/silent_witness/Nargo.toml",
        ),
    ]
    layers.append(
        {
            "name": "circuit",
            "version": components["circuit"]["version"],
            "api_version": components["circuit"].get("api_version"),
            "proof_system": circuit_proof,
            "sources": _layer_sources("circuit"),
            "checks": circuit_checks,
            "status": "compatible" if all(c["status"] == "pass" for c in circuit_checks) else "incompatible",
        }
    )

    # verifier
    binding = read_json_bounded(DEFAULT_BINDING)
    verifier_proof = str(components["verifier"].get("proof_system") or "")
    binding_proof = str(binding.get("proof_system") or "")
    binding_domain = str(binding.get("crypto_domain") or "")
    protocol_domain = str((manifest.get("protocol") or {}).get("crypto_domain") or "")
    verifier_checks = [
        _check(
            "proof_system_matches_manifest",
            binding_proof == verifier_proof,
            f"binding={binding_proof} manifest={verifier_proof}",
        ),
        _check(
            "crypto_domain_matches_protocol",
            binding_domain == protocol_domain,
            f"binding={binding_domain} protocol={protocol_domain}",
        ),
        _check(
            "public_inputs_version",
            binding.get("public_inputs_version")
            == (manifest.get("compatibility") or {}).get("proof_public_inputs_version"),
            str(binding.get("public_inputs_version")),
        ),
        _check(
            "api_version",
            components["verifier"].get("api_version") == 1,
            str(components["verifier"].get("api_version")),
        ),
    ]
    layers.append(
        {
            "name": "verifier",
            "version": components["verifier"]["version"],
            "api_version": components["verifier"].get("api_version"),
            "proof_system": verifier_proof,
            "sources": _layer_sources("verifier"),
            "checks": verifier_checks,
            "status": "compatible" if all(c["status"] == "pass" for c in verifier_checks) else "incompatible",
        }
    )

    # registry
    cargo = read_text_bounded(
        ROOT / "contracts" / "contracts" / "harpocrates-registry" / "Cargo.toml"
    )
    cargo_version = _extract_cargo_version(cargo)
    registry_checks = [
        _check(
            "cargo_version_matches_manifest",
            cargo_version == components["registry"]["version"],
            f"cargo={cargo_version} manifest={components['registry']['version']}",
        ),
        _check(
            "contract_interface_version",
            components["registry"].get("contract_interface_version") == 1,
            str(components["registry"].get("contract_interface_version")),
        ),
        _check(
            "api_version",
            components["registry"].get("api_version") == 1,
            str(components["registry"].get("api_version")),
        ),
    ]
    layers.append(
        {
            "name": "registry",
            "version": components["registry"]["version"],
            "api_version": components["registry"].get("api_version"),
            "sources": _layer_sources("registry"),
            "checks": registry_checks,
            "status": "compatible" if all(c["status"] == "pass" for c in registry_checks) else "incompatible",
        }
    )

    return layers


def evaluate_cross_layer(manifest: dict[str, Any], layers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    components = manifest["components"]
    circuit_proof = str(components["circuit"].get("proof_system") or "")
    verifier_proof = str(components["verifier"].get("proof_system") or "")
    compatibility = manifest.get("compatibility") or {}

    artifact_checks: list[str] = []
    for artifact in manifest.get("artifacts") or []:
        if not isinstance(artifact, dict):
            artifact_checks.append("invalid artifact entry")
            continue
        rel = str(artifact.get("path") or "")
        expected = str(artifact.get("sha256") or "")
        path = ROOT / rel
        if not path.is_file():
            artifact_checks.append(f"missing:{rel}")
            continue
        if path.stat().st_size > MAX_SOURCE_BYTES and not rel.endswith((".json", ".nr", ".rs", ".py", ".ts", ".toml")):
            # Large binary artifacts are still hashed; bound only pathological sizes via release_guard.
            pass
        actual = sha256_file(path)
        if actual != expected:
            artifact_checks.append(f"mismatch:{rel}")

    cross = [
        _check(
            "circuit_verifier_proof_system",
            circuit_proof == verifier_proof and bool(circuit_proof),
            f"circuit={circuit_proof} verifier={verifier_proof}",
        ),
        _check(
            "frontend_registry_contract_interface",
            components["frontend"].get("contract_interface_version")
            == components["registry"].get("contract_interface_version")
            == 1,
            "contract_interface_version=1",
        ),
        _check(
            "metadata_version",
            compatibility.get("metadata_version") == 1,
            str(compatibility.get("metadata_version")),
        ),
        _check(
            "proof_public_inputs_version",
            compatibility.get("proof_public_inputs_version") == 1,
            str(compatibility.get("proof_public_inputs_version")),
        ),
        _check(
            "all_layers_present",
            {layer["name"] for layer in layers} == set(LAYERS),
            ",".join(sorted(layer["name"] for layer in layers)),
        ),
        _check(
            "artifact_digests",
            not artifact_checks,
            "ok" if not artifact_checks else "; ".join(artifact_checks[:12]),
        ),
    ]
    return cross


def build_report(manifest_path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    if not manifest_path.is_file():
        raise ReportError(f"manifest not found: {manifest_path}")
    manifest = read_json_bounded(manifest_path)
    for key in ("release_id", "network", "protocol", "components", "compatibility", "artifacts"):
        if key not in manifest:
            raise ReportError(f"manifest missing required field '{key}'")
    if set(manifest["components"]) != set(LAYERS):
        raise ReportError("manifest.components must contain exactly the five release layers")

    layers = evaluate_layers(manifest)
    cross = evaluate_cross_layer(manifest, layers)
    version_ok = all(layer["status"] == "compatible" for layer in layers) and all(
        item["status"] == "pass" for item in cross if item["id"] != "artifact_digests"
    )
    artifacts_ok = next(item["status"] == "pass" for item in cross if item["id"] == "artifact_digests")
    if version_ok and artifacts_ok:
        status = "compatible"
    elif version_ok:
        status = "version_compatible_digest_drift"
    else:
        status = "incompatible"

    return {
        "format": FORMAT,
        "schema_version": SCHEMA_VERSION,
        "generated_by": "devx/compatibility_report.py",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "release_id": manifest["release_id"],
        "network": manifest["network"],
        "protocol": manifest["protocol"],
        "compatibility": manifest["compatibility"],
        "status": status,
        "layers": layers,
        "cross_layer": cross,
        "privacy": {
            "includes_private_material": False,
            "note": (
                "Report contains only public release identity, versions, "
                "interface bindings, and check outcomes."
            ),
        },
        "migration": (manifest.get("compatibility") or {}).get("migration"),
        "threat_model_notes": (
            "Cross-layer disagreement on proof system, crypto domain, metadata "
            "version, or contract interface is treated as a fail-closed boundary "
            "violation. Operators must not mix layers from different release_id bundles."
        ),
        "rollback": (
            "Redeploy the previous immutable release_id bundle in full. Do not "
            "roll back a single layer independently."
        ),
    }


def validate_report(report: dict[str, Any]) -> None:
    if report.get("format") != FORMAT:
        raise ReportError("report.format is invalid")
    if report.get("schema_version") != SCHEMA_VERSION:
        raise ReportError("report.schema_version must be 1")
    if report.get("status") not in {
        "compatible",
        "version_compatible_digest_drift",
        "incompatible",
    }:
        raise ReportError("report.status is invalid")
    if not isinstance(report.get("layers"), list) or len(report["layers"]) != 5:
        raise ReportError("report.layers must list all five layers")
    _reject_sensitive_keys(report, "report")
    encoded = canonical_json(report).encode("utf-8")
    if len(encoded) > MAX_REPORT_BYTES:
        raise ReportError("report exceeds the 256 KiB limit")


def write_report(report: dict[str, Any], output: Path) -> None:
    validate_report(report)
    # Stabilize published artifact: drop volatile timestamp for byte-stable commits
    # when callers ask for a checked-in snapshot via --write --stable.
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(canonical_json(report), encoding="utf-8")


def stabilize(report: dict[str, Any]) -> dict[str, Any]:
    """Return a copy suitable for committing (no volatile timestamp)."""
    stable = json.loads(json.dumps(report))
    stable.pop("generated_at", None)
    stable["generated_at"] = "committed"
    return stable


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Publish or verify the Harpocrates cross-layer compatibility report"
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_REPORT)
    parser.add_argument(
        "--write",
        action="store_true",
        help="write the report JSON to --output",
    )
    parser.add_argument(
        "--stable",
        action="store_true",
        help="replace generated_at with 'committed' for reproducible git snapshots",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="require version/protocol compatibility (digest drift allowed)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="require full compatibility including artifact digests",
    )
    parser.add_argument(
        "--verify-existing",
        action="store_true",
        help="compare regenerated stable report to the file at --output",
    )
    args = parser.parse_args(argv)

    try:
        report = build_report(args.manifest.resolve())
        if args.stable or args.write or args.verify_existing:
            report = stabilize(report)
        validate_report(report)

        if args.verify_existing:
            existing = read_json_bounded(args.output.resolve(), MAX_REPORT_BYTES)
            # Compare without care for key order via canonical form
            if canonical_json(existing) != canonical_json(report):
                raise ReportError(
                    f"checked-in report at {args.output} is stale; regenerate with --write --stable"
                )

        if args.write:
            write_report(report, args.output.resolve())

        print(canonical_json(report), end="")

        if args.strict and report["status"] != "compatible":
            print(
                f"compatibility report strict check failed: status={report['status']}",
                file=sys.stderr,
            )
            return 1
        if args.check and report["status"] == "incompatible":
            print(
                f"compatibility report check failed: status={report['status']}",
                file=sys.stderr,
            )
            return 1
        return 0
    except ReportError as exc:
        print(f"compatibility report failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
