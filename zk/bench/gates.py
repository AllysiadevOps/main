#!/usr/bin/env python3
"""ZK Circuit gate and opcode count regression check.

Tracks ACIR opcode counts (via `nargo info`) and backend gate counts (via `bb gates`)
against a committed baseline in `zk/bench/gates.lock.json`. Fails when any circuit
grows by more than a configured threshold (default 5.0%).

Usage:
    python zk/bench/gates.py check [--threshold 5.0] [--summary path]
    python zk/bench/gates.py --update
    python zk/bench/gates.py update

See docs/zk-benchmarks.md and docs/zk-reproducible-builds.md.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

GATES_LOCK_FORMAT = "harpocrates.zk-gates-lock"
GATES_LOCK_VERSION = 1
DEFAULT_THRESHOLD_PERCENT = 5.0

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TOOLCHAIN_LOCK = REPO_ROOT / "zk" / "toolchain.lock.json"
DEFAULT_GATES_LOCK = REPO_ROOT / "zk" / "bench" / "gates.lock.json"
CIRCUIT_ROOT = REPO_ROOT / "zk" / "noir"

DEFAULT_CIRCUITS = (
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

EXIT_OK = 0
EXIT_REGRESSION = 1
EXIT_USAGE = 2
EXIT_FATAL = 3


class GatesError(RuntimeError):
    """Fatal, non-recoverable condition in gates tooling."""


@dataclass(frozen=True)
class CircuitCounts:
    acir_opcodes: int
    backend_gates: int

    def to_dict(self) -> dict[str, int]:
        return {
            "acir_opcodes": self.acir_opcodes,
            "backend_gates": self.backend_gates,
        }


@dataclass(frozen=True)
class CircuitDiff:
    name: str
    locked_opcodes: int | None
    actual_opcodes: int | None
    opcode_growth_pct: float | None
    locked_gates: int | None
    actual_gates: int | None
    gate_growth_pct: float | None
    status: str  # "OK", "REGRESSION", "NEW", "MISSING"
    details: str = ""


@dataclass(frozen=True)
class ComparisonResult:
    diffs: list[CircuitDiff]
    has_regression: bool
    threshold_percent: float

    @property
    def passed(self) -> bool:
        return not self.has_regression


# ── Toolchain & Circuits Discovery ──────────────────────────────────────────


def load_toolchain_info(path: Path = DEFAULT_TOOLCHAIN_LOCK) -> dict[str, str]:
    """Extract pinned toolchain metadata from zk/toolchain.lock.json."""
    if not path.is_file():
        raise GatesError(f"toolchain lock file not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise GatesError(f"failed to parse toolchain lock at {path}: {exc}") from exc

    tc = raw.get("toolchain", {})
    return {
        "nargo": str(tc.get("nargo", {}).get("version", "")),
        "barretenberg": str(tc.get("barretenberg", {}).get("version", "")),
        "proving_scheme": str(tc.get("proving_scheme", "ultra_honk")),
        "oracle_hash": str(tc.get("oracle_hash", "keccak")),
    }


def discover_circuits(noir_root: Path = CIRCUIT_ROOT) -> list[str]:
    """Discover all Noir binary circuit packages under zk/noir/."""
    if not noir_root.is_dir():
        return list(DEFAULT_CIRCUITS)

    found = []
    for entry in sorted(noir_root.iterdir()):
        if not entry.is_dir():
            continue
        nargo_toml = entry / "Nargo.toml"
        if not nargo_toml.is_file():
            continue
        try:
            content = nargo_toml.read_text(encoding="utf-8")
            if re.search(r'type\s*=\s*["\']lib["\']', content):
                continue
        except OSError:
            continue
        found.append(entry.name)

    # Prefer found binary packages, fallback to DEFAULT_CIRCUITS if empty
    return found if found else list(DEFAULT_CIRCUITS)


# ── Parsing Outputs ─────────────────────────────────────────────────────────


def parse_nargo_info(output: str) -> int:
    """Parse ACIR opcode count from nargo info stdout.

    Supports JSON format (`nargo info --json`) across Noir versions,
    as well as table format (`nargo info`) fallback.
    """
    output = output.strip()
    if not output:
        raise GatesError("empty output from nargo info")

    # Try JSON parsing
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            # Format: {"programs": [{"name": "...", "acir_opcodes": 125, ...}]}
            # or {"programs": [{"package": "...", "functions": [{"name": "main", "acir_opcodes": 125}]}]}
            programs = data.get("programs")
            if isinstance(programs, list) and len(programs) > 0:
                for prog in programs:
                    if isinstance(prog, dict):
                        if "acir_opcodes" in prog:
                            return int(prog["acir_opcodes"])
                        functions = prog.get("functions")
                        if isinstance(functions, list) and len(functions) > 0:
                            for fn in functions:
                                if fn.get("name") in ("main", None) and "acir_opcodes" in fn:
                                    return int(fn["acir_opcodes"])
                            if "acir_opcodes" in functions[0]:
                                return int(functions[0]["acir_opcodes"])

            # Format: {"functions": [{"name": "main", "acir_opcodes": 125}]}
            functions = data.get("functions")
            if isinstance(functions, list) and len(functions) > 0:
                for fn in functions:
                    if fn.get("name") in ("main", None) and "acir_opcodes" in fn:
                        return int(fn["acir_opcodes"])
                if "acir_opcodes" in functions[0]:
                    return int(functions[0]["acir_opcodes"])

            if "acir_opcodes" in data:
                return int(data["acir_opcodes"])
    except json.JSONDecodeError:
        pass

    # Fallback: Parse table format output
    # Columns usually: | Package | Function | ACIR Opcodes | Brillig Opcodes |
    lines = output.splitlines()
    header_idx = None
    for line in lines:
        if "acir opcodes" in line.lower() or "opcodes" in line.lower():
            cols = [c.strip().lower() for c in line.split("|") if c.strip()]
            for idx, col in enumerate(cols):
                if "acir" in col or "opcode" in col:
                    header_idx = idx
                    break

    for line in lines:
        if "|" in line:
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if not parts:
                continue
            # If line contains numeric values
            nums = [p for p in parts if p.isdigit()]
            if nums:
                if header_idx is not None and header_idx < len(parts) and parts[header_idx].isdigit():
                    return int(parts[header_idx])
                return int(nums[0])

    # Direct regex fallback
    match = re.search(r"acir[_\s]+opcodes?[\s:=]+(\d+)", output, re.IGNORECASE)
    if match:
        return int(match.group(1))

    raise GatesError(f"could not parse ACIR opcode count from nargo info output:\n{output[:300]}")


def parse_bb_gates(output: str) -> int:
    """Parse backend gate count (circuit_size) from bb gates stdout.

    Supports JSON format (`{"functions": [{"circuit_size": 3143}]}`)
    as well as plain integer or key-value representations.
    """
    output = output.strip()
    if not output:
        raise GatesError("empty output from bb gates")

    # Try JSON parsing
    try:
        data = json.loads(output)
        if isinstance(data, dict):
            # Format: {"functions": [{"circuit_size": 3143, ...}]}
            functions = data.get("functions")
            if isinstance(functions, list) and len(functions) > 0:
                fn = functions[0]
                if isinstance(fn, dict):
                    for key in ("circuit_size", "gates", "sub_gates_total", "total_gates"):
                        if key in fn and str(fn[key]).isdigit():
                            return int(fn[key])

            for key in ("circuit_size", "gates", "total_gates"):
                if key in data and str(data[key]).isdigit():
                    return int(data[key])
    except json.JSONDecodeError:
        pass

    # Try direct integer
    if output.isdigit():
        return int(output)

    # Regex for circuit_size or gates
    match = re.search(r'(?:"circuit_size"|circuit_size|gates|total_gates)\s*[:=]\s*(\d+)', output, re.IGNORECASE)
    if match:
        return int(match.group(1))

    # Regex for any integer line
    for line in output.splitlines():
        line = line.strip()
        if line.isdigit():
            return int(line)

    raise GatesError(f"could not parse gate count from bb gates output:\n{output[:300]}")


# ── Measurement Execution ───────────────────────────────────────────────────


def measure_circuit(
    circuit: str,
    repo_root: Path = REPO_ROOT,
    toolchain_info: Mapping[str, str] | None = None,
) -> CircuitCounts:
    """Run nargo info and bb gates to measure counts for a circuit."""
    circuit_dir = repo_root / "zk" / "noir" / circuit
    if not circuit_dir.is_dir():
        raise GatesError(f"circuit directory not found: {circuit_dir}")

    # 1. ACIR opcodes via nargo info
    try:
        res = subprocess.run(
            ["nargo", "info", "--json"],
            cwd=circuit_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode != 0:
            # Fallback to plain nargo info
            res = subprocess.run(
                ["nargo", "info"],
                cwd=circuit_dir,
                capture_output=True,
                text=True,
                check=False,
            )
        if res.returncode != 0:
            err = res.stderr.strip() or res.stdout.strip()
            raise GatesError(f"nargo info failed for {circuit} (exit code {res.returncode}): {err}")
        acir_opcodes = parse_nargo_info(res.stdout)
    except FileNotFoundError as exc:
        raise GatesError("nargo command not found on PATH; required for measuring circuit counts") from exc

    # 2. Backend gates via bb gates
    target_json = circuit_dir / "target" / f"{circuit}.json"
    if not target_json.is_file():
        # Attempt compile if missing
        compile_res = subprocess.run(
            ["nargo", "compile"],
            cwd=circuit_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        if compile_res.returncode != 0:
            err = compile_res.stderr.strip() or compile_res.stdout.strip()
            raise GatesError(f"nargo compile failed for {circuit}: {err}")

    if not target_json.is_file():
        raise GatesError(f"compiled artifact missing for {circuit}: {target_json}")

    scheme = (toolchain_info or {}).get("proving_scheme", "ultra_honk")
    try:
        res_bb = subprocess.run(
            ["bb", "gates", "-b", str(target_json), "--scheme", scheme],
            cwd=circuit_dir,
            capture_output=True,
            text=True,
            check=False,
        )
        if res_bb.returncode != 0:
            # Retry without --scheme flag for different bb CLI versions
            res_bb = subprocess.run(
                ["bb", "gates", "-b", str(target_json)],
                cwd=circuit_dir,
                capture_output=True,
                text=True,
                check=False,
            )
        if res_bb.returncode != 0:
            err = res_bb.stderr.strip() or res_bb.stdout.strip()
            raise GatesError(f"bb gates failed for {circuit} (exit code {res_bb.returncode}): {err}")
        backend_gates = parse_bb_gates(res_bb.stdout)
    except FileNotFoundError as exc:
        raise GatesError("bb command not found on PATH; required for measuring circuit counts") from exc

    return CircuitCounts(acir_opcodes=acir_opcodes, backend_gates=backend_gates)


def measure_all_circuits(
    circuits: Sequence[str] | None = None,
    repo_root: Path = REPO_ROOT,
    toolchain_info: Mapping[str, str] | None = None,
) -> dict[str, CircuitCounts]:
    """Measure counts across all target circuits."""
    targets = circuits or discover_circuits(repo_root / "zk" / "noir")
    counts: dict[str, CircuitCounts] = {}
    for c in targets:
        counts[c] = measure_circuit(c, repo_root=repo_root, toolchain_info=toolchain_info)
    return counts


# ── Comparison Logic ────────────────────────────────────────────────────────


def calculate_growth_percent(locked: int, actual: int) -> float:
    """Calculate percentage growth from locked to actual.

    Positive means growth (increase in constraints/opcodes).
    Negative means shrinkage (optimization).
    """
    if locked <= 0:
        return 100.0 if actual > 0 else 0.0
    return ((actual - locked) / float(locked)) * 100.0


def compare_counts(
    locked_circuits: Mapping[str, Any],
    current_circuits: Mapping[str, Any],
    threshold_percent: float = DEFAULT_THRESHOLD_PERCENT,
) -> ComparisonResult:
    """Compare current circuit counts against locked counts."""
    all_circuits = sorted(set(locked_circuits.keys()) | set(current_circuits.keys()))
    diffs: list[CircuitDiff] = []
    has_regression = False

    for name in all_circuits:
        locked_raw = locked_circuits.get(name)
        current_raw = current_circuits.get(name)

        if locked_raw is None:
            # Circuit added but not locked
            curr_c = current_raw if isinstance(current_raw, CircuitCounts) else CircuitCounts(
                acir_opcodes=int(current_raw.get("acir_opcodes", 0)),
                backend_gates=int(current_raw.get("backend_gates", 0)),
            )
            diffs.append(
                CircuitDiff(
                    name=name,
                    locked_opcodes=None,
                    actual_opcodes=curr_c.acir_opcodes,
                    opcode_growth_pct=None,
                    locked_gates=None,
                    actual_gates=curr_c.backend_gates,
                    gate_growth_pct=None,
                    status="NEW",
                    details="Circuit is missing from gates.lock.json (untracked)",
                )
            )
            has_regression = True
            continue

        if current_raw is None:
            # Circuit locked but missing from current build
            locked_c = locked_raw if isinstance(locked_raw, CircuitCounts) else CircuitCounts(
                acir_opcodes=int(locked_raw.get("acir_opcodes", 0)),
                backend_gates=int(locked_raw.get("backend_gates", 0)),
            )
            diffs.append(
                CircuitDiff(
                    name=name,
                    locked_opcodes=locked_c.acir_opcodes,
                    actual_opcodes=None,
                    opcode_growth_pct=None,
                    locked_gates=locked_c.backend_gates,
                    actual_gates=None,
                    gate_growth_pct=None,
                    status="MISSING",
                    details="Circuit is missing from current build",
                )
            )
            has_regression = True
            continue

        locked_c = locked_raw if isinstance(locked_raw, CircuitCounts) else CircuitCounts(
            acir_opcodes=int(locked_raw.get("acir_opcodes", 0)),
            backend_gates=int(locked_raw.get("backend_gates", 0)),
        )
        curr_c = current_raw if isinstance(current_raw, CircuitCounts) else CircuitCounts(
            acir_opcodes=int(current_raw.get("acir_opcodes", 0)),
            backend_gates=int(current_raw.get("backend_gates", 0)),
        )

        opcode_growth = calculate_growth_percent(locked_c.acir_opcodes, curr_c.acir_opcodes)
        gate_growth = calculate_growth_percent(locked_c.backend_gates, curr_c.backend_gates)

        # Regressed if growth strictly exceeds the configured threshold
        opcode_regressed = opcode_growth > threshold_percent
        gate_regressed = gate_growth > threshold_percent

        if opcode_regressed or gate_regressed:
            reasons = []
            if opcode_regressed:
                reasons.append(f"ACIR opcodes +{opcode_growth:.1f}% > {threshold_percent:.1f}%")
            if gate_regressed:
                reasons.append(f"Backend gates +{gate_growth:.1f}% > {threshold_percent:.1f}%")
            status = "REGRESSION"
            has_regression = True
            details = "; ".join(reasons)
        else:
            status = "OK"
            details = "Within threshold"

        diffs.append(
            CircuitDiff(
                name=name,
                locked_opcodes=locked_c.acir_opcodes,
                actual_opcodes=curr_c.acir_opcodes,
                opcode_growth_pct=opcode_growth,
                locked_gates=locked_c.backend_gates,
                actual_gates=curr_c.backend_gates,
                gate_growth_pct=gate_growth,
                status=status,
                details=details,
            )
        )

    return ComparisonResult(
        diffs=diffs,
        has_regression=has_regression,
        threshold_percent=threshold_percent,
    )


# ── Formatting & Presentation ───────────────────────────────────────────────


def _fmt_pct(pct: float | None) -> str:
    if pct is None:
        return "N/A"
    sign = "+" if pct >= 0 else ""
    return f"{sign}{pct:.1f}%"


def _fmt_int(val: int | None) -> str:
    if val is None:
        return "N/A"
    return f"{val:,}"


def format_markdown_table(result: ComparisonResult) -> str:
    """Generate GitHub-Flavored Markdown summary for job summaries."""
    lines = [
        "### ZK Circuit Gate & Opcode Counts",
        "",
    ]

    if result.passed:
        lines.append(
            f"> [!NOTE]\n> All {len(result.diffs)} circuits passed gate and opcode growth checks (threshold: {result.threshold_percent:.1f}%)."
        )
    else:
        lines.append(
            f"> [!CAUTION]\n> Circuit size regression detected! Threshold: **{result.threshold_percent:.1f}%** maximum allowed growth."
        )

    lines.append("")
    lines.append(
        "| Circuit | ACIR (Locked) | ACIR (Actual) | ACIR Diff | Gates (Locked) | Gates (Actual) | Gates Diff | Status |"
    )
    lines.append(
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
    )

    for d in result.diffs:
        if d.status == "OK":
            status_badge = "✅ OK"
        elif d.status == "REGRESSION":
            status_badge = "❌ **REGRESSION**"
        elif d.status == "NEW":
            status_badge = "⚠️ NEW"
        else:
            status_badge = "❌ MISSING"

        lines.append(
            f"| `{d.name}` | {_fmt_int(d.locked_opcodes)} | {_fmt_int(d.actual_opcodes)} | "
            f"`{_fmt_pct(d.opcode_growth_pct)}` | {_fmt_int(d.locked_gates)} | {_fmt_int(d.actual_gates)} | "
            f"`{_fmt_pct(d.gate_growth_pct)}` | {status_badge} |"
        )

    if not result.passed:
        lines.append("")
        lines.append("#### Regression Details")
        for d in result.diffs:
            if d.status != "OK":
                lines.append(f"- **`{d.name}`**: {d.details}")

    lines.append("")
    return "\n".join(lines)


def format_ascii_table(result: ComparisonResult) -> str:
    """Generate plain ASCII table for console stdout."""
    headers = [
        "Circuit",
        "ACIR (Lock)",
        "ACIR (Act)",
        "ACIR Diff",
        "Gates (Lock)",
        "Gates (Act)",
        "Gate Diff",
        "Status",
    ]
    rows = []
    for d in result.diffs:
        rows.append(
            [
                d.name,
                _fmt_int(d.locked_opcodes),
                _fmt_int(d.actual_opcodes),
                _fmt_pct(d.opcode_growth_pct),
                _fmt_int(d.locked_gates),
                _fmt_int(d.actual_gates),
                _fmt_pct(d.gate_growth_pct),
                d.status,
            ]
        )

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(val))

    def make_row(items: list[str]) -> str:
        return " | ".join(f"{items[i]:<{col_widths[i]}}" for i in range(len(items)))

    sep = "-+-".join("-" * w for w in col_widths)
    output_lines = [
        make_row(headers),
        sep,
    ]
    for row in rows:
        output_lines.append(make_row(row))

    return "\n".join(output_lines)


# ── Lock File Storage ───────────────────────────────────────────────────────


def load_gates_lock(path: Path = DEFAULT_GATES_LOCK) -> dict[str, Any]:
    """Load and validate zk/bench/gates.lock.json."""
    if not path.is_file():
        raise GatesError(f"gates lock file not found: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise GatesError(f"failed to parse gates lock {path}: {exc}") from exc

    if raw.get("format") != GATES_LOCK_FORMAT:
        raise GatesError(f"unexpected format in {path}: {raw.get('format')!r} != {GATES_LOCK_FORMAT!r}")
    if raw.get("version") != GATES_LOCK_VERSION:
        raise GatesError(f"unsupported version in {path}: {raw.get('version')!r}")

    return raw


def save_gates_lock(
    circuits: Mapping[str, CircuitCounts],
    path: Path = DEFAULT_GATES_LOCK,
    toolchain_lock_path: Path = DEFAULT_TOOLCHAIN_LOCK,
    threshold_percent: float = DEFAULT_THRESHOLD_PERCENT,
) -> None:
    """Save updated counts to zk/bench/gates.lock.json."""
    toolchain_info = load_toolchain_info(toolchain_lock_path)
    circuits_data = {
        name: counts.to_dict() if isinstance(counts, CircuitCounts) else counts
        for name, counts in sorted(circuits.items())
    }

    payload = {
        "format": GATES_LOCK_FORMAT,
        "version": GATES_LOCK_VERSION,
        "description": (
            "Committed ACIR opcode and backend gate counts per circuit. "
            f"Regressions exceeding threshold (default {threshold_percent:.1f}%) fail CI. "
            "Update via python zk/bench/gates.py --update."
        ),
        "threshold_percent": threshold_percent,
        "toolchain": toolchain_info,
        "circuits": circuits_data,
    }

    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")


# ── CLI Commands ────────────────────────────────────────────────────────────


def command_check(
    gates_lock_path: Path = DEFAULT_GATES_LOCK,
    threshold_override: float | None = None,
    summary_path: Path | None = None,
    current_counts_override: Mapping[str, CircuitCounts] | None = None,
) -> int:
    """Check current counts against gates.lock.json and print table."""
    lock_data = load_gates_lock(gates_lock_path)
    threshold = (
        threshold_override
        if threshold_override is not None
        else float(lock_data.get("threshold_percent", DEFAULT_THRESHOLD_PERCENT))
    )
    locked_circuits = lock_data.get("circuits", {})

    if current_counts_override is not None:
        current_counts = current_counts_override
    else:
        toolchain_info = load_toolchain_info()
        current_counts = measure_all_circuits(toolchain_info=toolchain_info)

    result = compare_counts(locked_circuits, current_counts, threshold_percent=threshold)

    # Print ASCII table to stdout
    print(format_ascii_table(result))
    print()

    # Markdown summary handling
    md = format_markdown_table(result)
    env_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    target_summary = summary_path or (Path(env_summary) if env_summary else None)

    if target_summary:
        try:
            target_summary.parent.mkdir(parents=True, exist_ok=True)
            with open(target_summary, "a", encoding="utf-8") as f:
                f.write(md + "\n")
            print(f"Summary written to {target_summary}")
        except Exception as exc:
            print(f"Warning: could not write summary to {target_summary}: {exc}", file=sys.stderr)

    if result.has_regression:
        print("ERROR: Circuit gate or opcode count regression detected!", file=sys.stderr)
        return EXIT_REGRESSION

    print(f"OK: All {len(result.diffs)} circuits within {threshold:.1f}% threshold.")
    return EXIT_OK


def command_update(
    gates_lock_path: Path = DEFAULT_GATES_LOCK,
    toolchain_lock_path: Path = DEFAULT_TOOLCHAIN_LOCK,
    threshold_percent: float = DEFAULT_THRESHOLD_PERCENT,
    counts_override: Mapping[str, CircuitCounts] | None = None,
) -> int:
    """Recompute counts and update gates.lock.json."""
    toolchain_info = load_toolchain_info(toolchain_lock_path)
    if counts_override is not None:
        counts = counts_override
    else:
        counts = measure_all_circuits(toolchain_info=toolchain_info)

    save_gates_lock(
        counts,
        path=gates_lock_path,
        toolchain_lock_path=toolchain_lock_path,
        threshold_percent=threshold_percent,
    )
    print(f"Updated {gates_lock_path} for {len(counts)} circuits.")
    diffs = [
        CircuitDiff(
            name=name,
            locked_opcodes=c.acir_opcodes,
            actual_opcodes=c.acir_opcodes,
            opcode_growth_pct=0.0,
            locked_gates=c.backend_gates,
            actual_gates=c.backend_gates,
            gate_growth_pct=0.0,
            status="OK",
        )
        for name, c in sorted(counts.items())
    ]
    print(format_ascii_table(ComparisonResult(diffs=diffs, has_regression=False, threshold_percent=threshold_percent)))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check or update ZK circuit ACIR opcode and backend gate counts."
    )
    parser.add_argument(
        "--lock",
        type=Path,
        default=DEFAULT_GATES_LOCK,
        help="Path to gates.lock.json (default: zk/bench/gates.lock.json)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Percentage growth threshold to fail CI (default: 5.0 or lock setting)",
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=None,
        help="File path to write markdown summary (default: $GITHUB_STEP_SUMMARY)",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="One-command action to recompute counts and write gates.lock.json",
    )
    parser.add_argument(
        "cmd",
        nargs="?",
        default=None,
        choices=["check", "update"],
        help="Subcommand: check (default) or update",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.update or args.cmd == "update":
            threshold = args.threshold if args.threshold is not None else DEFAULT_THRESHOLD_PERCENT
            return command_update(
                gates_lock_path=args.lock,
                threshold_percent=threshold,
            )

        # Default mode is check
        return command_check(
            gates_lock_path=args.lock,
            threshold_override=args.threshold,
            summary_path=args.summary,
        )
    except GatesError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_FATAL
    except Exception as exc:
        print(f"Fatal error: {exc}", file=sys.stderr)
        return EXIT_FATAL


if __name__ == "__main__":
    sys.exit(main())
