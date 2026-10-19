#!/usr/bin/env python3
"""Verify dependency pins and lockfiles across the Harpocrates repository.

Why this gate exists
--------------------
Harpocrates ships four dependency surfaces, and each one pins versions with a
different mechanism that fails silently in a different way:

``backend/requirements.txt`` (pip)
    There is no lockfile, so the requirements file *is* the pin.  A bare name
    or a ``>=`` range silently floats the interpreter that verifies C2PA
    manifests and RFC 3161 chains between two runs of the same commit.

``cli`` and ``frontend`` (npm)
    ``package-lock.json`` is the pin, so the manifest is allowed to carry
    ranges.  Editing ``package.json`` without re-running ``npm install``
    leaves the lock describing a tree that is not the tree under review, and
    CI installs the stale one.

``contracts`` (cargo)
    ``Cargo.lock`` is the pin for a workspace whose output is Soroban
    bytecode deployed on-chain.  A missing or stale lock changes the artifact
    that gets deployed, not just the build time.

``zk`` (noir)
    ``zk/toolchain.lock.json`` pins the compiler and proving backend that
    produce the ACIR bundles and verification keys, which must be
    byte-identical across two independent builds.

Checks performed
----------------
pip
  - Every requirement is ``name``/``name[extras]`` followed by ``==`` (or
    ``===``) and a concrete version, optionally with an environment marker.
  - Ranges, bare names, wildcard versions, option lines (``-e``, ``-r``, ...)
    and direct URLs are rejected: none of them can be reproduced from a clean
    checkout.
  - Duplicate distributions (PEP 503 canonicalized) are rejected.
  - Lines that look like pasted credentials are rejected by line number; the
    matched value is never echoed back into CI logs.

npm
  - ``package-lock.json`` exists next to every workspace manifest, uses
    ``lockfileVersion`` 2 or newer, and names the same package.
  - The lock's root package dependency maps match ``package.json`` exactly,
    which is the drift check for "manifest edited, install not run".
  - Every declared dependency is resolved to a package entry in the lock.
  - Wildcard/dist-tag specifiers and remote or local link specifiers are
    rejected; semver ranges are fine because the lock resolves them.

cargo
  - ``Cargo.lock`` exists, declares ``version`` 3 or newer, and contains a
    package entry for every registry dependency reachable from the workspace
    root and its members (``workspace = true`` is resolved through
    ``[workspace.dependencies]``).
  - Workspace member packages appear in the lock at the version their
    manifest declares, catching a lock that predates a member bump.
  - ``=x.y.z`` pins must be resolved at exactly that version; short numeric
    requirements (``"27"``) must at least resolve within their own prefix.
  - ``path`` dependencies are treated as local; ``git`` dependencies must pin
    ``rev`` or ``tag`` (a ``branch`` is a moving target).

noir
  - ``zk/toolchain.lock.json`` exists and pins a concrete ``nargo`` and
    ``barretenberg`` version; ``latest``/``*`` style values are rejected.
  - Every ``zk/noir/*/Nargo.toml`` declares a constrained
    ``compiler_version``, and its dependencies are local paths that exist or
    git sources that pin ``rev``/``tag``.

Exit codes
----------
  0   every dependency surface is pinned and in sync
  1   policy finding (unpinned dependency, drift, stale lock)
  2   an input is missing or unreadable
  3   an input does not parse as JSON or TOML

Privacy
-------
Only dependency names, versions, and workspace-relative paths are read,
printed, and reported.  Secrets, media, witness values, and private keys are
never logged; credential-looking requirement lines are reported by line
number only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - the release gate pins 3.12
    print(
        "python 3.11+ is required (tomllib); the release gate uses 3.12",
        file=sys.stderr,
    )
    raise SystemExit(1)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from devx._io import (
    contains_sensitive_text as _io_contains_sensitive_text,
    read_json_bounded as _io_read_json_bounded,
    read_text_bounded as _io_read_text_bounded,
    read_toml_bounded as _io_read_toml_bounded,
)


# ── repository layout ─────────────────────────────────────────────────────────

PIP_MANIFEST = "backend/requirements.txt"
NPM_WORKSPACES = ("cli", "frontend")
CARGO_WORKSPACE = "contracts"
ZK_TOOLCHAIN_LOCK = "zk/toolchain.lock.json"
ZK_CIRCUITS_DIR = "zk/noir"

# ── limits ────────────────────────────────────────────────────────────────────

MAX_FILE_BYTES = 4 * 1024 * 1024   # 4 MiB; the largest committed lock is ~190 KiB
MAX_FINDINGS = 200                 # bound on report size for a hostile tree
MAX_LISTED = 6                     # items named per message before "…"

# ── policy ────────────────────────────────────────────────────────────────────

EXACT_PIP_OPERATORS = ("==", "===")
UNPINNED_VERSIONS = {"", "*", "x", "X", "latest", "head", "main", "master"}
NPM_REMOTE_PREFIXES = (
    "git+",
    "git://",
    "github:",
    "gitlab:",
    "bitbucket:",
    "http://",
    "https://",
    "file:",
    "link:",
    "portal:",
)
NPM_DEP_FIELDS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)
CARGO_DEP_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")
MIN_CARGO_LOCK_VERSION = 3
MIN_NPM_LOCKFILE_VERSION = 2

# name[extras] operator version [; marker] — the only accepted pip grammar.
PIP_REQUIREMENT_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[(?P<extras>[A-Za-z0-9._,-]+)\])?"
    r"\s*(?P<operator>===|==|~=|!=|>=|<=|>|<)\s*"
    r"(?P<version>[^\s;#]+)"
    r"(?:\s*;\s*(?P<marker>[^#]+))?$"
)
PIP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9._,-]+\])?$")
NUMERIC_VERSION_RE = re.compile(r"^[0-9]+(\.[0-9]+)*$")

# Matched against manifest lines so a pasted token is flagged, never printed.
SECRET_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bsk-[A-Za-z0-9]{16,}"),
    re.compile(r"\bnpm_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bwitness\b.*[0-9a-fA-F]{32,}"),
)


class PinError(ValueError):
    """Raised when a single manifest entry cannot be parsed or validated."""


# ── report ────────────────────────────────────────────────────────────────────

@dataclass
class Report:
    """Collected findings, grouped by exit-code severity."""

    max_findings: int = MAX_FINDINGS
    findings: list[str] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    summaries: list[str] = field(default_factory=list)
    suppressed: int = 0

    def finding(self, message: str) -> None:
        if len(self.findings) >= self.max_findings:
            self.suppressed += 1
            return
        self.findings.append(message)

    def extend_findings(self, messages: list[str]) -> None:
        for message in messages:
            self.finding(message)

    def exit_code(self) -> int:
        if self.unreadable:
            return 2
        if self.parse_errors:
            return 3
        if self.findings:
            return 1
        return 0

    def ok(self) -> bool:
        return self.exit_code() == 0

    def as_dict(self, root: Path) -> dict[str, Any]:
        return {
            "ok": self.ok(),
            "exitCode": self.exit_code(),
            "root": str(root),
            "summaries": self.summaries,
            "findings": self.findings,
            "unreadable": self.unreadable,
            "parseErrors": self.parse_errors,
            "counts": {
                "findings": len(self.findings),
                "suppressed": self.suppressed,
            },
        }


# ── loading ───────────────────────────────────────────────────────────────────

def _check_size(path: Path, report: Report) -> bool:
    """Return False (and record it) if the file exceeds MAX_FILE_BYTES."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        report.unreadable.append(f"{path}: cannot stat: {exc}")
        return False
    if size > MAX_FILE_BYTES:
        report.unreadable.append(
            f"{path}: {size} bytes exceeds the {MAX_FILE_BYTES} byte limit"
        )
        return False
    return True


def read_text(path: Path, report: Report) -> str | None:
    """Read a UTF-8 text file, recording size and I/O problems."""
    if not path.is_file():
        report.unreadable.append(f"{path}: file is missing")
        return None
    try:
        return _io_read_text_bounded(
            path,
            limit=MAX_FILE_BYTES,
            display_name=str(path),
        )
    except OSError as exc:
        report.unreadable.append(f"{path}: cannot read: {exc}")
        return None
    except ValueError as exc:
        msg = str(exc)
        if "exceeds the" in msg:
            size = path.stat().st_size
            report.unreadable.append(
                f"{path}: {size} bytes exceeds the {MAX_FILE_BYTES} byte limit"
            )
        elif "not valid UTF-8" in msg:
            report.parse_errors.append(f"{path}: not valid UTF-8: {exc.__cause__ or exc}")
        else:
            report.unreadable.append(f"{path}: cannot read: {exc}")
        return None


def load_json(path: Path, report: Report) -> Any | None:
    """Parse a JSON file, recording parse failures."""
    if not path.is_file():
        report.unreadable.append(f"{path}: file is missing")
        return None
    try:
        return _io_read_json_bounded(
            path,
            limit=MAX_FILE_BYTES,
            display_name=str(path),
            sensitive_pattern=None,
            require_dict=False,
        )
    except OSError as exc:
        report.unreadable.append(f"{path}: cannot read: {exc}")
        return None
    except ValueError as exc:
        msg = str(exc)
        if "exceeds the" in msg:
            size = path.stat().st_size
            report.unreadable.append(
                f"{path}: {size} bytes exceeds the {MAX_FILE_BYTES} byte limit"
            )
        elif "malformed JSON" in msg:
            report.parse_errors.append(f"{path}: invalid JSON: {exc.__cause__ or exc}")
        elif "not valid UTF-8" in msg:
            report.parse_errors.append(f"{path}: not valid UTF-8: {exc.__cause__ or exc}")
        else:
            report.unreadable.append(f"{path}: cannot read: {exc}")
        return None


def load_toml(path: Path, report: Report) -> Any | None:
    """Parse a TOML file, recording parse failures."""
    if not path.is_file():
        report.unreadable.append(f"{path}: file is missing")
        return None
    try:
        return _io_read_toml_bounded(
            path,
            limit=MAX_FILE_BYTES,
            display_name=str(path),
        )
    except OSError as exc:
        report.unreadable.append(f"{path}: cannot read: {exc}")
        return None
    except ValueError as exc:
        msg = str(exc)
        if "exceeds the" in msg:
            size = path.stat().st_size
            report.unreadable.append(
                f"{path}: {size} bytes exceeds the {MAX_FILE_BYTES} byte limit"
            )
        elif "malformed TOML" in msg:
            report.parse_errors.append(f"{path}: invalid TOML: {exc.__cause__ or exc}")
        elif "not valid UTF-8" in msg:
            report.parse_errors.append(f"{path}: not valid UTF-8: {exc.__cause__ or exc}")
        else:
            report.unreadable.append(f"{path}: cannot read: {exc}")
        return None


def _clip(items: list[str]) -> str:
    """Render a bounded, sorted, comma-separated list for a message."""
    ordered = sorted(items)
    head = ordered[:MAX_LISTED]
    if len(ordered) > MAX_LISTED:
        head.append(f"… {len(ordered) - MAX_LISTED} more")
    return ", ".join(head)


def _has_secret(text: str) -> bool:
    return _io_contains_sensitive_text(text, SECRET_PATTERNS)


# ── pip (backend/requirements.txt) ────────────────────────────────────────────

@dataclass(frozen=True)
class Requirement:
    """One parsed requirements.txt entry."""

    name: str
    extras: tuple[str, ...]
    operator: str
    version: str
    marker: str | None

    @property
    def canonical_name(self) -> str:
        """PEP 503 normalized distribution name."""
        return re.sub(r"[-_.]+", "-", self.name).lower()


def parse_pip_requirement(line: str) -> Requirement:
    """Parse a single requirement line.

    Raises PinError for option lines, direct URLs, bare names, and any other
    form that cannot be reproduced from a clean checkout.
    """
    stripped = line.strip()
    if not stripped:
        raise PinError("empty requirement line")
    if stripped.startswith("-"):
        raise PinError(
            "option lines (-e, -r, --hash, ...) cannot be pinned; "
            "inline the requirement instead"
        )
    if "://" in stripped or stripped.startswith(("git+", "hg+", "svn+")):
        raise PinError("direct URL and VCS requirements are not reproducible")
    if "/" in stripped.split(";")[0] or "@" in stripped.split(";")[0]:
        raise PinError("path and '@' requirements are not reproducible")

    match = PIP_REQUIREMENT_RE.match(stripped)
    if not match:
        if PIP_NAME_RE.match(stripped):
            raise PinError(
                f"{stripped!r} has no version specifier; "
                "pin it with '=='"
            )
        raise PinError("not a valid 'name==version' requirement")

    extras = match.group("extras")
    return Requirement(
        name=match.group("name"),
        extras=tuple(e for e in (extras or "").split(",") if e),
        operator=match.group("operator"),
        version=match.group("version"),
        marker=(match.group("marker") or "").strip() or None,
    )


def validate_pip_pins(text: str, source: str = PIP_MANIFEST) -> list[str]:
    """Validate a requirements file's contents, returning finding messages."""
    messages: list[str] = []
    requirements: list[Requirement] = []
    seen: dict[str, int] = {}

    lines = text.splitlines()
    lineno = 0
    pending = ""
    for raw_line in lines:
        lineno += 1
        line = pending + raw_line
        # A trailing backslash continues the requirement onto the next line.
        if line.rstrip().endswith("\\"):
            pending = line.rstrip()[:-1]
            continue
        pending = ""

        content = line.split("#", 1)[0].strip()
        if not content:
            continue

        location = f"{source}:{lineno}"
        if _has_secret(content):
            messages.append(
                f"{location}: line looks like a pasted credential; "
                "remove it (value intentionally not printed)"
            )
            continue
        try:
            requirement = parse_pip_requirement(content)
        except PinError as exc:
            messages.append(f"{location}: {exc}")
            continue

        if requirement.operator not in EXACT_PIP_OPERATORS:
            messages.append(
                f"{location}: {requirement.name} uses {requirement.operator!r}; "
                "an exact '==' pin is required (no lockfile exists for pip here)"
            )
            continue
        if requirement.version in UNPINNED_VERSIONS or "*" in requirement.version:
            messages.append(
                f"{location}: {requirement.name} is pinned to "
                f"{requirement.version!r}, which is not a concrete version"
            )
            continue
        if not re.match(r"^[0-9]", requirement.version):
            messages.append(
                f"{location}: {requirement.name} version "
                f"{requirement.version!r} does not start with a digit"
            )
            continue

        canonical = requirement.canonical_name
        if canonical in seen:
            messages.append(
                f"{location}: duplicate requirement {canonical!r} "
                f"(already declared on line {seen[canonical]})"
            )
            continue
        seen[canonical] = lineno
        requirements.append(requirement)

    if pending:
        messages.append(f"{source}:{lineno}: line continuation at end of file")
    if not requirements and not messages:
        messages.append(f"{source}: no pinned requirements found")
    return messages


def check_pip(root: Path, report: Report) -> None:
    """Check the pip manifest for the backend service."""
    path = root / PIP_MANIFEST
    text = read_text(path, report)
    if text is None:
        return
    messages = validate_pip_pins(text, source=PIP_MANIFEST)
    report.extend_findings(messages)
    pinned = [
        line.split("#", 1)[0].strip()
        for line in text.splitlines()
        if line.split("#", 1)[0].strip()
    ]
    if not messages:
        report.summaries.append(
            f"{PIP_MANIFEST}: {len(pinned)} requirement(s), "
            "all pinned to an exact version"
        )


# ── npm (cli/, frontend/) ─────────────────────────────────────────────────────

def validate_npm_workspace(
    manifest: Any,
    lock: Any | None,
    source: str,
    lock_source: str,
) -> list[str]:
    """Validate one npm workspace's manifest against its lockfile."""
    messages: list[str] = []
    if not isinstance(manifest, dict):
        return [f"{source}: manifest root must be a JSON object"]

    declared: dict[str, str] = {}
    for field_name in NPM_DEP_FIELDS:
        section = manifest.get(field_name)
        if section is None:
            continue
        if not isinstance(section, dict):
            messages.append(f"{source}: {field_name} must be an object")
            continue
        for name, spec in section.items():
            if not isinstance(spec, str):
                messages.append(
                    f"{source}: {field_name}.{name} must be a version string"
                )
                continue
            declared[name] = spec
            if spec.strip() in UNPINNED_VERSIONS:
                messages.append(
                    f"{source}: {field_name}.{name} is {spec!r}; "
                    "glob and dist-tag specifiers are not reviewable"
                )
            elif spec.strip().lower().startswith(NPM_REMOTE_PREFIXES):
                messages.append(
                    f"{source}: {field_name}.{name} uses non-registry source "
                    f"{spec!r}; commit-impossible to reproduce locally"
                )

    if lock is None:
        messages.append(
            f"{lock_source}: lockfile is missing; run 'npm install' in "
            "this workspace and commit the lock"
        )
        return messages
    if not isinstance(lock, dict):
        return messages + [f"{lock_source}: lockfile root must be a JSON object"]

    lockfile_version = lock.get("lockfileVersion")
    if not isinstance(lockfile_version, int) or isinstance(lockfile_version, bool):
        messages.append(f"{lock_source}: lockfileVersion must be an integer")
    elif lockfile_version < MIN_NPM_LOCKFILE_VERSION:
        messages.append(
            f"{lock_source}: lockfileVersion {lockfile_version} predates v2; "
            "regenerate the lock with a current npm"
        )

    if manifest.get("name") and lock.get("name") != manifest.get("name"):
        messages.append(
            f"{lock_source}: lock names {lock.get('name')!r} but the manifest "
            f"names {manifest.get('name')!r}"
        )

    packages = lock.get("packages")
    if not isinstance(packages, dict) or not packages:
        return messages + [
            f"{lock_source}: 'packages' map is missing or empty; "
            "regenerate the lock with lockfileVersion 2 or newer"
        ]

    root_package = packages.get("")
    if not isinstance(root_package, dict):
        messages.append(f"{lock_source}: no root '' package entry to compare")
        root_package = {}

    for field_name in ("dependencies", "devDependencies", "optionalDependencies"):
        expected = manifest.get(field_name) or {}
        actual = root_package.get(field_name) or {}
        if not isinstance(expected, dict) or not isinstance(actual, dict):
            continue
        if expected == actual:
            continue
        missing = [k for k in expected if k not in actual]
        extra = [k for k in actual if k not in expected]
        changed = [
            k for k in expected if k in actual and expected[k] != actual[k]
        ]
        detail: list[str] = []
        if missing:
            detail.append(f"absent from the lock: {_clip(missing)}")
        if extra:
            detail.append(f"only in the lock: {_clip(extra)}")
        if changed:
            detail.append(
                "resolved specifier differs: "
                + _clip([f"{k} ({expected[k]} vs {actual[k]})" for k in changed])
            )
        messages.append(
            f"{source}: {field_name} is out of sync with {lock_source} "
            f"({'; '.join(detail)}); run 'npm install' and commit the lock"
        )

    resolved: set[str] = set()
    for key in packages:
        if not isinstance(key, str) or not key:
            continue
        _, _, tail = key.rpartition("node_modules/")
        if tail:
            resolved.add(tail)

    unresolved = [name for name in declared if name not in resolved]
    if unresolved:
        messages.append(
            f"{source}: declared but not resolved in {lock_source}: "
            f"{_clip(unresolved)}"
        )
    return messages


def check_npm_workspace(root: Path, rel: str, report: Report) -> None:
    """Check one npm workspace directory."""
    manifest_rel = f"{rel}/package.json"
    lock_rel = f"{rel}/package-lock.json"
    manifest = load_json(root / manifest_rel, report)
    if manifest is None:
        return
    lock_path = root / lock_rel
    lock = load_json(lock_path, report) if lock_path.is_file() else None
    messages = validate_npm_workspace(
        manifest,
        lock,
        source=manifest_rel,
        lock_source=lock_rel,
    )
    report.extend_findings(messages)
    if not messages and isinstance(lock, dict):
        declared = sum(
            len(manifest.get(f) or {})
            for f in NPM_DEP_FIELDS
            if isinstance(manifest.get(f), dict)
        )
        report.summaries.append(
            f"{manifest_rel}: lockfileVersion {lock.get('lockfileVersion')}, "
            f"{declared} declared dependency(ies), "
            f"{len(lock.get('packages') or {})} resolved package entry(ies)"
        )


# ── cargo (contracts/) ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CargoDependency:
    """One resolved dependency declaration from a Cargo manifest."""

    name: str
    origin: str
    version: str | None = None
    path: str | None = None
    git: str | None = None
    rev: str | None = None
    tag: str | None = None
    branch: str | None = None

    @property
    def key(self) -> str:
        return re.sub(r"_", "-", self.name).lower()


def _iter_dep_tables(doc: Any) -> Iterator[tuple[str, dict]]:
    """Yield (table, mapping) for every dependency table in a Cargo manifest."""
    if not isinstance(doc, dict):
        return
    for table in CARGO_DEP_TABLES:
        section = doc.get(table)
        if isinstance(section, dict):
            yield table, section
    workspace = doc.get("workspace")
    if isinstance(workspace, dict) and isinstance(
        workspace.get("dependencies"), dict
    ):
        yield "workspace.dependencies", workspace["dependencies"]
    target = doc.get("target")
    if isinstance(target, dict):
        for cfg, section in target.items():
            if not isinstance(section, dict):
                continue
            for table in CARGO_DEP_TABLES:
                nested = section.get(table)
                if isinstance(nested, dict):
                    yield f"target.{cfg}.{table}", nested


def _cargo_dependency(
    name: str,
    value: Any,
    workspace_deps: dict,
    origin: str,
) -> tuple[CargoDependency | None, list[str]]:
    """Normalize one dependency entry, resolving `workspace = true`."""
    messages: list[str] = []
    if isinstance(value, str):
        spec: dict[str, Any] = {"version": value}
    elif isinstance(value, dict):
        spec = dict(value)
    else:
        return None, [
            f"{origin}: dependency {name!r} must be a version string or a table"
        ]

    if spec.get("workspace") is True:
        inherited = workspace_deps.get(name)
        if inherited is None:
            return None, [
                f"{origin}: {name} declares 'workspace = true' but the "
                "workspace root does not define it in [workspace.dependencies]"
            ]
        if isinstance(inherited, str):
            spec = {"version": inherited}
        elif isinstance(inherited, dict):
            if inherited.get("workspace") is True:
                return None, [
                    f"{origin}: {name} cannot inherit from itself in "
                    "[workspace.dependencies]"
                ]
            spec = dict(inherited)
        else:
            return None, [
                f"{origin}: {name} has an unusable [workspace.dependencies] entry"
            ]

    def as_text(key: str) -> str | None:
        raw = spec.get(key)
        if raw is None:
            return None
        if isinstance(raw, str):
            return raw.strip()
        return None

    return (
        CargoDependency(
            name=name,
            origin=origin,
            version=as_text("version"),
            path=as_text("path"),
            git=as_text("git"),
            rev=as_text("rev"),
            tag=as_text("tag"),
            branch=as_text("branch"),
        ),
        messages,
    )


def _cargo_version_matches(requirement: str, resolved: str) -> bool:
    """Best-effort check that `resolved` can satisfy `requirement`.

    Only the unambiguous forms are judged: an explicit ``=x.y.z`` pin, and the
    short numeric requirements (``"27"``) whose leading components Cargo
    compares as a prefix.  Full ranges are left to Cargo itself.
    """
    requirement = requirement.strip()
    if requirement.startswith("="):
        return resolved.strip() == requirement.lstrip("=").strip()
    if not NUMERIC_VERSION_RE.match(requirement):
        return True
    parts = requirement.split(".")
    resolved_parts = resolved.split(".")
    if len(parts) >= 3:
        return parts[0] == resolved_parts[0]
    if len(parts) > len(resolved_parts):
        return False
    return parts == resolved_parts[: len(parts)]


def validate_cargo_workspace(workspace: Path, report: Report) -> list[str]:
    """Validate the contract workspace manifests and lockfile.

    File level problems (missing or unparseable inputs) are recorded on the
    report; the returned list holds policy findings only.
    """
    messages: list[str] = []
    manifest_path = workspace / "Cargo.toml"
    lock_path = workspace / "Cargo.lock"
    rel = workspace.name

    doc = load_toml(manifest_path, report)
    if doc is None:
        return messages

    workspace_section = doc.get("workspace")
    workspace_deps: dict = {}
    members: list[Path] = []
    if isinstance(workspace_section, dict):
        if isinstance(workspace_section.get("dependencies"), dict):
            workspace_deps = workspace_section["dependencies"]
        patterns = workspace_section.get("members")
        if not isinstance(patterns, list) or not patterns:
            messages.append(
                f"{rel}/Cargo.toml: workspace declares no members"
            )
        else:
            excluded = {
                str(item).strip().rstrip("/")
                for item in (workspace_section.get("exclude") or [])
            }
            for pattern in patterns:
                if not isinstance(pattern, str):
                    continue
                glob = pattern if pattern.endswith("Cargo.toml") else f"{pattern}/Cargo.toml"
                matched = sorted(
                    path.parent
                    for path in workspace.glob(glob)
                    if path.is_file()
                    and str(path.parent.relative_to(workspace)) not in excluded
                    and "target" not in path.parts
                )
                if not matched:
                    messages.append(
                        f"{rel}/Cargo.toml: member pattern {pattern!r} "
                        "matches no Cargo.toml"
                    )
                members.extend(matched)

    manifests: list[tuple[str, Path, Any]] = [(f"{rel}/Cargo.toml", manifest_path, doc)]
    for member in sorted(set(members)):
        member_doc = load_toml(member / "Cargo.toml", report)
        if member_doc is None:
            continue
        manifests.append(
            (str((member / "Cargo.toml").relative_to(workspace.parent)), member / "Cargo.toml", member_doc)
        )

    declarations: list[CargoDependency] = []
    seen_keys: set[tuple] = set()
    for source, _path, manifest_doc in manifests:
        for table, entries in _iter_dep_tables(manifest_doc):
            for name, value in entries.items():
                dependency, notes = _cargo_dependency(
                    name, value, workspace_deps, f"{source} [{table}]"
                )
                messages.extend(notes)
                if dependency is None:
                    continue
                if dependency.key in seen_keys:
                    continue
                seen_keys.add(dependency.key)
                declarations.append(dependency)

    lock = load_toml(lock_path, report)
    if lock is None:
        return messages

    lock_version = lock.get("version")
    if not isinstance(lock_version, int) or isinstance(lock_version, bool):
        messages.append(f"{rel}/Cargo.lock: 'version' must be an integer")
    elif lock_version < MIN_CARGO_LOCK_VERSION:
        messages.append(
            f"{rel}/Cargo.lock: version {lock_version} predates v3; "
            "regenerate the lock with a current cargo"
        )

    packages = lock.get("package")
    if not isinstance(packages, list) or not packages:
        messages.append(f"{rel}/Cargo.lock: no [[package]] entries found")
        return messages

    resolved: dict[str, set[str]] = {}
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        version = entry.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            messages.append(
                f"{rel}/Cargo.lock: package entry without string name/version"
            )
            continue
        resolved.setdefault(re.sub(r"_", "-", name).lower(), set()).add(version)

    for source, _path, manifest_doc in manifests:
        package = manifest_doc.get("package")
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        key = re.sub(r"_", "-", name).lower()
        locked = resolved.get(key)
        if not locked:
            messages.append(
                f"{source}: workspace member {name} {version} is absent from "
                f"{rel}/Cargo.lock; run cargo to refresh the lock"
            )
        elif version not in locked:
            messages.append(
                f"{source}: workspace member {name} is {version} but "
                f"{rel}/Cargo.lock resolves {sorted(locked)}; "
                "the lock predates the manifest"
            )

    for dependency in declarations:
        if dependency.path:
            continue  # local path crate: pinned by the checkout itself
        if dependency.git and not (dependency.rev or dependency.tag):
            pinned_by = "branch" if dependency.branch else "nothing"
            messages.append(
                f"{dependency.origin}: git dependency {dependency.name} is "
                f"pinned by {pinned_by}; use 'rev' or 'tag'"
            )
        if dependency.version is not None:
            if dependency.version.strip() in UNPINNED_VERSIONS or "*" in dependency.version:
                messages.append(
                    f"{dependency.origin}: {dependency.name} uses version "
                    f"{dependency.version!r}, which floats"
                )
                continue
        locked = resolved.get(dependency.key)
        if not locked:
            messages.append(
                f"{dependency.origin}: {dependency.name} is not resolved in "
                f"{rel}/Cargo.lock"
            )
            continue
        if dependency.version and not any(
            _cargo_version_matches(dependency.version, version)
            for version in locked
        ):
            messages.append(
                f"{dependency.origin}: {dependency.name} requires "
                f"{dependency.version!r} but {rel}/Cargo.lock resolves "
                f"{sorted(locked)}"
            )
    return messages


def check_cargo(root: Path, report: Report) -> None:
    """Check the Soroban contract cargo workspace."""
    workspace = root / CARGO_WORKSPACE
    manifest_path = workspace / "Cargo.toml"
    if not manifest_path.is_file():
        report.unreadable.append(f"{manifest_path}: Cargo workspace is missing")
        return
    messages = validate_cargo_workspace(workspace, report)
    report.extend_findings(messages)
    lock = load_toml(workspace / "Cargo.lock", report) if not messages else None
    if not messages and isinstance(lock, dict):
        report.summaries.append(
            f"{CARGO_WORKSPACE}/Cargo.lock: version {lock.get('version')}, "
            f"{len(lock.get('package') or [])} resolved crate(s), "
            "all workspace dependencies present"
        )


# ── noir (zk/) ────────────────────────────────────────────────────────────────

def validate_zk_toolchain(lock: Any, source: str = ZK_TOOLCHAIN_LOCK) -> list[str]:
    """Validate zk/toolchain.lock.json pins the compiler and prover."""
    messages: list[str] = []
    if not isinstance(lock, dict):
        return [f"{source}: toolchain lock root must be a JSON object"]

    lock_version = lock.get("version")
    if not isinstance(lock_version, int) or isinstance(lock_version, bool):
        messages.append(f"{source}: 'version' must be an integer")

    toolchain = lock.get("toolchain")
    if not isinstance(toolchain, dict):
        return messages + [f"{source}: 'toolchain' mapping is missing"]

    for tool in ("nargo", "barretenberg"):
        entry = toolchain.get(tool)
        if not isinstance(entry, dict):
            messages.append(f"{source}: toolchain.{tool} entry is missing")
            continue
        version = entry.get("version")
        if not isinstance(version, str) or not version.strip():
            messages.append(f"{source}: toolchain.{tool}.version must be a string")
            continue
        if version.strip().lower() in UNPINNED_VERSIONS:
            messages.append(
                f"{source}: toolchain.{tool}.version is {version!r}; "
                "pin a concrete compiler version"
            )
    return messages


def validate_nargo_manifest(doc: Any, source: str, directory: Path) -> list[str]:
    """Validate one Nargo.toml's package and dependency declarations."""
    messages: list[str] = []
    if not isinstance(doc, dict):
        return [f"{source}: manifest root must be a TOML table"]

    package = doc.get("package")
    if not isinstance(package, dict) or not package.get("name"):
        messages.append(f"{source}: [package] must declare a name")
    else:
        compiler = package.get("compiler_version")
        if not isinstance(compiler, str) or not compiler.strip():
            messages.append(
                f"{source}: [package].compiler_version is missing; pin the "
                "circuit compiler"
            )
        elif not any(character.isdigit() for character in compiler):
            messages.append(
                f"{source}: compiler_version {compiler!r} names no version"
            )

    dependencies = doc.get("dependencies")
    if dependencies is None:
        return messages
    if not isinstance(dependencies, dict):
        return messages + [f"{source}: [dependencies] must be a table"]

    for name, value in dependencies.items():
        location = f"{source}: dependency {name!r}"
        if not isinstance(value, dict):
            messages.append(
                f"{location} must be a table with a 'path' or pinned 'git' source"
            )
            continue
        path = value.get("path")
        if isinstance(path, str) and path.strip():
            target = (directory / path.strip()).resolve()
            if not target.exists():
                messages.append(
                    f"{location} points at {path!r}, which does not exist"
                )
            continue
        git = value.get("git")
        if isinstance(git, str) and git.strip():
            if not (value.get("rev") or value.get("tag")):
                messages.append(
                    f"{location} uses a git source without 'rev' or 'tag'"
                )
            continue
        messages.append(
            f"{location} declares neither 'path' nor 'git'; it cannot be reviewed"
        )
    return messages


def check_zk(root: Path, report: Report) -> None:
    """Check the zk toolchain lock and every circuit manifest."""
    lock_path = root / ZK_TOOLCHAIN_LOCK
    if not lock_path.is_file():
        report.unreadable.append(
            f"{lock_path}: toolchain lock is missing; circuits are not "
            "reproducible without it"
        )
        return
    lock = load_json(lock_path, report)
    if lock is None:
        return
    messages = validate_zk_toolchain(lock)
    report.extend_findings(messages)

    circuits_dir = root / ZK_CIRCUITS_DIR
    manifests = sorted(circuits_dir.glob("*/Nargo.toml"))
    if not manifests:
        report.finding(
            f"{ZK_CIRCUITS_DIR}: no circuit manifests found under */Nargo.toml"
        )
        return
    for manifest in manifests:
        rel = str(manifest.relative_to(root))
        doc = load_toml(manifest, report)
        if doc is None:
            continue
        report.extend_findings(validate_nargo_manifest(doc, rel, manifest.parent))

    if not messages:
        toolchain = lock.get("toolchain") if isinstance(lock, dict) else {}
        nargo = (toolchain or {}).get("nargo") or {}
        barretenberg = (toolchain or {}).get("barretenberg") or {}
        report.summaries.append(
            f"{ZK_TOOLCHAIN_LOCK}: nargo {nargo.get('version')}, "
            f"barretenberg {barretenberg.get('version')}; "
            f"{len(manifests)} circuit manifest(s) checked"
        )


# ── entry point ───────────────────────────────────────────────────────────────

def run_checks(root: Path, max_findings: int = MAX_FINDINGS) -> Report:
    """Run every dependency-surface check against a repository root."""
    report = Report(max_findings=max(1, max_findings))
    if not root.is_dir():
        report.unreadable.append(f"{root}: repository root is not a directory")
        return report
    check_pip(root, report)
    for workspace in NPM_WORKSPACES:
        check_npm_workspace(root, workspace, report)
    check_cargo(root, report)
    check_zk(root, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify that pip, npm, cargo, and noir dependencies are pinned "
            "and that their lockfiles are in sync."
        )
    )
    parser.add_argument(
        "--root",
        default=None,
        help="repository root to scan (default: the parent of devx/)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit the report as JSON on stdout",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=MAX_FINDINGS,
        help=f"stop collecting findings after N entries (default {MAX_FINDINGS})",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parents[1]
    report = run_checks(root, max_findings=args.max_findings)

    if args.json:
        print(json.dumps(report.as_dict(root), indent=2, sort_keys=False))
    else:
        for summary in report.summaries:
            print(f"ok: {summary}")
        for message in report.findings:
            print(f"finding: {message}", file=sys.stderr)
        for message in report.unreadable:
            print(f"unreadable: {message}", file=sys.stderr)
        for message in report.parse_errors:
            print(f"parse error: {message}", file=sys.stderr)
        if report.suppressed:
            print(
                f"note: {report.suppressed} further finding(s) suppressed",
                file=sys.stderr,
            )
        if report.ok():
            print(
                f"dependency pins ok: {len(report.summaries)} surface(s) verified"
            )
        else:
            print(
                "dependency pins failed: "
                f"{len(report.findings)} finding(s), "
                f"{len(report.unreadable)} unreadable input(s), "
                f"{len(report.parse_errors)} parse error(s)",
                file=sys.stderr,
            )
    return report.exit_code()


if __name__ == "__main__":
    sys.exit(main())
