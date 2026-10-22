#!/usr/bin/env python3
"""Check that pull requests touching protocol paths include a changelog fragment.

Checks performed
----------------
1. If the PR carries the bypass label ('no-changelog'), the check passes immediately.
2. If any touched path falls under protocol paths (contracts/, zk/noir/, release/compatibility-manifest.json):
   - A valid fragment file must exist in changelog.d/*.md (excluding README.md and hidden files).
   - Each fragment must contain at least one valid type header:
     ### Added, ### Changed, ### Fixed, or ### Security (case-insensitive)
     followed by changelog entries.

Exit codes
----------
  0   Check passed (either not touching protocol paths, fragment present & valid, or bypassed)
  1   Validation failure (protocol path touched without fragment, or fragment is invalid)
  2   Usage / configuration error
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Iterable, Sequence

# Canonical protocol paths defined in the issue specification
PROTOCOL_PATH_PREFIXES = (
    "contracts/",
    "zk/noir/",
    "release/compatibility-manifest.json",
)

BYPASS_LABEL = "no-changelog"

VALID_TYPES = ("added", "changed", "fixed", "security")
TYPE_HEADER_RE = re.compile(r"^###\s+([A-Za-z]+)\s*$", re.MULTILINE)


class ChangelogCheckError(Exception):
    """Raised when changelog fragment verification fails."""


def normalize_path(path: str) -> str:
    """Normalize a path to forward slashes with leading ./ removed."""
    normalized = path.replace("\\", "/").strip()
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def is_protocol_path(path: str) -> bool:
    """Return True if the given path touches protocol components."""
    norm = normalize_path(path)
    for prefix in PROTOCOL_PATH_PREFIXES:
        if prefix.endswith("/"):
            if norm == prefix[:-1] or norm.startswith(prefix):
                return True
        else:
            if norm == prefix:
                return True
    return False


def touches_protocol_paths(changed_files: Iterable[str]) -> list[str]:
    """Filter changed files to those that match protocol paths."""
    matched = [f for f in changed_files if is_protocol_path(f)]
    matched.sort()
    return matched


def parse_labels(labels_arg: str | Sequence[str] | None) -> set[str]:
    """Parse label names from a comma-separated string, JSON list, or iterable."""
    if not labels_arg:
        return set()
    if isinstance(labels_arg, str):
        trimmed = labels_arg.strip()
        if not trimmed:
            return set()
        if trimmed.startswith("[") and trimmed.endswith("]"):
            try:
                parsed = json.loads(trimmed)
                if isinstance(parsed, list):
                    labels = set()
                    for item in parsed:
                        if isinstance(item, dict) and "name" in item:
                            labels.add(item["name"])
                        elif isinstance(item, str):
                            labels.add(item)
                    return labels
            except json.JSONDecodeError:
                pass
        return {item.strip() for item in trimmed.split(",") if item.strip()}
    return {str(item).strip() for item in labels_arg if str(item).strip()}


def has_bypass_label(labels: Iterable[str], bypass_label: str = BYPASS_LABEL) -> bool:
    """Return True if any of the given labels matches the bypass label."""
    return bypass_label.lower() in {lbl.lower() for lbl in labels}


def is_fragment_file(path: Path | str) -> bool:
    """Return True if the filename qualifies as a changelog fragment."""
    name = Path(path).name
    if name.startswith(".") or name.lower() == "readme.md":
        return False
    return name.endswith(".md")


def parse_fragment(content: str, filename: str = "") -> dict[str, list[str]]:
    """Parse a changelog fragment into sections by type.

    Each section starts with `### <type>` (Added, Changed, Fixed, Security).
    Returns a dict mapping lowercase type name to list of entry strings.
    Raises ChangelogCheckError if no valid headers exist or invalid type header found.
    """
    sections: dict[str, list[str]] = {}
    current_type: str | None = None
    current_lines: list[str] = []

    lines = content.splitlines()
    has_header = False

    for line in lines:
        match = TYPE_HEADER_RE.match(line)
        if match:
            raw_type = match.group(1).lower()
            if raw_type not in VALID_TYPES:
                raise ChangelogCheckError(
                    f"Fragment '{filename}' has invalid type header '{match.group(0).strip()}'. "
                    f"Allowed types: {', '.join(t.capitalize() for t in VALID_TYPES)}"
                )
            if current_type is not None:
                text = "\n".join(current_lines).strip()
                if text:
                    sections.setdefault(current_type, []).append(text)
            current_type = raw_type
            current_lines = []
            has_header = True
        else:
            if current_type is not None:
                current_lines.append(line)
            elif line.strip() and not has_header:
                # Content before any header
                pass

    if current_type is not None:
        text = "\n".join(current_lines).strip()
        if text:
            sections.setdefault(current_type, []).append(text)

    if not has_header:
        raise ChangelogCheckError(
            f"Fragment '{filename}' must contain at least one valid type header "
            f"(e.g., '### Added', '### Changed', '### Fixed', '### Security')."
        )

    # Ensure there is actual content in at least one section
    total_entries = sum(len(entries) for entries in sections.values())
    if total_entries == 0:
        raise ChangelogCheckError(
            f"Fragment '{filename}' has type header(s) but contains no entry items."
        )

    return sections


def find_fragments(changelog_dir: Path) -> list[Path]:
    """Find all valid fragment paths in changelog_dir."""
    if not changelog_dir.is_dir():
        return []
    fragments = [
        p for p in changelog_dir.iterdir()
        if p.is_file() and is_fragment_file(p)
    ]
    fragments.sort(key=lambda p: p.name)
    return fragments


def validate_fragments_in_dir(changelog_dir: Path) -> list[Path]:
    """Find and validate all fragments in the given changelog directory."""
    fragments = find_fragments(changelog_dir)
    if not fragments:
        raise ChangelogCheckError(
            f"No changelog fragments found in {changelog_dir}. "
            f"Please add a fragment file in changelog.d/<name>.md"
        )
    for frag in fragments:
        content = frag.read_text(encoding="utf-8")
        parse_fragment(content, frag.name)
    return fragments


def check_pr(
    changed_files: Sequence[str],
    labels: Iterable[str],
    changelog_dir: Path,
) -> tuple[bool, str]:
    """Perform full check on changed files and labels.

    Returns (passed, message).
    """
    label_set = parse_labels(labels)
    if has_bypass_label(label_set):
        return True, f"Bypassed changelog fragment check via label '{BYPASS_LABEL}'."

    proto_changes = touches_protocol_paths(changed_files)
    if not proto_changes:
        return True, "No protocol paths touched; changelog fragment not required."

    # Protocol paths touched, fragment required
    try:
        valid_frags = validate_fragments_in_dir(changelog_dir)
    except ChangelogCheckError as err:
        return False, (
            f"Protocol paths modified ({len(proto_changes)} file(s)), but changelog fragment check failed:\n"
            f"  {err}\n"
            f"Modified protocol files:\n" + "\n".join(f"  - {f}" for f in proto_changes)
        )

    frag_names = [f.name for f in valid_frags]
    return True, (
        f"Changelog fragment check passed. Modified protocol paths: {len(proto_changes)}. "
        f"Found {len(frag_names)} valid fragment(s): {', '.join(frag_names)}."
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify changelog fragments for pull requests modifying protocol paths."
    )
    parser.add_argument(
        "--changed-files",
        nargs="*",
        default=None,
        help="List of changed file paths in the PR.",
    )
    parser.add_argument(
        "--changed-files-file",
        type=Path,
        default=None,
        help="Path to a file containing changed file paths (one per line).",
    )
    parser.add_argument(
        "--labels",
        default=None,
        help="Comma-separated labels or JSON array string of PR labels.",
    )
    parser.add_argument(
        "--labels-file",
        type=Path,
        default=None,
        help="Path to a file containing PR labels (one per line or JSON).",
    )
    parser.add_argument(
        "--changelog-dir",
        type=Path,
        default=None,
        help="Directory where changelog fragments are located (default: changelog.d).",
    )
    parser.add_argument(
        "--bypass-label",
        default=BYPASS_LABEL,
        help=f"Label to bypass changelog fragment check (default: {BYPASS_LABEL}).",
    )

    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parents[1]
    changelog_dir = args.changelog_dir or (root / "changelog.d")

    # Gather changed files
    files: list[str] = []
    if args.changed_files:
        files.extend(args.changed_files)
    if args.changed_files_file and args.changed_files_file.is_file():
        content = args.changed_files_file.read_text(encoding="utf-8")
        files.extend(line.strip() for line in content.splitlines() if line.strip())

    # Gather labels
    labels_raw: list[str] = []
    if args.labels:
        labels_raw.append(args.labels)
    if args.labels_file and args.labels_file.is_file():
        labels_raw.append(args.labels_file.read_text(encoding="utf-8"))

    # If running in GitHub Actions without explicit changed files, attempt git diff if possible
    if not files and os.getenv("GITHUB_BASE_REF"):
        import subprocess
        base = os.getenv("GITHUB_BASE_REF")
        try:
            res = subprocess.run(
                ["git", "diff", "--name-only", f"origin/{base}...HEAD"],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                files.extend(line.strip() for line in res.stdout.splitlines() if line.strip())
        except Exception:
            pass

    label_set = parse_labels(labels_raw)
    passed, message = check_pr(files, label_set, changelog_dir)

    if passed:
        print(f"SUCCESS: {message}")
        return 0
    else:
        print(f"FAILURE: {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
