#!/usr/bin/env python3
"""Validate .github/labels.yml and .github/labeler.yml for Harpocrates.

Checks performed
----------------
labels.yml
  - Required top-level keys: schema_version (int == 1), labels (list).
  - Every label has: name (str), color (6-char hex, no leading #), description (str).
  - Name follows <namespace>/<slug> convention (namespace in NAMESPACES).
  - Description is non-empty and below MAX_DESCRIPTION_BYTES.
  - No duplicate label names.
  - No forbidden sensitive terms in names or descriptions (privacy guard).
  - File does not exceed MAX_FILE_BYTES.

labeler.yml (cross-reference mode)
  - Every label referenced exists in labels.yml.
  - Every glob pattern entry has the required changed-files structure.
  - File does not exceed MAX_FILE_BYTES.

Privacy guarantee
-----------------
Descriptions are scanned for patterns that could inadvertently document secret
material (private keys, witnesses, nullifier values, credentials).  A match
fails validation so that label metadata cannot become an accidental data sink.

Exit codes
----------
  0   all checks passed
  1   validation error (printed to stderr)
  2   file not found or unreadable
  3   YAML parse error
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    print("pyyaml is required: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from devx._io import (
    find_sensitive_match as _io_find_sensitive_match,
    read_text_bounded as _io_read_text_bounded,
)

# ── constants ─────────────────────────────────────────────────────────────────

MAX_FILE_BYTES = 64 * 1024          # 64 KiB — labels files are never large
MAX_DESCRIPTION_BYTES = 512
SCHEMA_VERSION = 1
COLOR_RE = re.compile(r"^[0-9a-fA-F]{6}$")
NAME_RE = re.compile(r"^[a-z0-9_/-]+$")

# Namespaces that must be present in labels.yml for the gate to be satisfied.
REQUIRED_NAMESPACES = {"impact", "layer", "type", "status"}

# Patterns whose presence in a label name or description signals accidental
# inclusion of secret material.  Checked case-insensitively.
SENSITIVE_PATTERNS = [
    re.compile(r"\bprivate[_\s-]?key\b", re.I),
    re.compile(r"\bnullifier[_\s-]?value\b", re.I),
    re.compile(r"\bcredential[_\s-]?secret\b", re.I),
    re.compile(r"\bmnemonic\b", re.I),
    re.compile(r"\bapi[_\s-]?token\b", re.I),
    re.compile(r"\bpassword\b", re.I),
    re.compile(r"-----BEGIN", re.I),
]


class LabelConfigError(ValueError):
    """Raised for any validation failure."""


# ── helpers ───────────────────────────────────────────────────────────────────

def _load_yaml(path: Path) -> Any:
    """Read and parse a YAML file, enforcing the size limit."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise FileNotFoundError(f"cannot stat {path}: {exc}") from exc
    if size > MAX_FILE_BYTES:
        raise LabelConfigError(
            f"{path}: file is {size} bytes, exceeds {MAX_FILE_BYTES} limit"
        )
    try:
        text = _io_read_text_bounded(
            path,
            limit=MAX_FILE_BYTES,
            display_name=str(path),
        )
    except (OSError, ValueError) as exc:
        raise FileNotFoundError(f"cannot read {path}: {exc}") from exc

    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise yaml.YAMLError(f"{path}: YAML parse error: {exc}") from exc


def _check_sensitive(text: str, location: str) -> None:
    """Fail if text contains any sensitive pattern."""
    match_info = _io_find_sensitive_match(text, SENSITIVE_PATTERNS)
    if match_info is not None:
        pattern, _match = match_info
        raise LabelConfigError(
            f"{location}: forbidden sensitive term matched by "
            f"pattern {pattern.pattern!r}"
        )


# ── labels.yml validation ─────────────────────────────────────────────────────

def validate_labels(data: Any, source: str = "<labels.yml>") -> list[str]:
    """Validate a parsed labels.yml structure.

    Returns the sorted list of canonical label names on success.
    Raises LabelConfigError on the first problem found.
    """
    if not isinstance(data, dict):
        raise LabelConfigError(f"{source}: root must be a YAML mapping")

    sv = data.get("schema_version")
    if sv != SCHEMA_VERSION:
        raise LabelConfigError(
            f"{source}: schema_version must be {SCHEMA_VERSION}, got {sv!r}"
        )

    labels = data.get("labels")
    if not isinstance(labels, list) or not labels:
        raise LabelConfigError(f"{source}: 'labels' must be a non-empty list")

    seen_names: set[str] = set()
    seen_namespaces: set[str] = set()

    for idx, entry in enumerate(labels):
        loc = f"{source}[{idx}]"
        if not isinstance(entry, dict):
            raise LabelConfigError(f"{loc}: each label must be a mapping")

        # Required fields
        for field in ("name", "color", "description"):
            if field not in entry:
                raise LabelConfigError(f"{loc}: missing required field {field!r}")

        name: str = entry["name"]
        color: str = entry["color"]
        description: str = entry["description"]

        # Types
        if not isinstance(name, str) or not name:
            raise LabelConfigError(f"{loc}: 'name' must be a non-empty string")
        if not isinstance(color, str):
            raise LabelConfigError(f"{loc}: 'color' must be a string")
        if not isinstance(description, str) or not description.strip():
            raise LabelConfigError(f"{loc}: 'description' must be a non-empty string")

        # Name format: lowercase, no leading #, uses / as namespace separator
        name_clean = name.strip()
        if not NAME_RE.match(name_clean):
            raise LabelConfigError(
                f"{loc}: name {name_clean!r} must match {NAME_RE.pattern}"
            )

        # Track namespace
        parts = name_clean.split("/", 1)
        if len(parts) > 1:
            seen_namespaces.add(parts[0])

        # Color — 6-char hex without leading #
        if color.startswith("#"):
            raise LabelConfigError(
                f"{loc}: color {color!r} must not include a leading '#'"
            )
        if not COLOR_RE.match(color):
            raise LabelConfigError(
                f"{loc}: color {color!r} must be a 6-character hex string"
            )

        # Description length
        desc_bytes = description.encode("utf-8")
        if len(desc_bytes) > MAX_DESCRIPTION_BYTES:
            raise LabelConfigError(
                f"{loc}: description is {len(desc_bytes)} bytes, "
                f"exceeds {MAX_DESCRIPTION_BYTES} limit"
            )

        # Privacy scan on both name and description
        _check_sensitive(name_clean, f"{loc}.name")
        _check_sensitive(description, f"{loc}.description")

        # Duplicate names
        if name_clean in seen_names:
            raise LabelConfigError(f"{loc}: duplicate label name {name_clean!r}")
        seen_names.add(name_clean)

    # Required namespaces must be represented
    missing = REQUIRED_NAMESPACES - seen_namespaces
    if missing:
        raise LabelConfigError(
            f"{source}: missing required namespaces: "
            + ", ".join(sorted(missing))
        )

    return sorted(seen_names)


# ── labeler.yml cross-reference ───────────────────────────────────────────────

def validate_labeler(
    labeler_data: Any,
    canonical_names: set[str],
    source: str = "<labeler.yml>",
) -> None:
    """Check every label in labeler.yml exists in labels.yml.

    Also verifies that each top-level entry has the expected changed-files
    structure as used by actions/labeler v5.
    """
    if not isinstance(labeler_data, dict):
        raise LabelConfigError(f"{source}: root must be a YAML mapping")

    unknown: list[str] = []
    malformed: list[str] = []

    for label_name, rules in labeler_data.items():
        if label_name not in canonical_names:
            unknown.append(label_name)

        # Each value should be a list of rule objects with 'changed-files'
        if not isinstance(rules, list):
            malformed.append(f"{label_name}: rules must be a list")
            continue
        for rule_idx, rule in enumerate(rules):
            if not isinstance(rule, dict):
                malformed.append(
                    f"{label_name}[{rule_idx}]: rule must be a mapping"
                )
                continue
            if "changed-files" not in rule:
                malformed.append(
                    f"{label_name}[{rule_idx}]: missing 'changed-files' key"
                )

    errors: list[str] = []
    if unknown:
        errors.append(
            f"{source}: labels not defined in labels.yml: "
            + ", ".join(sorted(unknown))
        )
    if malformed:
        errors.append(
            f"{source}: malformed labeler rules: " + "; ".join(malformed)
        )
    if errors:
        raise LabelConfigError("\n".join(errors))


# ── CLI ───────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate Harpocrates label configuration files."
    )
    parser.add_argument(
        "--check",
        metavar="LABELS_YML",
        help="Validate a labels.yml file.",
    )
    parser.add_argument(
        "--check-labeler",
        nargs=2,
        metavar=("LABELER_YML", "LABELS_YML"),
        help="Cross-check labeler.yml against labels.yml.",
    )
    args = parser.parse_args(argv)

    if not args.check and not args.check_labeler:
        parser.print_help()
        return 0

    try:
        if args.check:
            labels_path = Path(args.check)
            data = _load_yaml(labels_path)
            names = validate_labels(data, source=str(labels_path))
            namespaces = sorted({n.split("/")[0] for n in names if "/" in n})
            print(
                f"labels.yml ok: {len(names)} labels, "
                f"namespaces: {', '.join(namespaces)}"
            )

        if args.check_labeler:
            labeler_path = Path(args.check_labeler[0])
            labels_path = Path(args.check_labeler[1])
            labels_data = _load_yaml(labels_path)
            canonical = set(validate_labels(labels_data, source=str(labels_path)))
            labeler_data = _load_yaml(labeler_path)
            validate_labeler(labeler_data, canonical, source=str(labeler_path))
            print(
                f"labeler.yml ok: {len(labeler_data)} entries, "
                f"all labels present in labels.yml"
            )

    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except yaml.YAMLError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except LabelConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
