#!/usr/bin/env python3
"""Fold changelog fragments from changelog.d/ into CHANGELOG.md.

Produces deterministic, canonically ordered changelog sections:
- Types are ordered: Added, Changed, Fixed, Security.
- Within each type, fragments are processed in alphanumeric order of fragment filenames.
- Strips merged fragment files (or preserves them with --no-delete).
- Can target an existing release header (e.g. '## Unreleased') or insert a new release section.

Exit codes
----------
  0   Success (fragments folded or nothing to fold)
  1   Error (e.g. malformed fragment or CHANGELOG.md target header not found)
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

# Make devx/ importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_changelog_fragment import (
    VALID_TYPES,
    find_fragments,
    parse_fragment,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CHANGELOG = ROOT / "CHANGELOG.md"
DEFAULT_CHANGELOG_DIR = ROOT / "changelog.d"

# Order defined for changelog sections
TYPE_ORDER = ("added", "changed", "fixed", "security")
TYPE_TITLES = {
    "added": "Added",
    "changed": "Changed",
    "fixed": "Fixed",
    "security": "Security",
}


def collect_fragment_entries(
    fragments: Sequence[Path],
) -> dict[str, list[str]]:
    """Collect entries from all fragments grouped by type in deterministic order.

    Returns dict mapping lowercase type -> list of formatted entries.
    Fragments are processed in deterministic sorted filename order.
    """
    sorted_frags = sorted(fragments, key=lambda p: p.name)
    grouped: dict[str, list[str]] = {t: [] for t in TYPE_ORDER}

    for frag in sorted_frags:
        content = frag.read_text(encoding="utf-8")
        parsed = parse_fragment(content, frag.name)
        for t in TYPE_ORDER:
            if t in parsed:
                for entry in parsed[t]:
                    grouped[t].append(entry)

    return grouped


def format_folded_section(
    grouped_entries: dict[str, list[str]],
    use_subheadings: bool = False,
) -> str:
    """Format the collected entries into markdown text.

    If use_subheadings is True, outputs:
      ### Added
      - entry
    Otherwise (standard existing changelog style in repository), outputs bullet points:
      - Added ...
      - Changed ...
      - Fixed ...
    """
    lines: list[str] = []

    for t in TYPE_ORDER:
        entries = grouped_entries.get(t, [])
        if not entries:
            continue

        if use_subheadings:
            lines.append(f"### {TYPE_TITLES[t]}\n")
            for entry in entries:
                lines.append(entry.strip())
            lines.append("")
        else:
            for entry in entries:
                lines.append(entry.strip())

    return "\n".join(lines).strip()


def fold_into_changelog_content(
    changelog_content: str,
    folded_text: str,
    release_header: str | None = None,
) -> str:
    """Insert folded entries into the changelog under the specified header or the first release section.

    If release_header is specified (e.g. '## Unreleased'), inserts entries under that header.
    If release_header does not exist, or None is provided:
      If '## Unreleased' exists in file, inserts directly below it.
      Otherwise, inserts below the '# Changelog' top heading.
    """
    if not folded_text.strip():
        return changelog_content

    lines = changelog_content.splitlines()

    target_idx = -1
    if release_header:
        target_norm = release_header.strip().lower()
        for idx, line in enumerate(lines):
            if line.strip().lower() == target_norm:
                target_idx = idx
                break
        if target_idx == -1:
            raise ValueError(f"Target release header '{release_header}' not found in CHANGELOG.md")
    else:
        # Look for ## Unreleased or first '## ' section
        for idx, line in enumerate(lines):
            if line.strip().startswith("## Unreleased") or line.strip().startswith("## [Unreleased]"):
                target_idx = idx
                break
        if target_idx == -1:
            # Fall back to finding '# Changelog'
            for idx, line in enumerate(lines):
                if line.strip().startswith("# Changelog"):
                    target_idx = idx
                    break

    if target_idx == -1:
        # Prepend to file
        return folded_text + "\n\n" + changelog_content

    # Insert after target header line and any blank line immediately following it
    insert_pos = target_idx + 1
    if insert_pos < len(lines) and not lines[insert_pos].strip():
        insert_pos += 1

    new_lines = (
        lines[:insert_pos]
        + [folded_text, ""]
        + lines[insert_pos:]
    )

    result = "\n".join(new_lines)
    # Ensure trailing newline
    if not result.endswith("\n"):
        result += "\n"
    return result


def fold_fragments(
    changelog_path: Path,
    changelog_dir: Path,
    release_header: str | None = None,
    delete_fragments: bool = True,
    dry_run: bool = False,
    use_subheadings: bool = False,
) -> tuple[int, str]:
    """Fold fragments from changelog_dir into changelog_path.

    Returns (count_of_fragments_folded, message).
    """
    fragments = find_fragments(changelog_dir)
    if not fragments:
        return 0, "No fragments to fold."

    grouped = collect_fragment_entries(fragments)
    folded_text = format_folded_section(grouped, use_subheadings=use_subheadings)

    if not folded_text:
        return 0, "Fragments did not contain any valid entries."

    if not changelog_path.is_file():
        raise FileNotFoundError(f"CHANGELOG file not found at {changelog_path}")

    current_changelog = changelog_path.read_text(encoding="utf-8")
    updated_changelog = fold_into_changelog_content(
        current_changelog,
        folded_text,
        release_header=release_header,
    )

    if not dry_run:
        changelog_path.write_text(updated_changelog, encoding="utf-8")
        if delete_fragments:
            for frag in fragments:
                frag.unlink()

    return len(fragments), f"Successfully folded {len(fragments)} fragment(s) into {changelog_path.name}."


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fold changelog fragments into CHANGELOG.md deterministically."
    )
    parser.add_argument(
        "--changelog",
        type=Path,
        default=DEFAULT_CHANGELOG,
        help="Path to CHANGELOG.md (default: repo root CHANGELOG.md)",
    )
    parser.add_argument(
        "--changelog-dir",
        type=Path,
        default=DEFAULT_CHANGELOG_DIR,
        help="Directory containing fragment files (default: changelog.d)",
    )
    parser.add_argument(
        "--release-header",
        default=None,
        help="Release header to insert entries under (e.g., '## Unreleased')",
    )
    parser.add_argument(
        "--no-delete",
        action="store_true",
        help="Do not delete fragment files after folding.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not write changes to disk; report what would be done.",
    )
    parser.add_argument(
        "--use-subheadings",
        action="store_true",
        help="Group entries under '### Added', '### Changed', etc. subheadings.",
    )

    args = parser.parse_args(argv)

    try:
        count, msg = fold_fragments(
            changelog_path=args.changelog,
            changelog_dir=args.changelog_dir,
            release_header=args.release_header,
            delete_fragments=not args.no_delete,
            dry_run=args.dry_run,
            use_subheadings=args.use_subheadings,
        )
        print(msg)
        return 0
    except Exception as exc:
        print(f"Error folding changelog fragments: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
