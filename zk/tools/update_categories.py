"""Noir assertion message normalization maintenance tool.

This utility consolidates legacy one-off scripts (formerly update_categories.py
and update_categories.js at the repository root) used to normalize descriptive
assertion failure messages in Noir circuits (zk/noir/**/*.nr) into standard
categorical error classifications (e.g. "malformed", "revoked", "unsupported",
"oversized").

When to use:
Use this script only during intentional codemod passes or when vendoring/importing
external Noir circuits that require assertion message categorization. Do not run as
part of standard builds or CI.

Usage:
    python zk/tools/update_categories.py [path/to/circuits]
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path


REPLACEMENTS: list[tuple[str | re.Pattern[str], str]] = [
    ('"credential root mismatch"', '"malformed"'),
    ('"nullifier mismatch"', '"malformed"'),
    ('"revocation root mismatch"', '"malformed"'),
    (re.compile(r'"credential is in revocation set \(leaf \d+\)"'), '"revoked"'),
    ('"domain tag mismatch"', '"unsupported"'),
    # Selective disclosure assertions
    ('"unknown predicate type"', '"unsupported"'),
    ('"equality predicate failed"', '"malformed"'),
    ('"set membership predicate failed"', '"malformed"'),
    ('"range predicate: below lower bound"', '"malformed"'),
    ('"range predicate: above upper bound"', '"malformed"'),
    ('"at least one attribute required"', '"malformed"'),
    ('"too many attributes"', '"oversized"'),
    ('"too many predicates"', '"oversized"'),
    ('"predicate attribute index out of range"', '"malformed"'),
    ('"set membership predicate requires non-empty set"', '"malformed"'),
    ('"set membership predicate: too many set values"', '"oversized"'),
    ('"verifier digest must be non-zero"', '"malformed"'),
    (re.compile(r'"root \d+ mismatch"'), '"malformed"'),
    (re.compile(r'"nullifier \d+ mismatch"'), '"malformed"'),
]


def update_file(filepath: Path) -> bool:
    """Apply category replacements to a single Noir file."""
    content = filepath.read_text(encoding="utf-8")
    original = content

    for pattern, replacement in REPLACEMENTS:
        if isinstance(pattern, re.Pattern):
            content = pattern.sub(replacement, content)
        else:
            content = content.replace(pattern, replacement)

    if content != original:
        filepath.write_text(content, encoding="utf-8")
        return True
    return False


def update_categories(target_dir: Path | str) -> int:
    """Walk target_dir and update all .nr files."""
    target_path = Path(target_dir)
    if not target_path.exists():
        raise FileNotFoundError(f"Target directory does not exist: {target_path}")

    modified_count = 0
    for root, _, files in os.walk(target_path):
        for file in files:
            if file.endswith(".nr"):
                filepath = Path(root) / file
                if update_file(filepath):
                    modified_count += 1
    return modified_count


def main() -> None:
    if len(sys.argv) > 1:
        target_dir = Path(sys.argv[1])
    else:
        repo_root = Path(__file__).resolve().parent.parent.parent
        target_dir = repo_root / "zk" / "noir"

    count = update_categories(target_dir)
    print(f"Updated {count} Noir files in {target_dir}")


if __name__ == "__main__":
    main()
