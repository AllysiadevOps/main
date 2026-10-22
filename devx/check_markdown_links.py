#!/usr/bin/env python3
"""Check relative Markdown links and heading anchors across the repository.

Exits non-zero listing file:line for broken links.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

# Root directory of the repository
REPO_ROOT = Path(__file__).resolve().parents[1]

# Default directories or patterns to ignore during recursive search
DEFAULT_EXCLUDE_DIRS = {
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    ".cargo",
    ".venv",
    "venv",
    "__pycache__",
}

# Regex to match Markdown link syntax: [text](target) or ![alt](target)
# Handles optional title: [text](target "title") or [text](<target>)
LINK_RE = re.compile(r'(?:!?)\[(?P<text>[^\]]*)\]\((?P<target>[^)]+)\)')

# Regex to match Markdown headings
HEADING_RE = re.compile(r'^(?P<hashes>#{1,6})\s+(?P<title>.+)$')

# External URL scheme prefix check
EXTERNAL_SCHEMES = ("http://", "https://", "mailto:", "ftp://", "ftps://")


@dataclass(frozen=True)
class BrokenLink:
    file_path: Path
    line_number: int
    target: str
    reason: str

    def format(self, root: Optional[Path] = None) -> str:
        display_path = self.file_path
        if root:
            try:
                display_path = self.file_path.relative_to(root)
            except ValueError:
                pass
        # Normalize to forward slashes for cross-platform consistency
        path_str = str(display_path).replace("\\", "/")
        return f"{path_str}:{self.line_number}: broken link '{self.target}' ({self.reason})"


def github_slug(text: str) -> str:
    """Generate a heading slug following GitHub's anchor rules.

    GitHub heading anchor algorithm:
    1. Strip raw HTML tags (<...>)
    2. Convert characters to lowercase
    3. Remove punctuation characters (keeps letters, numbers, spaces, hyphens, underscores)
    4. Replace each space with a hyphen '-'
    """
    # 1. Remove HTML tags
    cleaned = re.sub(r"<[^>]+>", "", text)
    # 2. Lowercase
    cleaned = cleaned.lower()
    # 3. Strip punctuation: keep alphanumeric, whitespace, hyphens, and underscores
    # Note: in Python regex, [^\w\s-] matches punctuation (where \w includes alphanumeric and underscore)
    cleaned = re.sub(r"[^\w\s-]", "", cleaned)
    # 4. Replace whitespace with hyphens
    cleaned = re.sub(r"\s", "-", cleaned)
    return cleaned


def extract_headings(file_content: str) -> Set[str]:
    """Extract all heading anchor slugs from markdown file content.

    Handles duplicate headings by appending -1, -2, etc. per GitHub rules.
    Skips headings inside fenced code blocks.
    Also extracts explicit HTML anchor names/ids (<a id="..." name="...">).
    """
    headings: Set[str] = set()
    slug_counts: Dict[str, int] = {}
    lines = file_content.replace("\r\n", "\n").replace("\r", "\n").split("\n")

    in_fenced_code = False
    fenced_delimiter = ""

    for line in lines:
        stripped = line.strip()

        # Fenced code block detection (``` or ~~~)
        if stripped.startswith("```") or stripped.startswith("~~~"):
            fence = stripped[:3]
            if not in_fenced_code:
                in_fenced_code = True
                fenced_delimiter = fence
                continue
            elif stripped.startswith(fenced_delimiter):
                in_fenced_code = False
                continue

        if in_fenced_code:
            continue

        # Check for HTML anchors: <a id="..." or <a name="..."
        for m in re.finditer(r'<a\s+[^>]*?(?:id|name)=["\']([^"\']+)["\']', line, re.IGNORECASE):
            headings.add(m.group(1).lower())

        # Check for Markdown heading
        match = HEADING_RE.match(line)
        if match:
            raw_title = match.group("title").strip()
            # Strip trailing heading markers e.g. "## Heading ##"
            raw_title = re.sub(r"\s*#+\s*$", "", raw_title)
            base_slug = github_slug(raw_title)
            if base_slug in slug_counts:
                slug_counts[base_slug] += 1
                unique_slug = f"{base_slug}-{slug_counts[base_slug]}"
            else:
                slug_counts[base_slug] = 0
                unique_slug = base_slug

            headings.add(unique_slug)

    return headings


def find_markdown_files(root_dir: Path, exclude_dirs: Optional[Set[str]] = None) -> List[Path]:
    """Find all markdown (.md) files under root_dir, respecting exclude_dirs."""
    if exclude_dirs is None:
        exclude_dirs = DEFAULT_EXCLUDE_DIRS

    md_files: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Exclude directories in-place to avoid traversing them
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for f in filenames:
            if f.endswith(".md"):
                md_files.append(Path(dirpath) / f)

    return sorted(md_files)


def clean_target(raw_target: str) -> str:
    """Clean raw target url extracted from markdown link."""
    target = raw_target.strip()
    # Strip enclosing angle brackets: <path/to/file>
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()

    # Strip title if present: path/to/file "optional title" or 'optional title'
    title_match = re.match(r'^(\S+)\s+["\'].*["\']$', target)
    if title_match:
        target = title_match.group(1)

    return target


def check_external_link(url: str, timeout: float = 5.0) -> Tuple[bool, str]:
    """Verify external HTTP/HTTPS URL with timeout."""
    if url.startswith("mailto:"):
        return True, ""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Harpocrates-Link-Checker/1.0"},
            method="HEAD",
        )
        with urllib.request.urlopen(req, timeout=timeout):
            return True, ""
    except urllib.error.HTTPError as e:
        # Some servers disallow HEAD; try GET with range or fall back
        if e.code in (403, 405):
            try:
                req_get = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Harpocrates-Link-Checker/1.0", "Range": "bytes=0-1024"},
                )
                with urllib.request.urlopen(req_get, timeout=timeout):
                    return True, ""
            except Exception as inner_e:
                return False, f"HTTP error {e.code}: {inner_e}"
        return False, f"HTTP error {e.code}"
    except Exception as e:
        return False, f"Request failed: {e}"


def check_markdown_file(
    file_path: Path,
    headings_cache: Dict[Path, Set[str]],
    check_external: bool = False,
    external_timeout: float = 5.0,
    repo_root: Optional[Path] = None,
) -> List[BrokenLink]:
    """Parse links in a markdown file and verify targets and anchors."""
    broken: List[BrokenLink] = []

    try:
        content = file_path.read_text(encoding="utf-8")
    except Exception as e:
        return [BrokenLink(file_path, 1, str(file_path), f"Cannot read file: {e}")]

    lines = content.replace("\r\n", "\n").replace("\r", "\n").split("\n")

    in_fenced_code = False
    fenced_delimiter = ""

    for line_idx, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Fenced code block detection
        if stripped.startswith("```") or stripped.startswith("~~~"):
            fence = stripped[:3]
            if not in_fenced_code:
                in_fenced_code = True
                fenced_delimiter = fence
                continue
            elif stripped.startswith(fenced_delimiter):
                in_fenced_code = False
                continue

        if in_fenced_code:
            continue

        for match in LINK_RE.finditer(line):
            raw_target = match.group("target")
            target = clean_target(raw_target)

            if not target:
                continue

            # Ignore empty anchor # or template parameters
            if target == "#":
                continue

            # External URL handling
            if target.startswith(EXTERNAL_SCHEMES):
                if check_external:
                    ok, err = check_external_link(target, timeout=external_timeout)
                    if not ok:
                        broken.append(BrokenLink(file_path, line_idx, target, err))
                continue

            # Split path and fragment / anchor
            if "#" in target:
                target_path_str, anchor = target.split("#", 1)
            else:
                target_path_str, anchor = target, ""

            # Unquote percent-encoding (e.g. %20 -> space)
            target_path_str = urllib.parse.unquote(target_path_str)
            anchor = urllib.parse.unquote(anchor).strip()

            target_file: Path
            if not target_path_str:
                # Same file anchor e.g. #my-section
                target_file = file_path
            else:
                # Relative or root-relative path
                if target_path_str.startswith("/"):
                    # Relative to repo root if available
                    base = repo_root if repo_root else file_path.parent
                    target_file = (base / target_path_str.lstrip("/")).resolve()
                else:
                    target_file = (file_path.parent / target_path_str).resolve()

                if not target_file.exists():
                    broken.append(
                        BrokenLink(
                            file_path,
                            line_idx,
                            target,
                            f"Target file does not exist: {target_path_str}",
                        )
                    )
                    continue

            # Check heading anchor if target is a Markdown file and anchor is non-empty
            if anchor and target_file.is_file() and target_file.suffix.lower() == ".md":
                if target_file not in headings_cache:
                    try:
                        headings_cache[target_file] = extract_headings(
                            target_file.read_text(encoding="utf-8")
                        )
                    except Exception:
                        headings_cache[target_file] = set()

                valid_anchors = headings_cache[target_file]
                if anchor.lower() not in valid_anchors:
                    broken.append(
                        BrokenLink(
                            file_path,
                            line_idx,
                            target,
                            f"Anchor '#{anchor}' not found in target file",
                        )
                    )

    return broken


def check_all_markdown_files(
    root_dir: Path,
    files: Optional[Iterable[Path]] = None,
    check_external: bool = False,
    external_timeout: float = 5.0,
) -> List[BrokenLink]:
    """Scan all markdown files in root_dir and return all broken links."""
    if files is None:
        files = find_markdown_files(root_dir)

    headings_cache: Dict[Path, Set[str]] = {}
    all_broken: List[BrokenLink] = []

    for file_path in files:
        broken = check_markdown_file(
            file_path,
            headings_cache=headings_cache,
            check_external=check_external,
            external_timeout=external_timeout,
            repo_root=root_dir,
        )
        all_broken.extend(broken)

    return all_broken


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify relative Markdown links and heading anchors across the repository."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Specific files or directories to check (defaults to whole repository)",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root directory (defaults to parent of devx)",
    )
    parser.add_argument(
        "--external",
        action="store_true",
        help="Also check external URLs (network access required)",
    )
    parser.add_argument(
        "--external-timeout",
        type=float,
        default=5.0,
        help="Timeout in seconds for external URL requests (default 5.0)",
    )

    args = parser.parse_args(argv)

    root_dir = args.root.resolve()
    target_files: List[Path] = []

    if args.paths:
        for p in args.paths:
            resolved = (root_dir / p).resolve() if not p.is_absolute() else p.resolve()
            if resolved.is_file() and resolved.suffix.lower() == ".md":
                target_files.append(resolved)
            elif resolved.is_dir():
                target_files.extend(find_markdown_files(resolved))
    else:
        target_files = find_markdown_files(root_dir)

    print(f"Checking {len(target_files)} Markdown file(s) under {root_dir}...")
    broken_links = check_all_markdown_files(
        root_dir=root_dir,
        files=target_files,
        check_external=args.external,
        external_timeout=args.external_timeout,
    )

    if broken_links:
        print(f"\nFound {len(broken_links)} broken link(s):\n", file=sys.stderr)
        for bl in broken_links:
            print(bl.format(root=root_dir), file=sys.stderr)
        return 1

    print("All Markdown links and heading anchors are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
