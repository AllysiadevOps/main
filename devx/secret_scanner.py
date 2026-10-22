#!/usr/bin/env python3
"""Privacy-preserving secret scanner for Harpocrates contributions.

Scans the repository for real media, secrets, witness values, and private keys.
Ensures that failure responses are stable and privacy-safe; sensitive values are never logged.
Handles malformed, oversized, expired, revoked, unsupported, and dependency-failure inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

# Privacy-preserving matchers. We only log the category of the violation, never the matched text.
STELLAR_SECRET_REGEX = re.compile(rb'\bS[A-Z2-7]{55}\b')
PRIVATE_KEY_REGEX = re.compile(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |AGE )?PRIVATE KEY')

RULES: Tuple[Tuple[str, re.Pattern[bytes]], ...] = (
    ("stellar_secret_key", STELLAR_SECRET_REGEX),
    ("private_key", PRIVATE_KEY_REGEX),
)

# Blocked extensions to prevent committing real sensitive media or large witness files
MEDIA_EXTENSIONS = {".mp4", ".mov", ".avi", ".mkv", ".jpg", ".jpeg", ".png", ".wav", ".mp3"}
WITNESS_EXTENSIONS = {".tr"}

# Max file size to scan to prevent memory exhaustion (oversized input check)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MiB

# Test fixtures and test suites containing synthetic/test credentials allowlisted from secret detection
ALLOWLISTED_SECRET_PATHS = {
    "devx/test_c2pa_parser.py",
    "devx/test_validate_c2pa_fixture.py",
    "devx/test_secret_scanner.py",
    "devx/tests/test_retain_proof_artifacts.py",
    "backend/test_redaction_adversarial.py",
    "backend/test_trace_fields.py",
}

ALLOWLISTED_FIXTURE_PREFIXES = (
    "devx/fixtures/",
)


def compute_line_hash(line: str | bytes) -> str:
    """Compute privacy-preserving SHA-256 hash of a line without trailing line endings."""
    if isinstance(line, str):
        line_bytes = line.rstrip("\r\n").encode("utf-8")
    else:
        line_bytes = line.rstrip(b"\r\n")
    return hashlib.sha256(line_bytes).hexdigest()


def rule_matches(entry_rule: str, finding_rule: str) -> bool:
    """Check if a baseline entry rule matches the finding rule."""
    if entry_rule == finding_rule:
        return True
    stellar_aliases = {"stellar_secret_key", "stellar_secret", "STELLAR_SECRET_REGEX"}
    if entry_rule in stellar_aliases and finding_rule in stellar_aliases:
        return True
    private_key_aliases = {"private_key", "rsa_private_key", "PRIVATE_KEY_REGEX"}
    if entry_rule in private_key_aliases and finding_rule in private_key_aliases:
        return True
    if entry_rule == "secrets violation: private key detected":
        return True
    return False


def load_baseline(baseline_path: Path) -> List[Dict[str, str]]:
    """Load baseline entries from JSON file."""
    if not baseline_path.exists():
        return []
    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        return []
    except Exception as e:
        print(f"Warning: Failed to load baseline {baseline_path}: {e}", file=sys.stderr)
        return []


def save_baseline(baseline_path: Path, entries: List[Dict[str, str]]) -> None:
    """Save baseline entries to JSON file."""
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    with open(baseline_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)
        f.write("\n")


def is_secret_allowlisted(file_path: Path | str, repo_root: Path | None = None) -> bool:
    """Check if the given file is an allowlisted test fixture or test suite."""
    posix_path = str(file_path).replace("\\", "/")
    if repo_root:
        try:
            posix_path = Path(file_path).resolve().relative_to(Path(repo_root).resolve()).as_posix()
        except (ValueError, OSError):
            pass

    for allowed in ALLOWLISTED_SECRET_PATHS:
        if posix_path == allowed or posix_path.endswith("/" + allowed):
            return True
            
    for prefix in ALLOWLISTED_FIXTURE_PREFIXES:
        if posix_path.startswith(prefix) or ("/" + prefix) in posix_path:
            return True

    return False


def get_files_to_scan(repo_root: Path) -> List[str]:
    """Retrieve the list of files to scan. Prefers git tracked files if available."""
    try:
        result = subprocess.run(
            ["git", "ls-files"], 
            cwd=repo_root, 
            capture_output=True, 
            text=True, 
            check=True
        )
        return [f.replace("\\", "/") for f in result.stdout.splitlines() if f]
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Fallback to walking the directory
        files = []
        for root, dirs, filenames in os.walk(repo_root):
            for d in [".git", "node_modules", "target", "dist", ".venv", "__pycache__"]:
                if d in dirs:
                    dirs.remove(d)
            for filename in filenames:
                rel_path = os.path.relpath(os.path.join(root, filename), repo_root).replace("\\", "/")
                files.append(rel_path)
        return files


def find_secrets(file_path: Path, repo_root: Path | None = None) -> List[Dict[str, str]]:
    """Scan a file and return secret findings as {path, rule, line_hash}."""
    findings = []
    if not file_path.is_file():
        return findings
    try:
        if file_path.stat().st_size > MAX_FILE_SIZE:
            return findings
        content = file_path.read_bytes()
    except OSError:
        return findings

    if b"harpocrates:ignore-file" in content or b"trufflehog:ignore" in content:
        return findings

    if repo_root:
        try:
            rel_path = file_path.resolve().relative_to(Path(repo_root).resolve()).as_posix()
        except (ValueError, OSError):
            rel_path = str(file_path).replace("\\", "/")
    else:
        try:
            rel_path = file_path.as_posix()
        except Exception:
            rel_path = str(file_path).replace("\\", "/")

    for line in content.splitlines():
        line_hash = compute_line_hash(line)
        for rule_name, regex in RULES:
            if regex.search(line):
                findings.append({
                    "path": rel_path,
                    "rule": rule_name,
                    "line_hash": line_hash,
                })
    return findings


def scan_file(
    file_path: Path,
    repo_root: Path | None = None,
    baseline: List[Dict[str, str]] | None = None,
    matched_entries: Optional[Set[int]] = None,
) -> List[str]:
    """Scan a single file for restricted extensions and sensitive contents."""
    errors = []
    
    # Check for unsupported or blocked file extensions (media/witness)
    suffix = file_path.suffix.lower()
    
    # Whitelist specific files
    rel_path = str(file_path).replace("\\", "/")
    if repo_root:
        try:
            rel_path = file_path.resolve().relative_to(Path(repo_root).resolve()).as_posix()
        except (ValueError, OSError):
            rel_path = str(file_path).replace("\\", "/")
    else:
        try:
            rel_path = file_path.as_posix()
        except Exception:
            rel_path = str(file_path).replace("\\", "/")

    if "frontend/src/assets/" in rel_path:
        # We allow media in assets
        pass
    else:
        if suffix in MEDIA_EXTENSIONS:
            errors.append("unsupported input: real media files are prohibited")
        if suffix in WITNESS_EXTENSIONS:
            errors.append("unsupported input: witness values are prohibited")
        
    if not file_path.exists():
        return errors
        
    if not file_path.is_file():
        return errors
        
    try:
        size = file_path.stat().st_size
        if size > MAX_FILE_SIZE:
            errors.append("oversized input: file exceeds maximum scan size")
            return errors
    except OSError:
        errors.append("malformed input: unable to stat file")
        return errors

    try:
        content = file_path.read_bytes()
    except OSError:
        errors.append("dependency-failure: unable to read file contents")
        return errors

    # Scan for credentials without capturing or logging the actual secret
    if b"harpocrates:ignore-file" not in content and b"trufflehog:ignore" not in content:
        for line in content.splitlines():
            line_hash = compute_line_hash(line)
            for rule_name, regex in RULES:
                if regex.search(line):
                    # Check baseline suppression
                    matched = False
                    if baseline is not None:
                        for idx, entry in enumerate(baseline):
                            entry_path = entry.get("path", "").replace("\\", "/")
                            if (
                                (entry_path == rel_path or rel_path.endswith("/" + entry_path) or entry_path.endswith("/" + rel_path) or entry_path == Path(file_path).name)
                                and entry.get("line_hash") == line_hash
                                and rule_matches(entry.get("rule", ""), rule_name)
                            ):
                                matched = True
                                if matched_entries is not None:
                                    matched_entries.add(idx)
                                break
                    if matched:
                        continue

                    # Check allowlist for synthetic test fixtures and suites
                    if is_secret_allowlisted(file_path, repo_root=repo_root):
                        continue

                    errors.append("secrets violation: private key detected")

    return errors


def main(argv: List[str] | None = None, repo_root: Path | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Privacy-preserving secret scanner for Harpocrates contributions."
    )
    parser.add_argument(
        "--baseline",
        default="devx/secret_baseline.json",
        help="Path to baseline file listing known suppressed findings (default: devx/secret_baseline.json)",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Write current findings to the baseline file",
    )
    args = parser.parse_args(argv)

    if repo_root is None:
        repo_root = Path(__file__).resolve().parents[1]

    baseline_path = Path(args.baseline)
    if not baseline_path.is_absolute():
        baseline_path = repo_root / baseline_path

    files = get_files_to_scan(repo_root)

    try:
        baseline_rel = baseline_path.resolve().relative_to(repo_root.resolve()).as_posix()
    except (ValueError, OSError):
        baseline_rel = str(baseline_path).replace("\\", "/")

    if args.update_baseline:
        all_findings = []
        for rel_path in files:
            file_path = repo_root / rel_path
            if file_path.name == "secret_scanner.py" or rel_path == baseline_rel:
                continue
            all_findings.extend(find_secrets(file_path, repo_root=repo_root))

        unique_findings = []
        seen = set()
        for f in all_findings:
            key = (f["path"], f["rule"], f["line_hash"])
            if key not in seen:
                seen.add(key)
                unique_findings.append({
                    "path": f["path"],
                    "rule": f["rule"],
                    "line_hash": f["line_hash"],
                })
        unique_findings.sort(key=lambda x: (x["path"], x["rule"], x["line_hash"]))
        save_baseline(baseline_path, unique_findings)
        print(f"Updated baseline with {len(unique_findings)} entries at {baseline_path}")
        return 0

    baseline_entries = load_baseline(baseline_path)
    matched_indices: Set[int] = set()
    has_errors = False

    for rel_path in files:
        file_path = repo_root / rel_path

        # Skip this scanner script itself and baseline file
        if file_path.name == "secret_scanner.py" or rel_path == baseline_rel:
            continue

        file_errors = scan_file(
            file_path,
            repo_root=repo_root,
            baseline=baseline_entries,
            matched_entries=matched_indices,
        )

        if file_errors:
            has_errors = True
            for err in set(file_errors):
                # Ensure stable, privacy-safe failure responses
                print(f"[{rel_path}] {err}", file=sys.stderr)

    # Warn about stale baseline entries
    for idx, entry in enumerate(baseline_entries):
        if idx not in matched_indices:
            print(
                f"Warning: Stale baseline entry: [{entry.get('path')}] rule '{entry.get('rule')}' (hash {entry.get('line_hash')})",
                file=sys.stderr,
            )

    if has_errors:
        print("Secret scanning failed: Unsafe boundaries detected.", file=sys.stderr)
        return 1

    print("Secret scanning passed: All boundaries safe.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
