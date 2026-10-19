#!/usr/bin/env python3
"""Validate .github/dependabot.yml configuration for Harpocrates.

Enforces policy for automated dependency updates:
- Version 2 configuration with required package ecosystems:
  * npm (/frontend, /cli)
  * pip (/backend)
  * cargo (/contracts)
  * github-actions (/)
- Grouped low-risk patch updates across all ecosystems.
- Sensitive dependency isolation: Stellar, Noir, and proof-system packages
  must be kept separate for focused review (excluded from generic patch groups
  or tracked in dedicated review groups).
- Conservative schedule (weekly or monthly) and PR limits (<= 10).
- Privacy and security: no hardcoded secrets or credentials.

Exit codes:
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

MAX_FILE_BYTES = 64 * 1024  # 64 KiB
ALLOWED_INTERVALS = {"weekly", "monthly"}
MAX_PR_LIMIT = 10

REQUIRED_SURFACES = [
    {"ecosystem": "npm", "directory": "/frontend"},
    {"ecosystem": "npm", "directory": "/cli"},
    {"ecosystem": "pip", "directory": "/backend"},
    {"ecosystem": "cargo", "directory": "/contracts"},
    {"ecosystem": "github-actions", "directory": "/"},
]

# Sensitive patterns that must never appear in config files
SENSITIVE_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{8,}", re.IGNORECASE),
]


class DependabotConfigError(Exception):
    """Raised when Dependabot configuration violates repository policy."""


def _check_sensitive_text(raw_text: str) -> None:
    match_info = _io_find_sensitive_match(raw_text, SENSITIVE_PATTERNS)
    if match_info is not None:
        _pat, match = match_info
        raise DependabotConfigError(
            f"forbidden credential pattern detected in config: {match.group(0)[:16]}..."
        )


def validate_dependabot_config(data: Any) -> list[str]:
    """Validate parsed Dependabot configuration.

    Returns a list of validation finding messages. An empty list means valid.
    """
    findings: list[str] = []

    if not isinstance(data, dict):
        return ["root must be a mapping (dict)"]

    if data.get("version") != 2:
        findings.append(f"version must be 2, got {data.get('version')!r}")

    updates = data.get("updates")
    if not isinstance(updates, list):
        findings.append("`updates` must be a list")
        return findings

    # Check each required surface is present
    for target in REQUIRED_SURFACES:
        matched = [
            u for u in updates
            if isinstance(u, dict)
            and u.get("package-ecosystem") == target["ecosystem"]
            and u.get("directory") == target["directory"]
        ]
        if not matched:
            findings.append(
                f"missing required update target: ecosystem={target['ecosystem']} directory={target['directory']}"
            )

    for idx, update in enumerate(updates):
        if not isinstance(update, dict):
            findings.append(f"updates[{idx}] must be a dict")
            continue

        ecosystem = update.get("package-ecosystem")
        directory = update.get("directory")
        loc = f"{ecosystem}:{directory}"

        # 1. Schedule checks
        schedule = update.get("schedule")
        if not isinstance(schedule, dict):
            findings.append(f"{loc}: missing `schedule` mapping")
        else:
            interval = schedule.get("interval")
            if interval not in ALLOWED_INTERVALS:
                findings.append(
                    f"{loc}: schedule interval must be one of {sorted(ALLOWED_INTERVALS)}, got {interval!r}"
                )

        # 2. PR limit checks
        pr_limit = update.get("open-pull-requests-limit")
        if pr_limit is None:
            findings.append(f"{loc}: `open-pull-requests-limit` must be explicitly specified")
        elif not isinstance(pr_limit, int) or pr_limit < 0 or pr_limit > MAX_PR_LIMIT:
            findings.append(
                f"{loc}: `open-pull-requests-limit` must be an integer between 0 and {MAX_PR_LIMIT}, got {pr_limit!r}"
            )

        # 3. Grouped updates check
        groups = update.get("groups")
        if not isinstance(groups, dict) or not groups:
            findings.append(f"{loc}: must configure at least one grouped update under `groups`")
            continue

        # Verify low-risk patch grouping exists
        has_patch_group = False
        for g_name, g_cfg in groups.items():
            if isinstance(g_cfg, dict):
                u_types = g_cfg.get("update-types", [])
                if isinstance(u_types, list) and "patch" in u_types:
                    has_patch_group = True
                    break

        if not has_patch_group:
            findings.append(f"{loc}: must configure a group for patch updates with `update-types: ['patch']`")

        # 4. Stellar / Noir / proof system isolation checks
        if directory in ("/frontend", "/cli", "/contracts"):
            # Check exclusions from generic patch group or dedicated groups
            patch_group = None
            for g_cfg in groups.values():
                if isinstance(g_cfg, dict) and "patch" in g_cfg.get("update-types", []):
                    patch_group = g_cfg
                    break

            excluded = set(patch_group.get("exclude-patterns", [])) if patch_group else set()

            if directory in ("/frontend", "/cli"):
                has_stellar_excluded = any("stellar" in p.lower() for p in excluded)
                has_stellar_group = any("stellar" in g.lower() for g in groups.keys())
                if not (has_stellar_excluded or has_stellar_group):
                    findings.append(
                        f"{loc}: Stellar dependencies must be excluded from generic patch groups or placed in a dedicated review group"
                    )

            if directory == "/frontend":
                has_noir_excluded = any(
                    any(term in p.lower() for term in ("noir", "aztec", "barretenberg"))
                    for p in excluded
                )
                has_noir_group = any(
                    any(term in g.lower() for term in ("noir", "proof", "aztec"))
                    for g in groups.keys()
                )
                if not (has_noir_excluded or has_noir_group):
                    findings.append(
                        f"{loc}: Noir and proof-system dependencies must be excluded from generic patch groups or placed in a dedicated review group"
                    )

            if directory == "/contracts":
                has_contract_excluded = any(
                    any(term in p.lower() for term in ("soroban", "stellar"))
                    for p in excluded
                )
                has_contract_group = any(
                    any(term in g.lower() for term in ("soroban", "stellar"))
                    for g in groups.keys()
                )
                if not (has_contract_excluded or has_contract_group):
                    findings.append(
                        f"{loc}: Soroban / Stellar contract dependencies must be excluded from generic patch groups or placed in a dedicated review group"
                    )

    return findings


def check_file(path: Path) -> int:
    """Validate a dependabot.yml file from disk. Returns process exit code."""
    if not path.is_file():
        print(f"error: file not found: {path}", file=sys.stderr)
        return 2

    try:
        raw_text = _io_read_text_bounded(
            path,
            limit=MAX_FILE_BYTES,
            display_name=str(path),
        )
    except OSError as e:
        print(f"error: cannot read {path}: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        msg = str(e)
        if "exceeds the" in msg:
            size = path.stat().st_size
            print(f"error: file size {size} exceeds limit of {MAX_FILE_BYTES} bytes", file=sys.stderr)
            return 1
        print(f"error: cannot read {path}: {e}", file=sys.stderr)
        return 2

    try:
        _check_sensitive_text(raw_text)
    except DependabotConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as e:
        print(f"error: YAML parse error in {path}: {e}", file=sys.stderr)
        return 3

    findings = validate_dependabot_config(data)
    if findings:
        for f in findings:
            print(f"error: {f}", file=sys.stderr)
        return 1

    update_count = len(data.get("updates", []))
    print(f"dependabot.yml ok: {update_count} update target(s) configured and verified")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate Harpocrates Dependabot configuration."
    )
    parser.add_argument(
        "--check",
        type=Path,
        default=Path(".github/dependabot.yml"),
        help="Path to dependabot.yml (default: .github/dependabot.yml)",
    )
    args = parser.parse_args(argv)
    return check_file(args.check)


if __name__ == "__main__":
    sys.exit(main())
