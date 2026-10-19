from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable, Sequence

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]


# Default sensitive key pattern matching concrete secret-bearing field names
DEFAULT_SENSITIVE_KEY_RE = re.compile(
    r"^(password|secret|private[_-]?key|witness|nullifier|credential|"
    r"proof_bytes|mnemonic|api[_-]?token|access[_-]?token|refresh[_-]?token)$",
    re.I,
)

# Common sensitive text patterns matching secret values / credentials
DEFAULT_SENSITIVE_TEXT_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"-----BEGIN", re.I),
    re.compile(r"\bprivate[_\s-]?key\b", re.I),
    re.compile(r"\bnullifier[_\s-]?value\b", re.I),
    re.compile(r"\bcredential[_\s-]?secret\b", re.I),
    re.compile(r"\bmnemonic\b", re.I),
    re.compile(r"\bapi[_\s-]?token\b", re.I),
    re.compile(r"\bpassword\b", re.I),
    re.compile(
        r"(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{8,}",
        re.I,
    ),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bsk-[A-Za-z0-9]{16,}"),
    re.compile(r"\bnpm_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"\bwitness\b.*[0-9a-fA-F]{32,}"),
)


def contains_sensitive_text(
    text: str,
    patterns: Sequence[re.Pattern] = DEFAULT_SENSITIVE_TEXT_PATTERNS,
) -> bool:
    """Return True if text matches any sensitive text pattern."""
    return any(p.search(text) for p in patterns)


def find_sensitive_match(
    text: str,
    patterns: Sequence[re.Pattern] = DEFAULT_SENSITIVE_TEXT_PATTERNS,
) -> tuple[re.Pattern, re.Match] | None:
    """Return the first (pattern, match) tuple found in text, or None."""
    for p in patterns:
        m = p.search(text)
        if m:
            return p, m
    return None


def reject_sensitive_keys(
    value: Any,
    location: str,
    pattern: re.Pattern = DEFAULT_SENSITIVE_KEY_RE,
    error_factory: Callable[[str], Exception] = ValueError,
) -> None:
    """Recursively reject sensitive field names in nested dict/list structures."""
    if isinstance(value, dict):
        for key, child in value.items():
            if pattern.search(str(key)):
                raise error_factory(f"{location} contains forbidden sensitive field '{key}'")
            reject_sensitive_keys(child, f"{location}.{key}", pattern, error_factory)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_sensitive_keys(child, f"{location}[{index}]", pattern, error_factory)


def read_text_bounded(
    path: Path,
    limit: int,
    error_factory: Callable[[str], Exception] = ValueError,
    display_name: str | None = None,
) -> str:
    """Read a UTF-8 text file up to limit bytes, raising via error_factory on failure."""
    name = display_name if display_name is not None else str(path)
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise error_factory(f"cannot read {name}: {exc}") from exc
    if size > limit:
        raise error_factory(f"{name} exceeds the {limit} byte limit")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise error_factory(f"not valid UTF-8 in {name}: {exc}") from exc
    except OSError as exc:
        raise error_factory(f"cannot read {name}: {exc}") from exc


def read_json_bounded(
    path: Path,
    limit: int,
    error_factory: Callable[[str], Exception] = ValueError,
    display_name: str | None = None,
    sensitive_pattern: re.Pattern | None = DEFAULT_SENSITIVE_KEY_RE,
    require_dict: bool = True,
) -> Any:
    """Read and parse a JSON file bounded by limit bytes.

    If require_dict is True, ensures the root is a JSON object (dict).
    If sensitive_pattern is provided, recursively validates that no forbidden keys exist.
    """
    name = display_name if display_name is not None else str(path)
    raw = read_text_bounded(path, limit, error_factory, display_name=name)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise error_factory(f"malformed JSON in {name}: {exc}") from exc
    if require_dict and not isinstance(value, dict):
        raise error_factory(f"{name} must be a JSON object")
    if sensitive_pattern is not None:
        reject_sensitive_keys(value, name, sensitive_pattern, error_factory)
    return value


def read_toml_bounded(
    path: Path,
    limit: int,
    error_factory: Callable[[str], Exception] = ValueError,
    display_name: str | None = None,
) -> dict[str, Any]:
    """Read and parse a TOML file bounded by limit bytes."""
    name = display_name if display_name is not None else str(path)
    if tomllib is None:
        raise RuntimeError("tomllib is required to parse TOML")
    raw = read_text_bounded(path, limit, error_factory, display_name=name)
    try:
        return tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise error_factory(f"malformed TOML in {name}: {exc}") from exc
