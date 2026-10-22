#!/usr/bin/env python3
"""Docker Compose smoke-test runner for Harpocrates deployment stack.

Spins up the composed services via `docker compose up -d --wait` (or polling),
probes backend /health and /ready and frontend root endpoints, bounds total runtime,
prints redacted container logs on failure, and guarantees stack teardown.

Privacy & Safety:
  Container logs and error outputs are sanitized so no environment secrets,
  private keys, or credential tokens are ever printed.

Exit codes:
  0 — stack started and all health/ready/frontend probes succeeded
  1 — service failed probes, timeout exceeded, or startup failed
  2 — invalid usage or compose file missing
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_COMPOSE_FILE = ROOT / "docker-compose.yml"
DEFAULT_COMPOSE_EXAMPLE = ROOT / "docker-compose.example.yml"
DEFAULT_BACKEND_ENV_EXAMPLE = ROOT / "backend" / ".env.example"
DEFAULT_BACKEND_ENV = ROOT / "backend" / ".env"

DEFAULT_BACKEND_URL = "http://127.0.0.1:5050"
DEFAULT_FRONTEND_URL = "http://127.0.0.1:8080"
DEFAULT_TIMEOUT_SECONDS = 120.0
DEFAULT_POLL_INTERVAL_SECONDS = 2.0
DEFAULT_PROBE_TIMEOUT_SECONDS = 5.0

# Redaction patterns for privacy and secrets safety
STELLAR_SECRET_RE = re.compile(r"\bS[A-Z2-7]{55}\b")
PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY[\s\S]*?-----END (?:[A-Z ]+)?PRIVATE KEY-----"
)
PRIVATE_KEY_LINE_RE = re.compile(r"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY[^\r\n]*")
URL_CREDENTIAL_RE = re.compile(
    r"([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)([^:@\s]+):([^@\s]+)@"
)
BEARER_TOKEN_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9\-_.~+/]+=*")
SENSITIVE_KV_RE = re.compile(
    r"""(?i)\b([a-z0-9_]*(?:password|secret|token|api_key|apikey|private_key|privatekey|credential|nullifier|witness|database_url)[a-z0-9_]*)\s*([:=])\s*([^\s,;'"\]}]+)"""
)
SENSITIVE_QUOTED_KV_RE = re.compile(
    r"""(?i)(["']?([a-z0-9_]*(?:password|secret|token|api_key|apikey|private_key|privatekey|credential|nullifier|witness|database_url)[a-z0-9_]*)["']?\s*[:=]\s*["'])([^"'\r\n]+)(["'])"""
)
SENSITIVE_HEADER_RE = re.compile(
    r"(?i)\b(authorization|cookie|x-api-key|x-token)\s*:\s*[^\r\n]+"
)


def redact_logs(text: str) -> str:
    """Sanitize container logs or output to prevent leaking env secrets or keys."""
    if not text:
        return ""

    sanitized = text
    # 1. Full PEM blocks
    sanitized = PRIVATE_KEY_BLOCK_RE.sub("[REDACTED:private_key]", sanitized)
    sanitized = PRIVATE_KEY_LINE_RE.sub("[REDACTED:private_key]", sanitized)

    # 2. Stellar secret keys
    sanitized = STELLAR_SECRET_RE.sub("[REDACTED:stellar_secret]", sanitized)

    # 3. URLs with embedded credentials
    sanitized = URL_CREDENTIAL_RE.sub(r"\1[REDACTED]:[REDACTED]@", sanitized)

    # 4. Bearer tokens
    sanitized = BEARER_TOKEN_RE.sub(r"\1[REDACTED]", sanitized)

    # 5. Sensitive headers
    sanitized = SENSITIVE_HEADER_RE.sub(r"\1: [REDACTED]", sanitized)

    # 6. Sensitive quoted key-values (JSON/YAML)
    sanitized = SENSITIVE_QUOTED_KV_RE.sub(r"\1[REDACTED]\4", sanitized)

    # 7. Sensitive unquoted key-values (ENV / logs)
    sanitized = SENSITIVE_KV_RE.sub(r"\1\2[REDACTED]", sanitized)

    return sanitized


def probe_endpoint(
    url: str, timeout: float = DEFAULT_PROBE_TIMEOUT_SECONDS
) -> tuple[bool, int | None, str]:
    """Probe an HTTP endpoint using standard library urllib.

    Returns (is_ok, status_code, message).
    """
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "harpocrates-compose-smoke/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status = response.status
            return (status == 200, status, f"HTTP {status}")
    except urllib.error.HTTPError as err:
        return (False, err.code, f"HTTPError {err.code}: {err.reason}")
    except urllib.error.URLError as err:
        return (False, None, f"URLError: {err.reason}")
    except TimeoutError:
        return (False, None, "TimeoutError")
    except Exception as exc:  # pylint: disable=broad-except
        return (False, None, f"{type(exc).__name__}: {exc}")


def probe_all_endpoints(
    backend_url: str,
    frontend_url: str,
    timeout: float = DEFAULT_PROBE_TIMEOUT_SECONDS,
    probe_fn: Callable[[str, float], tuple[bool, int | None, str]] = probe_endpoint,
) -> dict[str, tuple[bool, int | None, str]]:
    """Probes backend /health, backend /ready, and frontend root."""
    backend_base = backend_url.rstrip("/")
    frontend_base = frontend_url.rstrip("/")

    results = {
        "backend_health": probe_fn(f"{backend_base}/health", timeout),
        "backend_ready": probe_fn(f"{backend_base}/ready", timeout),
        "frontend_root": probe_fn(f"{frontend_base}/", timeout),
    }
    return results


def wait_for_healthy(
    backend_url: str,
    frontend_url: str,
    timeout_seconds: float,
    poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
    probe_fn: Callable[[str, float], tuple[bool, int | None, str]] = probe_endpoint,
) -> tuple[bool, dict[str, tuple[bool, int | None, str]]]:
    """Polls backend and frontend endpoints until all are healthy or timeout expires."""
    deadline = time.monotonic() + timeout_seconds
    last_results: dict[str, tuple[bool, int | None, str]] = {}

    while time.monotonic() < deadline:
        remaining = max(0.5, deadline - time.monotonic())
        probe_timeout = min(DEFAULT_PROBE_TIMEOUT_SECONDS, remaining)
        last_results = probe_all_endpoints(
            backend_url=backend_url,
            frontend_url=frontend_url,
            timeout=probe_timeout,
            probe_fn=probe_fn,
        )

        all_ok = all(ok for ok, _, _ in last_results.values())
        if all_ok:
            return True, last_results

        remaining_wait = deadline - time.monotonic()
        if remaining_wait <= 0:
            break
        time.sleep(min(poll_interval, remaining_wait))

    return False, last_results


def compose_up(
    compose_file: Path | str,
    wait: bool = True,
    timeout: float = 120.0,
    runner: Callable[..., subprocess.CompletedProcess] | None = None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Invokes `docker compose up -d [--wait]`."""
    run_cmd = runner or subprocess.run
    cmd = ["docker", "compose", "-f", str(compose_file), "up", "-d"]
    if wait:
        cmd.append("--wait")

    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)

    return run_cmd(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )


def compose_down(
    compose_file: Path | str,
    timeout: float = 60.0,
    runner: Callable[..., subprocess.CompletedProcess] | None = None,
) -> subprocess.CompletedProcess:
    """Invokes `docker compose down -v` to ensure full teardown."""
    run_cmd = runner or subprocess.run
    cmd = ["docker", "compose", "-f", str(compose_file), "down", "-v"]

    return run_cmd(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def compose_logs(
    compose_file: Path | str,
    timeout: float = 30.0,
    runner: Callable[..., subprocess.CompletedProcess] | None = None,
) -> str:
    """Gathers container logs via `docker compose logs --no-color`."""
    run_cmd = runner or subprocess.run
    cmd = ["docker", "compose", "-f", str(compose_file), "logs", "--no-color"]
    try:
        proc = run_cmd(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return (proc.stdout or "") + "\n" + (proc.stderr or "")
    except Exception as exc:
        return f"Failed to retrieve container logs: {exc}"


def ensure_backend_env_present(compose_file: Path) -> tuple[bool, Path]:
    """If the compose file references backend/.env and it doesn't exist, create a stub."""
    backend_env = DEFAULT_BACKEND_ENV
    created = False
    if not backend_env.exists():
        if DEFAULT_BACKEND_ENV_EXAMPLE.exists():
            content = DEFAULT_BACKEND_ENV_EXAMPLE.read_text(encoding="utf-8")
        else:
            content = "APP_ENV=production\nPORT=5050\n"
        backend_env.write_text(content, encoding="utf-8")
        created = True
    return created, backend_env


def run_smoke(
    compose_file: Path | str | None = None,
    backend_url: str = DEFAULT_BACKEND_URL,
    frontend_url: str = DEFAULT_FRONTEND_URL,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
    wait: bool = True,
    runner: Callable[..., subprocess.CompletedProcess] | None = None,
    probe_fn: Callable[[str, float], tuple[bool, int | None, str]] = probe_endpoint,
) -> int:
    """Executes the complete compose smoke lifecycle with guaranteed teardown."""
    if compose_file is None:
        if DEFAULT_COMPOSE_FILE.is_file():
            target_compose = DEFAULT_COMPOSE_FILE
        elif DEFAULT_COMPOSE_EXAMPLE.is_file():
            target_compose = DEFAULT_COMPOSE_EXAMPLE
        else:
            sys.stderr.write("Error: Neither docker-compose.yml nor docker-compose.example.yml found.\n")
            return 2
    else:
        target_compose = Path(compose_file)
        if not target_compose.is_file():
            sys.stderr.write(f"Error: Compose file not found: {target_compose}\n")
            return 2

    created_env, env_path = ensure_backend_env_present(target_compose)
    start_time = time.monotonic()
    deadline = start_time + timeout

    print(f"[compose_smoke] Starting stack with compose file: {target_compose}")
    print(f"[compose_smoke] Total runtime timeout: {timeout:.1f}s")

    success = False

    try:
        # 1. Bring up containers
        remaining = max(1.0, deadline - time.monotonic())
        up_proc = compose_up(
            compose_file=target_compose,
            wait=wait,
            timeout=remaining,
            runner=runner,
        )

        if up_proc.returncode != 0:
            failure_reason = (
                f"docker compose up exited with code {up_proc.returncode}.\n"
                f"stdout: {up_proc.stdout}\nstderr: {up_proc.stderr}"
            )
            print(f"[compose_smoke] Startup failed: {redact_logs(failure_reason)}", file=sys.stderr)
        else:
            # 2. Wait and poll endpoints
            remaining = max(0.5, deadline - time.monotonic())
            healthy, probe_results = wait_for_healthy(
                backend_url=backend_url,
                frontend_url=frontend_url,
                timeout_seconds=remaining,
                poll_interval=poll_interval,
                probe_fn=probe_fn,
            )

            if healthy:
                print("[compose_smoke] All services are healthy!")
                for name, (_, code, msg) in probe_results.items():
                    print(f"  - {name}: {msg} (code {code})")
                success = True
            else:
                failure_reason = f"Endpoints failed to become healthy within timeout: {probe_results}"
                print(f"[compose_smoke] {failure_reason}", file=sys.stderr)

        if not success:
            print("[compose_smoke] Dumping container logs on failure (redacted):", file=sys.stderr)
            remaining_for_logs = max(5.0, min(30.0, deadline - time.monotonic()))
            raw_logs = compose_logs(
                compose_file=target_compose,
                timeout=remaining_for_logs,
                runner=runner,
            )
            print(redact_logs(raw_logs), file=sys.stderr)

    except Exception as exc:  # pylint: disable=broad-except
        failure_reason = f"Unhandled exception during smoke run: {type(exc).__name__}: {exc}"
        print(f"[compose_smoke] {redact_logs(failure_reason)}", file=sys.stderr)
        try:
            raw_logs = compose_logs(compose_file=target_compose, timeout=10.0, runner=runner)
            print(redact_logs(raw_logs), file=sys.stderr)
        except Exception:
            pass
        success = False

    finally:
        print("[compose_smoke] Tearing down compose stack...")
        try:
            compose_down(compose_file=target_compose, timeout=60.0, runner=runner)
            print("[compose_smoke] Teardown complete.")
        except Exception as down_exc:
            print(f"[compose_smoke] Warning: teardown encountered error: {down_exc}", file=sys.stderr)

        if created_env and env_path.is_file():
            try:
                env_path.unlink()
            except OSError:
                pass

    return 0 if success else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run docker compose smoke test and health verification with fail-safe teardown.",
    )
    parser.add_argument(
        "-f",
        "--compose-file",
        help="Path to docker compose YAML file (default: docker-compose.yml or docker-compose.example.yml)",
        default=None,
    )
    parser.add_argument(
        "--backend-url",
        help=f"Backend base URL to probe (default: {DEFAULT_BACKEND_URL})",
        default=DEFAULT_BACKEND_URL,
    )
    parser.add_argument(
        "--frontend-url",
        help=f"Frontend base URL to probe (default: {DEFAULT_FRONTEND_URL})",
        default=DEFAULT_FRONTEND_URL,
    )
    parser.add_argument(
        "--timeout",
        help=f"Total timeout bound in seconds (default: {DEFAULT_TIMEOUT_SECONDS})",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
    )
    parser.add_argument(
        "--poll-interval",
        help=f"Polling interval in seconds (default: {DEFAULT_POLL_INTERVAL_SECONDS})",
        type=float,
        default=DEFAULT_POLL_INTERVAL_SECONDS,
    )
    parser.add_argument(
        "--wait",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Whether to pass --wait to docker compose up (default: True)",
    )

    args = parser.parse_args(argv)
    return run_smoke(
        compose_file=args.compose_file,
        backend_url=args.backend_url,
        frontend_url=args.frontend_url,
        timeout=args.timeout,
        poll_interval=args.poll_interval,
        wait=args.wait,
    )


if __name__ == "__main__":
    sys.exit(main())
