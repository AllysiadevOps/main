"""Automated tests for per-endpoint rate limiting (issue #15).

Strategy
--------
* Create a fresh Flask app with very tight limits (e.g. "2 per minute") so
  tests are fast and do not depend on wall-clock time for the burst check.
* Burst test: fire (limit + 1) requests and assert the last one returns 429
  with a ``Retry-After`` header.
* Reset test: override the limiter's storage with a fresh in-memory backend
  between test cases so each test starts from zero — no actual clock sleep
  required.
* Key-function test: verify that spoofed X-Forwarded-For headers are ignored
  when no trusted proxies are configured.

All tests use Flask's built-in test client (no live server needed).
"""
from __future__ import annotations

import io
import json
import os
import unittest

# ---------------------------------------------------------------------------
# Patch environment BEFORE importing app so create_app() picks up tight limits
# ---------------------------------------------------------------------------
os.environ.setdefault("RATELIMIT_ENABLED", "true")
os.environ["RATELIMIT_EMBED"] = "2 per minute"
os.environ["RATELIMIT_EXTRACT"] = "2 per minute"
os.environ["RATELIMIT_SILENT_WITNESS"] = "2 per minute"
os.environ["RATELIMIT_REGISTER"] = "2 per minute"
# Use in-memory storage so tests are self-contained
os.environ["RATELIMIT_STORAGE_URI"] = "memory://"
# Disable DB / Noir worker to keep tests self-contained
os.environ.setdefault("DATABASE_URL", "")
os.environ.setdefault("NOIR_WORKER_ENABLED", "false")
os.environ.setdefault("TRUSTED_PROXIES", "")


def _make_fresh_app():
    """Return a new Flask app + test client with a clean rate-limit store."""
    # Re-import create_app after env vars are set so each call gets a fresh
    # Limiter instance backed by a new in-memory store.
    import importlib
    import app as app_module
    importlib.reload(app_module)
    flask_app = app_module.app
    flask_app.config["TESTING"] = True
    return flask_app, flask_app.test_client()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _video_file():
    return (io.BytesIO(b"\x00" * 16), "test.mp4", "video/mp4")


def _valid_metadata():
    return json.dumps(
        {
            "protocol": "harpocrates",
            "version": 1,
            "tier": "silent",
            "sourceHash": "11" * 32,
            "proofId": "22" * 32,
            "timestamp": "2026-06-18T00:00:00.000Z",
        }
    )


def _valid_register_payload():
    return {
        "fileName": "evidence.mp4",
        "videoHash": "ab" * 32,
        "metadataHash": "cd" * 32,
        "proofId": "ef" * 32,
        "tier": "source",
        "txHash": "tx123",
        "txStatus": "PENDING",
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class EmbedRateLimitTest(unittest.TestCase):
    """POST /api/stego/embed — limit: 2 per minute."""

    def setUp(self):
        self.flask_app, self.client = _make_fresh_app()

    def _post_embed(self, xff=None):
        headers = {"X-Forwarded-For": xff} if xff else {}
        return self.client.post(
            "/api/stego/embed",
            data={
                "metadata": _valid_metadata(),
                "video": _video_file(),
            },
            content_type="multipart/form-data",
            headers=headers,
        )

    def test_requests_within_limit_are_not_blocked(self):
        """First two requests must not be rate-limited."""
        for _ in range(2):
            resp = self._post_embed()
            # 400/500 are OK here (no real ffmpeg); 429 is the failure case.
            self.assertNotEqual(resp.status_code, 429, "Unexpected 429 within limit")

    def test_burst_triggers_429(self):
        """Third request (over the 2/min limit) must return 429."""
        for _ in range(2):
            self._post_embed()
        resp = self._post_embed()
        self.assertEqual(resp.status_code, 429)

    def test_429_includes_retry_after_header(self):
        """429 response must include a Retry-After header."""
        for _ in range(3):
            resp = self._post_embed()
        self.assertEqual(resp.status_code, 429)
        self.assertIn("Retry-After", resp.headers)
        retry_after = resp.headers["Retry-After"]
        # Must be a non-empty string that represents a non-negative integer.
        self.assertTrue(retry_after.strip().isdigit(), f"Retry-After is not an integer: {retry_after!r}")

    def test_429_response_body_has_error_key(self):
        """429 response body must contain an 'error' field."""
        for _ in range(3):
            resp = self._post_embed()
        self.assertEqual(resp.status_code, 429)
        body = resp.get_json()
        self.assertIn("error", body)

    def test_spoofed_xff_does_not_bypass_limit_without_trusted_proxies(self):
        """Without TRUSTED_PROXIES, X-Forwarded-For must be ignored.

        Client sends requests from the real loopback address but injects
        a spoofed XFF header pretending to be a different IP.  The limiter
        must key on REMOTE_ADDR (loopback) so the limit still fires.
        """
        for _ in range(2):
            self._post_embed(xff="203.0.113.1")
        # Third request from same real IP, different spoofed XFF.
        resp = self._post_embed(xff="203.0.113.2")
        self.assertEqual(resp.status_code, 429, "Spoofed XFF bypassed rate limiter")


class ExtractRateLimitTest(unittest.TestCase):
    """POST /api/stego/extract — limit: 2 per minute."""

    def setUp(self):
        self.flask_app, self.client = _make_fresh_app()

    def _post_extract(self):
        return self.client.post(
            "/api/stego/extract",
            data={"video": _video_file()},
            content_type="multipart/form-data",
        )

    def test_requests_within_limit_are_not_blocked(self):
        for _ in range(2):
            resp = self._post_extract()
            self.assertNotEqual(resp.status_code, 429)

    def test_burst_triggers_429(self):
        for _ in range(2):
            self._post_extract()
        resp = self._post_extract()
        self.assertEqual(resp.status_code, 429)

    def test_429_includes_retry_after_header(self):
        for _ in range(3):
            resp = self._post_extract()
        self.assertEqual(resp.status_code, 429)
        self.assertIn("Retry-After", resp.headers)


class SilentWitnessRateLimitTest(unittest.TestCase):
    """POST /api/noir/silent-witness — limit: 2 per minute."""

    def setUp(self):
        self.flask_app, self.client = _make_fresh_app()

    def _post_silent_witness(self):
        payload = {
            "videoHash": "aa" * 32,
            "credentialSecret": "12345",
            "nullifierSecret": "67890",
        }
        return self.client.post(
            "/api/noir/silent-witness",
            data=json.dumps(payload),
            content_type="application/json",
        )

    def test_requests_within_limit_are_not_blocked(self):
        for _ in range(2):
            resp = self._post_silent_witness()
            # 404 is expected because noir_worker_enabled=false; 429 is failure.
            self.assertNotEqual(resp.status_code, 429)

    def test_burst_triggers_429(self):
        for _ in range(2):
            self._post_silent_witness()
        resp = self._post_silent_witness()
        self.assertEqual(resp.status_code, 429)

    def test_429_includes_retry_after_header(self):
        for _ in range(3):
            resp = self._post_silent_witness()
        self.assertEqual(resp.status_code, 429)
        self.assertIn("Retry-After", resp.headers)


class RegisterRateLimitTest(unittest.TestCase):
    """POST /api/proofs/register — limit: 2 per minute."""

    def setUp(self):
        self.flask_app, self.client = _make_fresh_app()

    def _post_register(self):
        return self.client.post(
            "/api/proofs/register",
            data=json.dumps(_valid_register_payload()),
            content_type="application/json",
        )

    def test_requests_within_limit_are_not_blocked(self):
        for _ in range(2):
            resp = self._post_register()
            self.assertNotEqual(resp.status_code, 429)

    def test_burst_triggers_429(self):
        for _ in range(2):
            self._post_register()
        resp = self._post_register()
        self.assertEqual(resp.status_code, 429)

    def test_429_includes_retry_after_header(self):
        for _ in range(3):
            resp = self._post_register()
        self.assertEqual(resp.status_code, 429)
        self.assertIn("Retry-After", resp.headers)


class RateLimitResetTest(unittest.TestCase):
    """Each test case gets a fresh app (fresh in-memory store = reset behaviour)."""

    def test_fresh_app_resets_counter(self):
        """A new app instance has no prior request history — first request is not blocked."""
        _, client1 = _make_fresh_app()
        # Exhaust limit on first client
        for _ in range(3):
            client1.post(
                "/api/stego/extract",
                data={"video": _video_file()},
                content_type="multipart/form-data",
            )

        # Second, freshly-created app must allow requests again.
        _, client2 = _make_fresh_app()
        resp = client2.post(
            "/api/stego/extract",
            data={"video": _video_file()},
            content_type="multipart/form-data",
        )
        self.assertNotEqual(resp.status_code, 429, "Fresh app should not inherit exhausted counter")


class HealthNotRateLimitedTest(unittest.TestCase):
    """Health and readiness probes must never receive a 429."""

    def setUp(self):
        # Tighten limits to 1/minute so health would be blocked if not exempt.
        os.environ["RATELIMIT_EMBED"] = "1 per minute"
        _, self.client = _make_fresh_app()
        # Restore
        os.environ["RATELIMIT_EMBED"] = "2 per minute"

    def test_health_never_rate_limited(self):
        for _ in range(10):
            resp = self.client.get("/health")
            self.assertNotEqual(resp.status_code, 429)

    def test_ready_never_rate_limited(self):
        for _ in range(10):
            resp = self.client.get("/ready")
            self.assertNotEqual(resp.status_code, 429)


# ---------------------------------------------------------------------------
# Concurrency & storage kind tests (pytest fixtures monkeypatch & caplog)
# ---------------------------------------------------------------------------

import logging


def test_warning_emitted_when_multi_worker_and_memory_storage(monkeypatch, caplog):
    monkeypatch.setenv("RATELIMIT_ENABLED", "true")
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        _make_fresh_app()

    warning_records = [
        r for r in caplog.records
        if "ratelimit_unshared_storage" in r.getMessage()
    ]
    assert len(warning_records) == 1
    assert warning_records[0].levelno == logging.WARNING


def test_no_warning_when_single_worker(monkeypatch, caplog):
    monkeypatch.setenv("RATELIMIT_ENABLED", "true")
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.setenv("WEB_CONCURRENCY", "1")
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        _make_fresh_app()

    warning_records = [
        r for r in caplog.records
        if "ratelimit_unshared_storage" in r.getMessage()
    ]
    assert len(warning_records) == 0


def test_no_warning_when_redis_storage(monkeypatch, caplog):
    monkeypatch.setenv("RATELIMIT_ENABLED", "true")
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "redis://localhost:6379/0")
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        _make_fresh_app()

    warning_records = [
        r for r in caplog.records
        if "ratelimit_unshared_storage" in r.getMessage()
    ]
    assert len(warning_records) == 0


def test_no_warning_when_rate_limiting_disabled(monkeypatch, caplog):
    monkeypatch.setenv("RATELIMIT_ENABLED", "false")
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        _make_fresh_app()

    warning_records = [
        r for r in caplog.records
        if "ratelimit_unshared_storage" in r.getMessage()
    ]
    assert len(warning_records) == 0


def test_storage_uri_credentials_never_logged(monkeypatch, caplog):
    secret_pass = "super_secret_redis_pass_xyz123"
    storage_uri = f"redis://app_user:{secret_pass}@redis.internal.net:6379/0"
    monkeypatch.setenv("RATELIMIT_ENABLED", "true")
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", storage_uri)
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        _, client = _make_fresh_app()
        resp = client.get("/ready")

    for record in caplog.records:
        assert secret_pass not in record.getMessage()
        assert storage_uri not in record.getMessage()

    assert resp.status_code in {200, 503}
    body_str = resp.get_data(as_text=True)
    assert secret_pass not in body_str
    assert storage_uri not in body_str
    assert resp.json.get("ratelimit_storage") == "redis"


def test_warning_when_gunicorn_worker_count_detectable(monkeypatch, caplog):
    monkeypatch.setenv("RATELIMIT_ENABLED", "true")
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.setenv("GUNICORN_CMD_ARGS", "--workers 3 --timeout 60")
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        _make_fresh_app()

    warning_records = [
        r for r in caplog.records
        if "ratelimit_unshared_storage" in r.getMessage()
    ]
    assert len(warning_records) == 1


def test_ready_endpoint_exposes_storage_kind(monkeypatch):
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")
    _, client = _make_fresh_app()
    resp = client.get("/ready")
    assert resp.status_code in {200, 503}
    assert resp.json.get("ratelimit_storage") == "memory"
    assert resp.json.get("storage_kind") == "memory"

    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "redis://localhost:6379/0")
    _, client = _make_fresh_app()
    resp = client.get("/ready")
    assert resp.json.get("ratelimit_storage") == "redis"
    assert resp.json.get("storage_kind") == "redis"

    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "rediss://localhost:6379/0")
    _, client = _make_fresh_app()
    resp = client.get("/ready")
    assert resp.json.get("ratelimit_storage") == "redis"
    assert resp.json.get("storage_kind") == "redis"

    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memcached://localhost:11211")
    _, client = _make_fresh_app()
    resp = client.get("/ready")
    assert resp.json.get("ratelimit_storage") == "other"
    assert resp.json.get("storage_kind") == "other"


if __name__ == "__main__":
    unittest.main()

