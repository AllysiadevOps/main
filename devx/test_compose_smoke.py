"""Tests for docker compose smoke test runner."""
from __future__ import annotations

import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import compose_smoke


class TestRedactLogs(unittest.TestCase):
    def test_redacts_stellar_secret_keys(self):
        log_sample = "Configuring stellar key: SB3DFM2Q6MZX7ZLK22W2E2NVMHXZZPQX2B6Q3M6J7L2Q4N6J7L2Q4N6J"
        redacted = compose_smoke.redact_logs(log_sample)
        self.assertNotIn("SB3DFM2Q6MZX7ZLK22W2E2NVMHXZZPQX2B6Q3M6J7L2Q4N6J7L2Q4N6J", redacted)
        self.assertIn("[REDACTED:stellar_secret]", redacted)

    def test_redacts_pem_private_keys(self):
        log_sample = (
            "Error loading key:\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA0Yv...\n"
            "-----END RSA PRIVATE KEY-----\n"
            "Failed."
        )
        redacted = compose_smoke.redact_logs(log_sample)
        self.assertNotIn("MIIEowIBAAKCAQEA0Yv...", redacted)
        self.assertIn("[REDACTED:private_key]", redacted)

    def test_redacts_database_urls_with_passwords(self):
        log_sample = "Connecting to postgresql://admin:super_secret_password123@db.example.com:5432/harpocrates"
        redacted = compose_smoke.redact_logs(log_sample)
        self.assertNotIn("super_secret_password123", redacted)
        self.assertIn("postgresql://[REDACTED]:[REDACTED]@db.example.com:5432/harpocrates", redacted)

    def test_redacts_env_key_values(self):
        log_sample = (
            "METRICS_TOKEN=scraping_token_xyz987\n"
            "REGISTER_API_KEY=reg_key_abc123\n"
            "PASSWORD=mypassword\n"
            "DATABASE_URL=postgres://u:p@h/d\n"
            "NULLIFIER_SECRET=nullifier123456\n"
            "CREDENTIAL_SECRET=credential98765\n"
            "WITNESS_SECRET=witness777\n"
        )
        redacted = compose_smoke.redact_logs(log_sample)
        self.assertNotIn("scraping_token_xyz987", redacted)
        self.assertNotIn("reg_key_abc123", redacted)
        self.assertNotIn("mypassword", redacted)
        self.assertNotIn("nullifier123456", redacted)
        self.assertNotIn("credential98765", redacted)
        self.assertNotIn("witness777", redacted)
        self.assertIn("METRICS_TOKEN=[REDACTED]", redacted)
        self.assertIn("REGISTER_API_KEY=[REDACTED]", redacted)
        self.assertIn("PASSWORD=[REDACTED]", redacted)

    def test_redacts_bearer_tokens_and_headers(self):
        log_sample = (
            "Request headers: Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token\n"
            "Cookie: session=xyz123abc456\n"
        )
        redacted = compose_smoke.redact_logs(log_sample)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token", redacted)
        self.assertNotIn("xyz123abc456", redacted)
        self.assertIn("Authorization: [REDACTED]", redacted)
        self.assertIn("Cookie: [REDACTED]", redacted)

    def test_redacts_json_formatted_secrets(self):
        log_sample = '{"secret": "hidden_value", "password": "pass", "safe": "public_data"}'
        redacted = compose_smoke.redact_logs(log_sample)
        self.assertNotIn("hidden_value", redacted)
        self.assertNotIn('"password": "pass"', redacted)
        self.assertIn('"safe": "public_data"', redacted)

    def test_handles_empty_or_clean_logs(self):
        self.assertEqual(compose_smoke.redact_logs(""), "")
        clean_log = "Server listening on 0.0.0.0:5050 and 0.0.0.0:8080"
        self.assertEqual(compose_smoke.redact_logs(clean_log), clean_log)


class TestProbeEndpoint(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_probe_endpoint_success_200(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        ok, status, msg = compose_smoke.probe_endpoint("http://127.0.0.1:5050/health")
        self.assertTrue(ok)
        self.assertEqual(status, 200)
        self.assertIn("HTTP 200", msg)

    @patch("urllib.request.urlopen")
    def test_probe_endpoint_http_error(self, mock_urlopen):
        import urllib.error

        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://127.0.0.1:5050/ready",
            code=503,
            msg="Service Unavailable",
            hdrs={},
            fp=None,
        )

        ok, status, msg = compose_smoke.probe_endpoint("http://127.0.0.1:5050/ready")
        self.assertFalse(ok)
        self.assertEqual(status, 503)
        self.assertIn("503", msg)

    @patch("urllib.request.urlopen")
    def test_probe_endpoint_url_error(self, mock_urlopen):
        import urllib.error

        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")

        ok, status, msg = compose_smoke.probe_endpoint("http://127.0.0.1:5050/health")
        self.assertFalse(ok)
        self.assertIsNone(status)
        self.assertIn("Connection refused", msg)

    @patch("urllib.request.urlopen")
    def test_probe_endpoint_timeout(self, mock_urlopen):
        mock_urlopen.side_effect = TimeoutError("Timed out")

        ok, status, msg = compose_smoke.probe_endpoint("http://127.0.0.1:5050/health")
        self.assertFalse(ok)
        self.assertIsNone(status)
        self.assertIn("TimeoutError", msg)


class TestPollingAndTimeout(unittest.TestCase):
    def test_probe_all_endpoints_calls_health_ready_and_root(self):
        probed_urls: list[str] = []

        def fake_probe(url: str, timeout: float):
            probed_urls.append(url)
            return (True, 200, "OK")

        results = compose_smoke.probe_all_endpoints(
            backend_url="http://127.0.0.1:5050",
            frontend_url="http://127.0.0.1:8080",
            probe_fn=fake_probe,
        )

        self.assertIn("http://127.0.0.1:5050/health", probed_urls)
        self.assertIn("http://127.0.0.1:5050/ready", probed_urls)
        self.assertIn("http://127.0.0.1:8080/", probed_urls)
        self.assertTrue(all(ok for ok, _, _ in results.values()))

    def test_wait_for_healthy_immediate_success(self):
        fake_probe = MagicMock(return_value=(True, 200, "OK"))
        healthy, results = compose_smoke.wait_for_healthy(
            backend_url="http://127.0.0.1:5050",
            frontend_url="http://127.0.0.1:8080",
            timeout_seconds=5.0,
            poll_interval=0.01,
            probe_fn=fake_probe,
        )
        self.assertTrue(healthy)
        self.assertEqual(len(results), 3)

    def test_wait_for_healthy_recovers_after_retry(self):
        attempts = 0

        def flaky_probe(url: str, timeout: float):
            nonlocal attempts
            attempts += 1
            # First round (3 probes) fails, second round succeeds
            if attempts <= 3:
                return (False, 503, "Starting")
            return (True, 200, "OK")

        healthy, results = compose_smoke.wait_for_healthy(
            backend_url="http://127.0.0.1:5050",
            frontend_url="http://127.0.0.1:8080",
            timeout_seconds=5.0,
            poll_interval=0.01,
            probe_fn=flaky_probe,
        )
        self.assertTrue(healthy)
        self.assertGreaterEqual(attempts, 6)

    def test_wait_for_healthy_times_out_when_service_never_recovers(self):
        fake_probe = MagicMock(return_value=(False, 503, "Unready"))
        healthy, results = compose_smoke.wait_for_healthy(
            backend_url="http://127.0.0.1:5050",
            frontend_url="http://127.0.0.1:8080",
            timeout_seconds=0.1,
            poll_interval=0.02,
            probe_fn=fake_probe,
        )
        self.assertFalse(healthy)
        self.assertFalse(results["backend_ready"][0])


class TestComposeSubprocessLifecycle(unittest.TestCase):
    def test_compose_up_includes_wait_flag(self):
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0))
        compose_smoke.compose_up("test-compose.yml", wait=True, runner=mock_runner)

        called_cmd = mock_runner.call_args[0][0]
        self.assertEqual(called_cmd, ["docker", "compose", "-f", "test-compose.yml", "up", "-d", "--wait"])

    def test_compose_up_without_wait_flag(self):
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0))
        compose_smoke.compose_up("test-compose.yml", wait=False, runner=mock_runner)

        called_cmd = mock_runner.call_args[0][0]
        self.assertEqual(called_cmd, ["docker", "compose", "-f", "test-compose.yml", "up", "-d"])

    def test_compose_down_includes_volumes(self):
        mock_runner = MagicMock(return_value=subprocess.CompletedProcess(args=[], returncode=0))
        compose_smoke.compose_down("test-compose.yml", runner=mock_runner)

        called_cmd = mock_runner.call_args[0][0]
        self.assertEqual(called_cmd, ["docker", "compose", "-f", "test-compose.yml", "down", "-v"])


class TestRunSmokeIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile("w", delete=False)
        self.temp_file.write("services:\n")
        self.temp_file.close()
        self.compose_path = Path(self.temp_file.name)

    def tearDown(self):
        if self.compose_path.is_file():
            self.compose_path.unlink()

    def test_run_smoke_success_exits_zero_and_tears_down(self):
        calls: list[list[str]] = []

        def mock_runner(cmd, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="ok", stderr="")

        def fake_probe(url: str, timeout: float):
            return (True, 200, "OK")

        exit_code = compose_smoke.run_smoke(
            compose_file=self.compose_path,
            timeout=5.0,
            poll_interval=0.01,
            runner=mock_runner,
            probe_fn=fake_probe,
        )

        self.assertEqual(exit_code, 0)
        # Verify compose up and compose down were both called
        self.assertTrue(any("up" in c for c in calls))
        self.assertTrue(any("down" in c for c in calls))

    def test_run_smoke_up_failure_tears_down_and_redacts_logs(self):
        calls: list[list[str]] = []

        def mock_runner(cmd, **kwargs):
            calls.append(cmd)
            if "up" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=1,
                    stdout="Started with METRICS_TOKEN=leaked_secret_token_1234",
                    stderr="Failed container setup",
                )
            if "logs" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=0,
                    stdout="Container logs with DATABASE_URL=postgresql://u:secret_password@host/db",
                    stderr="",
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0)

        fake_probe = MagicMock(return_value=(False, 503, "Unhealthy"))

        stderr_capture = io.StringIO()
        with patch("sys.stderr", stderr_capture):
            exit_code = compose_smoke.run_smoke(
                compose_file=self.compose_path,
                timeout=5.0,
                poll_interval=0.01,
                runner=mock_runner,
                probe_fn=fake_probe,
            )

        self.assertEqual(exit_code, 1)
        # Teardown must be called
        self.assertTrue(any("down" in c for c in calls))

        # Check stderr has redacted output and no secret leaks
        captured = stderr_capture.getvalue()
        self.assertNotIn("leaked_secret_token_1234", captured)
        self.assertNotIn("secret_password", captured)
        self.assertIn("[REDACTED]", captured)

    def test_run_smoke_probe_timeout_tears_down_and_prints_logs(self):
        calls: list[list[str]] = []

        def mock_runner(cmd, **kwargs):
            calls.append(cmd)
            if "logs" in cmd:
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=0,
                    stdout="Log entry: REGISTER_API_KEY=key_secret_777",
                    stderr="",
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0)

        # Probes always fail
        fake_probe = MagicMock(return_value=(False, 503, "Database down"))

        stderr_capture = io.StringIO()
        with patch("sys.stderr", stderr_capture):
            exit_code = compose_smoke.run_smoke(
                compose_file=self.compose_path,
                timeout=0.1,
                poll_interval=0.02,
                runner=mock_runner,
                probe_fn=fake_probe,
            )

        self.assertEqual(exit_code, 1)
        self.assertTrue(any("down" in c for c in calls))

        captured = stderr_capture.getvalue()
        self.assertNotIn("key_secret_777", captured)
        self.assertIn("[REDACTED]", captured)

    def test_run_smoke_exception_always_tears_down(self):
        calls: list[list[str]] = []

        def mock_runner(cmd, **kwargs):
            calls.append(cmd)
            if "up" in cmd:
                raise RuntimeError("Unexpected daemon crash: PASSWORD=super_secret")
            return subprocess.CompletedProcess(args=cmd, returncode=0)

        stderr_capture = io.StringIO()
        with patch("sys.stderr", stderr_capture):
            exit_code = compose_smoke.run_smoke(
                compose_file=self.compose_path,
                timeout=5.0,
                poll_interval=0.01,
                runner=mock_runner,
            )

        self.assertEqual(exit_code, 1)
        # Teardown must still be called in finally block
        self.assertTrue(any("down" in c for c in calls))

        captured = stderr_capture.getvalue()
        self.assertNotIn("super_secret", captured)
        self.assertIn("[REDACTED]", captured)


if __name__ == "__main__":
    unittest.main()
