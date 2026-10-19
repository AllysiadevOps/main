#!/usr/bin/env python3
"""Unit tests for devx/deploy.py covering argument parsing, dry-run, rollback selection, and mocked subprocess calls."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import devx.deploy as deploy


class TestDeployArgumentParsing(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = deploy.build_parser()

    def test_deploy_defaults(self) -> None:
        args = self.parser.parse_args(["deploy"])
        self.assertEqual(args.subcommand, "deploy")
        self.assertEqual(args.admin, "harpocrates-admin")
        self.assertEqual(args.issuer, "harpocrates-issuer")
        self.assertEqual(args.network, "testnet")
        self.assertEqual(args.verifier, "CCP2EQPKT5XAYTOARX3LGHNMJ37A6W2WY3H54MRIHEZVTVAZZPUSGZQJ")
        self.assertEqual(args.rpc_url, "https://soroban-testnet.stellar.org")
        self.assertFalse(args.skip_build)
        self.assertFalse(args.skip_issuer)
        self.assertFalse(args.skip_e2e)
        self.assertEqual(args.stellar_timeout_seconds, 180)

    def test_deploy_custom_flags(self) -> None:
        args = self.parser.parse_args([
            "deploy",
            "--admin", "custom-admin",
            "--issuer", "custom-issuer",
            "--network", "local",
            "--skip-build",
            "--skip-issuer",
            "--skip-e2e",
            "--stellar-timeout-seconds", "30",
        ])
        self.assertEqual(args.admin, "custom-admin")
        self.assertEqual(args.issuer, "custom-issuer")
        self.assertEqual(args.network, "local")
        self.assertTrue(args.skip_build)
        self.assertTrue(args.skip_issuer)
        self.assertTrue(args.skip_e2e)
        self.assertEqual(args.stellar_timeout_seconds, 30)

    def test_rollback_args(self) -> None:
        args = self.parser.parse_args(["rollback", "--manifest-file", "manifest.json", "--skip-docker"])
        self.assertEqual(args.subcommand, "rollback")
        self.assertEqual(args.manifest_file, "manifest.json")
        self.assertTrue(args.skip_docker)

    def test_rollback_requires_manifest(self) -> None:
        with patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                self.parser.parse_args(["rollback"])

    def test_e2e_args(self) -> None:
        args = self.parser.parse_args([
            "e2e",
            "--backend-url", "http://localhost:5050",
            "--contract-id", "C1234567890123456789012345678901234567890123456789012345",
            "--ensure-credential-root",
            "--register-on-chain",
        ])
        self.assertEqual(args.subcommand, "e2e")
        self.assertEqual(args.backend_url, "http://localhost:5050")
        self.assertTrue(args.ensure_credential_root)
        self.assertTrue(args.register_on_chain)


class TestDeployExecution(unittest.TestCase):
    @patch("devx.deploy.get_stellar_address")
    @patch("devx.deploy.run_command")
    @patch("devx.deploy.set_env_value")
    def test_run_deploy_skip_e2e(self, mock_set_env, mock_run_cmd, mock_stellar_addr) -> None:
        mock_stellar_addr.side_effect = lambda key: f"G_ADDR_{key}"
        # Contract deploy output contains contract ID
        mock_deploy_output = subprocess.CompletedProcess(
            args=["stellar", "contract", "deploy"],
            returncode=0,
            stdout="Contract deployed at CCKTQNMBLXZXMWVR2WG4HDDUI3QGJU5LV5NTLFPCB72UITWE5TEDK7BT\n",
            stderr="",
        )
        mock_generic_success = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="",
            stderr="",
        )
        mock_run_cmd.side_effect = [
            mock_generic_success,  # cargo test
            mock_generic_success,  # stellar contract build
            mock_deploy_output,    # stellar contract deploy
            mock_generic_success,  # init
            mock_generic_success,  # set_verifier
            mock_generic_success,  # add_issuer
        ]

        parser = deploy.build_parser()
        args = parser.parse_args(["deploy", "--skip-e2e"])
        summary = deploy.run_deploy(args)

        self.assertTrue(summary["ok"])
        self.assertEqual(summary["contractId"], "CCKTQNMBLXZXMWVR2WG4HDDUI3QGJU5LV5NTLFPCB72UITWE5TEDK7BT")
        self.assertEqual(summary["admin"], "G_ADDR_harpocrates-admin")
        self.assertEqual(summary["issuer"], "G_ADDR_harpocrates-issuer")
        self.assertIsNone(summary["e2e"])
        # Verify frontend env values were updated
        mock_set_env.assert_any_call(deploy.FRONTEND_ENV_LOCAL, "VITE_HARPOCRATES_REGISTRY_ID", summary["contractId"])

    def test_get_first_contract_id(self) -> None:
        text = "Created contract: CCKTQNMBLXZXMWVR2WG4HDDUI3QGJU5LV5NTLFPCB72UITWE5TEDK7BT with hash"
        self.assertEqual(deploy.get_first_contract_id(text), "CCKTQNMBLXZXMWVR2WG4HDDUI3QGJU5LV5NTLFPCB72UITWE5TEDK7BT")

        with self.assertRaises(deploy.DeployError):
            deploy.get_first_contract_id("No contract ID here")

    def test_set_env_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env.test"
            env_file.write_text("FOO=BAR\nEXISTING=VAL\n", encoding="utf-8")
            deploy.set_env_value(env_file, "FOO", "NEW_BAR")
            deploy.set_env_value(env_file, "BAZ", "ADDED")
            content = env_file.read_text(encoding="utf-8")
            self.assertIn("FOO=NEW_BAR", content)
            self.assertIn("EXISTING=VAL", content)
            self.assertIn("BAZ=ADDED", content)


class TestRollbackSelectionAndValidation(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp_dir.name)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def create_manifest(self, state: str = "rollback", previous_release: str = "harpocrates-0.9.0") -> Path:
        data = {
            "schema_version": 1,
            "release_id": "harpocrates-1.0.0",
            "rollout": {
                "state": state,
                "previous_release": previous_release,
            },
        }
        path = self.tmp_path / "manifest.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_missing_manifest_file(self) -> None:
        parser = deploy.build_parser()
        args = parser.parse_args(["rollback", "--manifest-file", str(self.tmp_path / "nonexistent.json"), "--skip-docker"])
        with self.assertRaises(deploy.DeployError) as ctx:
            deploy.run_rollback(args)
        self.assertEqual(ctx.exception.exit_code, 3)

    def test_malformed_json_manifest(self) -> None:
        bad_json = self.tmp_path / "bad.json"
        bad_json.write_text("{ malformed json", encoding="utf-8")
        parser = deploy.build_parser()
        args = parser.parse_args(["rollback", "--manifest-file", str(bad_json), "--skip-docker"])
        with self.assertRaises(deploy.DeployError) as ctx:
            deploy.run_rollback(args)
        self.assertEqual(ctx.exception.exit_code, 5)

    def test_oversized_manifest(self) -> None:
        oversized = self.tmp_path / "oversized.json"
        oversized.write_bytes(b"a" * (257 * 1024))
        parser = deploy.build_parser()
        args = parser.parse_args(["rollback", "--manifest-file", str(oversized), "--skip-docker"])
        with self.assertRaises(deploy.DeployError) as ctx:
            deploy.run_rollback(args)
        self.assertEqual(ctx.exception.exit_code, 4)

    def test_unsupported_rollout_state(self) -> None:
        manifest = self.create_manifest(state="active")
        parser = deploy.build_parser()
        args = parser.parse_args(["rollback", "--manifest-file", str(manifest), "--skip-docker"])
        with patch("devx.deploy.run_command") as mock_cmd:
            mock_cmd.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
            with self.assertRaises(deploy.DeployError) as ctx:
                deploy.run_rollback(args)
            self.assertEqual(ctx.exception.exit_code, 7)

    def test_missing_previous_release(self) -> None:
        manifest = self.create_manifest(state="rollback", previous_release="")
        parser = deploy.build_parser()
        args = parser.parse_args(["rollback", "--manifest-file", str(manifest), "--skip-docker"])
        with patch("devx.deploy.run_command") as mock_cmd:
            mock_cmd.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
            with self.assertRaises(deploy.DeployError) as ctx:
                deploy.run_rollback(args)
            self.assertEqual(ctx.exception.exit_code, 8)

    @patch("devx.deploy.run_command")
    def test_successful_rollback_skip_docker(self, mock_cmd) -> None:
        manifest = self.create_manifest(state="rollback", previous_release="harpocrates-0.9.0")
        mock_cmd.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        parser = deploy.build_parser()
        args = parser.parse_args(["rollback", "--manifest-file", str(manifest), "--skip-docker"])
        ret = deploy.run_rollback(args)
        self.assertEqual(ret, 0)
        self.assertEqual(os.environ.get("HARPOCRATES_RELEASE_TARGET"), "harpocrates-0.9.0")

    def test_rollback_with_docker_restore_failure(self) -> None:
        manifest = self.create_manifest(state="rollback", previous_release="harpocrates-0.9.0")
        parser = deploy.build_parser()
        args = parser.parse_args(["rollback", "--manifest-file", str(manifest)])

        with patch.object(deploy, "ROOT", self.tmp_path), patch("devx.deploy.run_command") as mock_cmd:
            compose_file = self.tmp_path / "docker-compose.yml"
            compose_file.write_text("services: {}", encoding="utf-8")
            mock_cmd.side_effect = [
                subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),  # docker compose down
                subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="error bringing up"),  # docker compose up
            ]
            with self.assertRaises(deploy.DeployError) as ctx:
                deploy.run_rollback(args)
            self.assertEqual(ctx.exception.exit_code, 9)


class TestSecretIsolation(unittest.TestCase):
    def test_secrets_read_from_environment(self) -> None:
        parser = deploy.build_parser()
        with patch.dict(os.environ, {
            "HARPOCRATES_CREDENTIAL_SECRET": "env-cred-sec",
            "HARPOCRATES_NULLIFIER_SECRET": "env-null-sec",
        }):
            args = parser.parse_args(["e2e"])
            # In run_e2e, credential_secret will resolve to the env var if args.credential_secret is None
            resolved_cred = args.credential_secret or os.environ.get("HARPOCRATES_CREDENTIAL_SECRET")
            resolved_null = args.nullifier_secret or os.environ.get("HARPOCRATES_NULLIFIER_SECRET")
            self.assertEqual(resolved_cred, "env-cred-sec")
            self.assertEqual(resolved_null, "env-null-sec")


if __name__ == "__main__":
    unittest.main()
