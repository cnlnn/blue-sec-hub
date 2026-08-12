from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
import json
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import platforms  # noqa: E402
import install  # noqa: E402


class PlatformContractTest(unittest.TestCase):
    def test_all_nine_platforms_share_one_effective_snapshot_and_uninstall_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(root / "home"),
                    "CODEX_HOME": str(root / "home/.codex"),
                    "CLAUDE_CONFIG_DIR": str(root / "home/.claude"),
                    "GEMINI_HOME": str(root / "home/.gemini"),
                    "BLUE_SEC_BIN": str(root / "bin"),
                    "BLUE_SEC_CACHE": str(root / "cache"),
                    "BLUE_SEC_CONFIG": str(root / "config"),
                    "BLUE_SEC_DATA": str(root / "data"),
                }
            )
            command = [
                sys.executable,
                str(ROOT / "scripts/install.py"),
                "--platform",
                "all",
                "--no-configure-mcp",
                "--no-hooks",
                "--no-knowledge-sync",
            ]
            installed = subprocess.run(
                command,
                check=True,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
            )
            payload = json.loads(installed.stdout.split("\n", 1)[1])
            self.assertEqual(9, len(payload["results"]))
            revisions = set()
            for item in payload["results"]:
                manifest = json.loads(
                    (Path(item["skill_root"]) / install.MANIFEST_NAME).read_text(encoding="utf-8")
                )
                revisions.add(manifest["effective_revision"])
                self.assertIn("/effective/current/skills", manifest["skill_source"].replace("\\", "/"))
            self.assertEqual(1, len(revisions))
            claude_result = next(item for item in payload["results"] if item["platform"] == "claude")
            self.assertEqual("ready", claude_result["agents"]["status"])
            for name in ("blue-sec-recon.md", "blue-sec-tester.md", "blue-sec-auditor.md"):
                self.assertTrue((root / "home/.claude/agents" / name).exists())
            self.assertTrue(
                all(
                    item["agents"]["status"] == "not-exposed"
                    for item in payload["results"]
                    if item["platform"] != "claude"
                )
            )

            doctor = subprocess.run(
                [sys.executable, str(ROOT / "scripts/doctor.py"), "--platform", "all", "--json"],
                check=True,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
            )
            doctor_payload = json.loads(doctor.stdout)
            matrix = doctor_payload["platforms"]
            self.assertEqual(9, len(matrix))
            self.assertTrue(all(item["capabilities"]["skills"] == "ready" for item in matrix.values()))
            self.assertEqual("degraded", doctor_payload["report_index"]["status"])
            self.assertEqual("ready", doctor_payload["runtime"]["core_runtime"]["status"])
            self.assertEqual("ready", doctor_payload["task_pin_health"]["status"])

            removed = subprocess.run(
                [*command, "--uninstall"],
                check=True,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
            )
            payload = json.loads(removed.stdout.split("\n", 1)[1])
            self.assertTrue(all(item["status"] == "removed" for item in payload["results"]))

    def test_hermes_cli_requires_verified_enabled_server(self) -> None:
        cancelled = subprocess.CompletedProcess([], 0, "Cancelled.\n")
        enabled = subprocess.CompletedProcess([], 0, "blue-sec-hub  stdio  all  enabled\n")
        self.assertFalse(install.cli_mcp_is_current("hermes-cli", cancelled))
        self.assertTrue(install.cli_mcp_is_current("hermes-cli", enabled))

    def test_registry_declares_complete_nine_platform_contract(self) -> None:
        self.assertEqual(
            {
                "codex",
                "claude",
                "gemini",
                "grok",
                "opencode",
                "openclaw",
                "hermes",
                "trae",
                "trae-cn",
            },
            set(platforms.platform_ids()),
        )
        for platform_id in platforms.platform_ids():
            contract = platforms.contract_summary(platforms.get_platform(platform_id))
            self.assertIn(contract["mcp_mode"], {
                "codex-cli",
                "claude-cli",
                "grok-cli",
                "hermes-cli",
                "json-mcpServers",
                "json-mcpServers-if-present",
                "json-opencode",
                "generated-snippet",
            })
            self.assertTrue(contract["skill_root"])
            self.assertEqual(["--version"], contract["version_probe"]["args"])
            self.assertIn(contract["subagents"], {"supported", "not-exposed"})

    @unittest.skipIf(os.name == "nt", "fixture uses a POSIX executable")
    def test_runtime_certification_is_receipt_bound_and_doctor_is_honest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "home"
            binary = root / "bin" / "codex"
            binary.parent.mkdir(parents=True)
            binary.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--version\" ]; then printf 'codex-cli 9.8.7\\n'; "
                "elif [ \"$1\" = \"mcp\" ]; then printf 'blue-sec-hub blue-sec-agent serve --stdio\\n'; fi\n",
                encoding="utf-8",
            )
            binary.chmod(0o755)
            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(home),
                    "CODEX_HOME": str(home / ".codex"),
                    "BLUE_SEC_BIN": str(root / "commands"),
                    "BLUE_SEC_CACHE": str(root / "cache"),
                    "BLUE_SEC_CONFIG": str(root / "config"),
                    "BLUE_SEC_DATA": str(root / "data"),
                    "PATH": str(binary.parent) + os.pathsep + environment.get("PATH", ""),
                }
            )
            subprocess.run(
                [sys.executable, str(ROOT / "scripts/install.py"), "--platform", "codex", "--no-knowledge-sync"],
                check=True,
                env=environment,
                stdout=subprocess.PIPE,
            )
            before = subprocess.run(
                [sys.executable, str(ROOT / "scripts/doctor.py"), "--platform", "codex", "--json"],
                check=True,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
            )
            self.assertEqual("contract-ready", json.loads(before.stdout)["platforms"]["codex"]["status"])
            for event in ("PreCompact", "SessionStart"):
                subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "scripts/context_hook.py"),
                        "--platform",
                        "codex",
                        "--event",
                        event,
                    ],
                    input="{}",
                    check=True,
                    env=environment,
                    text=True,
                    stdout=subprocess.PIPE,
                )
            certified = subprocess.run(
                [sys.executable, str(ROOT / "scripts/platform_certify.py"), "--platform", "codex", "--json"],
                check=True,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
            )
            self.assertEqual("runtime-certified", json.loads(certified.stdout)["results"][0]["status"])
            after = subprocess.run(
                [sys.executable, str(ROOT / "scripts/doctor.py"), "--platform", "codex", "--json"],
                check=True,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
            )
            platform = json.loads(after.stdout)["platforms"]["codex"]
            self.assertEqual("runtime-certified", platform["status"])
            self.assertEqual("9.8.7", platform["version"]["version"])
            binary.write_text("#!/bin/sh\nprintf 'codex-cli 9.8.8\\n'\n", encoding="utf-8")
            changed = subprocess.run(
                [sys.executable, str(ROOT / "scripts/doctor.py"), "--platform", "codex", "--json"],
                check=True,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
            )
            platform = json.loads(changed.stdout)["platforms"]["codex"]
            self.assertEqual("degraded", platform["status"])
            self.assertIn("runtime version changed or unavailable", platform["certification"]["reasons"])

    def test_json_mcp_merge_preserves_unrelated_servers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            settings = home / ".gemini" / "settings.json"
            settings.parent.mkdir()
            settings.write_text(
                json.dumps({"mcpServers": {"existing": {"command": "keep"}}, "theme": "dark"}),
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment.update({"HOME": str(home), "GEMINI_HOME": str(home / ".gemini"), "BLUE_SEC_BIN": str(home / "bin")})
            subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "install.py"), "--platform", "gemini", "--no-knowledge-sync"],
                check=True,
                env=environment,
                stdout=subprocess.PIPE,
            )
            configured = json.loads(settings.read_text(encoding="utf-8"))
            self.assertEqual("keep", configured["mcpServers"]["existing"]["command"])
            self.assertEqual("blue-sec-agent", configured["mcpServers"]["blue-sec-hub"]["command"])
            self.assertEqual("dark", configured["theme"])

    def test_dry_run_does_not_create_platform_home(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            gemini_home = home / ".gemini"
            environment = os.environ.copy()
            environment.update({"HOME": str(home), "GEMINI_HOME": str(gemini_home), "BLUE_SEC_BIN": str(home / "bin")})
            subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "install.py"), "--platform", "gemini", "--dry-run", "--no-knowledge-sync"],
                check=True,
                env=environment,
                stdout=subprocess.PIPE,
            )
            self.assertFalse(gemini_home.exists())
            self.assertFalse((home / "bin").exists())

    def test_detected_desktop_without_callable_runtime_is_contract_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            config = home / ".config" / "Trae CN" / "User" / "mcp.json"
            config.parent.mkdir(parents=True)
            config.write_text("{}\n", encoding="utf-8")
            environment = os.environ.copy()
            environment.update({"HOME": str(home), "BLUE_SEC_BIN": str(home / "bin")})
            subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "install.py"), "--platform", "trae-cn", "--no-knowledge-sync"],
                check=True,
                env=environment,
                stdout=subprocess.PIPE,
            )
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "doctor.py"), "--platform", "trae-cn", "--json"],
                check=True,
                env=environment,
                stdout=subprocess.PIPE,
                text=True,
            )
            self.assertEqual("contract-ready", json.loads(result.stdout)["platforms"]["trae-cn"]["status"])

    def test_codex_hooks_are_managed_without_rewriting_existing_toml(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            codex_home = home / ".codex"
            codex_home.mkdir()
            config = codex_home / "config.toml"
            config.write_text('model = "test-model"\n', encoding="utf-8")
            environment = os.environ.copy()
            environment.update({"HOME": str(home), "CODEX_HOME": str(codex_home), "BLUE_SEC_BIN": str(home / "bin")})
            command = [
                sys.executable,
                str(ROOT / "scripts" / "install.py"),
                "--platform",
                "codex",
                "--no-configure-mcp",
                "--no-knowledge-sync",
            ]
            subprocess.run(command, check=True, env=environment, stdout=subprocess.PIPE)
            configured = tomllib.loads(config.read_text(encoding="utf-8"))
            self.assertEqual("test-model", configured["model"])
            self.assertIn("PreCompact", configured["hooks"])
            manifest = json.loads((codex_home / "blue-sec-hub-hooks.json").read_text())
            self.assertTrue(manifest["active"])
            subprocess.run(command + ["--uninstall"], check=True, env=environment, stdout=subprocess.PIPE)
            self.assertEqual({"model": "test-model"}, tomllib.loads(config.read_text(encoding="utf-8")))

    def test_lifecycle_hook_reconciles_before_compaction_and_restores_after(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "task"
            transcript = root / "session.jsonl"
            environment = os.environ.copy()
            environment["BLUE_SEC_DATA"] = str(root / "data")
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/context_checkpoint.py"),
                    "init",
                    "--workspace",
                    str(workspace),
                    "--task-kind",
                    "incident-reconstruction",
                ],
                check=True,
                env=environment,
                stdout=subprocess.PIPE,
            )
            transcript.write_text(
                json.dumps(
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "message",
                            "role": "user",
                            "content": [{"type": "input_text", "text": "确认下一步保全原始证据"}],
                        },
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            payload = json.dumps(
                {
                    "cwd": str(workspace),
                    "session_id": "session-one",
                    "transcript_path": str(transcript),
                }
            )
            subprocess.run(
                [sys.executable, str(ROOT / "scripts/context_hook.py"), "--platform", "codex", "--event", "PreCompact"],
                input=payload,
                text=True,
                check=True,
                env=environment,
                stdout=subprocess.PIPE,
            )
            restored = subprocess.run(
                [sys.executable, str(ROOT / "scripts/context_hook.py"), "--platform", "codex", "--event", "SessionStart"],
                input=json.dumps({"session_id": "session-one"}),
                text=True,
                check=True,
                env=environment,
                stdout=subprocess.PIPE,
            )
            value = json.loads(restored.stdout)
            self.assertEqual("ready", value["blue_sec_context_restore"])
            self.assertTrue(value["requires_reconciliation"])
            self.assertEqual("确认下一步保全原始证据", value["critical_clues"][0]["summary"])

    def test_host_hook_invocation_is_observed_even_without_a_bound_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = os.environ.copy()
            data = Path(temporary) / "data"
            environment["BLUE_SEC_DATA"] = str(data)
            subprocess.run(
                [sys.executable, str(ROOT / "scripts/context_hook.py"), "--platform", "codex", "--event", "PreCompact"],
                input=json.dumps({"session_id": "host-session"}),
                text=True,
                check=True,
                env=environment,
                stdout=subprocess.PIPE,
            )
            observation = json.loads(
                (data / "platform-certifications/hook-observations/codex.json").read_text(encoding="utf-8")
            )
            self.assertIn("precompact", observation["events"])
            self.assertNotIn("host-session", json.dumps(observation))

    @unittest.skipIf(os.name == "nt", "Windows does not provide WSL symlink semantics")
    def test_install_supports_wsl_style_mounted_home(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            mounted_home = Path(temporary) / "mnt" / "c" / "Users" / "analyst"
            codex_home = mounted_home / ".codex"
            mounted_home.mkdir(parents=True)
            environment = os.environ.copy()
            environment["HOME"] = str(mounted_home)
            environment["CODEX_HOME"] = str(codex_home)
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "install.py"),
                    "--platform",
                    "codex",
                    "--no-configure-mcp",
                    "--no-knowledge-sync",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )
            self.assertIn("[ok] installed", result.stdout)
            installed = codex_home / "skills" / "blue-team-security"
            self.assertTrue(installed.is_symlink())
            manifest = json.loads((codex_home / "skills" / ".blue-sec-install.json").read_text())
            self.assertEqual(
                installed.resolve(),
                (Path(manifest["skill_source"]) / "blue-team-security").resolve(),
            )
            command = mounted_home / ".local" / "bin" / "blue-sec-update"
            self.assertTrue(command.is_symlink())
            planner = mounted_home / ".local" / "bin" / "blue-sec-web-assessment"
            self.assertTrue(planner.is_symlink())
            self.assertEqual(
                planner.resolve(),
                (ROOT / "scripts" / "web_assessment.py").resolve(),
            )
            runner = mounted_home / ".local" / "bin" / "blue-sec-web-runner"
            self.assertTrue(runner.is_symlink())
            self.assertEqual(
                runner.resolve(),
                (ROOT / "scripts" / "web_runner.py").resolve(),
            )
            agent = mounted_home / ".local" / "bin" / "blue-sec-agent"
            self.assertEqual(agent.resolve(), (ROOT / "scripts" / "agent.py").resolve())
            context = mounted_home / ".local" / "bin" / "blue-sec-context"
            self.assertEqual(
                context.resolve(),
                (ROOT / "scripts" / "context_checkpoint.py").resolve(),
            )
            session_distiller = mounted_home / ".local" / "bin" / "blue-sec-session-distill"
            self.assertEqual(
                session_distiller.resolve(),
                (ROOT / "scripts" / "session_distill.py").resolve(),
            )
            payload_catalog = mounted_home / ".local" / "bin" / "blue-sec-payload-catalog"
            self.assertEqual(
                payload_catalog.resolve(),
                (ROOT / "scripts" / "payload_catalog.py").resolve(),
            )


if __name__ == "__main__":
    unittest.main()
