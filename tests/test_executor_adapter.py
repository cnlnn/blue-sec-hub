from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import install  # noqa: E402
import executor_adapter  # noqa: E402
import executor_native  # noqa: E402


class ExecutorAdapterTest(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "Windows installer creates .cmd launchers")
    def test_every_installed_command_source_is_executable(self) -> None:
        for name, script in install.COMMANDS.items():
            path = ROOT / "scripts" / script
            self.assertTrue(path.is_file(), name)
            self.assertTrue(path.stat().st_mode & 0o111, f"{name}: {path}")

    def test_plan_is_scope_bound_and_does_not_persist_credential_reference(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            environment = os.environ.copy()
            environment["BLUE_SEC_DATA"] = str(root / "data")
            command = [
                sys.executable,
                str(ROOT / "scripts/executor_control.py"),
                "plan",
                "--engine",
                "shannon",
                "--target",
                "https://app.example.test",
                "--scope",
                "https://app.example.test",
                "--source",
                str(source),
                "--credential-lease",
                "lease://secret-reference",
                "--instruction",
                "Use token=private-value-only in the temporary runtime",
            ]
            result = subprocess.run(command, check=True, env=environment, text=True, stdout=subprocess.PIPE)
            task = json.loads(result.stdout)
            material = (root / "data" / "executions" / "tasks" / task["task_id"] / "task.json").read_text(encoding="utf-8")
            self.assertNotIn("secret-reference", material)
            self.assertNotIn("private-value-only", material)
            self.assertIn("[REDACTED_SECRET]", material)
            self.assertRegex(task["request"]["credential_lease_hash"], r"^[0-9a-f]{64}$")
            self.assertEqual("planned", task["state"])
            self.assertEqual([], task["plan"]["command"])
            self.assertIn(task["plan"]["status"], {"contract-ready", "not-installed"})

    def test_target_must_be_explicitly_in_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = os.environ.copy()
            environment["BLUE_SEC_DATA"] = str(Path(temporary) / "data")
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/executor_control.py"),
                    "plan",
                    "--engine",
                    "strix",
                    "--target",
                    "https://outside.example.test",
                    "--scope",
                    "https://inside.example.test",
                ],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(2, result.returncode)
            self.assertIn("scope must explicitly contain the target", result.stderr)
            self.assertFalse((Path(temporary) / "data").exists())

    @unittest.skipIf(os.name == "nt", "fixture uses a POSIX executable")
    def test_executable_detection_is_only_contract_ready_until_adapter_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "sigma"
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = str(binary.parent) + os.pathsep + environment.get("PATH", "")
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/executor_status.py"), "--json"],
                check=True,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
            )
            items = {item["engine"]: item for item in json.loads(result.stdout)["executors"]}
            self.assertEqual("contract-ready", items["sigma-cli"]["status"])
            self.assertEqual("pending", items["sigma-cli"]["adapter"])

    def test_event_ledger_is_hash_chained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = os.environ.copy()
            root = Path(temporary) / "data"
            environment["BLUE_SEC_DATA"] = str(root)
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/executor_control.py"),
                    "plan",
                    "--engine",
                    "cai",
                    "--target",
                    "local-lab",
                    "--scope",
                    "local-lab",
                ],
                check=True,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
            )
            task = json.loads(result.stdout)
            task_root = root / "executions" / "tasks" / task["task_id"]
            event = json.loads((task_root / "events.jsonl").read_text(encoding="utf-8"))
            current = json.loads((task_root / "task.json").read_text(encoding="utf-8"))
            self.assertEqual(event["sha256"], current["event_head"])
            self.assertIsNone(event["previous_sha256"])

    @unittest.skipIf(os.name == "nt", "fixture uses a POSIX executable")
    def test_shannon_adapter_runs_only_after_scope_authorization_and_hashes_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            binary = root / "bin" / "shannon"
            binary.parent.mkdir()
            binary.write_text(
                "#!/bin/sh\n"
                "out=''\n"
                "while [ $# -gt 0 ]; do\n"
                "  if [ \"$1\" = \"-o\" ]; then out=\"$2\"; shift 2; else shift; fi\n"
                "done\n"
                "mkdir -p \"$out\"\n"
                "printf 'verified fixture finding\\n' > \"$out/report.md\"\n",
                encoding="utf-8",
            )
            binary.chmod(0o755)
            environment = os.environ.copy()
            environment["BLUE_SEC_DATA"] = str(root / "data")
            environment["PATH"] = str(binary.parent) + os.pathsep + environment.get("PATH", "")
            planned = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/executor_control.py"),
                    "plan",
                    "--engine",
                    "shannon",
                    "--target",
                    "https://app.example.test",
                    "--scope",
                    "https://app.example.test",
                    "--source",
                    str(source),
                    "--allow-network",
                ],
                check=True,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
            )
            task = json.loads(planned.stdout)
            self.assertEqual("runtime-ready", task["plan"]["status"])
            denied = subprocess.run(
                [sys.executable, str(ROOT / "scripts/executor_control.py"), "run", task["task_id"]],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(2, denied.returncode)
            self.assertIn("requires --authorized", denied.stderr)
            completed = subprocess.run(
                [sys.executable, str(ROOT / "scripts/executor_control.py"), "run", task["task_id"], "--authorized"],
                check=True,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
            )
            task = json.loads(completed.stdout)
            self.assertEqual("completed", task["state"])
            report = next(item for item in task["result"]["artifacts"] if item["path"] == "output/report.md")
            self.assertRegex(report["sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(25, report["bytes"])

    @unittest.skipIf(os.name == "nt", "fixture uses a POSIX executable")
    def test_cai_adapter_uses_guarded_agent_as_tool_orchestration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            binary = root / "bin" / "cai"
            binary.parent.mkdir()
            binary.write_text(
                "#!/bin/sh\n"
                "mkdir -p \"$CAI_WORKSPACE_DIR\"\n"
                "printf '%s|%s|%s|%s' \"$CAI_AGENT_TYPE\" \"$CAI_MAX_TURNS\" \"$CAI_PRICE_LIMIT\" \"$CAI_GUARDRAILS\" > \"$CAI_WORKSPACE_DIR/runtime.txt\"\n"
                "printf '%s' \"$*\" > \"$CAI_WORKSPACE_DIR/arguments.txt\"\n",
                encoding="utf-8",
            )
            binary.chmod(0o755)
            environment = os.environ.copy()
            environment["BLUE_SEC_DATA"] = str(root / "data")
            environment["PATH"] = str(binary.parent) + os.pathsep + environment.get("PATH", "")
            planned = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/executor_control.py"),
                    "plan",
                    "--engine",
                    "cai",
                    "--target",
                    "local-lab",
                    "--scope",
                    "local-lab",
                    "--source",
                    str(source),
                    "--max-turns",
                    "7",
                    "--max-cost-usd",
                    "1.5",
                ],
                check=True,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
            )
            task = json.loads(planned.stdout)
            self.assertEqual("runtime-ready", task["plan"]["status"])
            self.assertIn("--prompt", task["plan"]["command"])
            self.assertNotIn("--yolo", task["plan"]["command"])
            completed = subprocess.run(
                [sys.executable, str(ROOT / "scripts/executor_control.py"), "run", task["task_id"], "--authorized"],
                check=True,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
            )
            task = json.loads(completed.stdout)
            task_root = root / "data" / "executions" / "tasks" / task["task_id"]
            self.assertEqual("orchestration_agent|7|1.5|true", (task_root / "output/runtime.txt").read_text())
            arguments = (task_root / "output/arguments.txt").read_text()
            self.assertIn("Exact scope: local-lab", arguments)
            self.assertIn("specialists as tools", arguments)
            self.assertEqual("completed", task["state"])

    @unittest.skipIf(os.name == "nt", "fixture uses a POSIX executable")
    def test_strix_adapter_runs_headless_and_treats_exit_two_as_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "bin" / "strix"
            binary.parent.mkdir()
            binary.write_text(
                "#!/bin/sh\n"
                "instructions=''\n"
                "args=\"$*\"\n"
                "while [ $# -gt 0 ]; do\n"
                "  if [ \"$1\" = \"--instruction-file\" ]; then instructions=\"$2\"; shift 2; else shift; fi\n"
                "done\n"
                "printf '%s' \"$args\" > invoked.txt\n"
                "cp \"$instructions\" received-instructions.txt\n"
                "printf 'finding evidence\\n' > strix-report.md\n"
                "exit 2\n",
                encoding="utf-8",
            )
            binary.chmod(0o755)
            environment = os.environ.copy()
            environment["BLUE_SEC_DATA"] = str(root / "data")
            environment["PATH"] = str(binary.parent) + os.pathsep + environment.get("PATH", "")
            planned = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/executor_control.py"),
                    "plan",
                    "--engine",
                    "strix",
                    "--target",
                    "https://app.example.test",
                    "--scope",
                    "https://app.example.test",
                    "--allow-network",
                    "--mode",
                    "quick",
                ],
                check=True,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
            )
            task = json.loads(planned.stdout)
            completed = subprocess.run(
                [sys.executable, str(ROOT / "scripts/executor_control.py"), "run", task["task_id"], "--authorized"],
                check=True,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
            )
            task = json.loads(completed.stdout)
            task_root = root / "data" / "executions" / "tasks" / task["task_id"]
            invoked = (task_root / "invoked.txt").read_text()
            self.assertIn("-n --target https://app.example.test --scan-mode quick", invoked)
            self.assertEqual(2, task["result"]["exit_code"])
            self.assertEqual("completed", task["state"])
            self.assertEqual("Strix completed with findings", task["result"]["detail"])
            constraints = (task_root / "received-instructions.txt").read_text()
            self.assertIn("Exact scope", constraints)
            self.assertIn("Do not access unrelated systems", constraints)
            paths = {item["path"] for item in task["result"]["artifacts"]}
            self.assertIn("strix-report.md", paths)

    def test_native_adapter_maps_interim_state_to_resumable_pause(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            task_root = Path(temporary)
            output = task_root / "output" / "assessment"
            output.mkdir(parents=True)
            (output / "context-capsule.json").write_text("{}\n", encoding="utf-8")
            request = executor_adapter.ExecutionRequest(
                engine="blue-sec-native",
                target="https://app.example.test",
                scope=("https://app.example.test",),
                allow_network=True,
            )
            spec = executor_adapter.load_executor_specs()["blue-sec-native"]
            adapter = executor_native.NativeExecutorAdapter(spec)
            completed = subprocess.CompletedProcess([], 2)
            with mock.patch.object(executor_native.subprocess, "run", return_value=completed):
                result = adapter.execute(["blue-sec-agent", "run"], request, task_root)
            self.assertEqual("paused", result.status)
            self.assertEqual(2, result.exit_code)
            self.assertIn("resumed", result.detail)
            self.assertIn("output/assessment/context-capsule.json", {item["path"] for item in result.artifacts})

    def test_native_plan_uses_same_site_agent_workspace_and_rate_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = os.environ.copy()
            environment["BLUE_SEC_DATA"] = str(root / "data")
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/executor_control.py"),
                    "plan",
                    "--engine",
                    "blue-sec-native",
                    "--target",
                    "https://app.example.test",
                    "--scope",
                    "https://app.example.test",
                    "--allow-network",
                ],
                check=True,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
            )
            task = json.loads(result.stdout)
            command = task["plan"]["command"]
            self.assertIn("agent.py", command[1])
            self.assertIn("--requests-per-second", command)
            self.assertIn("--no-refresh-knowledge", command)
            self.assertIn(task["plan"]["status"], {"runtime-ready", "contract-ready"})


if __name__ == "__main__":
    unittest.main()
