from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import agent  # noqa: E402
import context_checkpoint  # noqa: E402
import web_assessment  # noqa: E402


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


class CrossPlatformAgentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.data_temporary = tempfile.TemporaryDirectory()
        self.previous_data = os.environ.get("BLUE_SEC_DATA")
        os.environ["BLUE_SEC_DATA"] = self.data_temporary.name
        self.previous_context_data = context_checkpoint.DATA_ROOT
        context_checkpoint.DATA_ROOT = Path(self.data_temporary.name)

    def tearDown(self) -> None:
        context_checkpoint.DATA_ROOT = self.previous_context_data
        if self.previous_data is None:
            os.environ.pop("BLUE_SEC_DATA", None)
        else:
            os.environ["BLUE_SEC_DATA"] = self.previous_data
        self.data_temporary.cleanup()

    def test_v5_state_migrates_to_fast_find_v7(self) -> None:
        coverage = web_assessment.migrate_coverage(
            {"schema_version": 5, "runtime": {}, "stop_gates": {}},
            "https://shop.example.test",
        )
        self.assertEqual(8, coverage["schema_version"])
        self.assertEqual("comprehensive-fast-first", coverage["mode"])
        self.assertIn("agent_roles", coverage["runtime"])
        self.assertIn("discovery_saturation_confirmed", coverage["stop_gates"])
        plan = web_assessment.migrate_plan(
            {
                "schema_version": 5,
                "test_cells": [{"id": "cell", "family": "identity-session.oauth-sso"}],
                "executable_cases": [
                    {"id": "case", "test_cell_id": "cell", "automation_state": "needs-agent"}
                ],
            }
        )
        self.assertEqual(8, plan["schema_version"])
        self.assertEqual("fast-find", plan["executable_cases"][0]["execution_lane"])
        self.assertEqual("tester", plan["executable_cases"][0]["agent_role"])

    def test_dual_plugin_manifests_share_the_repository_components(self) -> None:
        codex = json.loads((ROOT / ".codex-plugin" / "plugin.json").read_text())
        claude = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
        mcp = json.loads((ROOT / ".mcp.json").read_text())
        self.assertEqual("blue-sec-hub", codex["name"])
        self.assertEqual(codex["name"], claude["name"])
        self.assertEqual("./skills/", codex["skills"])
        self.assertEqual("blue-sec-agent", mcp["mcpServers"]["blue-sec-hub"]["command"])

    def workspace_with_agent_case(self, root: Path) -> Path:
        workspace = root / "assessment"
        web_assessment.initialize(workspace, "https://shop.example.test")
        source = root / "surface.json"
        write_json(
            source,
            {
                "surfaces": [
                    {
                        "method": "GET",
                        "url": "/api/orders",
                        "validation_state": "runtime-observed",
                        "runtime_observed": True,
                    }
                ]
            },
        )
        web_assessment.compile_workspace(workspace, [("manual", source)])
        state = agent.new_state("https://shop.example.test", workspace, "codex")
        agent.save_state(workspace, state)
        return workspace

    def test_three_role_actions_are_stable_and_leased(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = self.workspace_with_agent_case(Path(temporary))
            state = agent.sync_actions(workspace, agent.load_state(workspace))
            tester = [
                item
                for item in state["actions"]
                if item["role"] == "tester" and item["status"] != "blocked"
            ]
            self.assertTrue(tester)
            self.assertTrue(all(item["safety"] == "agent-safe" for item in tester))
            agent.save_state(workspace, state)
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "agent.py"), "next", "--workspace", str(workspace), "--platform", "claude"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            )
            leased = json.loads(result.stdout)
            self.assertEqual("leased", leased["status"])
            self.assertEqual("claude", leased["lease"]["platform"])

    def test_protocol_profiles_create_explicit_agent_dispositions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "assessment"
            web_assessment.initialize(workspace, "https://project.example.test")
            source = root / "protocols.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {"kind": "graphql-operation", "method": "POST", "url": "/graphql", "profiles": ["graphql"], "validation_state": "runtime-observed"},
                        {"kind": "api", "method": "GET", "url": "wss://project.example.test/events", "protocol": "wss", "profiles": ["websocket-sse"], "validation_state": "runtime-observed"},
                        {"kind": "api", "method": "POST", "url": "/soap/service", "profiles": ["soap-xml"], "validation_state": "runtime-observed"},
                        {"kind": "api", "method": "GET", "url": "/oauth/authorize", "profiles": ["oauth-oidc"], "validation_state": "runtime-observed"},
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            coverage = json.loads((workspace / "coverage.json").read_text())
            profiles = {item["id"] for item in coverage["protocol_profiles"]}
            self.assertTrue({"graphql", "websocket-sse", "soap-xml", "oauth-oidc"} <= profiles)
            plan = json.loads((workspace / "test-plan.json").read_text())
            families = {
                item.get("family")
                for item in plan["executable_cases"]
                if item.get("automation_state") == "needs-agent"
            }
            self.assertIn("api-protocol.graphql", families)
            self.assertIn("api-protocol.websocket-sse-soap", families)

    def test_resolved_action_requires_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = self.workspace_with_agent_case(Path(temporary))
            state = agent.sync_actions(workspace, agent.load_state(workspace))
            action = next(item for item in state["actions"] if item["role"] == "tester")
            agent.save_state(workspace, state)
            event = Path(temporary) / "result.json"
            write_json(event, {"action_id": action["id"], "status": "resolved", "events": []})
            with self.assertRaisesRegex(ValueError, "requires machine-readable events"):
                agent.command_record(argparse.Namespace(workspace=workspace, event=event))

    def test_pending_candidate_prerequisite_becomes_agent_action(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = self.workspace_with_agent_case(Path(temporary))
            web_assessment.append_event(
                workspace,
                {
                    "type": "candidate",
                    "id": "compound-candidate",
                    "title": "compound signal",
                    "validation_dependencies": [
                        {
                            "id": "concrete-consumer",
                            "kind": "impact",
                            "status": "pending",
                            "reason": "a concrete protected consumer has not been found",
                            "resolution_action": "discover-protected-consumer",
                        }
                    ],
                },
            )
            web_assessment.compile_workspace(workspace)
            state = agent.sync_actions(workspace, agent.load_state(workspace))
            action = next(
                item
                for item in state["actions"]
                if item["source_id"].startswith("prerequisite:")
                and item.get("instruction", {}).get("owner_id")
                == "compound-candidate"
            )
            self.assertEqual("recon", action["role"])
            self.assertEqual("agent-safe", action["safety"])
            self.assertEqual(
                "resolve-prerequisite", action["instruction"]["action"]
            )
            self.assertIn("prerequisite-result", action["expected_events"])

    def test_expired_lease_is_requeued_and_stale_is_not_complete(self) -> None:
        action = {
            "status": "leased",
            "lease": {
                "leased_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            },
            "result": None,
        }
        agent.expire_abandoned_lease(action, max_age_seconds=1)
        self.assertEqual("failed", action["status"])
        self.assertIsNone(action["lease"])
        self.assertNotIn("stale", agent.FINAL_ACTION_STATES)

    def test_mcp_stdio_lists_same_public_actions_as_cli(self) -> None:
        process = subprocess.Popen(
            [sys.executable, str(ROOT / "scripts" / "agent.py"), "serve", "--stdio"],
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdin and process.stdout
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}) + "\n")
        process.stdin.flush()
        initialized = json.loads(process.stdout.readline())
        self.assertEqual("blue-sec-hub", initialized["result"]["serverInfo"]["name"])
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n")
        process.stdin.flush()
        listed = json.loads(process.stdout.readline())
        names = {item["name"] for item in listed["result"]["tools"]}
        self.assertEqual(
            {
                "start_web_assessment",
                "next_agent_action",
                "record_agent_result",
                "resume_web_assessment",
                "get_assessment_status",
                "audit_assessment",
                "get_assessment_context",
                "get_assessment_brief",
                "record_security_context_event",
                "record_security_conclusion",
                "record_conversation_learning_event",
                "checkpoint_security_context",
                "restore_security_context",
            },
            names,
        )
        self.assertTrue(
            {
                "start_assessment",
                "continue_assessment",
                "record_action_result",
                "get_assessment_report",
                "distill_assessment",
            }.isdisjoint(names)
        )
        start = next(item for item in listed["result"]["tools"] if item["name"] == "start_web_assessment")
        self.assertEqual(["target"], start["inputSchema"]["required"])
        process.stdin.close()
        process.wait(timeout=5)
        process.stdout.close()
        assert process.stderr
        process.stderr.close()

    def test_mcp_next_returns_the_leased_action_not_the_whole_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = self.workspace_with_agent_case(Path(temporary))
            state = agent.sync_actions(workspace, agent.load_state(workspace))
            agent.save_state(workspace, state)
            code, value = agent.invoke_mcp_tool(
                "next_agent_action",
                {"workspace": str(workspace), "role": "tester"},
            )
            self.assertEqual(0, code)
            self.assertEqual("tester", value["role"])
            self.assertEqual("leased", value["status"])
            self.assertNotIn("actions", value)

    def test_hidden_compatibility_aliases_remain_callable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = self.workspace_with_agent_case(Path(temporary))
            code, value = agent.invoke_mcp_tool(
                "continue_assessment", {"workspace": str(workspace)}
            )
            self.assertIn(code, {0, 2})
            self.assertEqual(str(workspace.resolve()), value["workspace"])
            code, report = agent.invoke_mcp_tool(
                "get_assessment_report", {"workspace": str(workspace)}
            )
            self.assertEqual(0, code)
            self.assertIn("findings", report)

    def test_job_manifest_references_standard_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = self.workspace_with_agent_case(Path(temporary))
            job = json.loads((workspace / "job.json").read_text(encoding="utf-8"))
            self.assertEqual("web-api-spa-assessment", job["kind"])
            self.assertEqual("assessment-events.jsonl", job["artifacts"]["event_ledger"])
            self.assertEqual("results.md", job["artifacts"]["report"])
            self.assertEqual("bounded-adaptive", job["budgets"]["retry_policy"])

    def test_generic_context_mcp_tools_checkpoint_and_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "incident"
            context_checkpoint.command_init(
                argparse.Namespace(
                    workspace=workspace,
                    task_kind="incident-reconstruction",
                    target="provided-evidence",
                    scope="provided-evidence-only",
                    safety="read-only",
                )
            )
            code, recorded = agent.invoke_mcp_tool(
                "record_security_context_event",
                {
                    "workspace": str(workspace),
                    "event": {
                        "type": "hypothesis",
                        "summary": "Authentication source may have changed",
                    },
                },
            )
            self.assertEqual(0, code)
            self.assertIn("checkpoint_id", recorded)
            code, learned = agent.invoke_mcp_tool(
                "record_conversation_learning_event",
                {
                    "workspace": str(workspace),
                    "learning_event": {
                        "type": "correction",
                        "summary": "Internal logs are seeds, not black-box prerequisites",
                        "source_platform": "codex",
                        "validation_state": "validated",
                    },
                },
            )
            self.assertEqual(0, code)
            self.assertEqual("correction", learned["learning_event"]["type"])
            code, conclusion = agent.invoke_mcp_tool(
                "record_security_conclusion",
                {
                    "workspace": str(workspace),
                    "conclusion": {
                        "schema_version": 1,
                        "claim_id": "mcp-risk",
                        "claim_kind": "vulnerability",
                        "validation_state": "candidate",
                        "title": "Potential command execution path",
                        "evidence_refs": ["evidence/static-sink.json"],
                        "attacker_prerequisites": [],
                        "validation_dependencies": [],
                        "potential_impact": "code execution",
                        "confirmed_impact": None,
                        "investigation_priority": "high",
                        "formal_severity": None,
                        "next_actions": [],
                        "alternative_explanations": ["sink may be unreachable"],
                        "coverage_effect": "continue",
                    },
                },
            )
            self.assertEqual(0, code)
            self.assertEqual("candidate", conclusion["conclusion"]["validation_state"])
            self.assertIn("checkpoint_id", conclusion)
            code, restored = agent.invoke_mcp_tool(
                "restore_security_context", {"workspace": str(workspace)}
            )
            self.assertEqual(0, code)
            self.assertEqual("ready", restored["status"])
            self.assertIn(
                "Authentication source may have changed",
                {
                    item["summary"]
                    for item in restored["capsule"]["critical_clues"]
                },
            )

    def test_claude_and_codex_install_share_skill_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(root),
                    "CODEX_HOME": str(root / ".codex"),
                    "CLAUDE_HOME": str(root / ".claude"),
                    "BLUE_SEC_BIN": str(root / "bin"),
                }
            )
            subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "install.py"), "--platform", "all", "--no-configure-mcp", "--no-knowledge-sync"],
                check=True,
                env=environment,
                stdout=subprocess.PIPE,
            )
            for platform in (".codex", ".claude"):
                installed = root / platform / "skills" / "blue-team-security"
                manifest = json.loads((root / platform / "skills" / ".blue-sec-install.json").read_text())
                expected = Path(manifest["skill_source"]) / "blue-team-security"
                self.assertEqual(installed.resolve(), expected.resolve())
                self.assertEqual(3, manifest["schema_version"])
                self.assertTrue(manifest["effective_revision"])
                self.assertEqual(21, len(manifest["skills"]))

    def test_all_platform_uninstall_removes_only_managed_installation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(root),
                    "CODEX_HOME": str(root / ".codex"),
                    "CLAUDE_HOME": str(root / ".claude"),
                    "BLUE_SEC_BIN": str(root / "bin"),
                }
            )
            install_command = [
                sys.executable,
                str(ROOT / "scripts" / "install.py"),
                "--platform",
                "all",
                "--no-configure-mcp",
                "--no-knowledge-sync",
            ]
            subprocess.run(install_command, check=True, env=environment, stdout=subprocess.PIPE)
            unmanaged = root / ".codex" / "skills" / "team-local"
            unmanaged.mkdir()
            subprocess.run(
                install_command + ["--uninstall"],
                check=True,
                env=environment,
                stdout=subprocess.PIPE,
            )
            self.assertTrue(unmanaged.is_dir())
            self.assertFalse((root / ".codex" / "skills" / "blue-team-security").exists())
            self.assertFalse((root / ".claude" / "skills" / "blue-team-security").exists())
            self.assertFalse((root / "bin" / "blue-sec-agent").exists())

    def test_installer_backs_up_an_unmanaged_skill_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            codex_home = root / ".codex"
            conflict = codex_home / "skills" / "blue-team-security"
            conflict.mkdir(parents=True)
            (conflict / "user-owned.txt").write_text("do-not-overwrite", encoding="utf-8")
            environment = os.environ.copy()
            environment.update(
                {
                    "HOME": str(root),
                    "CODEX_HOME": str(codex_home),
                    "BLUE_SEC_BIN": str(root / "bin"),
                }
            )
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "install.py"),
                    "--platform",
                    "codex",
                    "--no-configure-mcp",
                    "--no-knowledge-sync",
                ],
                check=True,
                env=environment,
                stdout=subprocess.PIPE,
            )
            backups = list((codex_home / "skill-backups").glob("*/blue-team-security/user-owned.txt"))
            self.assertEqual(1, len(backups))
            self.assertEqual("do-not-overwrite", backups[0].read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
