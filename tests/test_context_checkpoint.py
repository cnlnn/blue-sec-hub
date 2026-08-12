from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import agent  # noqa: E402
import context_checkpoint  # noqa: E402
import effective_skills  # noqa: E402
import web_assessment  # noqa: E402


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


class ContextCheckpointTest(unittest.TestCase):
    def test_security_conclusion_is_downgraded_and_persisted_before_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "incident"
            normalized = context_checkpoint.append_security_conclusion(
                workspace,
                {
                    "schema_version": 1,
                    "claim_id": "electron-rce-signal",
                    "claim_kind": "vulnerability",
                    "validation_state": "confirmed",
                    "title": "High RCE in Electron application",
                    "evidence_refs": ["evidence/asar-web-preferences.json"],
                    "attacker_prerequisites": [],
                    "validation_dependencies": [],
                    "potential_impact": "remote code execution",
                    "confirmed_impact": "remote code execution",
                    "investigation_priority": "critical",
                    "formal_severity": "critical",
                    "next_actions": [],
                    "alternative_explanations": ["dangerous configuration is unreachable"],
                    "coverage_effect": "complete",
                },
            )
            self.assertEqual("candidate", normalized["validation_state"])
            self.assertIsNone(normalized["formal_severity"])
            self.assertTrue((workspace / context_checkpoint.CONCLUSIONS_NAME).is_file())
            event = next(context_checkpoint.read_jsonl(workspace / context_checkpoint.EVENTS_NAME))
            self.assertEqual("hypothesis", event["type"])
    def setUp(self) -> None:
        self.data_temporary = tempfile.TemporaryDirectory()
        self.previous_data = os.environ.get("BLUE_SEC_DATA")
        os.environ["BLUE_SEC_DATA"] = self.data_temporary.name
        self.previous_context_data = context_checkpoint.DATA_ROOT
        context_checkpoint.DATA_ROOT = Path(self.data_temporary.name)
        effective_skills.atomic_json(
            effective_skills.state_path(),
            {"schema_version": 1, "active_revision": "revision-current", "history": []},
        )

    def tearDown(self) -> None:
        context_checkpoint.DATA_ROOT = self.previous_context_data
        if self.previous_data is None:
            os.environ.pop("BLUE_SEC_DATA", None)
        else:
            os.environ["BLUE_SEC_DATA"] = self.previous_data
        self.data_temporary.cleanup()

    def test_generic_security_task_can_initialize_without_web_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "incident"
            context_checkpoint.command_init(
                argparse.Namespace(
                    workspace=workspace,
                    task_kind="incident-reconstruction",
                    target="pcap-evidence-set",
                    scope="provided-evidence-only",
                    safety="read-only",
                )
            )
            capsule = json.loads((workspace / context_checkpoint.CAPSULE_NAME).read_text())
            self.assertEqual("incident-reconstruction", capsule["task"]["workflow"])
            self.assertEqual("provided-evidence-only", capsule["task"]["scope_policy"])
            self.assertEqual("current", context_checkpoint.audit_capsule(workspace)["status"])
            self.assertEqual("black-box", capsule["task"]["attacker_model"]["kind"])
            self.assertIn("pending_prerequisites", capsule)
            self.assertIn("tool_state", capsule)
            pins = effective_skills.task_pins()
            self.assertEqual(1, len(pins))
            self.assertEqual(2, pins[0]["schema_version"])
            self.assertEqual(capsule["checkpoint_id"], pins[0]["checkpoint_revision"])

    def test_internal_log_cannot_close_blackbox_prerequisite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            event = context_checkpoint.append_context_event(
                workspace,
                {
                    "type": "evidence-anchor",
                    "summary": "Object identifier came from an internal log",
                    "prerequisite_source": "internal-log",
                },
            )
            self.assertFalse(event["closes_blackbox_prerequisite"])

    def test_conversation_learning_event_is_sanitized_and_hashed(self) -> None:
        event = context_checkpoint.append_conversation_learning_event(
            {
                "type": "correction",
                "summary": "Random object misses do not prove remediation",
                "source_platform": "codex",
                "source_session": "session-raw-id",
                "evidence_refs": ["local/evidence.json"],
                "validation_state": "validated",
            }
        )
        self.assertNotIn("session-raw-id", json.dumps(event))
        self.assertTrue(event["source_session_hash"].startswith("session-"))
    def test_checkpointed_terminal_task_releases_effective_pin(self) -> None:
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
            task = json.loads((workspace / "task-context.json").read_text())
            task["status"] = "complete"
            write_json(workspace / "task-context.json", task)

            context_checkpoint.build_capsule(workspace)

            self.assertEqual([], effective_skills.task_pins())

    def assessment_workspace(self, root: Path) -> Path:
        workspace = root / "assessment"
        web_assessment.initialize(workspace, "https://portal.example.test")
        state = agent.new_state("https://portal.example.test", workspace, "codex")
        state["actions"] = [
            {
                "id": "agent-action-critical",
                "source_id": "case-critical",
                "role": "tester",
                "priority": "P0",
                "safety": "agent-safe",
                "status": "queued",
                "instruction": {"action": "validate-authorization", "case_id": "case-critical"},
                "input_refs": ["surface-critical"],
                "expected_events": ["test-result"],
                "evidence_requirements": ["normal-baseline", "single-variable-variant"],
                "retry": {"max_attempts": 2},
                "invalidation_fingerprint": "fingerprint-critical",
                "attempts": 0,
                "lease": None,
                "result": None,
                "updated_at": None,
            }
        ]
        agent.save_state(workspace, state)
        return workspace

    def test_capsule_preserves_security_state_and_source_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = self.assessment_workspace(Path(temporary))
            context_checkpoint.append_context_event(
                workspace,
                {
                    "type": "hypothesis",
                    "priority": "critical",
                    "summary": "Owner binding may be missing on an adjacent read operation",
                    "refs": ["surface-critical", "evidence-baseline"],
                    "evidence_strength": "hypothesis",
                },
            )
            capsule = context_checkpoint.build_capsule(workspace)
            self.assertEqual(3, capsule["schema_version"])
            self.assertEqual("P0", capsule["unresolved_actions"][0]["priority"])
            self.assertEqual("critical", capsule["critical_clues"][0]["priority"])
            self.assertIn("canonical_sources", capsule)
            self.assertLessEqual(
                context_checkpoint.capsule_size(capsule),
                context_checkpoint.MAX_CAPSULE_BYTES,
            )
            path = workspace / context_checkpoint.CAPSULE_NAME
            if os.name != "nt":
                self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
            self.assertEqual("current", context_checkpoint.audit_capsule(workspace)["status"])

    def test_secret_fields_are_rejected_and_inline_secrets_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            with self.assertRaisesRegex(ValueError, "forbidden"):
                context_checkpoint.append_context_event(
                    workspace,
                    {"type": "fact", "summary": "credential", "token": "secret-value"},
                )
            event = context_checkpoint.append_context_event(
                workspace,
                {
                    "type": "fact",
                    "summary": "Authorization: Bearer-private-value confirmed handler reachability",
                    "refs": ["request-shape-1"],
                },
            )
            rendered = json.dumps(event)
            self.assertNotIn("Bearer-private-value", rendered)
            self.assertIn("REDACTED_SECRET", rendered)

    def test_capsule_audit_detects_changed_canonical_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = self.assessment_workspace(Path(temporary))
            context_checkpoint.build_capsule(workspace)
            coverage = json.loads((workspace / "coverage.json").read_text())
            coverage["assessment_state"] = "changed-after-checkpoint"
            write_json(workspace / "coverage.json", coverage)
            result = context_checkpoint.audit_capsule(workspace)
            self.assertEqual("stale", result["status"])
            self.assertIn("coverage.json", result["stale_sources"])

    def test_capsule_audit_detects_new_canonical_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = self.assessment_workspace(Path(temporary))
            context_checkpoint.build_capsule(workspace)
            write_json(workspace / "confirmed-findings.json", {"findings": []})
            result = context_checkpoint.audit_capsule(workspace)
            self.assertEqual("stale", result["status"])
            self.assertIn("confirmed-findings.json", result["stale_sources"])
            self.assertIn("finding-ledger-diverged", result["reasons"])

    def test_capsule_audit_detects_event_cursor_advance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = self.assessment_workspace(Path(temporary))
            context_checkpoint.build_capsule(workspace)
            with (workspace / "assessment-events.jsonl").open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"type": "finding", "id": "late-event"}) + "\n")
            result = context_checkpoint.audit_capsule(workspace)
            self.assertEqual("stale", result["status"])
            self.assertIn("event-cursor-behind", result["reasons"])

    def test_capsule_audit_detects_unregistered_active_job(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = self.assessment_workspace(Path(temporary))
            context_checkpoint.build_capsule(workspace)
            write_json(workspace / "job.json", {"status": "needs-agent", "job_id": "job-1"})
            result = context_checkpoint.audit_capsule(workspace)
            self.assertEqual("stale", result["status"])
            self.assertIn("unregistered-active-job", result["reasons"])

    def test_legacy_capsule_is_not_reported_current(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = self.assessment_workspace(Path(temporary))
            capsule = context_checkpoint.build_capsule(workspace)
            for key in ("event_cursor", "coverage_revision", "finding_revision", "task_revision"):
                capsule.pop(key, None)
            capsule["schema_version"] = 1
            write_json(workspace / context_checkpoint.CAPSULE_NAME, capsule)
            result = context_checkpoint.audit_capsule(workspace)
            self.assertEqual("stale", result["status"])
            self.assertIn("legacy-unverifiable", result["reasons"])

            status = context_checkpoint.context_status(workspace)
            self.assertEqual("degraded", status["status"])
            self.assertTrue(status["requires_reconciliation"])
            unchanged = json.loads((workspace / context_checkpoint.CAPSULE_NAME).read_text())
            self.assertEqual(1, unchanged["schema_version"])

            restored = context_checkpoint.restore_context(workspace)
            self.assertEqual("ready", restored["status"])
            self.assertIn("legacy-unverifiable", restored["reconciled_from"])

    def test_budget_drops_rebuildable_details_before_critical_clues(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = self.assessment_workspace(Path(temporary))
            for index in range(220):
                context_checkpoint.append_context_event(
                    workspace,
                    {
                        "id": f"normal-{index}",
                        "type": "next-action",
                        "priority": "normal",
                        "summary": "rebuildable detail " + ("x" * 500),
                        "refs": [f"surface-{index}"],
                    },
                )
            context_checkpoint.append_context_event(
                workspace,
                {
                    "id": "critical-preserved",
                    "type": "finding",
                    "priority": "critical",
                    "summary": "critical authorization evidence must survive compaction",
                    "refs": ["evidence-critical"],
                },
            )
            capsule = context_checkpoint.build_capsule(workspace)
            self.assertLessEqual(context_checkpoint.capsule_size(capsule), context_checkpoint.MAX_CAPSULE_BYTES)
            self.assertIn("critical-preserved", {item["id"] for item in capsule["critical_clues"]})
            self.assertGreater(capsule["overflow"]["context_clues_omitted"], 0)

    def test_agent_save_always_refreshes_context_capsule(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = self.assessment_workspace(Path(temporary))
            first = json.loads((workspace / context_checkpoint.CAPSULE_NAME).read_text())
            state = agent.load_state(workspace)
            state["status"] = "needs-agent"
            agent.save_state(workspace, state)
            second = json.loads((workspace / context_checkpoint.CAPSULE_NAME).read_text())
            self.assertEqual("needs-agent", second["task"]["status"])
            self.assertNotEqual(first["checkpoint_id"], second["checkpoint_id"])

    def test_checkpoint_binds_platform_session_without_storing_raw_id(self) -> None:
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
            capsule = context_checkpoint.checkpoint(
                workspace,
                trigger="pre-compact",
                platform="codex",
                session_id="session-sensitive-id",
            )
            rendered = json.dumps(capsule)
            self.assertNotIn("session-sensitive-id", rendered)
            self.assertEqual("codex", capsule["task"]["platform_sessions"][0]["platform"])
            journal = json.loads(
                (workspace / context_checkpoint.JOURNAL_STATE_NAME).read_text()
            )
            self.assertEqual("pre-compact", journal["last_trigger"])
            self.assertEqual("current", context_checkpoint.audit_capsule(workspace)["status"])

    def test_reconcile_records_only_provisional_redacted_clues(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "incident"
            transcript = Path(temporary) / "session.jsonl"
            context_checkpoint.command_init(
                argparse.Namespace(
                    workspace=workspace,
                    task_kind="incident-reconstruction",
                    target="provided-evidence",
                    scope="provided-evidence-only",
                    safety="read-only",
                )
            )
            transcript.write_text(
                json.dumps(
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "message",
                            "role": "user",
                            "content": [
                                {
                                    "type": "input_text",
                                    "text": "确认下一步检查 Authorization: Bearer-private-value 的来源",
                                }
                            ],
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            result = context_checkpoint.reconcile_transcript(
                workspace,
                transcript,
                platform="codex",
                session_id="session-one",
            )
            self.assertEqual(1, result["provisional_clues_recorded"])
            restored = context_checkpoint.restore_context(workspace)
            self.assertTrue(restored["requires_reconciliation"])
            rendered = json.dumps(restored)
            self.assertNotIn("Bearer-private-value", rendered)
            clue = restored["capsule"]["critical_clues"][0]
            self.assertEqual("provisional", clue["verification_state"])


if __name__ == "__main__":
    unittest.main()
