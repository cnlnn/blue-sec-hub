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

import effective_skills  # noqa: E402
import learning_policy  # noqa: E402
import learning_store  # noqa: E402


def run(
    data: Path,
    *args: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["BLUE_SEC_DATA"] = str(data)
    environment["BLUE_SEC_CONFIG"] = str(data / "config")
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "learning.py"), *args],
        cwd=ROOT,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )


def record(
    data: Path,
    *,
    kind: str = "instruction-rule",
    semantic_id: str = "normalized-routes",
    variant: str = "Normalize route metadata before semantic ranking",
) -> str:
    result = run(
        data,
        "record",
        "--skill",
        "blue-web-patrol",
        "--ownership",
        "local",
        "--kind",
        kind,
        "--semantic-id",
        semantic_id,
        "--task",
        "Compare reusable route metadata",
        "--failure",
        "Unnormalized route metadata causes inconsistent classification.",
        "--correction",
        f"{variant}.",
        "--success",
        f"{variant} for consistent classification.",
        "--conditions",
        "Applies to SPA route inventories with stable request metadata.",
        "--evidence",
        "tests/test_web_assessment.py",
        "--confidence",
        "high",
    )
    return next(line.split()[1] for line in result.stdout.splitlines() if line.startswith("[recorded]"))


def write_legacy_record(data: Path, record_id: str, state: str, occurrences: int = 1) -> None:
    root = data / "learning" / "records"
    root.mkdir(parents=True, exist_ok=True)
    value = {
        "schema_version": 1,
        "id": record_id,
        "state": state,
        "created_at": "2026-07-24T08:20:46+00:00",
        "last_seen_at": "2026-07-24T08:20:46+00:00",
        "occurrences": occurrences,
        "fingerprint": "f" * 64,
        "target": {
            "skill": "blue-web-patrol",
            "ownership": "local",
            "source": None,
        },
        "task": "Compare reusable route metadata",
        "failure": "Unnormalized route metadata causes inconsistent classification.",
        "correction": "Normalize route metadata before semantic ranking.",
        "successful_pattern": "Normalize route metadata for consistent classification.",
        "conditions": "Applies to SPA route inventories with stable request metadata.",
        "evidence_refs": ["tests/test_web_assessment.py"],
        "confidence": "high",
        "sensitivity": "public",
        "promotion": None,
    }
    if state == "dismissed":
        value["dismissed_reason"] = "superseded evidence"
    (root / f"{record_id}.json").write_text(
        json.dumps(value, ensure_ascii=False), encoding="utf-8"
    )


def write_eval_report(data: Path, skill: str = "blue-web-patrol") -> Path:
    core = {
        "schema_version": 1,
        "host": "codex",
        "model": "test-model",
        "effective_revision": "revision-before-learning",
        "dataset_sha256": "d" * 64,
        "cases": [
            {
                "id": "behavior-test",
                "skill": skill,
                "type": "behavior",
                "passed": True,
                "failures": [],
            }
        ],
    }
    report = {**core, "passed": True, "result_sha256": learning_store.digest(core)}
    path = data / "eval-results" / "report.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


class LearningContentPlaneTest(unittest.TestCase):
    def test_effective_snapshot_injects_one_global_conclusion_policy_into_every_skill(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            with mock.patch.dict(os.environ, {"BLUE_SEC_DATA": str(data)}):
                metadata = effective_skills.compile_snapshot()
                root = data / "effective" / metadata["revision"] / "skills"
                entries = sorted(root.glob("*/SKILL.md"))
                self.assertEqual(21, len(entries))
                for entry in entries:
                    self.assertEqual(
                        1,
                        entry.read_text(encoding="utf-8").count(
                            effective_skills.GLOBAL_POLICY_MARKER
                        ),
                    )
                self.assertEqual(
                    effective_skills.global_policy_sha256(),
                    metadata["global_policy_sha256"],
                )
                self.assertGreater(metadata["global_policy_tokens"], 0)
                self.assertTrue(
                    all(
                        value["global_policy_tokens"] == metadata["global_policy_tokens"]
                        for value in metadata["prompt_budgets"].values()
                    )
                )

    def test_effective_status_detects_global_policy_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            with mock.patch.dict(os.environ, {"BLUE_SEC_DATA": str(data)}):
                effective_skills.compile_snapshot(activate=True)
                self.assertEqual("ready", effective_skills.status()["status"])
                with mock.patch.object(
                    effective_skills,
                    "global_policy_sha256",
                    return_value="changed-policy",
                ):
                    status = effective_skills.status()
                self.assertEqual("degraded", status["status"])
                self.assertTrue(
                    any("global policy" in item for item in status["failures"])
                )
    def test_legacy_migration_is_complete_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            write_legacy_record(data, "legacy-candidate", "candidate", occurrences=2)
            write_legacy_record(data, "legacy-promoted", "promoted")
            write_legacy_record(data, "legacy-dismissed", "dismissed")

            before = json.loads(run(data, "status").stdout)
            self.assertEqual("degraded", before["status"])
            self.assertEqual(3, before["migration"]["pending_records"])

            dry_run = json.loads(run(data, "migrate", "--dry-run").stdout)
            self.assertEqual(
                {"candidate": 1, "archived-in-base": 1, "revoked": 1},
                dry_run["states"],
            )
            self.assertFalse((data / "learning/ledger.jsonl").exists())

            first = json.loads(run(data, "migrate").stdout)
            ledger = data / "learning/ledger.jsonl"
            first_lines = ledger.read_text(encoding="utf-8").splitlines()
            second = json.loads(run(data, "migrate").stdout)
            second_lines = ledger.read_text(encoding="utf-8").splitlines()

            self.assertEqual(3, first["migrated"])
            self.assertEqual(first["revision"], second["revision"])
            self.assertEqual(first_lines, second_lines)
            status = json.loads(run(data, "status").stdout)
            self.assertEqual("ready", status["status"])
            self.assertEqual(0, status["migration"]["pending_records"])
            self.assertEqual(1, status["candidate"])
            self.assertEqual(1, status["revoked"])
            self.assertEqual(1, status["archived_in_base"])
            self.assertEqual(0, status["approved"])

            environment = os.environ | {"BLUE_SEC_DATA": str(data)}
            metadata = json.loads(
                subprocess.run(
                    [sys.executable, str(ROOT / "scripts/effective_skills.py"), "compile"],
                    cwd=ROOT,
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                    env=environment,
                ).stdout
            )
            self.assertEqual(0, metadata["active_objects"])

    def test_promote_uses_local_ledger_without_creating_git_branch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            branch_before = subprocess.run(
                ["git", "branch", "--show-current"], cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE
            ).stdout.strip()
            record_id = record(data)
            run(data, "promote", record_id, "--review")
            branch_after = subprocess.run(
                ["git", "branch", "--show-current"], cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE
            ).stdout.strip()
            self.assertEqual(branch_before, branch_after)
            self.assertTrue((data / "learning" / "ledger.jsonl").is_file())
            skill = data / "effective" / "current" / "skills" / "blue-web-patrol" / "SKILL.md"
            self.assertIn("normalized-routes", skill.read_text(encoding="utf-8"))
            self.assertNotIn("normalized-routes", (ROOT / "skills/blue-web-patrol/SKILL.md").read_text(encoding="utf-8"))

    def test_single_session_correction_requires_eval_and_stays_local_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            record_id = record(data)
            blocked = run(data, "promote", record_id, "--session-correction", check=False)
            self.assertNotEqual(0, blocked.returncode)
            self.assertIn("requires --eval-result", blocked.stderr)

            report = write_eval_report(data)
            run(
                data,
                "promote",
                record_id,
                "--session-correction",
                "--eval-result",
                str(report),
            )
            record_state = json.loads(run(data, "show", record_id).stdout)
            approval = next(
                event
                for event in record_state["events"]
                if event["event"] == "approved"
            )
            self.assertEqual(1, approval["independent_scenarios"])
            self.assertEqual(
                "single-session-user-correction-with-skill-eval",
                approval["approval_basis"],
            )
            archive = json.loads(run(data, "archive", "--dry-run").stdout)
            self.assertEqual(0, archive["eligible"])

    def test_target_filters_cover_people_fields_and_full_plans(self) -> None:
        material = "\n".join(
            (
                "林家乐的账号必须保留。",
                "participantUserRightId 必须写入规则。",
                "1. 修复接口",
                "2. 更新对象 ID",
                "3. 发布任务",
            )
        )
        findings = learning_policy.target_specific_findings(material)
        self.assertTrue(any("person or account" in item for item in findings))
        self.assertTrue(any("task field" in item for item in findings))
        self.assertIn("full execution plan", findings)

    def test_failed_compile_does_not_approve_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            result = run(
                data,
                "record",
                "--skill",
                "missing-security-skill",
                "--semantic-id",
                "missing-target",
                "--task",
                "Compile a reusable security rule",
                "--failure",
                "The requested target Skill does not exist.",
                "--correction",
                "Reject approval when its target Skill cannot be compiled.",
                "--success",
                "Keep the candidate inactive after compilation fails.",
                "--conditions",
                "Applies whenever an Effective Skill target is missing.",
                "--evidence",
                "tests/test_learning_review.py",
                "--confidence",
                "high",
            )
            record_id = next(
                line.split()[1]
                for line in result.stdout.splitlines()
                if line.startswith("[recorded]")
            )
            promoted = run(data, "promote", record_id, check=False)
            self.assertNotEqual(0, promoted.returncode)
            status = json.loads(run(data, "status").stdout)
            self.assertEqual(1, status["candidate"])
            self.assertEqual(0, status["approved"])
            events = [
                json.loads(line)
                for line in (data / "learning/ledger.jsonl").read_text().splitlines()
            ]
            self.assertEqual(["recorded"], [event["event"] for event in events])

    def test_snapshot_tamper_is_detected_and_reconciled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            record_id = record(data)
            run(data, "promote", record_id)
            skill = data / "effective/current/skills/blue-web-patrol/SKILL.md"
            skill.write_text(skill.read_text(encoding="utf-8") + "\ntampered\n", encoding="utf-8")

            status = json.loads(run(data, "status").stdout)
            self.assertEqual("degraded", status["effective"]["status"])
            self.assertTrue(status["effective"]["failures"])

            reconciled = json.loads(run(data, "reconcile").stdout)
            self.assertEqual("ready", reconciled["status"])
            self.assertTrue(reconciled["quarantined"])
            status = json.loads(run(data, "status").stdout)
            self.assertEqual("ready", status["effective"]["status"])
            self.assertNotIn("tampered", skill.read_text(encoding="utf-8"))

    def test_knowledge_entry_is_searchable_but_not_in_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            record_id = record(data, kind="knowledge-entry", semantic_id="route-knowledge")
            run(data, "promote", record_id)
            skill = data / "effective/current/skills/blue-web-patrol/SKILL.md"
            self.assertNotIn("route-knowledge", skill.read_text(encoding="utf-8"))
            knowledge = list((data / "effective/current/knowledge/blue-web-patrol").glob("*.md"))
            self.assertEqual(1, len(knowledge))
            environment = os.environ.copy()
            environment["BLUE_SEC_DATA"] = str(data)
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/search_knowledge.py"), "semantic ranking", "--source", "overlays"],
                cwd=ROOT,
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                env=environment,
            )
            normalized_output = result.stdout.replace("\\", "/")
            self.assertIn("effective/current/knowledge/blue-web-patrol", normalized_output)
            self.assertIn("semantic ranking", result.stdout)

    def test_revoke_activates_new_revision_and_removes_rule(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            record_id = record(data)
            run(data, "promote", record_id)
            before = json.loads(
                subprocess.run(
                    [sys.executable, str(ROOT / "scripts/effective_skills.py"), "status"],
                    check=True,
                    text=True,
                    stdout=subprocess.PIPE,
                    env=os.environ | {"BLUE_SEC_DATA": str(data)},
                ).stdout
            )["active_revision"]
            run(data, "revoke", record_id, "--reason", "regression")
            status = json.loads(run(data, "status").stdout)
            after = status["effective"]["active_revision"]
            self.assertNotEqual(before, after)
            skill = data / "effective/current/skills/blue-web-patrol/SKILL.md"
            self.assertNotIn("normalized-routes", skill.read_text(encoding="utf-8"))

    def test_secret_or_target_is_rejected_before_object_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            result = run(
                data,
                "record",
                "--skill",
                "blue-web-patrol",
                "--kind",
                "knowledge-entry",
                "--task",
                "Inspect https://target.example/api/private",
                "--failure",
                "A target-specific note was proposed.",
                "--correction",
                "Bear" + "er abcdefghijklmnopqrstuvwxyz1234",
                "--success",
                "Keep secrets out of shared knowledge.",
                "--conditions",
                "Applies to equivalent evidence.",
                "--confidence",
                "high",
                check=False,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertFalse((data / "learning/ledger.jsonl").exists())

    def test_archive_dry_run_does_not_change_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            record_id = record(data, kind="knowledge-entry")
            run(data, "promote", record_id)
            before = subprocess.run(
                ["git", "status", "--porcelain"], cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE
            ).stdout
            value = json.loads(run(data, "archive", "--dry-run").stdout)
            after = subprocess.run(
                ["git", "status", "--porcelain"], cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE
            ).stdout
            self.assertEqual(1, value["eligible"])
            self.assertEqual(before, after)

    def test_supersede_is_required_for_a_stable_semantic_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            old = record(data)
            run(data, "promote", old)
            replacement = record(
                data,
                variant="Normalize and deduplicate route metadata before semantic ranking",
            )
            blocked = run(data, "promote", replacement, check=False)
            self.assertNotEqual(0, blocked.returncode)
            self.assertIn("use supersede", blocked.stderr)
            run(data, "supersede", old, replacement, "--reason", "more precise validated rule")
            status = json.loads(run(data, "status").stdout)
            self.assertEqual(1, status["approved"])
            self.assertEqual(1, status["superseded"])
            skill = data / "effective/current/skills/blue-web-patrol/SKILL.md"
            text = skill.read_text(encoding="utf-8")
            self.assertIn("Normalize and deduplicate", text)

    def test_audit_reports_a_corrupt_ledger_line(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            ledger = data / "learning/ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text("{not-json}\n", encoding="utf-8")
            result = run(data, "audit", check=False)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("ledger line 1: invalid JSON", result.stderr)

    def test_corrupt_ledger_blocks_new_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            ledger = data / "learning/ledger.jsonl"
            ledger.parent.mkdir(parents=True)
            ledger.write_text("{not-json}\n", encoding="utf-8")
            result = run(
                data,
                "record",
                "--skill",
                "blue-web-patrol",
                "--task",
                "Compare reusable route metadata",
                "--failure",
                "Unnormalized route metadata causes inconsistent classification.",
                "--correction",
                "Normalize route metadata before semantic ranking.",
                "--success",
                "Normalize route metadata for consistent classification.",
                "--conditions",
                "Applies to SPA route inventories with stable request metadata.",
                "--evidence",
                "tests/test_web_assessment.py",
                "--confidence",
                "high",
                check=False,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertEqual("{not-json}\n", ledger.read_text(encoding="utf-8"))

    def test_repeated_observations_have_unique_event_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            previous = os.environ.get("BLUE_SEC_DATA")
            os.environ["BLUE_SEC_DATA"] = str(data)
            try:
                first = learning_store.append_event(
                    {"event": "observed", "record_id": "same", "occurrences": 1}
                )
                second = learning_store.append_event(
                    {"event": "observed", "record_id": "same", "occurrences": 1}
                )
                self.assertNotEqual(first["event_id"], second["event_id"])
                self.assertEqual(2, len(learning_store.read_jsonl(learning_store.ledger_path())))
            finally:
                if previous is None:
                    os.environ.pop("BLUE_SEC_DATA", None)
                else:
                    os.environ["BLUE_SEC_DATA"] = previous

    def test_reconcile_base_is_deterministic_idempotent_and_does_not_approve(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            created = run(
                data,
                "record",
                "--skill",
                "blue-web-patrol",
                "--kind",
                "instruction-rule",
                "--task",
                "Compile open-ended assessments into resumable risk-prioritized test plans",
                "--failure",
                "A narrative checklist lost progress across sessions.",
                "--correction",
                "Use stable work units and an append-only event ledger.",
                "--success",
                "Every source mapping resumes without silent omissions.",
                "--conditions",
                "Applies to comprehensive Web assessments.",
                "--confidence",
                "high",
            )
            record_id = next(
                line.split()[1]
                for line in created.stdout.splitlines()
                if line.startswith("[recorded]")
            )

            preview = json.loads(run(data, "reconcile-base", "--dry-run").stdout)
            self.assertEqual(1, preview["eligible"])
            self.assertEqual(record_id, preview["records"][0]["record_id"])
            self.assertEqual(
                "web-resumable-risk-plan",
                preview["records"][0]["capability_id"],
            )

            applied = json.loads(run(data, "reconcile-base", "--apply").stdout)
            self.assertEqual(1, applied["reconciled"])
            status = json.loads(run(data, "status").stdout)
            self.assertEqual(0, status["candidate"])
            self.assertEqual(0, status["approved"])
            self.assertEqual(1, status["archived_in_base"])
            self.assertEqual(
                "ready",
                status["base_reconciliation"]["status"],
            )

            repeated = json.loads(run(data, "reconcile-base", "--apply").stdout)
            self.assertEqual(0, repeated["reconciled"])
            events = [
                item
                for item in learning_store.read_jsonl(data / "learning" / "ledger.jsonl")
                if item["event"] == "covered-by-base"
            ]
            self.assertEqual(1, len(events))
            receipt = json.loads(
                (data / "learning" / "base-reconciliation.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(1, len(receipt["records"]))

    def test_pinned_task_revision_survives_snapshot_pruning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            previous = os.environ.get("BLUE_SEC_DATA")
            os.environ["BLUE_SEC_DATA"] = str(data)
            try:
                revisions = [f"revision-{number}" for number in range(4)]
                def create_snapshot(revision: str) -> None:
                    root = data / "effective" / revision
                    (root / "skills").mkdir(parents=True)
                    learning_store.atomic_json(
                        root / "manifest.json",
                        {
                            "schema_version": 1,
                            "revision": revision,
                            "files": {},
                        },
                    )
                create_snapshot(revisions[0])
                effective_skills.activate_revision(revisions[0])
                workspace = data / "workspace"
                workspace.mkdir()
                learning_store.atomic_json(
                    workspace / "task-context.json",
                    {"task_id": "active-task", "status": "active"},
                )
                learning_store.atomic_json(
                    workspace / "context-capsule.json",
                    {"checkpoint_id": "checkpoint-active"},
                )
                pin = effective_skills.pin_task(
                    "active-task",
                    workspace,
                    revisions[0],
                    checkpoint_revision="checkpoint-active",
                    task_status="active",
                )
                self.assertEqual(2, pin["schema_version"])
                self.assertEqual(
                    1,
                    effective_skills.gc_task_pins()["counts"]["active"],
                )
                for revision in revisions[1:]:
                    create_snapshot(revision)
                    effective_skills.activate_revision(revision)
                self.assertTrue((data / "effective" / revisions[0] / "skills").is_dir())
                effective_skills.release_task("active-task")
            finally:
                if previous is None:
                    os.environ.pop("BLUE_SEC_DATA", None)
                else:
                    os.environ["BLUE_SEC_DATA"] = previous

    def test_task_pin_gc_releases_only_checkpointed_terminal_orphans(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary)
            previous = os.environ.get("BLUE_SEC_DATA")
            os.environ["BLUE_SEC_DATA"] = str(data)
            try:
                active = data / "active"
                terminal = data / "terminal"
                for workspace, task_id, status, checkpoint in (
                    (active, "task-active", "active", "checkpoint-active"),
                    (terminal, "task-terminal", "complete", "checkpoint-terminal"),
                ):
                    workspace.mkdir()
                    learning_store.atomic_json(
                        workspace / "task-context.json",
                        {"task_id": task_id, "status": status},
                    )
                    learning_store.atomic_json(
                        workspace / "context-capsule.json",
                        {"checkpoint_id": checkpoint},
                    )
                    effective_skills.pin_task(
                        task_id,
                        workspace,
                        "revision-1",
                        checkpoint_revision=checkpoint,
                        task_status=status,
                    )
                legacy = {
                    "schema_version": 1,
                    "task_id": "legacy-task",
                    "effective_revision": "revision-0",
                    "workspace_hash": "f" * 64,
                    "updated_at": "2026-08-02T00:00:00+00:00",
                }
                learning_store.atomic_json(
                    effective_skills.task_pins_root() / "legacy-task.json",
                    legacy,
                )

                preview = effective_skills.gc_task_pins()
                self.assertEqual(1, preview["counts"]["active"])
                self.assertEqual(1, preview["counts"]["orphaned"])
                self.assertEqual(1, preview["counts"]["recoverable"])

                applied = effective_skills.gc_task_pins(apply=True)
                self.assertEqual(1, applied["counts"]["released"])
                remaining = {item["task_id"] for item in effective_skills.task_pins()}
                self.assertEqual({"task-active", "legacy-task"}, remaining)
                migrated = next(
                    item for item in effective_skills.task_pins()
                    if item["task_id"] == "legacy-task"
                )
                self.assertEqual(2, migrated["schema_version"])
                self.assertEqual("quarantined-unverifiable", migrated["migration_state"])
            finally:
                if previous is None:
                    os.environ.pop("BLUE_SEC_DATA", None)
                else:
                    os.environ["BLUE_SEC_DATA"] = previous

    def test_effective_status_uses_source_tree_not_rewritten_commit_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            previous = os.environ.get("BLUE_SEC_DATA")
            os.environ["BLUE_SEC_DATA"] = temporary
            try:
                effective_skills.compile_snapshot(activate=True)
                self.assertEqual("ready", effective_skills.status()["status"])
                with mock.patch.object(effective_skills, "repository_revision", return_value="new-main-revision"):
                    value = effective_skills.status()
                self.assertEqual("ready", value["status"])
                with mock.patch.object(effective_skills, "repository_tree_sha256", return_value="changed-tree"):
                    value = effective_skills.status()
                self.assertEqual("degraded", value["status"])
                self.assertIn("active snapshot was compiled from a different source tree", value["failures"])
            finally:
                if previous is None:
                    os.environ.pop("BLUE_SEC_DATA", None)
                else:
                    os.environ["BLUE_SEC_DATA"] = previous

    def test_compile_excludes_runtime_cache_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            previous = os.environ.get("BLUE_SEC_DATA")
            os.environ["BLUE_SEC_DATA"] = temporary
            try:
                metadata = effective_skills.compile_snapshot()
                self.assertFalse(
                    any(
                        "__pycache__" in path or path.endswith(".pyc")
                        for path in metadata["files"]
                    )
                )
            finally:
                if previous is None:
                    os.environ.pop("BLUE_SEC_DATA", None)
                else:
                    os.environ["BLUE_SEC_DATA"] = previous


if __name__ == "__main__":
    unittest.main()
