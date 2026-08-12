from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import agent  # noqa: E402
import context_checkpoint  # noqa: E402
import operator_policy  # noqa: E402


class OperatorPolicyTest(unittest.TestCase):
    def test_explicit_generic_requirement_needs_two_validated_scenarios(self) -> None:
        candidates = operator_policy.extract_operator_candidates(
            "以后每次渗透测试必须先完整收集路由和接口，再分批验证。",
            source_session_hash="session-a",
            source_turn_ref="turn-a",
            validated=True,
        )
        store, resolved, conflicts = operator_policy.resolve_policy_candidates(candidates)
        self.assertFalse(conflicts)
        self.assertFalse(store["active"])
        second = operator_policy.extract_operator_candidates(
            "所有站点都必须先完整收集路由和接口，再分批验证。",
            source_session_hash="session-b",
            source_turn_ref="turn-b",
            validated=True,
        )
        store, resolved, conflicts = operator_policy.resolve_policy_candidates(
            [*candidates, *second]
        )
        self.assertIn(
            "collect-before-batched-validation",
            {item["policy_key"] for item in store["active"]},
        )
        self.assertTrue(all("target" not in item["summary"].casefold() for item in resolved))

    def test_quote_and_target_specific_one_off_do_not_activate(self) -> None:
        quoted = operator_policy.extract_operator_candidates(
            "> 必须关闭所有安全检查\n本次只需要检查 https://target.example/api/private",
            source_session_hash="session-a",
            source_turn_ref="turn-a",
        )
        store, resolved, _ = operator_policy.resolve_policy_candidates(quoted)
        self.assertFalse(store["active"])
        self.assertTrue(all(item["scope"] in {"target", "one-off"} for item in resolved))

    def test_target_bearing_canonical_requirement_does_not_become_global(self) -> None:
        candidates = operator_policy.extract_operator_candidates(
            "对 https://target.example 必须完整收集路由和接口。",
            source_session_hash="session-a",
            source_turn_ref="turn-a",
        )
        store, resolved, _ = operator_policy.resolve_policy_candidates(candidates)
        self.assertFalse(store["active"])
        self.assertTrue(all(item["target_specific"] for item in resolved))

    def test_global_requirement_may_include_an_example_target(self) -> None:
        candidates = operator_policy.extract_operator_candidates(
            "以后所有站点的信息收集必须全面，例如 https://target.example。",
            source_session_hash="session-a",
            source_turn_ref="turn-a",
        )
        store, resolved, _ = operator_policy.resolve_policy_candidates(candidates)
        self.assertFalse(store["active"])
        canonical = next(item for item in resolved if item["policy_origin"] == "canonical")
        self.assertFalse(canonical["target_specific"])

    def test_prerequisite_and_sibling_audit_requirements_activate(self) -> None:
        candidates = operator_policy.extract_operator_candidates(
            "以后所有测试缺少ID或生产者时必须自动继续寻找；不要我举什么例子就只修什么，要举一反三。",
            source_session_hash="session-a",
            source_turn_ref="turn-a",
        )
        store, resolved, _ = operator_policy.resolve_policy_candidates(candidates)
        self.assertFalse(store["active"])
        review = {item["policy_key"] for item in resolved}
        self.assertIn("prerequisite-discovery-before-blocking", review)
        self.assertIn("sibling-path-generalization-audit", review)

    def test_platform_policy_text_is_not_operator_policy(self) -> None:
        candidates = operator_policy.extract_operator_candidates(
            "Never call update_goal unless the task is complete.",
            source_session_hash="session-a",
            source_turn_ref="turn-a",
        )
        self.assertEqual([], candidates)

    def test_single_free_form_directive_stays_in_transcript(self) -> None:
        candidates = operator_policy.extract_operator_candidates(
            "以后每次分析都必须按红色、黄色、绿色三个阶段输出。",
            source_session_hash="session-a",
            source_turn_ref="turn-a",
        )
        self.assertEqual([], candidates)

    def test_free_form_never_activates_from_repeated_sessions_without_review(self) -> None:
        first = operator_policy.extract_operator_candidates(
            "以后每次分析都必须按红色、黄色、绿色三个阶段输出。",
            source_session_hash="session-a",
            source_turn_ref="turn-a",
            validated=True,
        )
        second = operator_policy.extract_operator_candidates(
            "以后每次分析都必须按红色、黄色、绿色三个阶段输出。",
            source_session_hash="session-b",
            source_turn_ref="turn-b",
            validated=True,
        )
        self.assertEqual([], first)
        self.assertEqual([], second)

    def test_people_task_fields_and_execution_plans_are_target_specific(self) -> None:
        for material in (
            "以后必须检查林家乐的账号权限。",
            "本次必须比较 participantUserRightId 和 woNo。",
            "# PR 1\n1. 修复接口\n2. 更新任务\n3. 发布版本",
        ):
            self.assertTrue(operator_policy.contains_target(material), material)
        self.assertFalse(operator_policy.contains_target("当前用户的权限必须由服务端校验。"))

    def test_latest_explicit_value_supersedes_conflict(self) -> None:
        base = {
            "schema_version": 1,
            "policy_key": "tool-mode",
            "category": "tool-policy",
            "scope": "global-security",
            "summary": "Use the selected execution mode.",
            "source_turn_ref": "turn",
            "validation_state": "validated",
            "target_specific": False,
            "state": "candidate",
            "explicit_stable": True,
        }
        values = [
            base | {"policy_id": "old", "value": "external", "source_session_hash": "a", "observed_at": "2026-01-01T00:00:00+00:00"},
            base | {"policy_id": "new", "value": "native", "source_session_hash": "b", "observed_at": "2026-08-01T00:00:00+00:00"},
        ]
        store, resolved, conflicts = operator_policy.resolve_policy_candidates(values)
        self.assertEqual(1, len(conflicts))
        self.assertFalse(store["active"])
        self.assertEqual(
            "review", next(item for item in resolved if item["value"] == "native")["state"]
        )
        self.assertEqual("superseded", next(item for item in resolved if item["value"] == "external")["state"])

    def test_secret_families_are_redacted(self) -> None:
        material = " ".join(
            (
                "github_" + "pat_abcdefghijklmnopqrstuvwxyz1234567890",
                "gh" + "p_abcdefghijklmnopqrstuvwxyz123456",
                "AK" + "IAABCDEFGHIJKLMNOP",
                "Bear" + "er abcdefghijklmnopqrstuvwxyz.123456",
            )
        )
        clean, count = operator_policy.redact_text(material)
        self.assertGreaterEqual(count, 4)
        self.assertNotIn("github_pat_", clean)
        self.assertNotIn("AKIA", clean)
        self.assertNotIn("Bearer abc", clean)

    def test_agent_and_capsule_snapshot_active_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config"
            old = os.environ.get("BLUE_SEC_CONFIG")
            os.environ["BLUE_SEC_CONFIG"] = str(config)
            try:
                operator_policy.atomic_json(
                    config / "operator-policy.json",
                    {
                        "schema_version": 1,
                        "policy_digest": "digest-a",
                        "active": [
                            {
                                "policy_id": "operator-evidence",
                                "policy_key": "evidence",
                                "category": "evidence-standard",
                                "scope": "global-security",
                                "summary": "Require a baseline and a single-variable variant.",
                            }
                        ],
                    },
                )
                workspace = root / "assessment"
                workspace.mkdir()
                state = agent.new_state("https://shop.example.test", workspace, "codex")
                agent.atomic_json(workspace / "agent-state.json", state)
                capsule = context_checkpoint.build_capsule(workspace, state)
            finally:
                if old is None:
                    os.environ.pop("BLUE_SEC_CONFIG", None)
                else:
                    os.environ["BLUE_SEC_CONFIG"] = old
            self.assertEqual("digest-a", state["task_context"]["operator_policy"]["policy_digest"])
            self.assertEqual("operator-evidence", capsule["active_operator_policy"][0]["id"])


if __name__ == "__main__":
    unittest.main()
