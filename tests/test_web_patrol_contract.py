from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import effective_skills  # noqa: E402

SKILL = ROOT / "skills" / "blue-web-patrol"


class WebPatrolContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.content = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        self.reference = (
            SKILL / "references" / "comprehensive-assessment.md"
        ).read_text(encoding="utf-8")
        self.template = json.loads(
            (SKILL / "templates" / "coverage-matrix.json").read_text(
                encoding="utf-8"
            )
        )
        self.events = (
            SKILL / "references" / "web-assessment-events.md"
        ).read_text(encoding="utf-8")
        self.operations = (
            SKILL / "references" / "operations-contract.md"
        ).read_text(encoding="utf-8")
        self.global_policy = (
            ROOT / "policies" / "security-conclusion.md"
        ).read_text(encoding="utf-8")

    def test_open_ended_site_assessment_defaults_to_comprehensive(self) -> None:
        self.assertIn("渗透测试", self.content)
        self.assertIn("主动发现漏洞", self.content)
        self.assertIn("默认\n  `comprehensive`", self.content)
        self.assertIn("不能自行缩成快速扫描", self.content)

    def test_core_prompt_stays_within_warning_budget(self) -> None:
        self.assertLessEqual(
            effective_skills.estimated_tokens(self.content),
            effective_skills.RECOMMENDED_SKILL_TOKENS,
        )

    def test_effective_prompt_hard_limit_rejects_activation(self) -> None:
        with self.assertRaisesRegex(ValueError, "exceeds token budget"):
            effective_skills.enforce_token_budget(
                "oversized test skill", effective_skills.MAX_SKILL_TOKENS + 1
            )

    def test_two_accounts_do_not_collapse_assessment_to_authorization(self) -> None:
        self.assertIn("两个账号", self.content)
        self.assertIn("不能决定整体测试边界", self.content)
        for domain in (
            "authorization",
            "injection",
            "browser-content",
            "server-side-processing",
            "files-data-export",
            "api-protocol-variants",
            "business-logic",
            "platform-exposure",
        ):
            self.assertIn(domain, {item["id"] for item in self.template["coverage"]})

    def test_known_vulnerability_hint_triggers_gap_and_adjacent_analysis(self) -> None:
        self.assertIn("此前为什么漏掉", self.content)
        self.assertIn("同数据源、同 sink", self.content)
        self.assertIn("一个渲染点转义不能外推", self.reference)

    def test_cold_start_searches_exact_historical_target(self) -> None:
        self.assertIn(
            "blue-sec-report-ingest search --system <target> --json",
            self.content,
        )
        self.assertIn("命中记为 `historical`", self.content)
        self.assertIn("历史差异轮", self.reference)
        self.assertIn("historical_baseline_checked", self.template["stop_gates"])
        self.assertIn("history", self.template)

    def test_active_hypotheses_cover_unrelated_workflow_shapes(self) -> None:
        for transformation in (
            "删除、清空或放宽",
            "替换身份、对象",
            "list/detail/create/update/approve/export/download",
            "Content-Type",
            "输入生产者到页面、预览、发布",
            "组合成可达路径",
        ):
            self.assertIn(transformation, self.reference)
        pass_ids = {item["id"] for item in self.template["phases"]}
        self.assertEqual(
            {
                "scope-safety",
                "history-cold-start",
                "related-passive-discovery",
                "surface-normalization",
                "work-unit-clustering",
                "test-plan-compilation",
                "risk-execution",
                "adjacent-replan",
            },
            pass_ids,
        )
        self.assertIn("missed_findings", self.template)

    def test_completion_requires_machine_readable_stop_gates(self) -> None:
        self.assertEqual(8, self.template["schema_version"])
        self.assertEqual("interim", self.template["assessment_state"])
        self.assertTrue(self.template["stop_gates"])
        self.assertIn("Stop Gates", self.content)
        self.assertIn("禁止用于“测试完成”的结论", self.content)
        self.assertIn("阶段性结果", self.content)
        self.assertIn("discovery_phases_resolved", self.template["stop_gates"])
        self.assertIn("test_queue_resolved", self.template["stop_gates"])
        self.assertIn("route_inventory_current_validated", self.template["stop_gates"])
        self.assertIn("route_navigation_and_render_complete", self.template["stop_gates"])

    def test_surface_model_covers_two_unrelated_application_shapes(self) -> None:
        for surface in (
            "页面、路由、lazy chunk、API",
            "角色、租户、对象所有权和业务状态",
            "输入点、客户端 sink、服务端处理器、文件",
        ):
            self.assertIn(surface, self.content)
        self.assertIn("SPA、REST/OpenAPI", self.reference)
        self.assertIn("GraphQL", self.reference)
        self.assertIn("WebSocket", self.reference)

    def test_spa_completion_uses_validated_surface_inventory(self) -> None:
        self.assertIn("surface-inventory.json", self.content)
        self.assertIn("`validApis`", self.content)
        self.assertIn("错误拼接", self.content)
        self.assertIn("真实 `404/410`", self.content)
        self.assertIn("假 `200`", self.content)
        self.assertIn("未映射控件", self.content)

    def test_executable_planner_and_related_scope_are_required(self) -> None:
        for command in (
            "blue-sec-agent run",
            "blue-sec-agent status",
            "blue-sec-web-assessment compile",
            "record-event",
            "blue-sec-web-assessment check",
        ):
            self.assertIn(command, self.content)
        self.assertEqual("related-discovery", self.template["scope"]["mode"])
        self.assertIn("不同注册主域", self.content)
        self.assertIn("results.md", self.content)

    def test_domains_are_split_into_derived_families(self) -> None:
        self.assertEqual(9, len(self.template["coverage"]))
        families = {
            family["id"]
            for domain in self.template["coverage"]
            for family in domain["families"]
        }
        for family in (
            "authorization.object-level",
            "api-protocol.graphql",
            "api-protocol.edge-backend-normalization",
            "business-logic.quota-resource-abuse",
            "identity-session.response-differential",
            "identity-session.token-claim-minimization",
            "platform-exposure.client-bootstrap-config",
            "platform-exposure.dependencies-supply-chain",
            "platform-exposure.error-exception-logging",
        ):
            self.assertIn(family, families)
        self.assertIn("顶层状态由 test cell 自动汇总", self.content)

    def test_priority_safety_and_negative_result_contract(self) -> None:
        for text in (
            "P0 新发现可以抢占",
            "安全等级独立记录",
            "surface fingerprint",
            "只完成 P0/P1",
            "missed-finding",
        ):
            self.assertIn(text, self.content + self.reference)

    def test_event_contract_covers_resume_evidence_and_learning(self) -> None:
        for event_type in (
            "surface-discovered",
            "test-result",
            "candidate-disposition",
            "candidate-dependency",
            "missed-finding",
            "runtime-condition",
        ):
            self.assertIn(event_type, self.events)
        self.assertIn("reversible", self.events)
        self.assertIn("cleanup", self.events)
        self.assertIn("不能复制 Cookie", self.events)
        self.assertIn("deferred-with-reason", self.events)
        self.assertIn("validation_dependencies", self.content)

    def test_context_compaction_restores_from_machine_state(self) -> None:
        for text in (
            "context-capsule.json",
            "blue-sec-agent checkpoint",
            "canonical source",
            "不能从聊天摘要猜测进度",
        ):
            self.assertIn(text, self.content)

    def test_blackbox_prerequisites_require_attacker_reachable_provenance(self) -> None:
        for source in (
            "attacker-public",
            "attacker-authenticated",
            "attacker-derived",
            "internal-log",
            "historical-report",
        ):
            self.assertIn(source, self.operations + self.global_policy)
        self.assertIn("producer -> controlled object -> consumer -> impact", self.operations)
        self.assertIn("随机、失效或未知所有权对象的空响应不能证明", self.operations)

    def test_traffic_history_requires_coverage_and_tolerant_parsing(self) -> None:
        for text in (
            "检索时间范围",
            "损坏记录",
            "解析失败",
            "最新成功认证响应",
            "继续扫描",
        ):
            self.assertIn(text, self.operations)

    def test_standard_references_are_versioned(self) -> None:
        refs = [
            reference
            for domain in self.template["coverage"]
            for family in domain["families"]
            for reference in family["standard_refs"]
        ]
        self.assertTrue(all(":" in ref or "v" in ref for ref in refs))
        self.assertTrue(
            all(
                not ref.startswith("WSTG-") or ref.startswith("WSTG-v4.2-")
                for ref in refs
            )
        )


if __name__ == "__main__":
    unittest.main()
