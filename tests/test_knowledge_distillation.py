from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SESSION = ROOT / "scripts" / "knowledge_session.py"
DISTILL = ROOT / "scripts" / "knowledge_distill.py"
CONFIG = ROOT / "scripts" / "hub_config.py"
INGEST = ROOT / "scripts" / "report_ingestion.py"


class KnowledgeDistillationTest(unittest.TestCase):
    def run_tool(
        self,
        environment: dict[str, str],
        script: Path,
        *args: str,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python", str(script), *args],
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )

    def environment(self, root: Path) -> dict[str, str]:
        value = os.environ.copy()
        value["BLUE_SEC_CACHE"] = str(root / "cache")
        value["BLUE_SEC_DATA"] = str(root / "data")
        value["BLUE_SEC_CONFIG"] = str(root / "config")
        return value

    def test_session_is_private_idempotent_and_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "temporary-knowledge"
            source.mkdir()
            environment = self.environment(root)

            first = self.run_tool(
                environment,
                SESSION,
                "open",
                str(source),
                "--session-id",
                "ks-fixture",
            )
            second = self.run_tool(environment, SESSION, "open", str(source))
            self.assertIn("[opened] ks-fixture", first.stdout)
            self.assertIn("[current] ks-fixture", second.stdout)
            session_root = root / "cache" / "sessions" / "ks-fixture"
            if os.name != "nt":
                self.assertEqual(
                    stat.S_IMODE(session_root.stat().st_mode),
                    0o700,
                )
                self.assertEqual(
                    stat.S_IMODE((session_root / "session.json").stat().st_mode),
                    0o600,
                )
            self.assertFalse((root / "config" / "config.json").exists())

            self.run_tool(environment, SESSION, "close", "ks-fixture")
            self.assertFalse(session_root.exists())
            self.assertTrue(source.exists())

    def test_security_report_root_mode_is_persistent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "persistent"
            source.mkdir()
            environment = self.environment(root)
            self.run_tool(
                environment,
                CONFIG,
                "add-report-root",
                str(source),
                "--mode",
                "security-reports",
            )
            value = json.loads(
                (root / "config" / "config.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                value["report_root_modes"][str(source.resolve())],
                "security-reports",
            )

    def test_configured_distillation_uses_only_accepted_current_ingestion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "reports"
            source.mkdir()
            accepted = source / "安全测试报告.txt"
            accepted.write_text(
                "安全测试报告\n安全测试对象\n安全测试结果详情\n"
                "[高危] 水平越权\n漏洞描述\n修复建议\n",
                encoding="utf-8",
            )
            rejected = source / "会议纪要.txt"
            rejected.write_text("季度会议纪要\n培训和预算安排\n", encoding="utf-8")
            environment = self.environment(root)
            self.run_tool(
                environment,
                CONFIG,
                "add-report-root",
                str(source),
                "--mode",
                "security-reports",
            )
            self.run_tool(environment, INGEST, "scan", "--configured", "--quiet")

            self.run_tool(
                environment,
                DISTILL,
                "run",
                "--configured",
                "--run-id",
                "kd-current-only",
            )
            ledger_path = (
                root
                / "data"
                / "knowledge-distillation"
                / "runs"
                / "kd-current-only"
                / "source-ledger.jsonl"
            )
            ledger_paths = {
                json.loads(line)["path"]
                for line in ledger_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            }
            self.assertIn(str(accepted.resolve()), ledger_paths)
            self.assertNotIn(str(rejected.resolve()), ledger_paths)

    def test_legacy_cache_without_system_identity_is_reextracted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "reports"
            source.mkdir()
            report = source / "订单系统安全测试报告.txt"
            report.write_text(
                "安全测试报告\n[高危] 水平越权\n漏洞描述\n修复建议\n",
                encoding="utf-8",
            )
            digest = hashlib.sha256(report.read_bytes()).hexdigest()
            legacy = (
                root
                / "data"
                / "knowledge-distillation"
                / "artifacts"
                / digest[:2]
                / f"{digest}.json"
            )
            legacy.parent.mkdir(parents=True)
            legacy.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "finding_id": "legacy",
                                "title": "水平越权",
                                "system_key": None,
                            }
                        ],
                        "diagnostics": {},
                    }
                ),
                encoding="utf-8",
            )
            environment = self.environment(root)
            self.run_tool(
                environment,
                DISTILL,
                "run",
                str(source),
                "--run-id",
                "kd-cache-identity",
            )
            ledger = (
                root
                / "data"
                / "knowledge-distillation"
                / "runs"
                / "kd-cache-identity"
                / "finding-ledger.jsonl"
            )
            findings = [json.loads(line) for line in ledger.read_text().splitlines()]
            self.assertTrue(findings)
            self.assertTrue(all(item.get("system_key") for item in findings))
            self.assertTrue(
                all(
                    item.get("system_identity_confidence") in {"strong", "weak"}
                    for item in findings
                )
            )

    def test_weak_filename_identities_do_not_count_as_independent_systems(self) -> None:
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        from knowledge_distill import independent_system_count

        findings = [
            {"system_key": "filename-a", "system_identity_confidence": "weak"},
            {"system_key": "filename-b", "system_identity_confidence": "weak"},
            {"system_key": "verified-a", "system_identity_confidence": "strong"},
            {"system_key": "verified-a", "system_identity_confidence": "strong"},
            {"system_key": "verified-b", "system_identity_confidence": "strong"},
        ]
        self.assertEqual(independent_system_count(findings), 2)

    def test_candidate_keys_remove_status_and_reject_report_labels(self) -> None:
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        from knowledge_distill import finding_cluster_key, generic_finding_title

        base = {"weakness_class": "不安全的前端加密"}
        fixed = {"weakness_class": "不安全的前端加密（已修复）"}
        self.assertEqual(finding_cluster_key(base), finding_cluster_key(fixed))
        self.assertTrue(generic_finding_title("具体描述"))
        self.assertTrue(generic_finding_title("漏洞修复统计结果展示"))
        self.assertTrue(generic_finding_title("漏洞管理闭环评估（基于表字段可审计性）"))
        self.assertTrue(
            generic_finding_title(
                "确保每个用户仅能访问其执行任务所需的最少资源，不得扩大权限范围"
            )
        )

        self.assertEqual(
            finding_cluster_key({"weakness_class": "用户名枚举"}),
            "identity-state-response-differential",
        )
        self.assertEqual(
            finding_cluster_key({"weakness_class": "电表MQTT通信未设置账号密码"}),
            "message-broker-authentication",
        )
        self.assertEqual(
            finding_cluster_key({"weakness_class": "远程断电漏洞"}),
            "ot-actuator-command-authorization",
        )

    def test_distillation_accounts_for_sources_and_separates_scanner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "reports"
            source.mkdir()
            manual = source / "渗透测试报告.txt"
            manual.write_text(
                "安全测试报告\n[高危] 水平越权\n漏洞描述\n修复建议\n",
                encoding="utf-8",
            )
            (source / "渗透测试报告副本.txt").write_bytes(manual.read_bytes())
            (source / "漏洞扫描报告.txt").write_text(
                "漏洞扫描报告\n[高危] SQL注入\n漏洞描述\n修复建议\n",
                encoding="utf-8",
            )
            (source / "bundle.js").write_text(
                "const token = 'not a report';",
                encoding="utf-8",
            )
            if os.name != "nt":
                (source / "outside-link.txt").symlink_to(manual)
            extracted_binary = source / "tool.exe.extracted"
            extracted_binary.mkdir()
            (extracted_binary / "resource.7z").write_bytes(b"not an archive")
            environment = self.environment(root)
            result = self.run_tool(
                environment,
                DISTILL,
                "run",
                str(source),
                "--run-id",
                "kd-fixture",
            )
            self.assertIn('"state": "complete"', result.stdout)
            run = root / "data" / "knowledge-distillation" / "runs" / "kd-fixture"
            sources = [
                json.loads(line)
                for line in (run / "source-ledger.jsonl").read_text(
                    encoding="utf-8"
                ).splitlines()
            ]
            expected_sources = 6 if os.name != "nt" else 5
            self.assertEqual(len(sources), expected_sources)
            statuses = {item["status"] for item in sources}
            self.assertIn("deduplicated", statuses)
            self.assertIn("unsupported", statuses)
            self.assertTrue(
                any(
                    item.get("reason") == "active-content-extraction"
                    for item in sources
                )
            )
            if os.name != "nt":
                self.assertTrue(
                    any(item.get("reason") == "symbolic-link" for item in sources)
                )
            findings = [
                json.loads(line)
                for line in (run / "finding-ledger.jsonl").read_text(
                    encoding="utf-8"
                ).splitlines()
            ]
            dispositions = {item["disposition"] for item in findings}
            self.assertIn("covered-by-pattern", dispositions)
            self.assertIn("scanner-only", dispositions)
            self.assertTrue(
                all(item["evidence_state"] == "historical" for item in findings)
            )
            before = (run / "source-ledger.jsonl").read_bytes()
            resumed = self.run_tool(
                environment,
                DISTILL,
                "run",
                str(source),
                "--run-id",
                "kd-fixture",
                "--resume",
            )
            self.assertIn('"state": "complete"', resumed.stdout)
            self.assertEqual(before, (run / "source-ledger.jsonl").read_bytes())
            summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual({}, summary["failure_reason_counts"])
            self.assertEqual([], summary["eligible_candidate_reviews"])

    def test_html_ignores_script_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "reports"
            source.mkdir()
            (source / "安全测试报告.html").write_text(
                "<html><script>水平越权 漏洞描述 修复建议</script>"
                "<body>普通工作记录</body></html>",
                encoding="utf-8",
            )
            environment = self.environment(root)
            self.run_tool(
                environment,
                DISTILL,
                "run",
                str(source),
                "--run-id",
                "kd-html",
            )
            summary = json.loads(
                (
                    root
                    / "data"
                    / "knowledge-distillation"
                    / "runs"
                    / "kd-html"
                    / "summary.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(summary["findings"], 0)

    def test_report_versions_share_one_lineage_and_one_independent_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "reports"
            source.mkdir()
            body = "安全测试报告\n[高危] 对象标识符来源链越权\n漏洞描述\n修复建议\n"
            for name in (
                "Product-渗透测试报告20260729.txt",
                "Product-渗透测试报告20260730.txt",
                "Product-渗透测试报告20260730-危害补强版.txt",
            ):
                (source / name).write_text(body + name, encoding="utf-8")
            environment = self.environment(root)
            self.run_tool(
                environment,
                DISTILL,
                "run",
                str(source),
                "--run-id",
                "kd-versions",
            )
            run = root / "data" / "knowledge-distillation" / "runs" / "kd-versions"
            ledger = [json.loads(line) for line in (run / "source-ledger.jsonl").read_text().splitlines()]
            self.assertEqual(1, len({item["version_family_id"] for item in ledger}))
            canonical = [item for item in ledger if item["canonical_version"]]
            self.assertEqual(1, len(canonical))
            self.assertIn("补强版", canonical[0]["path"])
            summary = json.loads((run / "summary.json").read_text())
            self.assertEqual(2, summary["version_lineage"]["noncanonical_versions"])
            findings = [json.loads(line) for line in (run / "finding-ledger.jsonl").read_text().splitlines()]
            self.assertGreaterEqual(
                sum(item["disposition"] == "duplicate-version" for item in findings),
                1,
            )

    def test_legacy_xml_document_is_read_without_office_execution(self) -> None:
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        from report_formats import extract_document

        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "security-report.doc"
            report.write_text(
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<document><title>安全测试报告</title>'
                '<finding>水平越权</finding></document>',
                encoding="utf-8",
            )
            value = extract_document(report)
            self.assertIsNotNone(value)
            self.assertIn("水平越权", value["text"])
            self.assertEqual(
                value["metadata"]["conversion"],
                "legacy-xml-text",
            )

    def test_legacy_html_document_uses_visible_text_only(self) -> None:
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        from report_formats import extract_document

        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "security-report.doc"
            report.write_text(
                '<html><script>ignore this finding</script><body>'
                '<h1>安全测试报告</h1><p>SQL注入</p></body></html>',
                encoding="utf-8",
            )
            value = extract_document(report)
            self.assertIsNotNone(value)
            self.assertIn("SQL注入", value["text"])
            self.assertNotIn("ignore this finding", value["text"])
            self.assertEqual(
                value["metadata"]["conversion"],
                "legacy-html-text",
            )

    def test_binary_legacy_office_requires_network_isolation(self) -> None:
        import sys
        from unittest import mock

        sys.path.insert(0, str(ROOT / "scripts"))
        from report_formats import FormatError, extract_document

        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "security-report.doc"
            report.write_bytes(b"\xd0\xcf\x11\xe0" + b"binary" * 32)

            def executable(name: str) -> str | None:
                if name == "libreoffice":
                    return "/usr/bin/libreoffice"
                return None

            with mock.patch("report_formats.shutil.which", side_effect=executable):
                with self.assertRaisesRegex(FormatError, "isolation is unavailable"):
                    extract_document(report)

    def test_archive_path_traversal_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "reports"
            source.mkdir()
            archive = source / "漏洞报告.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("../escape.txt", "[高危] 水平越权")
            environment = self.environment(root)
            self.run_tool(
                environment,
                DISTILL,
                "run",
                str(source),
                "--run-id",
                "kd-archive",
            )
            ledger = json.loads(
                (
                    root
                    / "data"
                    / "knowledge-distillation"
                    / "runs"
                    / "kd-archive"
                    / "source-ledger.jsonl"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(ledger["status"], "unsafe-archive")
            self.assertFalse((root / "escape.txt").exists())

    def test_generic_pattern_files_contain_no_deployment_identifiers(self) -> None:
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        from learning_policy import target_specific_findings

        pattern_root = ROOT / "skills" / "blue-vulnerability-patterns" / "references"
        forbidden = (
            "/opt/",
            "/home/",
            "ai." + "csg.cn",
            "customer" + "service",
            "天融" + "信",
            "南方" + "电网",
        )
        for path in pattern_root.glob("*.json"):
            content = path.read_text(encoding="utf-8")
            self.assertEqual([], target_specific_findings(content), path.name)
            for marker in forbidden:
                self.assertNotIn(marker, content, path.name)

    def test_patterns_generalize_across_unrelated_domains(self) -> None:
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        from knowledge_distill import load_patterns, pattern_for_finding

        patterns = load_patterns()
        fixtures = (
            ("电商订单详情水平越权", "object-authorization-lifecycle"),
            ("医疗预约记录BOLA", "object-authorization-lifecycle"),
            ("项目审批状态绕过", "workflow-precondition-bypass"),
            ("数据库组件CVE补丁核验", "component-exposure-and-patch-validation"),
            ("移动端接口主体绑定", "implicit-subject-binding"),
            ("工业管理面未授权", "ot-management-plane-boundary"),
            ("CSRF跨站请求伪造", "cross-site-request-forgery"),
            ("服务端远程代码执行", "server-side-code-execution"),
            ("富文本存储型XSS", "client-injection-to-credential-impact"),
            ("附件下载opaque ID来源链缺失", "identifier-provenance-chain"),
            ("WebSocket跨协议权限不一致", "cross-protocol-authorization-parity"),
            ("短信验证码发送接口滥用", "message-delivery-abuse-control"),
            ("OAuth公共客户端未校验PKCE", "oauth-public-client-binding"),
            ("注册状态响应差异导致账号枚举", "identity-state-response-differential"),
        )
        for title, expected in fixtures:
            with self.subTest(title=title):
                self.assertEqual(
                    pattern_for_finding(
                        {
                            "title": title,
                            "weakness_class": title,
                            "term_matches": [],
                        },
                        patterns,
                    ),
                    expected,
                )

    def test_single_system_infrastructure_roots_remain_local_hypotheses(self) -> None:
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        from knowledge_distill import root_cause_for_finding

        fixtures = {
            "ServiceAccount RBAC 可跨命名空间访问": "workload-identity-rbac-blast-radius",
            "代理转发 Bearer 凭据到任意目标": "credential-forwarding-confused-deputy",
            "监控控制面允许匿名写入告警": "monitoring-control-plane-integrity",
            "状态写入触发控制器调谐并创建特权工作负载": "controller-reconciliation-amplification",
            "流式注册允许抢占当前会话": "stream-registration-preemption",
            "节点工作负载凭据具有集群配置写权限": "workload-identity-rbac-blast-radius",
            "匿名中断其他租户配置通道": "object-authorization-lifecycle",
            "耗尽流式客户端槽位": "stream-registration-preemption",
        }
        for title, expected in fixtures.items():
            with self.subTest(title=title):
                self.assertEqual(
                    expected,
                    root_cause_for_finding(
                        {"title": title, "weakness_class": title, "term_matches": []}
                    ),
                )

    def test_generic_cross_tenant_and_anonymous_internal_access_are_classified(self) -> None:
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        from knowledge_distill import root_cause_for_finding

        self.assertEqual(
            "object-authorization-lifecycle",
            root_cause_for_finding(
                {"title": "低权限账号跨企业读取业务记录", "weakness_class": "IDOR"}
            ),
        )
        self.assertEqual(
            "authorization-boundary-classification",
            root_cause_for_finding(
                {"title": "匿名读取内部审批记录", "weakness_class": ""}
            ),
        )
        self.assertEqual(
            "sensitive-data-exposure",
            root_cause_for_finding(
                {"title": "匿名读取生产监控日志", "weakness_class": ""}
            ),
        )
        self.assertEqual(
            "server-side-code-execution",
            root_cause_for_finding(
                {"title": "低权限工作负载容器逃逸取得宿主机 root", "weakness_class": ""}
            ),
        )

    def test_report_scaffolding_is_not_a_pattern_candidate(self) -> None:
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        from knowledge_distill import GENERIC_FINDING_LABEL

        for label in (
            "View Source Code",
            "发现方式（漏洞扫描、网络安全通报、攻防演练、专项检查、其他方式）",
            "攻击内容",
            "未发现漏洞",
            "统一资产发现与漏洞检测工具",
            "高危漏洞",
        ):
            with self.subTest(label=label):
                self.assertIsNotNone(GENERIC_FINDING_LABEL.search(label))


if __name__ == "__main__":
    unittest.main()
