from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from argparse import Namespace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "report_ingestion.py"
CONFIG_SCRIPT = ROOT / "scripts" / "hub_config.py"
WORD_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def paragraph(value: str) -> str:
    return f"<w:p><w:r><w:t>{value}</w:t></w:r></w:p>"


def table(rows: list[list[str]]) -> str:
    output = ["<w:tbl>"]
    for row in rows:
        output.append("<w:tr>")
        for value in row:
            output.append(f"<w:tc>{paragraph(value)}</w:tc>")
        output.append("</w:tr>")
    output.append("</w:tbl>")
    return "".join(output)


def write_docx(path: Path, body: str) -> None:
    document = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<w:document xmlns:w="{WORD_NS}"><w:body>{body}</w:body></w:document>'
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("word/document.xml", document)


class ReportIngestionTest(unittest.TestCase):
    def run_tool(
        self,
        data_root: Path,
        *args: str,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["BLUE_SEC_DATA"] = str(data_root)
        return subprocess.run(
            ["python", str(SCRIPT), *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )

    def artifact(self, data_root: Path) -> dict:
        index = data_root / "report-ingestion" / "index.jsonl"
        entry = json.loads(index.read_text(encoding="utf-8").strip())
        return json.loads(Path(entry["artifact"]).read_text(encoding="utf-8"))

    def test_versions_recognizes_redacts_and_reuses_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "portal-report-20260724.docx"
            write_docx(
                report,
                "".join(
                    [
                        paragraph("攻击成果报告"),
                        table(
                            [
                                ["攻击队伍", "test team"],
                                ["目标系统名称", "订单系统"],
                                ["URL", "https://portal.example.test/"],
                                ["攻击类型", "水平越权"],
                            ]
                        ),
                        paragraph("攻击路径"),
                        paragraph("GET /api/orders/123 HTTP/1.1"),
                        paragraph("Cookie: session=secret-value"),
                        paragraph("phone=13800138000"),
                        paragraph("复测结论：已修复"),
                    ]
                ),
            )
            data = root / "data"

            first = self.run_tool(data, "scan", str(report))
            self.assertIn("[created]", first.stdout)
            second = self.run_tool(data, "scan", str(report))
            self.assertIn("[current]", second.stdout)
            self.assertTrue(report.exists())

            index = data / "report-ingestion" / "index.jsonl"
            self.assertEqual(len(index.read_text(encoding="utf-8").splitlines()), 1)
            if os.name != "nt":
                self.assertEqual(index.stat().st_mode & 0o777, 0o600)

            artifact = self.artifact(data)
            self.assertEqual(artifact["schema_version"], 2)
            self.assertEqual(artifact["extractor_version"], "1.4.0")
            self.assertEqual(
                artifact["recognition"]["profile_id"],
                "attack-result-report",
            )
            self.assertEqual(artifact["document"]["system_id"], "portal.example.test")
            self.assertEqual(artifact["document"]["report_date"], "2026-07-24")
            self.assertEqual(len(artifact["findings"]), 1)
            finding = artifact["findings"][0]
            self.assertEqual(finding["weakness_class"], "object-authorization")
            self.assertEqual(finding["status"], "fixed")
            self.assertIn("GET /api/orders/123", finding["entrypoints"])
            self.assertIn(
                "Cookie: <redacted>",
                "\n".join(block["text"] for block in artifact["blocks"]),
            )
            self.assertNotIn(
                "secret-value",
                json.dumps(artifact, ensure_ascii=False),
            )
            self.assertNotIn(
                "13800138000",
                json.dumps(artifact, ensure_ascii=False),
            )

    def test_standard_report_splits_multiple_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "security-test-20260724.docx"
            write_docx(
                report,
                "".join(
                    [
                        paragraph("安全测试报告"),
                        paragraph("安全问题归纳"),
                        paragraph("安全测试对象"),
                        paragraph("https://app.example.test/"),
                        paragraph("安全测试结果详情"),
                        paragraph("4.2.1. 越权漏洞"),
                        paragraph("GET /api/users/123 HTTP/1.1"),
                        paragraph("4.2.2. SQL注入"),
                        paragraph("POST /api/search HTTP/1.1"),
                        paragraph("修复建议"),
                    ]
                ),
            )
            data = root / "data"
            self.run_tool(data, "scan", "--quiet", str(report))
            artifact = self.artifact(data)

            self.assertEqual(
                artifact["recognition"]["profile_id"],
                "standard-security-test",
            )
            findings = artifact["findings"]
            self.assertEqual(len(findings), 2)
            self.assertEqual(
                {item["weakness_class"] for item in findings},
                {"broken-access-control", "sql-injection"},
            )
            by_weakness = {item["weakness_class"]: item for item in findings}
            self.assertEqual(
                by_weakness["broken-access-control"]["entrypoints"],
                ["GET /api/users/123"],
            )
            self.assertEqual(
                by_weakness["sql-injection"]["entrypoints"],
                ["POST /api/search"],
            )

    def test_search_uses_exact_system_and_excludes_unrelated_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            portal = root / "portal-report.docx"
            factory = root / "factory-report.docx"
            write_docx(
                portal,
                "".join(
                    [
                        paragraph("攻击成果报告"),
                        table(
                            [
                                ["目标系统名称", "订单门户"],
                                ["URL", "https://portal.example.test:8443/"],
                                ["攻击类型", "水平越权"],
                            ]
                        ),
                        paragraph("攻击路径"),
                        paragraph("GET /api/orders/123 HTTP/1.1"),
                    ]
                ),
            )
            write_docx(
                factory,
                "".join(
                    [
                        paragraph("安全测试报告"),
                        paragraph("安全测试对象"),
                        paragraph("https://factory.example.test/"),
                        paragraph("安全测试结果详情"),
                        paragraph("4.2.1. 跨站脚本攻击"),
                        paragraph("POST /api/notices HTTP/1.1"),
                    ]
                ),
            )
            data = root / "data"
            self.run_tool(data, "scan", "--quiet", str(portal), str(factory))

            result = self.run_tool(
                data,
                "search",
                "--system",
                "https://portal.example.test:8443/app",
                "--json",
            )
            matches = json.loads(result.stdout)
            self.assertEqual(len(matches), 1)
            self.assertEqual(
                matches[0]["document"]["system_id"],
                "portal.example.test",
            )
            self.assertEqual(len(matches[0]["findings"]), 1)
            self.assertNotIn(
                "factory.example.test",
                json.dumps(matches, ensure_ascii=False),
            )

    def test_search_matches_product_and_weakness_without_report_body(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "service-report.docx"
            write_docx(
                report,
                "".join(
                    [
                        paragraph("攻击成果报告"),
                        table(
                            [
                                ["目标系统名称", "客户服务平台"],
                                ["URL", "https://support.example.test/"],
                                ["攻击类型", "水平越权"],
                            ]
                        ),
                        paragraph("攻击路径"),
                        paragraph("GET /api/tickets/42 HTTP/1.1"),
                        paragraph("Cookie: session=do-not-return"),
                    ]
                ),
            )
            data = root / "data"
            self.run_tool(data, "scan", "--quiet", str(report))

            result = self.run_tool(
                data,
                "search",
                "--query",
                "客户服务平台",
                "--json",
            )
            matches = json.loads(result.stdout)
            self.assertEqual(len(matches), 1)
            material = json.dumps(matches, ensure_ascii=False)
            self.assertIn("客户服务平台", material)
            self.assertNotIn("do-not-return", material)

    def test_configured_documents_mode_accepts_docm_and_skips_log(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "mixed-cache"
            cache.mkdir()
            report = cache / "security-retest.docm"
            write_docx(
                report,
                "".join(
                    [
                        paragraph("安全测试报告"),
                        paragraph("安全测试对象"),
                        paragraph("https://portal.example.test/"),
                        paragraph("安全测试结果详情"),
                        paragraph("4.2.1. 越权漏洞"),
                    ]
                ),
            )
            noise = cache / "runtime.log"
            noise.write_text(
                "GET /not-a-report HTTP/1.1",
                encoding="utf-8",
            )

            environment = os.environ.copy()
            environment["BLUE_SEC_CONFIG"] = str(root / "config")
            environment["BLUE_SEC_DATA"] = str(root / "data")
            subprocess.run(
                [
                    "python",
                    str(CONFIG_SCRIPT),
                    "add-report-root",
                    str(cache),
                    "--mode",
                    "documents",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )
            result = subprocess.run(
                ["python", str(SCRIPT), "scan", "--configured", "--quiet"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )
            self.assertIn("processed=1", result.stdout)
            index = (
                root / "data" / "report-ingestion" / "index.jsonl"
            ).read_text(encoding="utf-8")
            records = [json.loads(line) for line in index.splitlines()]
            sources = {Path(item["source"]) for item in records}
            self.assertIn(report.resolve(), sources)
            self.assertNotIn(noise.resolve(), sources)

    def test_invalid_office_file_does_not_abort_directory_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reports = root / "reports"
            reports.mkdir()
            broken = reports / "broken.xlsx"
            broken.write_bytes(b"legacy-or-corrupt-office-file")
            report = reports / "valid.docx"
            write_docx(
                report,
                paragraph("安全测试报告")
                + paragraph("安全测试对象")
                + paragraph("安全测试结果详情"),
            )

            result = self.run_tool(
                root / "data",
                "scan",
                "--quiet",
                str(reports),
            )
            self.assertIn("[error]", result.stdout)
            self.assertIn('"created": 1', result.stdout)
            self.assertIn('"error": 1', result.stdout)

    def test_non_security_document_is_decided_without_report_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            document = root / "meeting-notes.docx"
            write_docx(
                document,
                paragraph("季度会议纪要") + paragraph("会议讨论预算与培训安排"),
            )
            data = root / "data"

            result = self.run_tool(data, "scan", "--quiet", str(document))

            self.assertIn('"non-security": 1', result.stdout)
            index = data / "report-ingestion" / "index.jsonl"
            self.assertEqual(index.read_text(encoding="utf-8"), "")
            decisions = [
                json.loads(line)
                for line in (data / "report-ingestion" / "decisions.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(
                decisions[0]["relevance"]["disposition"],
                "non-security",
            )
            self.assertIsNone(decisions[0]["artifact"])
            self.assertEqual(
                list((data / "report-ingestion" / "artifacts").rglob("*.json")),
                [],
            )

    def test_ambiguous_report_requires_explicit_inclusion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "notes.docx"
            write_docx(
                report,
                paragraph("漏洞记录")
                + paragraph("请求与响应证据")
                + paragraph("修复建议"),
            )
            data = root / "data"

            self.run_tool(data, "scan", "--quiet", str(report))
            index = data / "report-ingestion" / "index.jsonl"
            self.assertEqual(index.read_text(encoding="utf-8"), "")

            self.run_tool(
                data,
                "scan",
                "--quiet",
                "--include-ambiguous",
                str(report),
            )
            self.assertEqual(len(index.read_text(encoding="utf-8").splitlines()), 1)

    def test_interrupted_scan_does_not_publish_staged_index(self) -> None:
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        import report_ingestion

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "report.docx"
            write_docx(source, paragraph("安全测试报告"))
            store = root / "data" / "report-ingestion"
            store.mkdir(parents=True)
            index = store / "index.jsonl"
            original = {"source": "/preserved", "artifact": "/preserved.json"}
            index.write_text(json.dumps(original) + "\n", encoding="utf-8")

            patches = {
                "STORE": store,
                "ARTIFACTS": store / "artifacts",
                "LOCAL_PROFILES": store / "profiles",
                "INDEX": index,
                "DECISIONS": store / "decisions.jsonl",
                "SCAN_RUNS": store / "scan-runs",
                "SCAN_STATE": store / "scan-state.json",
            }
            args = Namespace(
                paths=[str(source)],
                configured=False,
                force=False,
                quiet=True,
                limit=None,
                include_ambiguous=False,
            )
            with mock.patch.multiple(report_ingestion, **patches), mock.patch.object(
                report_ingestion,
                "scan_one",
                side_effect=KeyboardInterrupt,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    report_ingestion.command_scan(args)

            self.assertEqual(index.read_text(encoding="utf-8"), json.dumps(original) + "\n")
            state = json.loads((store / "scan-state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["latest_state"], "interrupted")

    def test_audit_json_reports_degraded_for_interrupted_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary) / "data"
            store = data / "report-ingestion"
            store.mkdir(parents=True)
            (store / "scan-state.json").write_text(
                json.dumps({"latest_state": "interrupted"}),
                encoding="utf-8",
            )

            result = self.run_tool(data, "audit", "--json")
            value = json.loads(result.stdout)
            self.assertEqual(value["status"], "degraded")
            self.assertIn("scan-interrupted", value["reasons"])

    def test_audit_reports_active_scan_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data = Path(temporary) / "data"
            store = data / "report-ingestion"
            run = store / "scan-runs" / "scan-test"
            run.mkdir(parents=True)
            (store / "scan-state.json").write_text(
                json.dumps(
                    {
                        "active_run": "scan-test",
                        "latest_run": "scan-test",
                        "latest_state": "complete",
                    }
                ),
                encoding="utf-8",
            )
            (run / "summary.json").write_text(
                json.dumps(
                    {
                        "state": "complete",
                        "processed": 3,
                        "states": {"error": 1, "oversized": 1},
                        "relevance": {"unclassified": 2},
                    }
                ),
                encoding="utf-8",
            )

            result = self.run_tool(data, "audit", "--json")
            value = json.loads(result.stdout)
            self.assertEqual(value["status"], "degraded")
            self.assertEqual(value["scan"]["processed"], 3)
            self.assertEqual(value["scan"]["states"]["error"], 1)
            self.assertTrue(
                {
                    "scan-errors",
                    "scan-oversized",
                    "scan-unclassified",
                }.issubset(value["reasons"])
            )


if __name__ == "__main__":
    unittest.main()
