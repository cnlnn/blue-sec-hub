from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "report_intelligence.py"


class ReportIntelligenceTest(unittest.TestCase):
    def run_tool(
        self, data_root: Path, *args: str
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

    def test_builds_bypass_chain_and_gap_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "attack-team-report.txt"
            report.write_text("redacted report fixture", encoding="utf-8")
            findings = [
                {
                    "finding_id": "orders-historical-idor",
                    "system_id": "orders.example.test",
                    "title": "Order detail IDOR",
                    "source": str(report),
                    "evidence_state": "historical",
                    "status": "fixed",
                    "weakness_class": "object-authorization",
                    "components": ["order-api"],
                    "entrypoints": ["GET /orders/:id"],
                    "objects": ["order"],
                    "root_causes": ["missing-object-ownership-check"],
                    "cwes": ["CWE-639"],
                    "preconditions": ["access:authenticated"],
                    "postconditions": ["capability:read-other-order"],
                    "alternate_surfaces": ["POST /orders/export"],
                    "remediation": {
                        "claim": "Added ownership check",
                        "mechanism": "Handler-specific check",
                        "scope": ["GET /orders/:id"],
                    },
                },
                {
                    "finding_id": "orders-current-export",
                    "system_id": "orders.example.test",
                    "title": "Order export authorization gap",
                    "source": str(report),
                    "evidence_state": "current",
                    "status": "confirmed-present",
                    "weakness_class": "object-authorization",
                    "components": ["order-api"],
                    "entrypoints": ["POST /orders/export"],
                    "objects": ["order"],
                    "root_causes": ["missing-object-ownership-check"],
                    "cwes": ["CWE-639"],
                    "preconditions": ["access:authenticated"],
                    "postconditions": ["capability:read-other-order"],
                },
                {
                    "finding_id": "orders-current-write",
                    "system_id": "orders.example.test",
                    "title": "Controlled server-side file write",
                    "source": str(report),
                    "evidence_state": "current",
                    "status": "confirmed-present",
                    "weakness_class": "file-write",
                    "entrypoints": ["POST /imports"],
                    "preconditions": ["access:authenticated"],
                    "postconditions": ["capability:write-server-file"],
                },
                {
                    "finding_id": "orders-current-load",
                    "system_id": "orders.example.test",
                    "title": "Template loader uses writable path",
                    "source": str(report),
                    "evidence_state": "current",
                    "status": "reported",
                    "weakness_class": "unsafe-template-load",
                    "entrypoints": ["POST /templates/render"],
                    "preconditions": ["capability:write-server-file"],
                    "postconditions": ["capability:execute-as-service"],
                },
            ]
            input_path = root / "findings.json"
            input_path.write_text(
                json.dumps(findings, ensure_ascii=False),
                encoding="utf-8",
            )

            first = self.run_tool(root / "data", "upsert", str(input_path))
            self.assertIn("added=4", first.stdout)
            second = self.run_tool(root / "data", "upsert", str(input_path))
            self.assertIn("unchanged=4", second.stdout)
            self.run_tool(
                root / "data",
                "analyze",
                "--system",
                "orders.example.test",
                "--format",
                "json",
            )
            self.run_tool(root / "data", "audit")

            analysis_path = (
                root
                / "data"
                / "report-intelligence"
                / "analysis"
                / "orders.example.test.json"
            )
            analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
            kinds = {item["kind"] for item in analysis["relations"]}
            self.assertIn("fix-bypass-or-regression", kinds)
            self.assertIn("postcondition-enables", kinds)
            self.assertIn("untested-alternate-surface", kinds)
            self.assertEqual(analysis["profile"]["finding_count"], 4)
            self.assertTrue(
                any(
                    item["nodes"]
                    == ["orders-current-write", "orders-current-load"]
                    for item in analysis["chains"]
                )
            )

            stored = json.loads(
                (
                    root
                    / "data"
                    / "report-intelligence"
                    / "findings"
                    / "orders-historical-idor.json"
                ).read_text(encoding="utf-8")
            )
            self.assertRegex(stored["source"]["sha256"], r"^[0-9a-f]{64}$")

    def test_normalizes_chinese_weakness_without_losing_original(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report.txt"
            report.write_text("fixture", encoding="utf-8")
            finding = {
                "system_id": "内部采购系统",
                "title": "订单详情水平越权",
                "source": str(report),
                "evidence_state": "historical",
                "status": "reported",
                "weakness_class": "水平越权",
            }
            input_path = root / "finding.json"
            input_path.write_text(
                json.dumps(finding, ensure_ascii=False),
                encoding="utf-8",
            )
            self.run_tool(root / "data", "upsert", str(input_path))
            stored_path = next(
                (root / "data" / "report-intelligence" / "findings").glob("*.json")
            )
            stored = json.loads(stored_path.read_text(encoding="utf-8"))
            self.assertEqual(stored["system_id"], "内部采购系统")
            self.assertEqual(stored["weakness_class"], "object-authorization")
            self.assertEqual(stored["weakness_class_original"], "水平越权")


if __name__ == "__main__":
    unittest.main()
