from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import web_assessment
import web_runner


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class PayloadPolicyContractTest(unittest.TestCase):
    def test_payload_registry_families_match_the_coverage_template(self) -> None:
        registry = json.loads(
            (ROOT / "skills" / "blue-web-patrol" / "references" / "payload-technique-registry.json").read_text()
        )
        template = json.loads(
            (ROOT / "skills" / "blue-web-patrol" / "templates" / "coverage-matrix.json").read_text()
        )
        families = {
            family["id"]
            for domain in template["coverage"]
            for family in domain["families"]
        }
        self.assertFalse(set(registry["families"]) - families)

    def test_registry_separates_safe_agent_and_blocked_techniques(self) -> None:
        safe = web_assessment.payload_case_metadata(
            "injection.sql-nosql-orm", "auto-ready"
        )
        agent = web_assessment.payload_case_metadata(
            "server-side-processing.ssrf-webhook-proxy", "auto-ready"
        )
        blocked = web_assessment.payload_case_metadata(
            "injection.command-code-template", "auto-ready"
        )
        self.assertEqual("safe-auto", safe["payload_policy"])
        self.assertTrue(safe["binding_requirements"])
        self.assertEqual("needs-agent", agent["payload_policy"])
        self.assertEqual("blocked", blocked["payload_policy"])

    def test_plan_v4_migration_adds_payload_contract_without_changing_coverage(self) -> None:
        old = {
            "schema_version": 4,
            "test_cells": [
                {"id": "cell", "family": "injection.sql-nosql-orm"}
            ],
            "executable_cases": [
                {
                    "id": "case",
                    "case_kind": "api-test",
                    "test_cell_id": "cell",
                    "automation_state": "auto-ready",
                }
            ],
        }
        migrated = web_assessment.migrate_plan(old)
        self.assertEqual(8, migrated["schema_version"])
        case = migrated["executable_cases"][0]
        self.assertEqual("safe-auto", case["payload_policy"])
        self.assertTrue(case["technique_refs"])
        self.assertTrue(case["oracle_id"])
        self.assertEqual(4, migrated["migration_history"][-1]["from_schema_version"])

    def test_auditor_rejects_auto_case_without_approved_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            write_json(
                workspace / "test-plan.json",
                {
                    "schema_version": 5,
                    "executable_cases": [
                        {
                            "id": "unsafe",
                            "case_kind": "api-test",
                            "automation_state": "auto-ready",
                            "payload_policy": "blocked",
                            "binding_requirements": ["controlled-lab"],
                            "oracle_id": "server-evaluation-capability",
                            "variants": [],
                            "status": "tested",
                        }
                    ],
                },
            )
            write_json(workspace / "route-inventory.json", {"routes": []})
            write_json(workspace / "coverage.json", {"candidates": []})
            write_json(workspace / "surface-inventory.json", {"blockers": []})
            audit = web_runner.audit_execution(workspace)
            self.assertEqual("blocked", audit["status"])
            self.assertEqual(1, audit["counts"]["unsafe_auto_policy"])

    def test_preauth_state_pattern_applies_across_unrelated_domains(self) -> None:
        fixtures = (
            ("https://shop.example.test/", "/account/recovery/verify"),
            ("https://clinic.example.test/", "/patient/mfa/challenge"),
        )
        for target, path in fixtures:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                workspace = root / "assessment"
                web_assessment.initialize(workspace, target)
                source = root / "surface.json"
                write_json(
                    source,
                    {
                        "surfaces": [
                            {
                                "kind": "api",
                                "method": "GET",
                                "url": target.rstrip("/") + path,
                                "validation_state": "runtime-observed",
                                "runtime_observed": True,
                            }
                        ]
                    },
                )
                web_assessment.compile_workspace(workspace, [("manual", source)])
                plan = json.loads((workspace / "test-plan.json").read_text(encoding="utf-8"))
                cases = [
                    item
                    for item in plan["executable_cases"]
                    if item.get("family") == "identity-session.response-differential"
                ]
                self.assertTrue(cases)
                self.assertTrue(
                    all("patt:account-takeover" in item["technique_refs"] for item in cases)
                )
                self.assertTrue(all(item["payload_policy"] == "needs-agent" for item in cases))

        patterns = json.loads(
            (
                ROOT
                / "skills"
                / "blue-vulnerability-patterns"
                / "references"
                / "identity-client.json"
            ).read_text(encoding="utf-8")
        )["patterns"]
        pattern = next(
            item for item in patterns if item["id"] == "pre-authentication-state-provenance"
        )
        self.assertIn("different purpose", pattern["variants"])
        self.assertIn("replayed state", pattern["variants"])

    def test_repository_payload_rules_contain_no_target_material(self) -> None:
        paths = (
            ROOT
            / "skills"
            / "blue-web-patrol"
            / "references"
            / "payload-technique-registry.json",
            ROOT
            / "skills"
            / "blue-vulnerability-patterns"
            / "references"
            / "identity-client.json",
        )
        forbidden = re.compile(
            r"https?://|(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)|"
            r"/(?:home|opt|api|rest|admin|internal)/|"
            r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b|(?:wxid|corp-target)_|target\.internal",
            re.I,
        )
        for path in paths:
            with self.subTest(path=path.name):
                self.assertIsNone(forbidden.search(path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
