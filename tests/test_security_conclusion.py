from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import security_conclusion  # noqa: E402


def dependency(identifier: str, status: str = "satisfied") -> dict:
    return {
        "id": identifier,
        "status": status,
        "evidence_refs": [f"evidence/{identifier}.json"] if status == "satisfied" else [],
        "reason": None if status == "satisfied" else "not yet validated",
    }


def confirmed_vulnerability() -> dict:
    value = {
        "schema_version": 1,
        "claim_id": "claim-rce",
        "claim_kind": "vulnerability",
        "validation_state": "confirmed",
        "title": "Remote code execution through a controlled renderer path",
        "evidence_refs": ["evidence/chain.json"],
        "attacker_prerequisites": ["remote content control"],
        "validation_dependencies": [],
        "potential_impact": "remote-code-execution",
        "confirmed_impact": "remote-code-execution",
        "investigation_priority": "critical",
        "formal_severity": "critical",
        "next_actions": ["continue remaining scope"],
        "alternative_explanations": [],
        "coverage_effect": "continue",
    }
    value["validation_dependencies"] = [
        dependency(item)
        for item in sorted(security_conclusion.required_dependency_ids(value))
    ]
    return value


class SecurityConclusionTest(unittest.TestCase):
    def test_electron_asar_dangerous_configuration_is_only_a_candidate(self) -> None:
        normalized = security_conclusion.normalize(
            {
                "schema_version": 1,
                "claim_id": "electron-asar",
                "claim_kind": "vulnerability",
                "validation_state": "confirmed",
                "title": "High RCE from Electron webPreferences",
                "evidence_refs": ["asar/main.js:webPreferences"],
                "attacker_prerequisites": [],
                "validation_dependencies": [],
                "potential_impact": "remote code execution",
                "confirmed_impact": "remote code execution",
                "investigation_priority": "critical",
                "formal_severity": "critical",
                "next_actions": [],
                "alternative_explanations": ["no attacker-controlled renderer content"],
                "coverage_effect": "complete",
            }
        )
        self.assertEqual("candidate", normalized["validation_state"])
        self.assertIn("controlled-input", security_conclusion.unresolved_dependencies(normalized))
        self.assertIn("privilege-bridge", security_conclusion.unresolved_dependencies(normalized))
        self.assertTrue(normalized["next_actions"])
        self.assertEqual("continue", normalized["coverage_effect"])

    def test_confirmed_finding_can_leave_severity_unscored(self) -> None:
        value = confirmed_vulnerability()
        value["formal_severity"] = None
        self.assertEqual([], security_conclusion.validate(value))
    def test_confirmed_vulnerability_requires_complete_chain(self) -> None:
        value = confirmed_vulnerability()
        self.assertEqual([], security_conclusion.validate(value))
        value["validation_dependencies"] = [
            item for item in value["validation_dependencies"] if item["id"] != "controlled-input"
        ]
        failures = security_conclusion.validate(value)
        self.assertTrue(any("controlled-input" in item for item in failures))

    def test_blackbox_confirmation_rejects_internal_log_prerequisite(self) -> None:
        value = confirmed_vulnerability()
        value["attacker_model"] = {"kind": "black-box"}
        for item in value["validation_dependencies"]:
            item["prerequisite_source"] = "attacker-derived"
        value["validation_dependencies"][0]["prerequisite_source"] = "internal-log"
        normalized = security_conclusion.normalize(value)
        self.assertEqual("candidate", normalized["validation_state"])
        self.assertIn("invalid-confirmed-claim-downgraded", normalized["policy_violations"])

    def test_incomplete_rce_is_downgraded_without_formal_severity(self) -> None:
        value = confirmed_vulnerability()
        value["title"] = "High RCE vulnerability"
        value["validation_dependencies"] = [dependency("reachable-path")]
        normalized = security_conclusion.normalize(value)
        self.assertEqual("candidate", normalized["validation_state"])
        self.assertIsNone(normalized["formal_severity"])
        self.assertIsNone(normalized["confirmed_impact"])
        self.assertEqual(
            "Potential code-execution path (prerequisites unresolved)",
            normalized["title"],
        )
        self.assertIn("invalid-confirmed-claim-downgraded", normalized["policy_violations"])
        self.assertTrue(normalized["next_actions"])

    def test_static_capability_can_be_observed_but_not_severity_rated(self) -> None:
        value = confirmed_vulnerability()
        value.update(
            claim_kind="static-capability",
            validation_state="observed",
            potential_impact="dangerous IPC handler could expose native capability",
            confirmed_impact=None,
            formal_severity=None,
            validation_dependencies=[],
        )
        self.assertEqual([], security_conclusion.validate(value))

    def test_historical_claim_preserves_reported_not_formal_severity(self) -> None:
        value = confirmed_vulnerability()
        value.update(
            claim_kind="historical-claim",
            validation_state="historical",
            confirmed_impact=None,
            formal_severity=None,
            reported_severity="critical",
            validation_dependencies=[],
        )
        self.assertEqual([], security_conclusion.validate(value))

    def test_blocked_external_stays_interim(self) -> None:
        value = security_conclusion.normalize(
            {
                "schema_version": 1,
                "claim_id": "blocked",
                "claim_kind": "vulnerability",
                "validation_state": "blocked-external",
                "title": "Potential privileged action",
                "evidence_refs": [],
                "attacker_prerequisites": ["low privilege account"],
                "validation_dependencies": [
                    dependency("controlled-input", "blocked-external")
                ],
                "potential_impact": "privilege escalation",
                "confirmed_impact": None,
                "investigation_priority": "high",
                "formal_severity": None,
                "next_actions": ["resume when the account is available"],
                "alternative_explanations": [],
                "coverage_effect": "interim",
            }
        )
        self.assertEqual([], security_conclusion.validate(value))
        self.assertNotEqual("complete", value["coverage_effect"])

    def test_cli_status_marks_legacy_finding_unverifiable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            (workspace / "confirmed-findings.json").write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "id": "legacy-rce",
                                "title": "High RCE vulnerability",
                                "validation_state": "confirmed",
                                "evidence_refs": ["one-static-string"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "security_conclusion.py"),
                    "status",
                    "--workspace",
                    str(workspace),
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            )
            value = json.loads(result.stdout)
            self.assertEqual("degraded", value["status"])
            self.assertEqual(1, value["invalid_confirmed_claims"])
            self.assertEqual({"candidate": 1}, value["states"])


if __name__ == "__main__":
    unittest.main()
