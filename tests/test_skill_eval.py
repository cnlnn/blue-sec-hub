from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import effective_skills  # noqa: E402
import skill_eval  # noqa: E402


class SkillEvalTest(unittest.TestCase):
    def test_contracts_cover_routing_behavior_and_negative_exposure(self) -> None:
        cases = skill_eval.load_cases()
        self.assertEqual([], skill_eval.validate_cases(cases))
        skills = skill_eval.repository_skills()
        self.assertEqual(21, len(skills))
        for skill in skills:
            self.assertTrue(
                any(case["type"] == "routing" and case["skill"] == skill for case in cases)
            )
            self.assertTrue(
                any(case["type"] == "routing" and case["skill"] != skill for case in cases)
            )
            self.assertTrue(
                any(case["type"] == "behavior" and case["skill"] == skill for case in cases)
            )

    def test_result_assertions_check_route_evidence_and_forbidden_conclusion(self) -> None:
        case = {
            "type": "behavior",
            "skill": "blue-vuln-retest",
            "must_include": ["fresh_evidence", "result"],
            "expect": {"conclusion_state": "interim"},
            "forbid_conclusion": ["complete"],
        }
        valid = {
            "selected_skill": "blue-vuln-retest",
            "claim_kind": "vulnerability",
            "validation_state": "candidate",
            "conclusion_state": "interim",
            "attacker_prerequisites": ["authorized account"],
            "attacker_prerequisite_sources": ["attacker-authenticated"],
            "attack_chain_closed": False,
            "evidence_state": "fresh evidence pending",
            "potential_impact": "authorization bypass",
            "confirmed_impact": None,
            "formal_severity": None,
            "validation_dependencies": [
                {"id": "controlled-input", "status": "pending", "reason": "not captured"}
            ],
            "continue_investigation": True,
            "alternative_explanations": ["stale report"],
            "coverage_state": "partial",
            "next_action": "replay current request",
            "forbidden_conclusions": ["complete"],
            "response": "fresh_evidence and result",
        }
        self.assertEqual(
            [],
            skill_eval.evaluate_result(case, valid),
        )
        invalid = dict(valid)
        invalid.update(selected_skill="blue-web-patrol", conclusion_state="complete", response="result")
        failures = skill_eval.evaluate_result(
            case,
            invalid,
        )
        self.assertEqual(4, len(failures))

    def test_blue_sec_skill_eval_entrypoint_validates_without_model(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/effective_skills.py"),
                "eval",
                "--validate-only",
            ],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        )
        self.assertIn('"status": "contract-valid"', result.stdout)
        self.assertIn('"cases": 71', result.stdout)

    def test_prompt_does_not_inject_skill_catalog_or_expected_labels(self) -> None:
        case = {
            "input": "verify a vendor report",
            "skill": "blue-vuln-retest",
            "must_include": ["fresh_evidence"],
        }
        prompt = skill_eval.prompt_for(case)
        self.assertNotIn("blue-vuln-retest", prompt)
        self.assertNotIn("fresh_evidence", prompt)
        self.assertNotIn("Available Skills", prompt)

    def test_host_install_uses_only_current_effective_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "effective" / "skills"
            (source / "blue-test").mkdir(parents=True)
            (source / "blue-test" / "SKILL.md").write_text("test", encoding="utf-8")
            with mock.patch.object(
                skill_eval.effective_skills,
                "status",
                return_value={"status": "ready", "active_revision": "revision-1"},
            ), mock.patch.object(
                skill_eval.effective_skills, "current_skills_root", return_value=source
            ):
                host, revision = skill_eval.install_effective_host(root / "run")
            self.assertEqual("revision-1", revision)
            self.assertEqual(
                "test", (host / "skills/blue-test/SKILL.md").read_text(encoding="utf-8")
            )

    def test_token_estimate_counts_cjk_and_ascii_material(self) -> None:
        self.assertEqual(5, effective_skills.estimated_tokens("安全 test-case"))


if __name__ == "__main__":
    unittest.main()
