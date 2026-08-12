from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from learning_policy import load_policy, promotion_failures, validate_policy


def record(**overrides: object) -> dict:
    value = {
        "task": "Improve report parsing across supported document formats",
        "failure": "Field boundaries were inferred from one heading style.",
        "correction": "Use structural sections and normalized field labels.",
        "successful_pattern": "Two unrelated templates produce the same schema.",
        "conditions": (
            "Applies to vulnerability reports with extractable text; scanned images "
            "still require OCR."
        ),
        "evidence_refs": ["tests/first.json", "tests/second.json"],
    }
    value.update(overrides)
    return value


class LearningPolicyTest(unittest.TestCase):
    def test_policy_covers_all_local_and_upstream_promotions(self) -> None:
        policy = load_policy()
        self.assertEqual([], validate_policy(policy))
        self.assertEqual("all", policy["scope"]["local_skill_updates"])
        self.assertEqual("all", policy["scope"]["upstream_supplements"])

    def test_generic_scoped_learning_passes(self) -> None:
        self.assertEqual([], promotion_failures(record()))

    def test_repository_filenames_are_not_mistaken_for_domains(self) -> None:
        self.assertEqual(
            [],
            promotion_failures(
                record(
                    correction=(
                        "Update SKILL.md and validate the behavior with fixture.json."
                    )
                )
            ),
        )

    def test_learning_approval_has_no_branch_creation_contract(self) -> None:
        content = (ROOT / "scripts" / "learning.py").read_text(encoding="utf-8")
        self.assertNotIn("switch -c", content)
        self.assertNotIn("learning/", content)

    def test_deployment_specific_material_is_blocked_for_any_skill(self) -> None:
        failures = promotion_failures(
            record(
                correction=(
                    "Reuse https://tenant.example.com/api/private and object "
                    "550e8400-e29b-41d4-a716-446655440000."
                )
            )
        )
        self.assertTrue(
            any("deployment-specific identifiers" in item for item in failures)
        )

    def test_explicit_scope_and_evidence_are_required(self) -> None:
        failures = promotion_failures(
            record(
                conditions="Applies to equivalent tasks and evidence.",
                evidence_refs=[],
            )
        )
        self.assertTrue(any("explicit applicability" in item for item in failures))
        self.assertTrue(any("validation evidence" in item for item in failures))


if __name__ == "__main__":
    unittest.main()
