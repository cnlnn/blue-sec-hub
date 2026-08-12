from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts import assessment_learning


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


class AssessmentLearningTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.old_data = os.environ.get("BLUE_SEC_DATA")
        self.old_config = os.environ.get("BLUE_SEC_CONFIG")
        os.environ["BLUE_SEC_DATA"] = str(self.root / "data")
        os.environ["BLUE_SEC_CONFIG"] = str(self.root / "config")

    def tearDown(self) -> None:
        if self.old_data is None:
            os.environ.pop("BLUE_SEC_DATA", None)
        else:
            os.environ["BLUE_SEC_DATA"] = self.old_data
        if self.old_config is None:
            os.environ.pop("BLUE_SEC_CONFIG", None)
        else:
            os.environ["BLUE_SEC_CONFIG"] = self.old_config
        self.temporary.cleanup()

    def workspace(self, name: str, target: str) -> Path:
        workspace = self.root / name
        workspace.mkdir()
        write_json(workspace / "agent-state.json", {"target": target})
        write_json(
            workspace / "coverage.json",
            {
                "findings": [
                    {
                        "id": "finding-current",
                        "title": "Authenticated response remains structurally accessible without credentials",
                        "validation_state": "confirmed",
                        "authorization_mode": "anonymous-boundary",
                        "evidence_refs": ["private-evidence-path"],
                    }
                ]
            },
        )
        return workspace

    def test_each_assessment_writes_target_independent_candidate(self) -> None:
        workspace = self.workspace("first", "https://internal-one.example.test")
        result = assessment_learning.distill(workspace, promote=False)
        body = (workspace / "learning-candidates.jsonl").read_text(encoding="utf-8")
        self.assertEqual(1, result["candidates"])
        self.assertNotIn("internal-one", body)
        self.assertNotIn("private-evidence-path", body)
        self.assertIn("anonymous-boundary", body)

    def test_two_independent_targets_approve_local_knowledge_without_git(self) -> None:
        first = self.workspace("first", "https://first.example.test")
        second = self.workspace("second", "https://second.example.org")
        assessment_learning.distill(first, promote=True)
        result = assessment_learning.distill(second, promote=True)
        self.assertEqual(1, result["ready"])
        self.assertEqual("approved", result["promotions"][0]["status"])
        self.assertFalse(result["git_branch_created"])
        ledger = self.root / "data/learning/ledger.jsonl"
        self.assertIn('"event": "approved"', ledger.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
