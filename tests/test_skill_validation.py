from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from skill_validation import validate_skill


class SkillValidationTest(unittest.TestCase):
    def test_repository_skills_are_self_contained_and_valid(self) -> None:
        for skill in sorted((ROOT / "skills").iterdir()):
            if skill.is_dir():
                self.assertEqual([], validate_skill(skill), skill.name)

    def test_directory_and_frontmatter_name_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            skill = Path(temporary) / "expected-name"
            skill.mkdir()
            (skill / "SKILL.md").write_text(
                "---\nname: wrong-name\ndescription: reusable fixture\n---\n",
                encoding="utf-8",
            )
            self.assertTrue(
                any("does not match directory" in item for item in validate_skill(skill))
            )


if __name__ == "__main__":
    unittest.main()
