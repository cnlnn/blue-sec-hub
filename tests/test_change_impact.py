from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import change_impact  # noqa: E402


class ChangeImpactTest(unittest.TestCase):
    def test_documentation_change_uses_content_gate_only(self) -> None:
        result = change_impact.classify(["README.md"])
        self.assertEqual("content", result["level"])
        self.assertEqual([], result["unknown_paths"])
        self.assertFalse(result["gates"]["unit"])
        self.assertFalse(result["gates"]["os_matrix"])
        self.assertFalse(result["gates"]["platform_matrix"])

    def test_prompt_only_change_uses_content_gate(self) -> None:
        result = change_impact.classify(["skills/blue-dfir-analysis/SKILL.md"])
        self.assertEqual("content", result["level"])
        self.assertFalse(result["gates"]["os_matrix"])
        self.assertFalse(result["gates"]["platform_matrix"])

    def test_skill_script_uses_os_but_not_agent_platform_matrix(self) -> None:
        result = change_impact.classify(
            ["skills/spa-security-object-graph/scripts/analyze_url.py"]
        )
        self.assertEqual("executable", result["level"])
        self.assertTrue(result["gates"]["os_matrix"])
        self.assertFalse(result["gates"]["platform_matrix"])

    def test_single_platform_package_selects_only_that_platform(self) -> None:
        result = change_impact.classify(["platform-packages/gemini/hooks/hooks.json"])
        self.assertEqual("platform-runtime", result["level"])
        self.assertEqual(["gemini"], result["platforms"])

    def test_shared_runtime_and_unknown_paths_use_full_matrix(self) -> None:
        for path in ("scripts/install.py", "new-unclassified-file.txt"):
            result = change_impact.classify([path])
            self.assertEqual("core-runtime", result["level"])
            self.assertEqual(set(change_impact.ALL_PLATFORMS), set(result["platforms"]))


if __name__ == "__main__":
    unittest.main()
