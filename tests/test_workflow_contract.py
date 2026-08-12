from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
ACTION_REF = re.compile(r"^\s*uses:\s*[^@\s]+@([0-9a-f]{40})\b", re.MULTILINE)


class WorkflowContractTest(unittest.TestCase):
    def test_ci_covers_supported_hosted_platforms_offline(self) -> None:
        content = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")

        for runner in ("ubuntu-24.04", "macos-15", "windows-2025"):
            self.assertIn(runner, content)
        self.assertNotIn("${{ runner.temp }}", content)
        self.assertIn('PYTHONUTF8: "1"', content)
        self.assertIn("scripts/validate.py --offline", content)
        self.assertIn("python -m unittest discover -s tests", content)
        self.assertIn('python: ["3.11", "3.12", "3.13", "3.14"]', content)
        self.assertIn("continue-on-error: true", content)
        self.assertNotIn("required-version", (ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertIn("kernel.apparmor_restrict_unprivileged_userns=0", content)

    def test_release_requires_matching_tag_and_publishes_checksums(self) -> None:
        content = (WORKFLOWS / "release.yml").read_text(encoding="utf-8")

        self.assertIn('tags:\n      - "v*"', content)
        self.assertIn("scripts/release.py", content)
        self.assertNotIn("uv run", content)
        self.assertNotIn("setup-uv", content)
        self.assertIn('--tag "$RELEASE_TAG"', content)
        self.assertIn("--artifact-only", content)
        self.assertIn("behavioral certification is not claimed", content)
        for platform in ("codex", "claude", "gemini", "grok", "opencode", "openclaw", "hermes", "trae", "trae-cn"):
            self.assertIn(platform, content)
        self.assertIn("dist/SHA256SUMS", content)
        self.assertIn("--verify-tag", content)

    def test_candidate_tags_promote_without_persistent_learning_branches(self) -> None:
        content = (WORKFLOWS / "candidate-promotion.yml").read_text(encoding="utf-8")

        self.assertIn('- "blue-sec-candidate/**"', content)
        self.assertIn("contents: write", content)
        self.assertIn("HEAD:refs/heads/main", content)
        self.assertNotIn("pulls.create", content)

    def test_main_is_stable_integration_while_short_lived_branches_are_audited(self) -> None:
        content = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        self.assertNotIn('"feature/**"', content)
        self.assertNotIn('"learning/**"', content)
        audit = (WORKFLOWS / "branch-audit.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/branch_audit.py --github --json", audit)
        self.assertIn("refs/heads/*:refs/remotes/origin/*", audit)
        self.assertIn("without PR", audit)

    def test_content_changes_do_not_require_platform_matrix(self) -> None:
        content = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/change_impact.py", content)
        self.assertIn("needs.impact.outputs.platform_matrix == 'true'", content)
        self.assertIn("scripts/validate_content.py", content)

    def test_external_actions_are_pinned_to_commit_shas(self) -> None:
        for path in sorted(WORKFLOWS.glob("*.yml")):
            content = path.read_text(encoding="utf-8")
            uses_lines = [
                line for line in content.splitlines() if line.lstrip().startswith("uses:")
            ]
            self.assertTrue(uses_lines, path)
            self.assertEqual(len(uses_lines), len(ACTION_REF.findall(content)), path)


if __name__ == "__main__":
    unittest.main()
