from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from privacy_scan import scan_repository  # noqa: E402


class PrivacyScanTest(unittest.TestCase):
    def test_current_repository_is_clean(self) -> None:
        self.assertEqual([], scan_repository(ROOT))

    def test_secret_and_local_evidence_path_are_reported_without_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secret = "github_" + "pat_abcdefghijklmnopqrstuvwxyz1234567890"
            (root / "fixture.txt").write_text(
                secret
                + "\n/home/"
                + "operator/Documents/private-report.docx\n",
                encoding="utf-8",
            )
            findings = scan_repository(root)
        self.assertIn("fixture.txt: github-access-token", findings)
        self.assertIn("fixture.txt: local-user-path", findings)
        self.assertTrue(all(secret not in item for item in findings))

    def test_generated_worktrees_and_virtualenvs_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for directory in (".venv", ".work"):
                path = root / directory / "fixture.txt"
                path.parent.mkdir()
                path.write_text(
                    "/home/" + "operator/Documents/private-report.docx\n",
                    encoding="utf-8",
                )
            self.assertEqual([], scan_repository(root))


if __name__ == "__main__":
    unittest.main()
