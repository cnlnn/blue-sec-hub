from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def git(repo: Path, *arguments: str, environment: dict[str, str] | None = None) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=repo,
        env=environment,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()


class BranchAuditTest(unittest.TestCase):
    def test_remote_ref_inherits_local_branch_pr_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            git(repo, "init", "-b", "main")
            git(repo, "config", "user.name", "Blue Sec Test")
            git(repo, "config", "user.email", "blue-sec@example.test")
            (repo / "base.txt").write_text("base\n", encoding="utf-8")
            git(repo, "add", "base.txt")
            git(repo, "commit", "-m", "base")
            git(repo, "switch", "-c", "release/next")
            (repo / "release.txt").write_text("release\n", encoding="utf-8")
            git(repo, "add", "release.txt")
            git(repo, "commit", "-m", "release")
            commit = git(repo, "rev-parse", "HEAD")
            git(repo, "update-ref", "refs/remotes/origin/release/next", commit)
            git(repo, "config", "branch.release/next.blue-sec-pr", "https://example.test/pr/2")

            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/branch_audit.py"), "--repo", str(repo), "--json"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            )
            value = json.loads(result.stdout)
            remote = next(item for item in value["branches"] if item["name"] == "origin/release/next")
            self.assertEqual("ahead-with-pr", remote["status"])
            self.assertEqual("https://example.test/pr/2", remote["pr"]["url"])
            self.assertEqual(0, value["summary"]["without_pr"])

    def test_reports_unmerged_commits_pr_binding_and_archive_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            git(repo, "init", "-b", "main")
            git(repo, "config", "user.name", "Blue Sec Test")
            git(repo, "config", "user.email", "blue-sec@example.test")
            (repo / "base.txt").write_text("base\n", encoding="utf-8")
            git(repo, "add", "base.txt")
            git(repo, "commit", "-m", "base")
            git(repo, "branch", "feature/with-pr")
            git(repo, "config", "branch.feature/with-pr.blue-sec-pr", "https://example.test/pr/1")
            git(repo, "switch", "-c", "feature/orphan")
            (repo / "orphan.txt").write_text("orphan\n", encoding="utf-8")
            git(repo, "add", "orphan.txt")
            environment = os.environ.copy()
            environment["GIT_AUTHOR_DATE"] = "2020-01-01T00:00:00+00:00"
            environment["GIT_COMMITTER_DATE"] = "2020-01-01T00:00:00+00:00"
            git(repo, "commit", "-m", "unmerged work", environment=environment)
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/branch_audit.py"), "--repo", str(repo), "--base", "main", "--json"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
            )
            value = json.loads(result.stdout)
            branches = {item["name"]: item for item in value["branches"]}
            self.assertEqual("archive-candidate", branches["feature/orphan"]["status"])
            self.assertEqual("unmerged work", branches["feature/orphan"]["unmerged_commits"][0]["subject"])
            self.assertEqual("https://example.test/pr/1", branches["feature/with-pr"]["pr"]["url"])
            self.assertEqual(1, value["summary"]["without_pr"])

    def test_fail_on_stale_uses_distinct_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            git(repo, "init", "-b", "main")
            git(repo, "config", "user.name", "Blue Sec Test")
            git(repo, "config", "user.email", "blue-sec@example.test")
            (repo / "base.txt").write_text("base\n", encoding="utf-8")
            git(repo, "add", "base.txt")
            git(repo, "commit", "-m", "base")
            git(repo, "switch", "-c", "fix/stale")
            (repo / "fix.txt").write_text("fix\n", encoding="utf-8")
            git(repo, "add", "fix.txt")
            environment = os.environ.copy()
            environment["GIT_AUTHOR_DATE"] = "2020-01-01T00:00:00+00:00"
            environment["GIT_COMMITTER_DATE"] = "2020-01-01T00:00:00+00:00"
            git(repo, "commit", "-m", "old fix", environment=environment)
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/branch_audit.py"), "--repo", str(repo), "--fail-on-stale"],
                text=True,
                stdout=subprocess.PIPE,
            )
            self.assertEqual(3, result.returncode)


if __name__ == "__main__":
    unittest.main()
