from __future__ import annotations

import json
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release.py"
VERSION = str(
    tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
)


class ReleaseTest(unittest.TestCase):
    def quality_result(self, root: Path) -> Path:
        path = root / "quality-result.json"
        path.write_text(
            json.dumps(
                {
                    "expected_finding_ids": ["a", "b", "c", "d", "e"],
                    "reported_finding_ids": ["a", "b", "c", "d"],
                    "first_result_seconds": 500,
                    "total_seconds": 5000,
                    "consecutive_runs": 3,
                    "successful_platforms": ["linux", "macos", "windows"],
                    "successful_agents": ["codex", "claude"],
                    "successful_agent_contracts": [
                        "codex",
                        "claude",
                        "gemini",
                        "grok",
                        "opencode",
                        "openclaw",
                        "hermes",
                        "trae",
                        "trae-cn",
                    ],
                    "fixtures": [
                        "owasp-juice-shop",
                        "owasp-crapi",
                        "owasp-webgoat",
                        "blue-sec-minimal-spa-api",
                    ],
                    "run_records": 72,
                    "generated_by": "blue-sec-benchmark-suite",
                    "state_corruption_events": 0,
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_release_is_versioned_and_contains_only_repository_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--tag",
                    f"v{VERSION}",
                    "--out",
                    str(output),
                    "--quality-result",
                    str(self.quality_result(output)),
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            tar_path = output / f"blue-sec-hub-{VERSION}.tar.gz"
            zip_path = output / f"blue-sec-hub-{VERSION}.zip"
            self.assertTrue((output / "SHA256SUMS").is_file())
            with tarfile.open(tar_path, "r:gz") as archive:
                tar_names = set(archive.getnames())
            with zipfile.ZipFile(zip_path) as archive:
                zip_names = set(archive.namelist())
            self.assertEqual(tar_names, zip_names)
            self.assertIn(f"blue-sec-hub-{VERSION}/README.md", tar_names)
            self.assertIn(
                f"blue-sec-hub-{VERSION}/skills/blue-team-security/SKILL.md",
                tar_names,
            )
            self.assertIn(
                f"blue-sec-hub-{VERSION}/scripts/web_assessment.py",
                tar_names,
            )
            self.assertIn(
                f"blue-sec-hub-{VERSION}/scripts/web_runner.py",
                tar_names,
            )
            self.assertIn(
                f"blue-sec-hub-{VERSION}/scripts/agent.py",
                tar_names,
            )
            self.assertIn(
                f"blue-sec-hub-{VERSION}/scripts/context_checkpoint.py",
                tar_names,
            )
            self.assertIn(
                f"blue-sec-hub-{VERSION}/.codex-plugin/plugin.json",
                tar_names,
            )
            self.assertIn(
                f"blue-sec-hub-{VERSION}/.claude-plugin/plugin.json",
                tar_names,
            )
            self.assertFalse(any(".git/" in name for name in tar_names))
            self.assertFalse(any(".local/share" in name for name in tar_names))

    def test_release_tag_must_match_project_version(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--tag",
                "v9.9.9",
                "--out",
                tempfile.gettempdir(),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("does not match project version", result.stderr)

    def test_release_requires_a_passing_quality_result(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--tag",
                f"v{VERSION}",
                "--out",
                tempfile.gettempdir(),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("requires a benchmark", result.stderr)

    def test_artifact_only_release_is_explicitly_uncertified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--tag",
                    f"v{VERSION}",
                    "--out",
                    temporary,
                    "--artifact-only",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertIn("behavioral benchmark certification is not claimed", result.stdout)
            self.assertTrue((Path(temporary) / "SHA256SUMS").is_file())


if __name__ == "__main__":
    unittest.main()
