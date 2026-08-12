from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG_SCRIPT = ROOT / "scripts" / "hub_config.py"
INGEST_SCRIPT = ROOT / "scripts" / "ingest_internal.py"


class ConfiguredReportRootsTest(unittest.TestCase):
    def run_script(
        self, environment: dict[str, str], script: Path, *args: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python", str(script), *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )

    def test_configured_root_is_indexed_without_moving_original(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reports = root / "work-reports"
            reports.mkdir()
            original = reports / "finding.txt"
            original.write_text("historical authorization finding", encoding="utf-8")

            environment = os.environ.copy()
            environment["BLUE_SEC_CONFIG"] = str(root / "config")
            environment["BLUE_SEC_DATA"] = str(root / "data")

            self.run_script(
                environment,
                CONFIG_SCRIPT,
                "add-report-root",
                str(reports),
            )
            ingest = self.run_script(environment, INGEST_SCRIPT)
            self.assertIn("indexed=1", ingest.stdout)
            self.assertTrue(original.exists())

            config_path = root / "config" / "config.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(
                [Path(value).resolve() for value in config["report_roots"]],
                [reports.resolve()],
            )
            if os.name != "nt":
                self.assertEqual(config_path.stat().st_mode & 0o777, 0o600)

            manifest_path = root / "data" / "internal" / "manifest.jsonl"
            entry = json.loads(manifest_path.read_text(encoding="utf-8").strip())
            self.assertEqual(Path(entry["source"]).resolve(), original.resolve())
            self.assertRegex(entry["sha256"], r"^[0-9a-f]{64}$")

    def test_documents_mode_skips_mixed_cache_noise(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "chat-cache"
            cache.mkdir()
            report = cache / "retest.docm"
            with zipfile.ZipFile(report, "w") as archive:
                archive.writestr(
                    "word/document.xml",
                    (
                        '<?xml version="1.0" encoding="UTF-8"?>'
                        '<w:document xmlns:w="http://schemas.openxmlformats.org/'
                        'wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>'
                        "安全复测报告"
                        "</w:t></w:r></w:p></w:body></w:document>"
                    ),
                )
            noise = cache / "bundle.js"
            noise.write_text("const token = 'not a report';", encoding="utf-8")

            environment = os.environ.copy()
            environment["BLUE_SEC_CONFIG"] = str(root / "config")
            environment["BLUE_SEC_DATA"] = str(root / "data")

            self.run_script(
                environment,
                CONFIG_SCRIPT,
                "add-report-root",
                str(cache),
                "--mode",
                "documents",
            )
            config = json.loads(
                (root / "config" / "config.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                config["report_root_modes"][str(cache.resolve())],
                "documents",
            )
            self.run_script(
                environment,
                CONFIG_SCRIPT,
                "add-report-root",
                str(cache),
            )
            config = json.loads(
                (root / "config" / "config.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                config["report_root_modes"][str(cache.resolve())],
                "documents",
            )

            ingest = self.run_script(environment, INGEST_SCRIPT)
            self.assertIn("indexed=1", ingest.stdout)
            manifest = (
                root / "data" / "internal" / "manifest.jsonl"
            ).read_text(encoding="utf-8")
            records = [json.loads(line) for line in manifest.splitlines()]
            sources = {Path(item["source"]) for item in records}
            self.assertIn(report.resolve(), sources)
            self.assertNotIn(noise.resolve(), sources)


if __name__ == "__main__":
    unittest.main()
