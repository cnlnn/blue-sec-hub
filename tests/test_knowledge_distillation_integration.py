from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    os.environ.get("BLUE_SEC_KNOWLEDGE_INTEGRATION") == "1",
    "set BLUE_SEC_KNOWLEDGE_INTEGRATION=1 for external extractor tests",
)
class KnowledgeDistillationIntegrationTest(unittest.TestCase):
    def test_legacy_office_conversion_runs_in_isolated_reader(self) -> None:
        import sys

        sys.path.insert(0, str(ROOT / "scripts"))
        from report_formats import extract_document

        for binary in ("libreoffice", "bwrap"):
            self.assertIsNotNone(shutil.which(binary), binary)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            csv = root / "fixture.csv"
            csv.write_text(
                "漏洞名称,水平越权\n修复建议,服务端校验对象所有权\n",
                encoding="utf-8",
            )
            subprocess.run(
                [
                    "libreoffice",
                    "--headless",
                    "--convert-to",
                    "xls",
                    "--outdir",
                    str(root),
                    str(csv),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=120,
            )
            legacy = root / "fixture.xls"
            self.assertTrue(legacy.exists())
            value = extract_document(legacy)
            self.assertIsNotNone(value)
            self.assertEqual(value["format"], "xls")
            self.assertIn("水平越权", value["text"])
            self.assertEqual(
                value["metadata"]["conversion"],
                "isolated-libreoffice",
            )


if __name__ == "__main__":
    unittest.main()
