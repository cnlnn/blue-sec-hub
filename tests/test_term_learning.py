from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


class TermLearningTest(unittest.TestCase):
    def environment(self, root: Path) -> dict[str, str]:
        environment = os.environ.copy()
        environment["BLUE_SEC_CACHE"] = str(root / "cache")
        environment["BLUE_SEC_DATA"] = str(root / "data")
        environment["BLUE_SEC_GLOSSARY"] = str(root / "security_terms.json")
        return environment

    def run_tool(
        self,
        root: Path,
        script: str,
        *args: str,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPTS / script), *args],
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment(root),
        )

    def prepare_fixture(self, root: Path) -> None:
        shutil.copy2(ROOT / "security_terms.json", root / "security_terms.json")
        cwe = root / "cache" / "feeds" / "mitre-cwe"
        cwe.mkdir(parents=True)
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7"
 Version="fixture" Date="2026-01-01">
  <Weaknesses>
    <Weakness ID="1321"
      Name="Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')"
      Status="Stable">
      <Alternate_Terms>
        <Alternate_Term><Term>Prototype Pollution</Term></Alternate_Term>
      </Alternate_Terms>
    </Weakness>
    <Weakness ID="1999"
      Name="Novel Cache Boundary Confusion"
      Status="Draft" />
    <Weakness ID="1997" Name="First Ambiguous Weakness" Status="Draft">
      <Alternate_Terms>
        <Alternate_Term><Term>Shared Alias</Term></Alternate_Term>
      </Alternate_Terms>
    </Weakness>
    <Weakness ID="1998" Name="Second Ambiguous Weakness" Status="Draft">
      <Alternate_Terms>
        <Alternate_Term><Term>Shared Alias</Term></Alternate_Term>
      </Alternate_Terms>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""
        with zipfile.ZipFile(cwe / "cwec_latest.xml.zip", "w") as archive:
            archive.writestr("cwec_fixture.xml", xml)

        strix = (
            root
            / "cache"
            / "upstreams"
            / "strix"
            / "vulnerabilities"
        )
        strix.mkdir(parents=True)
        (strix / "cache_key_confusion.md").write_text(
            "---\nname: cache-key-confusion\n"
            "description: Cache key confusion testing\n---\n"
            "# Cache Key Confusion\n",
            encoding="utf-8",
        )
        (strix / "prototype_pollution.md").write_text(
            "---\nname: prototype-pollution\n"
            "description: Prototype pollution testing\n---\n"
            "# Prototype Pollution\n",
            encoding="utf-8",
        )
        hack = (
            root
            / "cache"
            / "upstreams"
            / "hack-skills"
            / "cache-key-confusion"
        )
        hack.mkdir(parents=True)
        (hack / "UPSTREAM_SKILL.md").write_text(
            "---\nname: cache-key-confusion\n"
            "description: Cache poisoning through key confusion\n---\n"
            "# Cache Key Confusion\n",
            encoding="utf-8",
        )

    def test_discovers_official_and_corroborated_terms(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.prepare_fixture(root)
            result = self.run_tool(root, "term_learning.py", "discover")
            self.assertIn("cwe=4", result.stdout)

            official = json.loads(
                (
                    root / "data" / "term-learning" / "official.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                [item["id"] for item in official["terms"]],
                ["cwe-1321", "cwe-1997", "cwe-1998", "cwe-1999"],
            )
            official_name = self.run_tool(
                root,
                "security_terms.py",
                "Improperly Controlled Modification of Object Prototype Attributes",
            )
            self.assertEqual(
                json.loads(official_name.stdout)["canonical"],
                ["prototype-pollution"],
            )
            novel = self.run_tool(
                root,
                "security_terms.py",
                "Novel Cache Boundary Confusion",
            )
            self.assertEqual(
                json.loads(novel.stdout)["canonical"],
                ["cwe-1999"],
            )
            ambiguous = self.run_tool(
                root,
                "security_terms.py",
                "Shared Alias",
            )
            self.assertEqual(json.loads(ambiguous.stdout)["canonical"], [])

            candidates = [
                json.loads(line)
                for line in (
                    root / "data" / "term-learning" / "candidates.jsonl"
                ).read_text(encoding="utf-8").splitlines()
            ]
            cache_candidate = next(
                item for item in candidates if item["term"] == "Cache Key Confusion"
            )
            self.assertEqual(cache_candidate["state"], "ready")
            self.assertEqual(cache_candidate["source_count"], 2)
            self.assertFalse(
                any(item["term"] == "Prototype Pollution" for item in candidates)
            )

            query = self.run_tool(
                root,
                "security_terms.py",
                "Cache Key Confusion",
            )
            expansion = json.loads(query.stdout)
            self.assertIn(cache_candidate["id"], expansion["candidate_matches"])
            self.assertEqual(expansion["canonical"], [])

    def test_promotes_reviewed_alias_and_blocks_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "promote"
            root.mkdir()
            self.prepare_fixture(root)
            self.run_tool(root, "term_learning.py", "discover")
            candidates = [
                json.loads(line)
                for line in (
                    root / "data" / "term-learning" / "candidates.jsonl"
                ).read_text(encoding="utf-8").splitlines()
            ]
            candidate = next(
                item for item in candidates if item["term"] == "Cache Key Confusion"
            )
            self.run_tool(
                root,
                "term_learning.py",
                "promote",
                candidate["id"],
                "--canonical",
                "cache-key-confusion",
                "--category",
                "cache",
                "--alias",
                "缓存键混淆",
                "--evidence",
                "tests/validated-fixture",
            )
            query = self.run_tool(root, "security_terms.py", "缓存键混淆")
            expansion = json.loads(query.stdout)
            self.assertEqual(expansion["canonical"], ["cache-key-confusion"])

            conflict_root = Path(temporary) / "conflict"
            conflict_root.mkdir()
            self.prepare_fixture(conflict_root)
            self.run_tool(conflict_root, "term_learning.py", "discover")
            candidates = [
                json.loads(line)
                for line in (
                    conflict_root
                    / "data"
                    / "term-learning"
                    / "candidates.jsonl"
                ).read_text(encoding="utf-8").splitlines()
            ]
            active = next(
                item for item in candidates if item["term"] == "Cache Key Confusion"
            )
            blocked = self.run_tool(
                conflict_root,
                "term_learning.py",
                "promote",
                active["id"],
                "--canonical",
                "another-cache-term",
                "--alias",
                "SQL注入",
                "--evidence",
                "tests/conflict-fixture",
                check=False,
            )
            self.assertNotEqual(blocked.returncode, 0)
            self.assertIn("alias conflicts", blocked.stderr)
            self.assertTrue(
                (
                    conflict_root
                    / "data"
                    / "term-learning"
                    / "conflicts.jsonl"
                ).is_file()
            )

    def test_adds_validated_local_term_without_upstream_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copy2(ROOT / "security_terms.json", root / "security_terms.json")
            self.run_tool(
                root,
                "term_learning.py",
                "add",
                "--canonical",
                "request-body-confusion",
                "--term",
                "Request Body Confusion",
                "--category",
                "request",
                "--alias",
                "请求体混淆",
                "--evidence",
                "tests/validated-fixture",
            )
            query = self.run_tool(root, "security_terms.py", "请求体混淆")
            self.assertEqual(
                json.loads(query.stdout)["canonical"],
                ["request-body-confusion"],
            )
            self.run_tool(root, "term_learning.py", "audit")


if __name__ == "__main__":
    unittest.main()
