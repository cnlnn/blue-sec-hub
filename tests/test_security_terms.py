from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from security_terms import canonicalize_term, expand_query, validate_glossary


class SecurityTermsTest(unittest.TestCase):
    def test_generic_authorization_expands_both_boundaries(self) -> None:
        expansion = expand_query("越权")
        self.assertEqual(expansion["canonical"], ["broken-access-control"])
        self.assertIn("IDOR", expansion["search_terms"])
        self.assertIn("BFLA", expansion["search_terms"])

    def test_horizontal_authorization_stays_object_specific(self) -> None:
        expansion = expand_query("这个接口可能存在水平越权")
        self.assertEqual(expansion["canonical"], ["object-authorization"])
        self.assertIn("BOLA", expansion["search_terms"])
        self.assertNotIn("BFLA", expansion["search_terms"])

    def test_chinese_weakness_is_canonicalized(self) -> None:
        self.assertEqual(canonicalize_term("水平越权"), "object-authorization")
        self.assertEqual(canonicalize_term("IDOR"), "object-authorization")
        self.assertEqual(canonicalize_term("BFLA"), "function-authorization")
        self.assertEqual(canonicalize_term("权限提升"), "privilege-escalation")
        self.assertEqual(canonicalize_term("GraphQL security"), "GraphQL security")
        self.assertEqual(
            expand_query("CWE-1427")["canonical"],
            ["prompt-injection"],
        )
        self.assertEqual(canonicalize_term("SQL 注入"), "sql-injection")
        self.assertEqual(canonicalize_term("custom-weakness"), "custom-weakness")
        self.assertEqual(validate_glossary(), [])

    def test_generic_protocol_words_do_not_route_to_attack_classes(self) -> None:
        for query in (
            "Analyze DNS logs",
            "Review the SSO URL",
            "Inspect AD ACLs",
            "Check SMTP and IMAP configuration",
            "Review WAF events",
        ):
            self.assertEqual([], expand_query(query)["canonical"], query)
        self.assertEqual(["dns-rebinding"], expand_query("test DNS Rebinding")["canonical"])

    def test_search_chinese_finds_english_upstream(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "cache"
            source = cache / "upstreams" / "fixture"
            source.mkdir(parents=True)
            document = source / "authorization.md"
            document.write_text(
                "Check broken object level authorization (BOLA) at each object boundary.",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["BLUE_SEC_CACHE"] = str(cache)
            environment["BLUE_SEC_DATA"] = str(Path(temporary) / "data")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "search_knowledge.py"),
                    "水平越权",
                    "--source",
                    "upstreams",
                    "--explain",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )
            lines = result.stdout.splitlines()
            explanation = json.loads(lines[0])
            self.assertIn("object-authorization", explanation["canonical"])
            self.assertTrue(any("authorization.md" in line for line in lines[1:]))

    def test_search_has_python_fallback_without_ripgrep(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "cache"
            source = cache / "upstreams" / "fixture"
            source.mkdir(parents=True)
            (source / "authorization.md").write_text(
                "Broken Object Level Authorization",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment["BLUE_SEC_CACHE"] = str(cache)
            environment["BLUE_SEC_DATA"] = str(Path(temporary) / "data")
            environment["PATH"] = str(Path(temporary) / "empty-path")
            self.assertIsNone(shutil.which("rg", path=environment["PATH"]))

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPTS / "search_knowledge.py"),
                    "水平越权",
                    "--source",
                    "upstreams",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
            )

            self.assertIn("authorization.md", result.stdout)


if __name__ == "__main__":
    unittest.main()
