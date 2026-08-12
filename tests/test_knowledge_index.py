from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import knowledge_index  # noqa: E402
import knowledge_sources  # noqa: E402


class KnowledgeIndexTest(unittest.TestCase):
    def test_repository_offline_pack_is_searchable_without_upstream_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            previous = os.environ.get("BLUE_SEC_DATA")
            os.environ["BLUE_SEC_DATA"] = str(Path(temporary) / "data")
            try:
                roots = [("vendored", ROOT / "knowledge")]
                result = knowledge_index.search(["unresolved prerequisites"], roots, 5)
                self.assertTrue(result)
                self.assertEqual("vendored", result[0]["source_kind"])
                self.assertEqual("internal", result[0]["trust"])
            finally:
                if previous is None:
                    os.environ.pop("BLUE_SEC_DATA", None)
                else:
                    os.environ["BLUE_SEC_DATA"] = previous

    def test_empty_and_full_cache_modes_are_distinguishable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            empty = root / "empty"
            empty.mkdir()
            full = root / "full" / "fixture"
            full.mkdir(parents=True)
            (full / "chain.md").write_text(
                "# Chain\n\nA sink is only a candidate until attacker input and observable impact are proven.\n",
                encoding="utf-8",
            )
            previous = os.environ.get("BLUE_SEC_DATA")
            os.environ["BLUE_SEC_DATA"] = str(root / "data")
            try:
                self.assertEqual([], knowledge_index.search(["observable impact"], [("upstreams", empty)], 5))
                result = knowledge_index.search(["observable impact"], [("upstreams", root / "full")], 5)
                self.assertEqual(1, len(result))
                self.assertEqual("fixture", result[0]["source_name"])
                self.assertEqual(0, result[0]["instruction_authority"])
                self.assertEqual("fts5-coverage-trust-fusion-v1", result[0]["retrieval"]["reranker"])
            finally:
                if previous is None:
                    os.environ.pop("BLUE_SEC_DATA", None)
                else:
                    os.environ["BLUE_SEC_DATA"] = previous

    def test_fts_results_include_anchor_provenance_and_no_instruction_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "upstreams" / "fixture"
            source.mkdir(parents=True)
            document = source / "authorization.md"
            document.write_text(
                "# Authorization\n\nCheck broken object level authorization at every boundary.\n",
                encoding="utf-8",
            )
            previous = os.environ.get("BLUE_SEC_DATA")
            os.environ["BLUE_SEC_DATA"] = str(root / "data")
            try:
                roots = [("upstreams", root / "upstreams")]
                result = knowledge_index.search(["object level authorization"], roots, 10)
                self.assertEqual(1, len(result))
                self.assertEqual(str(document), result[0]["path"])
                self.assertGreaterEqual(result[0]["line_start"], 1)
                self.assertEqual("community", result[0]["trust"])
                self.assertEqual(0, result[0]["instruction_authority"])
                first_fingerprint = knowledge_index.root_fingerprint(roots)
                document.write_text("Different content", encoding="utf-8")
                self.assertNotEqual(first_fingerprint, knowledge_index.root_fingerprint(roots))
                self.assertFalse(knowledge_index.is_current(roots))
            finally:
                if previous is None:
                    os.environ.pop("BLUE_SEC_DATA", None)
                else:
                    os.environ["BLUE_SEC_DATA"] = previous

    def test_candidate_diff_never_grants_instruction_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            active = {"sources": {"fixture": {"commit": "old"}}}
            candidate = {
                "sources": {
                    "fixture": {
                        "commit": "new",
                        "trust": "community",
                        "content_policy": "retrieval-only-untrusted",
                    }
                },
                "review": {
                    "status": "candidate",
                    "instruction_authority": False,
                    "required_checks": ["source-diff"],
                },
            }
            old_cache = knowledge_sources.CACHE_ROOT
            old_root = knowledge_sources.ROOT
            try:
                knowledge_sources.CACHE_ROOT = cache
                knowledge_sources.ROOT = cache / "repo"
                knowledge_sources.ROOT.mkdir()
                (knowledge_sources.ROOT / "sources.lock.json").write_text(
                    json.dumps(active), encoding="utf-8"
                )
                lock = cache / "source-candidates/lock.json"
                lock.parent.mkdir(parents=True)
                lock.write_text(json.dumps(candidate), encoding="utf-8")
                result = knowledge_sources.diff()
                self.assertFalse(result["instruction_authority"])
                self.assertTrue(result["changes"][0]["changed"])
            finally:
                knowledge_sources.CACHE_ROOT = old_cache
                knowledge_sources.ROOT = old_root


if __name__ == "__main__":
    unittest.main()
