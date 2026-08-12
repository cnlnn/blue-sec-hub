from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "skills" / "spa-security-object-graph" / "scripts"))

import agent  # noqa: E402
import knowledge_runtime  # noqa: E402
import web_assessment  # noqa: E402
import web_runner  # noqa: E402
import source_mapper  # noqa: E402
from collect_browser_assets import resolve_dynamic_routes  # noqa: E402


class FastFindClosedLoopTest(unittest.TestCase):
    def test_default_workspace_and_brief_are_non_technical_entrypoint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            old = agent.os.environ.get("BLUE_SEC_EVIDENCE_ROOT")
            agent.os.environ["BLUE_SEC_EVIDENCE_ROOT"] = temporary
            try:
                workspace = agent.default_workspace("https://shop.example.test/path")
            finally:
                if old is None:
                    agent.os.environ.pop("BLUE_SEC_EVIDENCE_ROOT", None)
                else:
                    agent.os.environ["BLUE_SEC_EVIDENCE_ROOT"] = old
            self.assertEqual(Path(temporary), workspace.parent)
            self.assertIn("shop.example.test", workspace.name)

    def test_fast_lane_does_not_remove_coverage_lane(self) -> None:
        auth = {"family": "authorization.object-level", "priority": "P2"}
        baseline = {"family": "platform-exposure.headers-cache-cors", "priority": "P3"}
        self.assertEqual("fast-find", web_assessment.execution_lane(auth))
        self.assertEqual("coverage-close", web_assessment.execution_lane(baseline))

    def test_dynamic_route_uses_only_current_observed_value(self) -> None:
        routes, bindings = resolve_dynamic_routes(
            {"/orders/:orderId", "/users/:userId/details"},
            {"orderid": [1234], "userid": ["self-5678"]},
        )
        self.assertEqual({"/orders/1234", "/users/self-5678/details"}, routes)
        self.assertTrue(all("bindingSlotId" in row for item in bindings for row in item["bindings"]))
        self.assertNotIn("Sha256", json.dumps(bindings))
        self.assertNotIn("self-5678", json.dumps(bindings))

    def test_local_hypotheses_filter_legal_noise_and_never_confirm(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "pattern-candidates.jsonl"
            source.write_text(
                "\n".join(
                    json.dumps(item, ensure_ascii=False)
                    for item in (
                        {"candidate_id": "a", "canonical_term": "水平越权访问", "independent_sources": 2},
                        {"candidate_id": "b", "canonical_term": "Executable means Covered Code", "independent_sources": 5},
                    )
                ),
                encoding="utf-8",
            )
            destination = Path(temporary) / "catalog.json"
            value = knowledge_runtime.build_catalog(source, destination)
            self.assertEqual(1, len(value["local_hypotheses"]))
            self.assertEqual("authorization.object-level", value["local_hypotheses"][0]["family"])
            self.assertIn("current response evidence required", value["finding_policy"])

    def test_native_openapi_sanitizer_keeps_shapes_without_examples(self) -> None:
        value = web_runner.sanitized_openapi(
            {
                "openapi": "3.0.0",
                "info": {"title": "fixture", "version": "1"},
                "paths": {
                    "/orders": {
                        "get": {
                            "parameters": [
                                {
                                    "name": "status",
                                    "in": "query",
                                    "schema": {"type": "string", "example": "private-value"},
                                }
                            ]
                        },
                        "post": {"requestBody": {"example": {"secret": "private-value"}}},
                    }
                },
            },
            "https://shop.example.test",
        )
        self.assertIsNotNone(value)
        rendered = json.dumps(value)
        self.assertIn("status", rendered)
        self.assertNotIn("private-value", rendered)
        parameter_schema = value["paths"]["/orders"]["get"]["parameters"][0]["schema"]
        self.assertNotIn("example", parameter_schema)

    def test_core_has_no_removed_assessment_tool_dependency(self) -> None:
        removed = ("ka" + "tana", "nu" + "clei", "schema" + "thesis", "had" + "rian")
        paths = [
            ROOT / "pyproject.toml",
            ROOT / "feeds.json",
            ROOT / "executors.json",
            ROOT / "scripts" / "agent.py",
            ROOT / "scripts" / "web_runner.py",
            ROOT / "scripts" / "bootstrap.py",
            ROOT / "scripts" / "doctor.py",
        ]
        material = "\n".join(path.read_text(encoding="utf-8").casefold() for path in paths)
        for name in removed:
            self.assertNotIn(name, material)
        self.assertFalse((ROOT / "web_tools.lock.json").exists())
        self.assertFalse((ROOT / "scripts" / ("web_" + "tooling.py")).exists())

    def test_attack_chain_is_hypothesis_without_direct_chain_evidence(self) -> None:
        value = web_assessment.build_attack_chain_analysis(
            {"findings": [], "candidates": []},
            {
                "test_cells": [
                    {"id": "a", "family": "authorization.object-level", "status": "tested"},
                    {"id": "b", "family": "files-data-export.path-read-download", "status": "tested"},
                ],
                "executable_cases": [
                    {"id": "ca", "test_cell_id": "a", "work_unit_id": "u", "status": "tested"},
                    {"id": "cb", "test_cell_id": "b", "work_unit_id": "u", "status": "tested"},
                ],
            },
        )
        self.assertEqual("hypothesis", value["edges"][0]["confidence"])

    def test_source_mapping_correlates_route_and_control_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "orders.py"
            source.write_text(
                "@app.get('/api/orders/{order_id}')\n"
                "def order(order_id, currentUser):\n"
                "    authorize(currentUser, 'read')\n"
                "    return repository.findById(order_id)\n",
                encoding="utf-8",
            )
            value = source_mapper.map_source(root)
            self.assertEqual(1, len(value["routes"]))
            signals = value["routes"][0]["control_signals"]
            self.assertTrue(signals["authorization_check_nearby"])
            self.assertTrue(signals["object_query_nearby"])
            self.assertEqual("documented", value["surfaces"][0]["validation_state"])


if __name__ == "__main__":
    unittest.main()
