from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "web_assessment.py"
SPEC = importlib.util.spec_from_file_location("web_assessment", SCRIPT)
assert SPEC and SPEC.loader
web_assessment = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(web_assessment)


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


class WebAssessmentTest(unittest.TestCase):
    def run_cli(
        self,
        *args: str,
        expected: int = 0,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(
            expected,
            result.returncode,
            f"stdout={result.stdout}\nstderr={result.stderr}",
        )
        return result

    def initialize(self, root: Path, target: str = "https://app.example.test/") -> Path:
        workspace = root / "assessment"
        self.run_cli("init", "--target", target, "--out", str(workspace))
        return workspace

    def test_init_creates_resumable_artifacts_and_pinned_standards(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = self.initialize(Path(temporary))
            for name in (
                "coverage.json",
                "route-inventory.json",
                "surface-inventory.json",
                "test-plan.json",
                "prerequisite-graph.json",
                "object-provenance.json",
                "evidence-index.json",
                "results.md",
            ):
                self.assertTrue((workspace / name).exists(), name)
            coverage = json.loads(
                (workspace / "coverage.json").read_text(encoding="utf-8")
            )
            self.assertEqual(8, coverage["schema_version"])
            self.assertEqual("comprehensive-fast-first", coverage["mode"])
            self.assertEqual("related-discovery", coverage["scope"]["mode"])
            self.assertTrue(
                all(
                    item["version"]
                    and item["source_ref"]
                    and len(item["source_commit"]) == 40
                    for item in coverage["standards"]
                )
            )

    def test_stable_surface_id_ignores_query_values_and_object_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "manual.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "method": "GET",
                            "url": "https://app.example.test/api/orders/123456?token=one",
                        },
                        {
                            "method": "GET",
                            "url": "https://app.example.test/api/orders/987654?token=two",
                        },
                    ]
                },
            )
            self.run_cli(
                "compile",
                "--workspace",
                str(workspace),
                "--input",
                f"manual={source}",
            )
            inventory = json.loads(
                (workspace / "surface-inventory.json").read_text(encoding="utf-8")
            )
            self.assertEqual(1, inventory["totals"]["surfaces"])
            self.assertEqual(
                "/api/orders/{id}",
                inventory["surfaces"][0]["path_template"],
            )
            self.assertEqual(["token"], inventory["surfaces"][0]["fields"])
            self.assertEqual(2, len(inventory["surfaces"][0]["source_refs"]))

    def test_large_api_surface_clusters_without_losing_mappings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "large.json"
            surfaces = [
                {
                    "kind": "api",
                    "method": "GET",
                    "url": (
                        "https://app.example.test/"
                        f"service/controller{index % 10}/getRecord{index}"
                    ),
                }
                for index in range(301)
            ]
            write_json(source, {"surfaces": surfaces})
            self.run_cli(
                "compile",
                "--workspace",
                str(workspace),
                "--input",
                f"manual={source}",
            )
            inventory = json.loads(
                (workspace / "surface-inventory.json").read_text(encoding="utf-8")
            )
            plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            api_units = [
                unit for unit in plan["work_units"] if unit["kind"] == "api"
            ]
            self.assertEqual(301, inventory["totals"]["surfaces"])
            self.assertEqual(301, inventory["totals"]["source_records"])
            self.assertEqual(10, len(api_units))
            mapped = {
                ref for unit in api_units for ref in unit["surface_refs"]
            }
            self.assertEqual(301, len(mapped))

    def test_nested_namespaces_do_not_leak_specialized_profiles(self) -> None:
        for domain, namespace, ordinary, file_resource in (
            ("commerce", "gateway/catalog", "products", "attachments"),
            ("healthcare", "platform/clinical", "patients", "reports"),
        ):
            with self.subTest(domain=domain), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                workspace = self.initialize(root)
                source = root / "nested.json"
                write_json(
                    source,
                    {
                        "surfaces": [
                            {
                                "method": "GET",
                                "url": f"/{namespace}/{ordinary}/list",
                                "runtime_observed": True,
                            },
                            {
                                "method": "GET",
                                "url": f"/{namespace}/{file_resource}/download",
                                "fields": ["filePath"],
                                "runtime_observed": True,
                            },
                        ]
                    },
                )
                web_assessment.compile_workspace(workspace, [("manual", source)])
                plan = json.loads(
                    (workspace / "test-plan.json").read_text(encoding="utf-8")
                )
                units = {
                    unit["controller"]: unit
                    for unit in plan["work_units"]
                    if unit["kind"] == "api"
                }
                ordinary_controller = f"{namespace}/{ordinary}"
                file_controller = f"{namespace}/{file_resource}"
                self.assertIn(ordinary_controller, units)
                self.assertIn(file_controller, units)
                self.assertNotIn(
                    "file-processing",
                    units[ordinary_controller]["profiles"],
                )
                self.assertIn(
                    "file-processing",
                    units[file_controller]["profiles"],
                )
                file_families = set(
                    units[file_controller]["applicable_families"]
                )
                self.assertIn(
                    "files-data-export.path-read-download",
                    file_families,
                )
                self.assertIn(
                    "files-data-export.storage-exposure",
                    file_families,
                )
                self.assertNotIn(
                    "files-data-export.upload-validation",
                    file_families,
                )
                self.assertNotIn(
                    "files-data-export.archive-extraction",
                    file_families,
                )
                self.assertNotIn(
                    "files-data-export.import-export-formula",
                    file_families,
                )

    def test_spa_recognized_probe_is_not_runtime_observed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "spa.json"
            write_json(
                source,
                {
                    "apis": [
                        {
                            "method": "GET",
                            "url": "/api/protected-candidate",
                            "validation": {
                                "state": "recognized",
                                "reason": "authentication-boundary",
                            },
                        },
                        {
                            "method": "GET",
                            "url": "/api/runtime",
                            "validation": {"state": "runtime-observed"},
                        },
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("spa", source)])
            inventory = json.loads(
                (workspace / "surface-inventory.json").read_text(
                    encoding="utf-8"
                )
            )
            by_path = {
                surface["path_template"]: surface
                for surface in inventory["surfaces"]
                if surface["kind"] == "api"
            }
            self.assertFalse(
                by_path["/api/protected-candidate"]["runtime_observed"]
            )
            self.assertTrue(by_path["/api/runtime"]["runtime_observed"])

    def test_replace_inputs_removes_superseded_collection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            first = root / "first.json"
            second = root / "second.json"
            write_json(
                first,
                {"surfaces": [{"method": "GET", "url": "/api/old"}]},
            )
            write_json(
                second,
                {"surfaces": [{"method": "GET", "url": "/api/current"}]},
            )
            event = root / "event.json"
            write_json(
                event,
                {
                    "type": "surface-discovered",
                    "surface": {
                        "method": "GET",
                        "url": "/api/runtime-event",
                        "runtime_observed": True,
                    },
                },
            )
            web_assessment.compile_workspace(
                workspace,
                [("manual", first)],
            )
            web_assessment.append_event(
                workspace,
                json.loads(event.read_text(encoding="utf-8")),
            )
            web_assessment.compile_workspace(
                workspace,
                [("manual", second)],
                replace_inputs=True,
            )
            coverage = json.loads(
                (workspace / "coverage.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                [{"kind": "manual", "path": str(second.resolve())}],
                coverage["input_sources"],
            )
            inventory = json.loads(
                (workspace / "surface-inventory.json").read_text(
                    encoding="utf-8"
                )
            )
            paths = {
                surface["path_template"]
                for surface in inventory["surfaces"]
            }
            self.assertEqual({"/api/current", "/api/runtime-event"}, paths)

    def test_nested_routes_cluster_by_function_not_entire_subapplication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "routes.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "kind": "route",
                            "method": "NAVIGATE",
                            "url": "/inferencePlatform/modelManager",
                        },
                        {
                            "kind": "route",
                            "method": "NAVIGATE",
                            "url": "/inferencePlatform/resourceMonitor",
                        },
                        {
                            "kind": "route",
                            "method": "NAVIGATE",
                            "url": "/dev/home/myNotebook",
                        },
                        {
                            "kind": "route",
                            "method": "NAVIGATE",
                            "url": "/dev/home/myModels",
                        },
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            route_units = {
                unit["controller"]: unit
                for unit in plan["work_units"]
                if unit["kind"] == "route"
            }
            self.assertIn("inferencePlatform/modelManager", route_units)
            self.assertIn("inferencePlatform/resourceMonitor", route_units)
            self.assertIn("dev/home", route_units)
            self.assertEqual(2, route_units["dev/home"]["surface_count"])

    def test_three_hundred_fifty_routes_create_exhaustive_navigation_cases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "routes-350.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "kind": "route",
                            "method": "NAVIGATE",
                            "url": (
                                f"/module-{index}/create"
                                if index % 50 == 0
                                else f"/module-{index}/page"
                            ),
                        }
                        for index in range(350)
                    ]
                },
            )
            result = web_assessment.compile_workspace(
                workspace, [("manual", source)]
            )
            route_inventory = json.loads(
                (workspace / "route-inventory.json").read_text(encoding="utf-8")
            )
            plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            coverage = json.loads(
                (workspace / "coverage.json").read_text(encoding="utf-8")
            )
            route_cases = [
                item
                for item in plan["executable_cases"]
                if item["case_kind"] == "route-navigation"
            ]
            self.assertEqual(350, route_inventory["summary"]["discovered"])
            self.assertEqual(350, len(route_cases))
            self.assertEqual(0, route_inventory["summary"]["current_validated"])
            self.assertFalse(
                coverage["stop_gates"]["route_inventory_current_validated"]
            )
            self.assertEqual("interim", result["assessment_state"])
            next_case = web_assessment.next_cell(workspace)
            self.assertEqual("route-navigation", next_case["case_kind"])

    def test_seven_hundred_historical_routes_cannot_count_as_current_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "historical-routes.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "kind": "route",
                            "method": "NAVIGATE",
                            "url": f"/historical/module-{index}",
                        }
                        for index in range(700)
                    ]
                },
            )
            web_assessment.compile_workspace(
                workspace, [("history", source)]
            )
            route_inventory = json.loads(
                (workspace / "route-inventory.json").read_text(encoding="utf-8")
            )
            plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            route_cases = [
                item
                for item in plan["executable_cases"]
                if item["case_kind"] == "route-navigation"
            ]
            self.assertEqual(700, len(route_cases))
            self.assertEqual(0, route_inventory["summary"]["current_validated"])
            self.assertTrue(all(item["status"] == "queued" for item in route_cases))

    def test_runtime_route_result_updates_route_stages_without_hiding_tests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "route.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "kind": "route",
                            "method": "NAVIGATE",
                            "url": "/orders/create",
                        }
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            route_inventory = json.loads(
                (workspace / "route-inventory.json").read_text(encoding="utf-8")
            )
            plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            case = next(
                item
                for item in plan["executable_cases"]
                if item["case_kind"] == "route-navigation"
            )
            route = route_inventory["routes"][0]
            web_assessment.append_event(
                workspace,
                {
                    "type": "route-result",
                    "route_id": route["id"],
                    "test_case_id": case["id"],
                    "status": "tested",
                    "evidence_refs": ["route-render.json"],
                    "stages": {
                        "current-validated": "completed",
                        "navigated": "completed",
                        "rendered": "completed",
                        "controls-extracted": "completed",
                        "runtime-api-linked": "completed",
                    },
                },
            )
            web_assessment.compile_workspace(workspace)
            updated = json.loads(
                (workspace / "route-inventory.json").read_text(encoding="utf-8")
            )
            updated_plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            updated_case = next(
                item
                for item in updated_plan["executable_cases"]
                if item["case_kind"] == "route-navigation"
            )
            self.assertEqual("tested", updated_case["status"])
            self.assertEqual(1, updated["summary"]["rendered"])
            self.assertEqual("pending", updated["routes"][0]["stages"]["tests-resolved"]["state"])

    def test_dynamic_route_template_uses_observed_route_without_persisting_value(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "dynamic-route.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "kind": "route",
                            "method": "NAVIGATE",
                            "url": "/orders/:orderId",
                            "route_parameter_names": ["orderId"],
                            "route_parameter_state": "unresolved",
                        },
                        {
                            "kind": "route",
                            "method": "NAVIGATE",
                            "url": "/orders/current-self-object",
                            "validation_state": "runtime-visited",
                            "runtime_observed": True,
                            "route_validation": {
                                "state": "runtime-visited",
                                "reason": "browser-navigation-and-render-confirmed",
                                "evidence": {"render": {"state": "rendered"}},
                            },
                            "route_control_refs": [],
                            "route_runtime_api_refs": [],
                        },
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            route_inventory = json.loads(
                (workspace / "route-inventory.json").read_text(encoding="utf-8")
            )
            self.assertEqual(1, len(route_inventory["routes"]))
            route = route_inventory["routes"][0]
            self.assertEqual("/orders/:orderId", route["path_template"])
            self.assertEqual("observed", route["parameter_state"])
            self.assertFalse(route["parameter_sources"][0]["value_persisted"])
            self.assertNotIn("current-self-object", json.dumps(route["parameter_sources"]))
            self.assertEqual(1, route_inventory["summary"]["rendered"])

    def test_authenticated_route_capture_still_queues_anonymous_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            web_assessment.append_event(
                workspace,
                {
                    "type": "identity",
                    "id": "member-low-privilege",
                    "status": "observed",
                    "evidence_refs": ["session-shape.json"],
                },
            )
            source = root / "runtime-route.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "kind": "route",
                            "method": "NAVIGATE",
                            "url": "/member/profile",
                            "validation_state": "runtime-visited",
                            "runtime_observed": True,
                            "route_validation": {
                                "state": "runtime-visited",
                                "reason": "browser-navigation-and-render-confirmed",
                                "evidence": {"render": {"state": "rendered"}},
                            },
                            "route_control_refs": [],
                            "route_runtime_api_refs": [],
                        }
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            route_cases = [
                item
                for item in plan["executable_cases"]
                if item["case_kind"] == "route-navigation"
            ]
            by_identity = {item["identity"]: item for item in route_cases}
            self.assertEqual("tested", by_identity["member-low-privilege"]["status"])
            self.assertEqual("queued", by_identity["anonymous"]["status"])

    def test_runtime_route_links_controls_and_apis(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "linked-route.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "kind": "route",
                            "method": "NAVIGATE",
                            "url": "/orders",
                            "validation_state": "runtime-visited",
                            "runtime_observed": True,
                            "route_validation": {
                                "state": "runtime-visited",
                                "reason": "browser-navigation-and-render-confirmed",
                                "evidence": {"render": {"state": "rendered"}},
                            },
                            "route_control_refs": ["ui:orders-search"],
                            "route_runtime_api_refs": [
                                "https://app.example.test/api/orders?page=:value"
                            ],
                        },
                        {
                            "kind": "api",
                            "method": "GET",
                            "url": "/api/orders",
                            "validation_state": "runtime-observed",
                            "runtime_observed": True,
                        },
                        {
                            "kind": "feature",
                            "method": "OBSERVE",
                            "url": "/orders",
                            "semantic_key": "ui:orders-search",
                            "feature_type": "runtime-ui-control",
                            "control": {
                                "visible": True,
                                "disabled": False,
                                "exerciseState": "exercised",
                            },
                            "control_exercise_state": "exercised",
                        },
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            route_inventory = json.loads(
                (workspace / "route-inventory.json").read_text(encoding="utf-8")
            )
            relations = {item["relation"] for item in route_inventory["surface_links"]}
            self.assertEqual({"runtime-api", "visible-control"}, relations)

    def test_scope_dispositions_keep_related_third_parties_passive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root, "https://portal.example.com/")
            source = root / "scope.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {"method": "GET", "url": "https://portal.example.com/api/me"},
                        {
                            "method": "GET",
                            "url": "https://api.example.com/v1/me",
                            "runtime_observed": True,
                        },
                        {"method": "GET", "url": "https://old.example.com/admin"},
                        {"method": "GET", "url": "https://cdn.vendor.net/script"},
                    ]
                },
            )
            self.run_cli(
                "compile",
                "--workspace",
                str(workspace),
                "--input",
                f"manual={source}",
            )
            inventory = json.loads(
                (workspace / "surface-inventory.json").read_text(encoding="utf-8")
            )
            dispositions = {
                item["url"]: item["scope_disposition"]
                for item in inventory["surfaces"]
            }
            self.assertEqual(
                "target-origin-active",
                dispositions["https://portal.example.com/api/me"],
            )
            self.assertEqual(
                "same-site-runtime-safe-read",
                dispositions["https://api.example.com/v1/me"],
            )
            self.assertEqual(
                "same-site-related-passive",
                dispositions["https://old.example.com/admin"],
            )
            self.assertEqual(
                "cross-site-related-passive",
                dispositions["https://cdn.vendor.net/script"],
            )

    def test_schema_v2_migration_preserves_legacy_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "assessment"
            workspace.mkdir()
            legacy = {
                "schema_version": 2,
                "mode": "comprehensive",
                "assessment_state": "interim",
                "history": {"lookup_state": "completed-with-matches"},
                "passes": [
                    {
                        "id": "active-hypotheses",
                        "status": "completed",
                        "evidence": ["old-proof"],
                    }
                ],
                "inventory": {"apis": [{"path": "/legacy"}]},
                "coverage": [],
                "candidates": [{"id": "candidate-old"}],
                "findings": [],
                "stop_gates": {"old_gate": True},
            }
            write_json(workspace / "coverage.json", legacy)
            self.run_cli(
                "migrate",
                "--workspace",
                str(workspace),
                "--target",
                "https://legacy.example.test/",
            )
            coverage = json.loads(
                (workspace / "coverage.json").read_text(encoding="utf-8")
            )
            self.assertEqual(8, coverage["schema_version"])
            self.assertEqual(
                legacy,
                coverage["migration"]["legacy_source"],
            )
            self.assertEqual("candidate-old", coverage["candidates"][0]["id"])

    def test_existing_v3_workspace_adds_new_families_without_losing_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            coverage_path = workspace / "coverage.json"
            coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
            coverage["candidates"] = [{"id": "preserve-me"}]
            for domain in coverage["coverage"]:
                domain["families"] = [
                    family
                    for family in domain["families"]
                    if family["id"]
                    != "platform-exposure.client-bootstrap-config"
                ]
            coverage.pop("planner_template_sha256", None)
            write_json(coverage_path, coverage)
            web_assessment.compile_workspace(workspace)
            reconciled = json.loads(coverage_path.read_text(encoding="utf-8"))
            families = {
                family["id"]
                for domain in reconciled["coverage"]
                for family in domain["families"]
            }
            self.assertIn(
                "platform-exposure.client-bootstrap-config",
                families,
            )
            self.assertEqual(
                [{"id": "preserve-me"}],
                reconciled["candidates"],
            )
            self.assertTrue(reconciled["planner_template_sha256"])
            self.assertIn(
                "platform-exposure.client-bootstrap-config",
                reconciled["schema_revisions"][-1]["added_families"],
            )

    def test_schema_v3_migrates_to_v5_with_route_and_runner_gates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            coverage_path = workspace / "coverage.json"
            coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
            coverage["schema_version"] = 3
            coverage.pop("route_coverage", None)
            coverage.pop("surface_execution_summary", None)
            for gate in (
                "route_inventory_current_validated",
                "route_navigation_and_render_complete",
                "visible_controls_resolved",
                "runtime_api_links_accounted",
                "route_tests_resolved",
                "discovery_queue_exhausted",
            ):
                coverage["stop_gates"].pop(gate, None)
            coverage["candidates"] = [{"id": "preserved-v3"}]
            write_json(coverage_path, coverage)
            migrated = web_assessment.ensure_workspace(workspace)
            self.assertEqual(8, migrated["schema_version"])
            self.assertEqual([{"id": "preserved-v3"}], migrated["candidates"])
            self.assertIn("route_coverage", migrated)
            self.assertFalse(
                migrated["stop_gates"]["route_inventory_current_validated"]
            )
            self.assertEqual(3, migrated["migration_history"][-1]["from_schema_version"])

    def test_schema_v4_migrates_to_v5_with_execution_gates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = self.initialize(Path(temporary))
            coverage_path = workspace / "coverage.json"
            coverage = json.loads(coverage_path.read_text(encoding="utf-8"))
            coverage["schema_version"] = 4
            coverage.pop("execution_coverage", None)
            for gate in (
                "auto_safe_queue_exhausted",
                "variant_matrix_resolved",
                "agent_review_queue_resolved",
                "credential_requirements_accounted",
                "independent_execution_audit_passed",
            ):
                coverage["stop_gates"].pop(gate, None)
            coverage["candidates"] = [{"id": "preserved-v4"}]
            write_json(coverage_path, coverage)
            migrated = web_assessment.ensure_workspace(workspace)
            self.assertEqual(8, migrated["schema_version"])
            self.assertEqual([{"id": "preserved-v4"}], migrated["candidates"])
            self.assertIn("execution_coverage", migrated)
            self.assertFalse(migrated["stop_gates"]["auto_safe_queue_exhausted"])
            self.assertEqual(4, migrated["migration_history"][-1]["from_schema_version"])

    def test_unknown_business_value_uses_middle_score_and_safety_is_separate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "write.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "method": "POST",
                            "url": "https://app.example.test/api/profile/update",
                            "validation_state": "unverified",
                        }
                    ]
                },
            )
            self.run_cli(
                "compile",
                "--workspace",
                str(workspace),
                "--input",
                f"manual={source}",
            )
            plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            unit = next(unit for unit in plan["work_units"] if unit["kind"] == "api")
            self.assertEqual(2, unit["risk"]["factors"]["business_impact"])
            self.assertGreaterEqual(unit["risk"]["score"], 6)
            self.assertEqual("blocked", unit["safety"]["class"])
            self.assertFalse(unit["safety"]["auto_actionable"])

    def test_semantic_read_post_requires_runtime_or_documented_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "post-reads.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "method": "POST",
                            "url": "/api/orders/search",
                            "validation_state": "runtime-observed",
                            "runtime_observed": True,
                            "fields": ["customerId"],
                        },
                        {
                            "method": "POST",
                            "url": "/api/clinical-records/list",
                            "validation_state": "documented",
                            "fields": ["patientId"],
                        },
                        {
                            "method": "POST",
                            "url": "/api/audit-events/query",
                            "validation_state": "recognized",
                            "fields": ["actorId"],
                        },
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            units = {
                (unit["controller"], unit["lifecycle"]): unit
                for unit in plan["work_units"]
                if unit["kind"] == "api"
            }
            self.assertEqual(
                "read-only",
                units[("orders/search", "read-list")]["safety"]["class"],
            )
            self.assertEqual(
                "evidence-backed-semantic-read-post",
                units[("orders/search", "read-list")]["safety"]["reason"],
            )
            self.assertNotIn(
                "business-logic.race-concurrency",
                units[("orders/search", "read-list")]["applicable_families"],
            )
            self.assertEqual(
                "read-only",
                units[("clinical-records/list", "read-list")]["safety"]["class"],
            )
            self.assertEqual(
                "blocked",
                units[("audit-events/query", "read-list")]["safety"]["class"],
            )

    def test_evidence_driven_families_cover_blind_gap_patterns(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "profiles.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {"method": "GET", "url": "/runtime-config.js"},
                        {
                            "method": "POST",
                            "url": "/auth/login",
                            "fields": ["account", "password"],
                        },
                        {
                            "method": "POST",
                            "url": "/auth/token",
                            "fields": ["refreshToken"],
                        },
                        {
                            "method": "POST",
                            "url": "/gateway/order-items/update",
                            "fields": ["orderId"],
                        },
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            by_controller = {
                unit["controller"]: set(unit["applicable_families"])
                for unit in plan["work_units"]
                if unit["kind"] == "api"
            }
            self.assertIn(
                "platform-exposure.client-bootstrap-config",
                by_controller["runtime-config.js"],
            )
            self.assertIn(
                "identity-session.response-differential",
                by_controller["auth/login"],
            )
            self.assertIn(
                "identity-session.token-claim-minimization",
                by_controller["auth/token"],
            )
            self.assertIn(
                "api-protocol.edge-backend-normalization",
                by_controller["gateway/order-items"],
            )

    def test_cross_function_links_require_shared_business_semantics(self) -> None:
        for domain, surfaces, expected_semantic in (
            (
                "commerce",
                [
                    {
                        "method": "POST",
                        "url": "/api/catalog/assets/upload",
                        "fields": ["assetKey"],
                    },
                    {
                        "method": "POST",
                        "url": "/api/catalog/products/publish",
                        "fields": ["assetKey"],
                    },
                ],
                "asset",
            ),
            (
                "healthcare",
                [
                    {
                        "method": "POST",
                        "url": "/api/records/documents/import",
                        "fields": ["documentPath"],
                    },
                    {
                        "method": "POST",
                        "url": "/api/records/review/approve",
                        "fields": ["documentPath"],
                    },
                ],
                "document",
            ),
        ):
            with self.subTest(domain=domain), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                workspace = self.initialize(root)
                source = root / f"{domain}.json"
                write_json(
                    source,
                    {
                        "surfaces": [
                            *surfaces,
                            {
                                "method": "POST",
                                "url": "/api/unrelated/delete",
                                "fields": ["id"],
                            },
                        ]
                    },
                )
                web_assessment.compile_workspace(workspace, [("manual", source)])
                plan = json.loads(
                    (workspace / "test-plan.json").read_text(encoding="utf-8")
                )
                linked = [
                    unit
                    for unit in plan["work_units"]
                    if unit.get("chain_links")
                    and expected_semantic
                    in {
                        semantic
                        for link in unit["chain_links"]
                        for semantic in link["shared_semantics"]
                    }
                ]
                self.assertEqual(2, len(linked))
                self.assertTrue(
                    all(
                        "business-logic.cross-function-chain"
                        in unit["applicable_families"]
                        for unit in linked
                    )
                )
                unrelated = next(
                    unit
                    for unit in plan["work_units"]
                    if unit.get("controller") == "unrelated/delete"
                )
                self.assertEqual([], unrelated["chain_links"])

    def test_generic_api_does_not_receive_every_specialized_family(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "status.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "method": "GET",
                            "url": "/api/status",
                            "validation_state": "runtime-observed",
                            "runtime_observed": True,
                        }
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            unit = next(
                unit for unit in plan["work_units"] if unit["kind"] == "api"
            )
            families = set(unit["applicable_families"])
            self.assertIn("authorization.function-level", families)
            self.assertNotIn("authorization.tenant-parent-state", families)
            self.assertNotIn("business-logic.cross-function-chain", families)
            self.assertNotIn("injection.sql-nosql-orm", families)

    def test_resolving_high_priorities_does_not_hide_p2_debt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "surface.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "method": "GET",
                            "url": "https://app.example.test/api/token/details",
                            "validation_state": "runtime-observed",
                            "runtime_observed": True,
                        }
                    ]
                },
            )
            web_assessment.compile_workspace(
                workspace, [("manual", source)]
            )
            web_assessment.append_event(
                workspace,
                {
                    "type": "evidence",
                    "path": "proof.json",
                    "kind": "request-response",
                },
            )
            plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            for cell in plan["test_cells"]:
                if (
                    cell["priority"] in {"P0", "P1"}
                    and cell["status"] != "blocked"
                    and not cell.get("dimensions", {}).get("authorization_mode")
                ):
                    web_assessment.append_event(
                        workspace,
                        {
                            "type": "test-result",
                            "test_cell_id": cell["id"],
                            "status": "tested",
                            "evidence_refs": ["proof.json"],
                        },
                    )
            result = web_assessment.compile_workspace(workspace)
            self.assertEqual("interim", result["assessment_state"])
            self.assertGreater(result["by_priority"]["P2"], 0)

    def test_not_applicable_requires_reason_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "surface.json"
            write_json(
                source,
                {"surfaces": [{"method": "GET", "url": "/api/status"}]},
            )
            web_assessment.compile_workspace(
                workspace, [("manual", source)]
            )
            cell = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )["test_cells"][0]
            with self.assertRaisesRegex(ValueError, "requires evidence_refs"):
                web_assessment.append_event(
                    workspace,
                    {
                        "type": "test-result",
                        "test_cell_id": cell["id"],
                        "status": "not-applicable",
                        "reason": "no parser",
                    },
                )

    def test_negative_result_is_invalidated_when_surface_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "surface.json"
            write_json(
                source,
                {"surfaces": [{"method": "GET", "url": "/api/items"}]},
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            cell = next(
                item
                for item in plan["test_cells"]
                if item["work_unit_id"]
                != next(
                    unit["id"]
                    for unit in plan["work_units"]
                    if unit["kind"] == "application-baseline"
                )
            )
            web_assessment.append_event(
                workspace,
                {
                    "type": "evidence",
                    "path": "negative.json",
                    "kind": "negative-control",
                },
            )
            web_assessment.append_event(
                workspace,
                {
                    "type": "test-result",
                    "test_cell_id": cell["id"],
                    "status": "tested",
                    "evidence_refs": ["negative.json"],
                    "negative_result": True,
                },
            )
            web_assessment.compile_workspace(workspace)
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "method": "GET",
                            "url": "/api/items",
                            "fields": ["newField"],
                        }
                    ]
                },
            )
            web_assessment.compile_workspace(workspace)
            changed = {
                item["id"]: item
                for item in json.loads(
                    (workspace / "test-plan.json").read_text(encoding="utf-8")
                )["test_cells"]
            }[cell["id"]]
            self.assertEqual("waiting-prerequisite", changed["status"])
            self.assertIn("prerequisite", changed["reason"])

    def test_blocked_cells_cannot_be_used_to_derive_complete_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "surface.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "method": "GET",
                            "url": "/api/status",
                            "validation_state": "runtime-observed",
                            "runtime_observed": True,
                        }
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            for mode in sorted(web_assessment.AUTHORIZATION_MODES):
                if mode == "cross-principal-ownership":
                    continue
                web_assessment.append_event(
                    workspace,
                    {
                        "type": "authorization-capability",
                        "id": mode,
                        "status": "unavailable",
                        "reason": "fixture does not exercise authorization",
                    },
                )
            web_assessment.append_event(
                workspace,
                {
                    "type": "history-lookup",
                    "status": "completed-no-match",
                    "target_keys": ["app.example.test"],
                },
            )
            for phase in json.loads(
                (workspace / "coverage.json").read_text(encoding="utf-8")
            )["phases"]:
                web_assessment.append_event(
                    workspace,
                    {
                        "type": "phase",
                        "phase_id": phase["id"],
                        "status": "completed",
                        "evidence_refs": ["proof.json"],
                    },
                )
            web_assessment.append_event(
                workspace,
                {
                    "type": "evidence",
                    "path": "proof.json",
                    "kind": "request-response",
                },
            )
            web_assessment.compile_workspace(workspace)
            plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            result = web_assessment.compile_workspace(workspace)
            self.assertEqual("interim", result["assessment_state"])
            self.run_cli(
                "check",
                "--workspace",
                str(workspace),
                expected=2,
            )

    def test_external_candidate_does_not_become_a_confirmed_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "surface.json"
            write_json(
                source,
                {"surfaces": [{"method": "GET", "url": "/api/status"}]},
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            web_assessment.append_event(
                workspace,
                {
                    "type": "candidate",
                    "id": "scanner-1",
                    "title": "scanner claim",
                    "source": "external-agent",
                },
            )
            result = web_assessment.compile_workspace(workspace)
            coverage = json.loads(
                (workspace / "coverage.json").read_text(encoding="utf-8")
            )
            self.assertEqual([], coverage["findings"])
            self.assertEqual("candidate", coverage["candidates"][0]["validation_state"])
            self.assertIn("high_risk_candidates_resolved", result["blockers"])

    def test_deferred_compound_candidate_keeps_prerequisite_gate_open(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "commerce.json"
            write_json(
                source,
                {"surfaces": [{"method": "GET", "url": "/api/orders/current"}]},
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            web_assessment.append_event(
                workspace,
                {
                    "type": "candidate",
                    "id": "commerce-compound",
                    "title": "cross-context policy signal",
                    "validation_dependencies": [
                        {
                            "id": "protected-consumer",
                            "kind": "impact",
                            "status": "pending",
                            "reason": "a protected concrete consumer has not been identified",
                        }
                    ],
                },
            )
            web_assessment.append_event(
                workspace,
                {
                    "type": "candidate-disposition",
                    "id": "commerce-compound",
                    "disposition": "deferred-with-reason",
                    "reason": "continue discovery later",
                },
            )
            result = web_assessment.compile_workspace(workspace)
            coverage = json.loads((workspace / "coverage.json").read_text())
            self.assertEqual("interim", result["assessment_state"])
            self.assertFalse(
                coverage["stop_gates"]["candidate_prerequisites_resolved"]
            )
            self.assertFalse(
                coverage["stop_gates"]["high_risk_candidates_resolved"]
            )
            self.assertEqual(
                ["commerce-compound:protected-consumer"],
                coverage["candidate_prerequisite_gaps"],
            )

    def test_evidence_backed_exhaustion_can_reject_compound_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "healthcare.json"
            write_json(
                source,
                {"surfaces": [{"method": "GET", "url": "/api/appointments/current"}]},
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            web_assessment.append_event(
                workspace,
                {
                    "type": "candidate",
                    "id": "healthcare-compound",
                    "title": "cross-context policy signal",
                    "validation_dependencies": [
                        {
                            "id": "protected-consumer",
                            "kind": "impact",
                            "status": "pending",
                            "reason": "protected consumer search is incomplete",
                        }
                    ],
                },
            )
            web_assessment.append_event(
                workspace,
                {
                    "type": "candidate-dependency",
                    "id": "healthcare-compound",
                    "dependency_id": "protected-consumer",
                    "status": "exhausted-with-evidence",
                    "reason": "all current appointment read surfaces were checked",
                    "evidence_refs": ["appointment-surface-ledger"],
                },
            )
            web_assessment.append_event(
                workspace,
                {
                    "type": "candidate-disposition",
                    "id": "healthcare-compound",
                    "disposition": "rejected",
                    "reason": "no protected consumer exists in the current observable surface",
                },
            )
            web_assessment.compile_workspace(workspace)
            coverage = json.loads((workspace / "coverage.json").read_text())
            self.assertTrue(
                coverage["stop_gates"]["candidate_prerequisites_resolved"]
            )
            self.assertTrue(
                coverage["stop_gates"]["high_risk_candidates_resolved"]
            )
            self.assertEqual([], coverage["candidate_prerequisite_gaps"])

    def test_confirmed_finding_with_pending_prerequisite_stays_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "project.json"
            write_json(
                source,
                {"surfaces": [{"method": "GET", "url": "/api/projects/current"}]},
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            web_assessment.append_event(
                workspace,
                {
                    "type": "finding",
                    "id": "project-compound",
                    "title": "unproven compound impact",
                    "validation_state": "confirmed",
                    "evidence_refs": ["policy-signal"],
                    "validation_dependencies": [
                        {
                            "id": "consumer-impact",
                            "kind": "impact",
                            "status": "pending",
                            "reason": "consumer impact has not been reproduced",
                        }
                    ],
                },
            )
            web_assessment.compile_workspace(workspace)
            coverage = json.loads((workspace / "coverage.json").read_text())
            self.assertEqual([], coverage["findings"])
            self.assertEqual("project-compound", coverage["candidates"][0]["id"])
            self.assertIn("confirmation_blocker", coverage["candidates"][0])

    def test_terminal_candidate_dependency_requires_evidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "requires evidence_refs"):
            web_assessment.validate_event_shape(
                {
                    "type": "candidate-dependency",
                    "id": "candidate-1",
                    "dependency_id": "impact",
                    "status": "satisfied",
                }
            )

    def test_reversible_test_without_cleanup_blocks_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "surface.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "method": "POST",
                            "url": "/api/drafts",
                            "safety": "reversible",
                        }
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            web_assessment.append_event(
                workspace,
                {
                    "type": "evidence",
                    "path": "write-proof.json",
                    "kind": "request-response",
                },
            )
            plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            cell = next(
                item
                for item in plan["test_cells"]
                if item["safety"] == "reversible"
            )
            web_assessment.append_event(
                workspace,
                {
                    "type": "test-result",
                    "test_cell_id": cell["id"],
                    "status": "tested",
                    "evidence_refs": ["write-proof.json"],
                },
            )
            web_assessment.compile_workspace(workspace)
            coverage = json.loads(
                (workspace / "coverage.json").read_text(encoding="utf-8")
            )
            self.assertFalse(
                coverage["stop_gates"]["cleanup_complete_or_documented"]
            )

    def test_graphql_openapi_and_har_adapters_enable_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            openapi = root / "openapi.json"
            graphql = root / "graphql.json"
            har = root / "traffic.har"
            write_json(
                openapi,
                {
                    "openapi": "3.0.0",
                    "paths": {
                        "/files/upload": {
                            "post": {
                                "operationId": "uploadFile",
                                "parameters": [{"name": "tenantId"}],
                            }
                        }
                    },
                },
            )
            write_json(
                graphql,
                {
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "mutationType": {"name": "Mutation"},
                            "types": [
                                {
                                    "name": "Query",
                                    "fields": [{"name": "viewer", "args": []}],
                                },
                                {
                                    "name": "Mutation",
                                    "fields": [
                                        {
                                            "name": "updateProfile",
                                            "args": [{"name": "input"}],
                                        }
                                    ],
                                },
                            ],
                        }
                    }
                },
            )
            write_json(
                har,
                {
                    "log": {
                        "entries": [
                            {
                                "request": {
                                    "method": "GET",
                                    "url": "https://api.example.test/events",
                                    "queryString": [],
                                },
                                "response": {
                                    "status": 200,
                                    "content": {"mimeType": "text/event-stream"},
                                },
                            }
                        ]
                    }
                },
            )
            self.run_cli(
                "compile",
                "--workspace",
                str(workspace),
                "--input",
                f"openapi={openapi}",
                "--input",
                f"graphql={graphql}",
                "--input",
                f"har={har}",
            )
            inventory = json.loads(
                (workspace / "surface-inventory.json").read_text(encoding="utf-8")
            )
            self.assertIn("openapi", inventory["profiles"])
            self.assertIn("graphql", inventory["profiles"])
            self.assertIn("file-processing", inventory["profiles"])
            self.assertIn("websocket-sse", inventory["profiles"])

    def test_single_account_keeps_non_cross_principal_authorization_executable(
        self,
    ) -> None:
        fixtures = (
            (
                "commerce",
                "/api/orders/detail",
                ["orderId", "ownerId", "tenantId"],
            ),
            (
                "healthcare",
                "/api/appointments/detail",
                ["appointmentId", "creatorId", "orgId"],
            ),
        )
        for domain, path, fields in fixtures:
            with self.subTest(domain=domain), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                workspace = self.initialize(root)
                source = root / f"{domain}.json"
                write_json(
                    source,
                    {
                        "surfaces": [
                            {
                                "method": "GET",
                                "url": path,
                                "fields": fields,
                                "validation_state": "runtime-observed",
                                "runtime_observed": True,
                            }
                        ]
                    },
                )
                web_assessment.compile_workspace(workspace, [("manual", source)])
                web_assessment.append_event(
                    workspace,
                    {
                        "type": "identity",
                        "id": "low-privilege",
                        "status": "observed",
                        "evidence_refs": ["session-shape"],
                    },
                )
                for mode in (
                    "self-owned-object",
                    "protected-property",
                    "tenant-parent-binding",
                ):
                    web_assessment.append_event(
                        workspace,
                        {
                            "type": "authorization-capability",
                            "id": mode,
                            "status": "available",
                            "evidence_refs": ["runtime-shape"],
                        },
                    )
                web_assessment.compile_workspace(workspace)
                coverage = json.loads(
                    (workspace / "coverage.json").read_text(encoding="utf-8")
                )
                plan = json.loads(
                    (workspace / "test-plan.json").read_text(encoding="utf-8")
                )
                capabilities = {
                    item["id"]: item["status"]
                    for item in coverage["dimensions"][
                        "authorization_capabilities"
                    ]
                }
                self.assertEqual(
                    "unavailable",
                    capabilities["cross-principal-ownership"],
                )
                self.assertEqual("available", capabilities["anonymous-boundary"])
                self.assertEqual(
                    "available",
                    capabilities["low-privilege-function"],
                )
                cases = {
                    case["authorization_mode"]
                    for case in plan["executable_cases"]
                }
                self.assertIn("anonymous-boundary", cases)
                self.assertIn("low-privilege-function", cases)
                self.assertIn("self-owned-object", cases)
                self.assertIn("tenant-parent-binding", cases)
                cross_cells = [
                    cell
                    for cell in plan["test_cells"]
                    if cell.get("dimensions", {}).get("authorization_mode")
                    == "cross-principal-ownership"
                ]
                self.assertTrue(cross_cells)
                self.assertTrue(
                    all(
                        cell["status"] in {"waiting-prerequisite", "blocked"}
                        for cell in cross_cells
                    )
                )
                graph = json.loads(
                    (workspace / "prerequisite-graph.json").read_text(
                        encoding="utf-8"
                    )
                )
                self.assertTrue(
                    any(
                        item["kind"] == "second-principal"
                        and item["status"] == "blocked-external"
                        for item in graph["prerequisites"]
                    )
                )

    def test_request_shapes_separate_documented_post_reads_from_static_debt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "post-shapes.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "method": "POST",
                            "url": "/api/catalog/search",
                            "validation_state": "documented",
                            "fields": ["ownerId"],
                        },
                        {
                            "method": "POST",
                            "url": "/api/catalog/query",
                            "validation_state": "recognized",
                            "fields": ["ownerId"],
                        },
                        {
                            "method": "GET",
                            "url": "/api/catalog/delete",
                            "validation_state": "runtime-observed",
                            "runtime_observed": True,
                        },
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            shapes = {
                shape["path"]: shape for shape in plan["request_shapes"]
            }
            self.assertEqual("read-only", shapes["/api/catalog/search"]["safety"])
            self.assertNotIn("/api/catalog/query", shapes)
            self.assertNotIn("/api/catalog/delete", shapes)

    def test_complex_family_case_emits_a_machine_readable_agent_action(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "surface.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "method": "GET",
                            "url": "/api/items",
                            "validation_state": "runtime-observed",
                            "runtime_observed": True,
                        }
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            case = next(
                item
                for item in plan["executable_cases"]
                if item.get("automation_state") == "needs-agent"
            )
            self.assertEqual(
                "perform-specialized-validation",
                case["agent_action"]["action"],
            )
            self.assertIn("normal-baseline", case["agent_action"]["required_evidence"])
            self.assertIn("family", case["agent_action"])

    def test_authorization_result_rejects_nonexistent_only_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "objects.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "method": "GET",
                            "url": "/api/records/detail",
                            "fields": ["recordId", "ownerId"],
                            "validation_state": "runtime-observed",
                            "runtime_observed": True,
                        }
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            web_assessment.append_event(
                workspace,
                {
                    "type": "identity",
                    "id": "low-privilege",
                    "status": "observed",
                },
            )
            web_assessment.append_event(
                workspace,
                {
                    "type": "authorization-capability",
                    "id": "self-owned-object",
                    "status": "available",
                },
            )
            web_assessment.append_event(
                workspace,
                {
                    "type": "evidence",
                    "path": "nonexistent-control.json",
                    "kind": "request-response",
                },
            )
            web_assessment.compile_workspace(workspace)
            plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            case = next(
                item
                for item in plan["executable_cases"]
                if item["authorization_mode"] == "self-owned-object"
            )
            with self.assertRaisesRegex(
                ValueError,
                "authorization tested result requires",
            ):
                web_assessment.append_event(
                    workspace,
                    {
                        "type": "test-result",
                        "test_cell_id": case["test_cell_id"],
                        "test_case_id": case["id"],
                        "status": "tested",
                        "evidence_refs": ["nonexistent-control.json"],
                        "authorization_evidence": [
                            "nonexistent-object-only"
                        ],
                    },
                )

    def test_reversible_authorization_case_requires_cleanup_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "drafts.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "method": "POST",
                            "url": "/api/drafts/update",
                            "fields": ["draftId", "ownerId"],
                            "validation_state": "runtime-observed",
                            "runtime_observed": True,
                            "safety": "reversible",
                        }
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            inventory = json.loads(
                (workspace / "surface-inventory.json").read_text(encoding="utf-8")
            )
            surface = inventory["surfaces"][0]
            web_assessment.append_event(
                workspace,
                {
                    "type": "identity",
                    "id": "low-privilege",
                    "status": "observed",
                },
            )
            web_assessment.append_event(
                workspace,
                {
                    "type": "authorization-capability",
                    "id": "protected-property",
                    "status": "available",
                },
            )
            web_assessment.append_event(
                workspace,
                {
                    "type": "request-shape",
                    "surface_ref": surface["id"],
                    "method": "POST",
                    "path": "/api/drafts/update",
                    "source": "runtime",
                    "semantics": "write",
                    "body_fields": ["draftId", "ownerId"],
                    "safety": "reversible",
                    "cleanup_evidence_refs": ["cleanup-handler"],
                },
            )
            web_assessment.append_event(
                workspace,
                {
                    "type": "evidence",
                    "path": "property-control.json",
                    "kind": "request-response",
                },
            )
            web_assessment.compile_workspace(workspace)
            plan = json.loads(
                (workspace / "test-plan.json").read_text(encoding="utf-8")
            )
            case = next(
                item
                for item in plan["executable_cases"]
                if item["authorization_mode"] == "protected-property"
            )
            with self.assertRaisesRegex(
                ValueError,
                "requires completed cleanup",
            ):
                web_assessment.append_event(
                    workspace,
                    {
                        "type": "test-result",
                        "test_cell_id": case["test_cell_id"],
                        "test_case_id": case["id"],
                        "status": "tested",
                        "evidence_refs": ["property-control.json"],
                        "authorization_evidence": [
                            "protected-property-baseline"
                        ],
                    },
                )

    def test_next_prefers_a_concrete_authorization_case(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "management.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "method": "GET",
                            "url": "/api/management/settings",
                            "validation_state": "runtime-observed",
                            "runtime_observed": True,
                        }
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            web_assessment.append_event(
                workspace,
                {
                    "type": "identity",
                    "id": "low-privilege",
                    "status": "observed",
                },
            )
            next_item = web_assessment.next_cell(workspace)
            self.assertIsNotNone(next_item)
            assert next_item is not None
            self.assertIn("test_cell", next_item)
            self.assertIn("request_shape", next_item)
            self.assertIn(
                next_item["authorization_mode"],
                {"anonymous-boundary", "low-privilege-function"},
            )

    def test_request_shape_event_rejects_raw_credentials_and_body(self) -> None:
        for forbidden in (
            {"headers": {"Authorization": "redacted"}},
            {"body": {"ownerId": "redacted"}},
            {"credential_values_persisted": True},
        ):
            with self.subTest(forbidden=next(iter(forbidden))):
                with self.assertRaisesRegex(
                    ValueError,
                    "cannot persist",
                ):
                    web_assessment.validate_event_shape(
                        {
                            "type": "request-shape",
                            "surface_ref": "surface-example",
                            "method": "POST",
                            "path": "/api/example/query",
                            "source": "runtime",
                            "semantics": "read",
                            "safety": "read-only",
                            **forbidden,
                        }
                    )

    def test_weak_function_authorization_evidence_stays_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = self.initialize(root)
            source = root / "admin.json"
            write_json(
                source,
                {"surfaces": [{"method": "GET", "url": "/api/admin/list"}]},
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            web_assessment.append_event(
                workspace,
                {
                    "type": "finding",
                    "id": "weak-bfla",
                    "title": "hidden handler reachable",
                    "validation_state": "confirmed",
                    "authorization_mode": "low-privilege-function",
                    "authorization_evidence_quality": "request-handler-only",
                    "evidence_refs": ["handler-response"],
                },
            )
            web_assessment.compile_workspace(workspace)
            coverage = json.loads(
                (workspace / "coverage.json").read_text(encoding="utf-8")
            )
            self.assertEqual([], coverage["findings"])
            self.assertEqual("weak-bfla", coverage["candidates"][0]["id"])


if __name__ == "__main__":
    unittest.main()
