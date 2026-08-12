from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import agent  # noqa: E402
import web_assessment  # noqa: E402
import web_runner  # noqa: E402


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


class PrerequisiteClosureTest(unittest.TestCase):
    def test_schema_v3_through_v7_migrate_without_losing_findings(self) -> None:
        template = json.loads(web_assessment.TEMPLATE.read_text(encoding="utf-8"))
        for version in range(3, 8):
            with self.subTest(version=version):
                coverage = {
                    **template,
                    "schema_version": version,
                    "assessment_id": f"assessment-v{version}",
                    "findings": [{"id": f"finding-v{version}"}],
                }
                migrated = web_assessment.migrate_coverage(coverage)
                web_assessment.reconcile_template_schema(migrated)
                self.assertEqual(8, migrated["schema_version"])
                self.assertEqual(
                    f"finding-v{version}", migrated["findings"][0]["id"]
                )
                self.assertIn(
                    "test_prerequisites_resolved", migrated["stop_gates"]
                )

                plan = web_assessment.migrate_plan(
                    {
                        "schema_version": version,
                        "test_cells": [
                            {
                                "id": f"cell-v{version}",
                                "family": "authorization.object-level",
                            }
                        ],
                        "executable_cases": [
                            {
                                "id": f"case-v{version}",
                                "test_cell_id": f"cell-v{version}",
                                "automation_state": "needs-agent",
                            }
                        ],
                    }
                )
                self.assertEqual(8, plan["schema_version"])
                self.assertIn(
                    "search_strategies", plan["executable_cases"][0]
                )

    def test_schema_v7_migration_preserves_state_and_adds_case_contract(self) -> None:
        template = json.loads(web_assessment.TEMPLATE.read_text(encoding="utf-8"))
        legacy_coverage = {
            **template,
            "schema_version": 7,
            "assessment_id": "assessment-legacy",
            "findings": [{"id": "finding-preserved"}],
        }
        migrated_coverage = web_assessment.migrate_coverage(legacy_coverage)
        self.assertEqual(8, migrated_coverage["schema_version"])
        self.assertEqual("finding-preserved", migrated_coverage["findings"][0]["id"])
        self.assertIn("test_prerequisites_resolved", migrated_coverage["stop_gates"])

        migrated_plan = web_assessment.migrate_plan(
            {
                "schema_version": 7,
                "test_cells": [
                    {"id": "cell-legacy", "family": "authorization.object-level"}
                ],
                "executable_cases": [
                    {
                        "id": "case-legacy",
                        "test_cell_id": "cell-legacy",
                        "automation_state": "needs-agent",
                    }
                ],
            }
        )
        case = migrated_plan["executable_cases"][0]
        self.assertEqual(8, migrated_plan["schema_version"])
        for field in (
            "prerequisite_refs",
            "binding_slots",
            "search_strategies",
            "exhaustion_criteria",
            "blocker_class",
        ):
            self.assertIn(field, case)

    def test_registry_explicitly_accounts_for_every_coverage_family(self) -> None:
        template = json.loads(web_assessment.TEMPLATE.read_text(encoding="utf-8"))
        expected = {
            family["id"]
            for domain in template["coverage"]
            for family in domain["families"]
        }
        registry = web_assessment.prerequisite_registry()
        self.assertEqual(expected, set(registry["families"]))
        self.assertTrue(
            all(isinstance(registry["families"][family], list) for family in expected)
        )
        representative = {
            "identity-session.cross-origin-csrf": "state-changing-consumer",
            "platform-exposure.headers-cache-cors": "protected-response",
            "server-side-processing.ssrf-webhook-proxy": "owned-oast",
            "files-data-export.upload-validation": "upload-consumer",
            "browser-content.xss-dom-richtext": "browser-or-persistent-sink",
            "business-logic.race-concurrency": "safe-concurrency-context",
            "business-logic.approval-invite-share": "business-state",
            "api-protocol.graphql": "graphql-operation-shape",
        }
        for family, prerequisite in representative.items():
            self.assertIn(prerequisite, registry["families"][family])

    def test_consumer_waits_until_current_producer_binding_appears(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            coverage = {
                "assessment_id": "assessment-fixture",
                "dimensions": {
                    "identities": [
                        {"id": "current-authenticated", "status": "available"}
                    ],
                    "authorization_capabilities": [
                        {"id": "self-owned-object", "status": "available"}
                    ],
                },
                "runtime": {},
                "candidates": [],
            }
            shape = {
                "id": "shape-orders-detail",
                "body_fields": [],
                "cleanup_evidence_refs": [],
            }
            plan = {"request_shapes": [shape]}
            case = {
                "id": "case-orders-detail",
                "family": "authorization.object-level",
                "case_kind": "api-test",
                "authorization_mode": "self-owned-object",
                "request_shape_id": shape["id"],
                "surface_ref": "surface-orders-detail",
                "automation_state": "auto-ready",
                "status": "queued",
                "safety": "read-only",
                "evidence_refs": [],
            }
            first = web_assessment.build_prerequisite_graph(
                workspace, coverage, plan, [case]
            )
            self.assertEqual("waiting-prerequisite", case["status"])
            self.assertTrue(first["summary"]["pending"])

            write_json(
                workspace / "object-provenance.json",
                {
                    "slots": [
                        {
                            "id": "binding-random-slot",
                            "kind": "object",
                            "producer": {"url": "/api/orders", "field": "id"},
                            "consumer": {
                                "url": "/api/orders/{id}",
                                "field": "orderId",
                            },
                            "consumer_refs": ["surface-orders-detail"],
                            "route_refs": [],
                        }
                    ],
                    "raw_values_persisted": False,
                },
            )
            case["status"] = "waiting-prerequisite"
            second = web_assessment.build_prerequisite_graph(
                workspace, coverage, plan, [case]
            )
            self.assertEqual("queued", case["status"])
            self.assertEqual(0, second["summary"]["pending"])
            self.assertEqual(["binding-random-slot"], case["binding_slots"])

    def test_persistent_provenance_uses_random_slots_without_object_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "assessment"
            browser_output = Path(temporary) / "browser"
            (browser_output / "browser-assets").mkdir(parents=True)
            (browser_output / "analysis").mkdir(parents=True)
            write_json(
                browser_output / "browser-assets" / "browser-manifest.json",
                {
                    "dataFlows": [
                        {
                            "bindingSlotId": "binding-random",
                            "from": {
                                "method": "GET",
                                "url": "https://shop.example.test/api/orders/self-1234",
                                "field": "response.orderId",
                            },
                            "to": {
                                "method": "GET",
                                "url": "https://shop.example.test/api/order/detail?id=self-1234",
                                "field": "query.orderId",
                            },
                        }
                    ]
                },
            )
            write_json(
                browser_output / "analysis" / "surface-inventory.json",
                {
                    "surfaces": [
                        {
                            "id": "surface-consumer",
                            "method": "GET",
                            "path_template": "/api/order/detail",
                        }
                    ]
                },
            )
            web_runner.update_object_provenance(workspace, browser_output)
            material = (workspace / "object-provenance.json").read_text()
            value = json.loads(material)
            self.assertNotIn("self-1234", material)
            self.assertNotIn("url", material.casefold())
            self.assertFalse(value["raw_values_persisted"])
            self.assertEqual("binding-random", value["slots"][0]["id"])
            self.assertEqual(
                ["surface-consumer"], value["slots"][0]["consumer_refs"]
            )

    def test_current_request_ids_create_value_free_binding_slots(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            write_json(
                workspace / "surface-inventory.json",
                {
                    "surfaces": [
                        {
                            "id": "surface-order-detail",
                            "method": "GET",
                            "path_template": "/api/orders/{id}",
                        }
                    ]
                },
            )
            write_json(
                workspace / "object-provenance.json",
                {"slots": [], "raw_values_persisted": False},
            )
            request = web_runner.RawRequest(
                "GET",
                "https://shop.example.test/api/orders/1842?ownerId=current-user-7",
                {},
                None,
                "browser-runtime",
            )
            web_runner.update_request_binding_provenance(workspace, [request])
            material = (workspace / "object-provenance.json").read_text()
            provenance = json.loads(material)
            self.assertNotIn("1842", material)
            self.assertNotIn("current-user-7", material)
            self.assertFalse(provenance["raw_values_persisted"])
            self.assertEqual(
                {"object", "subject"},
                {item["kind"] for item in provenance["slots"]},
            )
            self.assertTrue(
                all(
                    item["consumer_refs"] == ["surface-order-detail"]
                    for item in provenance["slots"]
                )
            )

    def test_response_identifier_producer_does_not_invent_a_consumer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            browser_output = workspace / "browser"
            (browser_output / "browser-assets").mkdir(parents=True)
            (browser_output / "analysis").mkdir(parents=True)
            write_json(
                browser_output / "browser-assets" / "browser-manifest.json",
                {
                    "valueProducers": [
                        {
                            "bindingSlotId": "binding-list-id",
                            "method": "GET",
                            "url": "https://shop.example.test/api/orders",
                            "field": "response.items[0].orderId",
                        }
                    ],
                    "dataFlows": [],
                },
            )
            write_json(
                browser_output / "analysis" / "surface-inventory.json",
                {
                    "surfaces": [
                        {
                            "id": "surface-orders-list",
                            "method": "GET",
                            "path_template": "/api/orders",
                        }
                    ]
                },
            )
            web_runner.update_object_provenance(workspace, browser_output)
            provenance = json.loads(
                (workspace / "object-provenance.json").read_text()
            )
            slot = provenance["slots"][0]
            self.assertEqual(["surface-orders-list"], slot["producer_refs"])
            self.assertEqual([], slot["consumer_refs"])

            case = {
                "id": "case-identifier-chain",
                "family": "authorization.identifier-provenance",
                "case_kind": "api-test",
                "request_shape_id": "shape-list",
                "surface_ref": "surface-orders-list",
                "automation_state": "needs-agent",
                "status": "queued",
                "safety": "read-only",
                "evidence_refs": [],
            }
            graph = web_assessment.build_prerequisite_graph(
                workspace,
                {
                    "assessment_id": "assessment-list",
                    "dimensions": {"identities": []},
                    "runtime": {},
                    "candidates": [],
                },
                {"request_shapes": [{"id": "shape-list", "body_fields": []}]},
                [case],
            )
            states = {item["kind"]: item["status"] for item in graph["prerequisites"]}
            self.assertEqual("satisfied", states["identifier-producer"])
            self.assertEqual("pending", states["identifier-consumer"])
            self.assertEqual("waiting-prerequisite", case["status"])

    def test_late_binding_rule_is_domain_independent(self) -> None:
        for domain, noun in (
            ("commerce", "order"),
            ("healthcare", "appointment"),
            ("project", "task"),
        ):
            with self.subTest(domain=domain), tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                surface_ref = f"surface-{noun}-detail"
                write_json(
                    workspace / "object-provenance.json",
                    {
                        "slots": [
                            {
                                "id": f"binding-{domain}",
                                "kind": "object",
                                "producer": {"field": f"{noun}Id"},
                                "consumer": {"field": f"{noun}Id"},
                                "consumer_refs": [surface_ref],
                                "route_refs": [],
                            }
                        ]
                    },
                )
                coverage = {
                    "assessment_id": f"assessment-{domain}",
                    "dimensions": {
                        "identities": [
                            {"id": "current-authenticated", "status": "available"}
                        ],
                        "authorization_capabilities": [],
                    },
                    "runtime": {},
                    "candidates": [],
                }
                plan = {
                    "request_shapes": [
                        {"id": f"shape-{domain}", "body_fields": []}
                    ]
                }
                case = {
                    "id": f"case-{domain}",
                    "family": "authorization.identifier-provenance",
                    "case_kind": "api-test",
                    "request_shape_id": f"shape-{domain}",
                    "surface_ref": surface_ref,
                    "automation_state": "auto-ready",
                    "status": "queued",
                    "safety": "read-only",
                    "evidence_refs": [],
                }
                graph = web_assessment.build_prerequisite_graph(
                    workspace, coverage, plan, [case]
                )
                self.assertFalse(graph["summary"]["pending"])
                self.assertEqual("queued", case["status"])

    def test_external_and_exhausted_prerequisites_remain_interim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "assessment"
            web_assessment.initialize(workspace, "https://shop.example.test")
            source = Path(temporary) / "surface.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "method": "GET",
                            "url": "/api/orders",
                            "validation_state": "runtime-observed",
                            "runtime_observed": True,
                        }
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            coverage = json.loads((workspace / "coverage.json").read_text())
            graph = json.loads((workspace / "prerequisite-graph.json").read_text())
            self.assertEqual("interim", coverage["assessment_state"])
            self.assertFalse(coverage["stop_gates"]["test_prerequisites_resolved"])
            self.assertTrue(
                any(
                    item["status"] in {"pending", "blocked-external"}
                    for item in graph["prerequisites"]
                )
            )
            self.assertIn("- Final: `false`", (workspace / "results.md").read_text())

    def test_external_capability_does_not_hide_discoverable_prerequisites(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            coverage = {
                "assessment_id": "assessment-ssrf",
                "dimensions": {"identities": []},
                "runtime": {"owned_oast_available": False},
                "candidates": [],
            }
            case = {
                "id": "case-ssrf",
                "family": "server-side-processing.ssrf-webhook-proxy",
                "case_kind": "api-test",
                "request_shape_id": None,
                "surface_ref": None,
                "automation_state": "needs-agent",
                "status": "queued",
                "safety": "blocked",
                "evidence_refs": [],
            }
            graph = web_assessment.build_prerequisite_graph(
                workspace, coverage, {"request_shapes": []}, [case]
            )
            states = {item["kind"]: item["status"] for item in graph["prerequisites"]}
            self.assertEqual("blocked-external", states["owned-oast"])
            self.assertEqual("pending", states["request-shape"])
            self.assertEqual("waiting-prerequisite", case["status"])
            self.assertIn("request-shape", case["reason"])

    def test_named_sibling_families_wait_for_missing_current_prerequisites(self) -> None:
        families = (
            "platform-exposure.headers-cache-cors",
            "identity-session.cross-origin-csrf",
            "server-side-processing.ssrf-webhook-proxy",
            "files-data-export.upload-validation",
            "browser-content.xss-dom-richtext",
            "business-logic.race-concurrency",
            "business-logic.approval-invite-share",
            "api-protocol.graphql",
        )
        for family in families:
            with self.subTest(family=family), tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                coverage = {
                    "assessment_id": f"assessment-{family}",
                    "dimensions": {"identities": []},
                    "runtime": {"owned_oast_available": False},
                    "candidates": [],
                }
                case = {
                    "id": f"case-{family}",
                    "family": family,
                    "case_kind": "api-test",
                    "request_shape_id": None,
                    "surface_ref": None,
                    "automation_state": "needs-agent",
                    "status": "queued",
                    "safety": "read-only",
                    "evidence_refs": [],
                }
                graph = web_assessment.build_prerequisite_graph(
                    workspace, coverage, {"request_shapes": []}, [case]
                )
                self.assertEqual("waiting-prerequisite", case["status"])
                self.assertEqual(
                    "discoverable-prerequisite", case["blocker_class"]
                )
                self.assertTrue(
                    any(
                        item["status"] in {"pending", "searching"}
                        for item in graph["prerequisites"]
                    )
                )

    def test_exhaustion_requires_all_strategy_evidence_and_two_rounds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "assessment"
            web_assessment.initialize(workspace, "https://medical.example.test")
            event = {
                "type": "prerequisite-result",
                "prerequisite_id": "prerequisite-fixture",
                "status": "exhausted-with-evidence",
                "reason": "all safe strategies found no current producer",
                "evidence_refs": ["evidence/no-producer.json"],
                "stable_rounds": 1,
            }
            with self.assertRaisesRegex(ValueError, "two stable rounds"):
                web_assessment.append_event(workspace, event)

    def test_generic_agent_actions_search_each_prerequisite_not_only_cors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "assessment"
            web_assessment.initialize(workspace, "https://project.example.test")
            source = Path(temporary) / "surface.json"
            write_json(
                source,
                {
                    "surfaces": [
                        {
                            "method": "POST",
                            "url": "/api/tasks/approve",
                            "fields": ["taskId", "state"],
                            "validation_state": "recognized",
                        }
                    ]
                },
            )
            web_assessment.compile_workspace(workspace, [("manual", source)])
            state = agent.new_state(
                "https://project.example.test", workspace, "generic"
            )
            agent.save_state(workspace, state)
            state = agent.sync_actions(workspace, state)
            actions = [
                item
                for item in state["actions"]
                if item.get("instruction", {}).get("action")
                == "resolve-prerequisite"
            ]
            self.assertTrue(actions)
            self.assertTrue(
                {
                    item["instruction"]["kind"] for item in actions
                }
                & {"request-shape", "business-state", "owned-object-binding"}
            )
            self.assertTrue(
                all(item["retry"]["max_attempts"] == 1 for item in actions)
            )
            self.assertEqual(
                len(actions),
                len(
                    {
                        item["instruction"]["prerequisite_id"]
                        for item in actions
                    }
                ),
            )
            first = actions[0]
            first["status"] = "blocked"
            first["result"] = {
                "reason": "runtime traffic source unavailable",
                "recorded_at": "2026-08-02T00:00:00+00:00",
            }
            state = agent.sync_actions(workspace, state)
            same_prerequisite = [
                item
                for item in state["actions"]
                if item.get("instruction", {}).get("prerequisite_id")
                == first["instruction"]["prerequisite_id"]
                and item.get("instruction", {}).get("action")
                == "resolve-prerequisite"
            ]
            self.assertEqual(
                {"blocked", "queued"},
                {item["status"] for item in same_prerequisite},
            )

    def test_auditor_counts_blocked_cases_and_prerequisites_as_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "assessment"
            web_assessment.initialize(workspace, "https://shop.example.test")
            web_assessment.compile_workspace(workspace)
            audit = web_runner.audit_execution(workspace)
            self.assertEqual("blocked", audit["status"])
            self.assertGreater(audit["counts"]["test_prerequisite_gaps"], 0)

    def test_auditor_requires_indexed_or_canonical_prerequisite_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            write_json(
                workspace / "test-plan.json",
                {"executable_cases": [], "test_cells": [], "request_shapes": []},
            )
            write_json(
                workspace / "surface-inventory.json",
                {"blockers": [], "surfaces": [], "totals": {"surfaces": 0}},
            )
            write_json(workspace / "route-inventory.json", {"routes": []})
            write_json(workspace / "coverage.json", {"candidates": []})
            write_json(
                workspace / "prerequisite-graph.json",
                {
                    "prerequisites": [
                        {
                            "id": "prerequisite-evidence-fixture",
                            "owner_kind": "test-case",
                            "owner_id": "case-fixture",
                            "status": "satisfied",
                            "evidence_refs": ["evidence-fixture"],
                        }
                    ]
                },
            )
            write_json(workspace / "evidence-index.json", {"evidence": []})
            missing = web_runner.audit_execution(workspace)
            self.assertEqual(1, missing["counts"]["prerequisite_evidence_gaps"])

            write_json(
                workspace / "evidence-index.json",
                {"evidence": [{"id": "evidence-fixture"}]},
            )
            indexed = web_runner.audit_execution(workspace)
            self.assertEqual(0, indexed["counts"]["prerequisite_evidence_gaps"])

    def test_only_external_prerequisites_yield_blocked_interim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            write_json(
                workspace / "test-plan.json",
                {"executable_cases": [], "test_cells": [], "request_shapes": []},
            )
            write_json(
                workspace / "surface-inventory.json",
                {"blockers": [], "surfaces": [], "totals": {"surfaces": 0}},
            )
            write_json(workspace / "route-inventory.json", {"routes": []})
            write_json(
                workspace / "coverage.json",
                {
                    "assessment_state": "interim",
                    "candidates": [],
                    "findings": [],
                    "runtime": {},
                },
            )
            write_json(workspace / "evidence-index.json", {"evidence": []})
            write_json(
                workspace / "prerequisite-graph.json",
                {
                    "prerequisites": [
                        {
                            "id": "prerequisite-second-principal",
                            "owner_kind": "test-case",
                            "owner_id": "case-cross-principal",
                            "kind": "second-principal",
                            "status": "blocked-external",
                            "reason": "second authorized principal is unavailable",
                            "evidence_refs": ["evidence/capability.json"],
                            "search_strategies": [],
                        }
                    ]
                },
            )
            state = agent.new_state(
                "https://shop.example.test", workspace, "generic"
            )
            state = agent.sync_actions(workspace, state)
            self.assertEqual("blocked-interim", state["status"])
            brief = agent.assessment_brief(workspace, state)
            self.assertFalse(brief["final"])
            self.assertEqual("report-explicit-blockers", brief["next_required_tool"])


if __name__ == "__main__":
    unittest.main()
