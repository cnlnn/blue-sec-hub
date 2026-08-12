from __future__ import annotations

import json
import base64
import tempfile
import threading
import unittest
import sys
from types import SimpleNamespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
RUNNER_SCRIPT = ROOT / "scripts" / "web_runner.py"
import web_assessment
import web_runner


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


class AuthorizationFixture(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        authenticated = bool(self.headers.get("Authorization"))
        if self.path == "/redirect-external":
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://localhost:{self.server.server_port}/vulnerable/users",
            )
            self.end_headers()
            return
        if self.path.startswith("/secure/") and not authenticated:
            body = b'{"code":401,"message":"login required"}'
            status = 401
        else:
            body = b'{"code":0,"items":[{"accountId":"shape-only","email":"redacted@example.test"}]}'
            status = 200
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class AdaptiveLimiterTest(unittest.TestCase):
    def test_rate_limiter_slows_and_recovers_without_exceeding_configured_rate(self) -> None:
        limiter = web_runner.RateLimiter(4.0)
        for _ in range(5):
            limiter.observe({"status": 429})
        degraded = limiter.snapshot()
        self.assertLess(degraded["current_requests_per_second"], 4.0)
        self.assertEqual(1, degraded["circuit_opened"])
        for _ in range(20):
            limiter.observe({"status": 200})
        self.assertEqual(4.0, limiter.snapshot()["current_requests_per_second"])


class TransactionFixture(BaseHTTPRequestHandler):
    value = "original-private-value"

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        body = json.dumps({"value": type(self).value}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PATCH(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length))
        type(self).value = str(body["value"])
        response = b'{"code":0}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class ProtocolDiscoveryFixture(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        if self.path == "/openapi.json":
            body = json.dumps(
                {
                    "openapi": "3.0.3",
                    "paths": {
                        "/api/orders": {
                            "get": {
                                "operationId": "listOrders",
                                "description": "must-not-be-persisted",
                                "parameters": [{"name": "page", "in": "query", "example": "private-value"}],
                            }
                        }
                    },
                }
            ).encode()
            content_type = "application/json"
        elif self.path == "/.well-known/openid-configuration":
            base = f"http://127.0.0.1:{self.server.server_port}"
            body = json.dumps({"issuer": base, "authorization_endpoint": base + "/oauth/authorize", "token_endpoint": base + "/oauth/token"}).encode()
            content_type = "application/json"
        elif self.path == "/robots.txt":
            body = b"User-agent: *\nAllow: /dashboard\nDisallow: /internal-*\n"
            content_type = "text/plain"
        elif self.path == "/sitemap.xml":
            base = f"http://127.0.0.1:{self.server.server_port}"
            body = f"<urlset><url><loc>{base}/reports</loc></url></urlset>".encode()
            content_type = "application/xml"
        else:
            body = b"<html><main>fallback shell</main></html>"
            content_type = "text/html"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class CorsFixture(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        body = b'{"code":0,"account":{"email":"redacted@example.test"}}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if self.path == "/api/profile" and self.headers.get("Origin"):
            self.send_header(
                "Access-Control-Allow-Origin", self.headers.get("Origin")
            )
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Vary", "Origin")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class WebRunnerTest(unittest.TestCase):
    def test_historical_entrypoint_accepts_in_scope_paths_only(self) -> None:
        target = "https://portal.example.test/"
        self.assertEqual(
            ("GET", "/api/orders"),
            web_runner.historical_entrypoint("GET /api/orders", target),
        )
        self.assertIsNone(
            web_runner.historical_entrypoint(
                "https://unrelated.invalid/api/orders", target
            )
        )
        self.assertIsNone(
            web_runner.historical_entrypoint("payload with spaces", target)
        )

    def test_protocol_discovery_keeps_valid_docs_and_rejects_fallback(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), ProtocolDiscoveryFixture)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary) / "assessment"
                target = f"http://127.0.0.1:{server.server_port}/"
                inputs = web_runner.collect_protocol_documents(
                    workspace, target, {}, 1000.0
                )
                self.assertIn("openapi", {kind for kind, _ in inputs})
                openapi_path = next(path for kind, path in inputs if kind == "openapi")
                persisted = openapi_path.read_text(encoding="utf-8")
                self.assertNotIn("must-not-be-persisted", persisted)
                self.assertNotIn("private-value", persisted)
                manual_path = next(path for kind, path in inputs if kind == "manual")
                manual = json.loads(manual_path.read_text(encoding="utf-8"))
                urls = {item["url"] for item in manual["surfaces"]}
                self.assertIn("/dashboard", urls)
                self.assertIn("/reports", urls)
                self.assertTrue(any(str(url).endswith("/oauth/authorize") for url in urls))
                ledger = json.loads(
                    (workspace / "current-protocol-discovery" / "discovery-ledger.json").read_text()
                )
                swagger = next(item for item in ledger["candidates"] if item["path"] == "/swagger.json")
                self.assertEqual("fallback-equivalent", swagger["reason"])
        finally:
            server.shutdown()
            server.server_close()

    def test_credential_lease_is_target_bound_and_consumable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lease.json"
            write_json(
                path,
                {
                    "target_origin": "https://portal.example.test",
                    "source": "burp-current-request",
                    "headers": {"Authorization": "Bearer fixture-credential"},
                },
            )
            path.chmod(0o600)
            lease = web_runner.load_credential_lease(
                "https://portal.example.test/app",
                None,
                path,
                True,
            )
            self.assertEqual(["Authorization"], lease.metadata("available")["header_names"])
            self.assertNotIn(
                "fixture-credential", json.dumps(lease.metadata("available"))
            )
            lease.cleanup()
            self.assertFalse(path.exists())

    def test_expired_lease_is_not_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lease.json"
            write_json(
                path,
                {
                    "target_origin": "https://portal.example.test",
                    "expires_at": "2000-01-01T00:00:00+00:00",
                    "headers": {"Authorization": "Bearer fixture-credential"},
                },
            )
            path.chmod(0o600)
            lease = web_runner.load_credential_lease(
                "https://portal.example.test", None, path, False
            )
            self.assertEqual({}, lease.headers)
            self.assertEqual("credential-lease-expired", lease.source)

    def test_transaction_corpus_is_target_bound_private_and_consumed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "transactions.json"
            request = {
                "method": "GET",
                "url": "https://portal.example.test/api/self/item",
                "headers": {"Authorization": "fixture-private-value"},
            }
            write_json(
                path,
                {
                    "target_origin": "https://portal.example.test",
                    "transactions": [
                        {
                            "test_case_id": "case-1",
                            "variant_id": "variant-1",
                            "ownership": "self-owned",
                            "reversible": True,
                            "prestate": request,
                            "mutation": {**request, "method": "PATCH"},
                            "rollback": {**request, "method": "PATCH"},
                            "verify": request,
                        }
                    ],
                },
            )
            path.chmod(0o600)
            transactions = web_runner.load_transaction_corpus(
                path, "https://portal.example.test"
            )
            self.assertIn("case-1", transactions)
            self.assertFalse(path.exists())

    def test_token_claim_summary_retains_names_only(self) -> None:
        payload = base64.urlsafe_b64encode(
            json.dumps(
                {"sub": "person-42", "tenantId": "tenant-7", "role": "member"}
            ).encode()
        ).decode().rstrip("=")
        token = f"header.{payload}.signature"
        summary = web_runner.token_claim_summary(
            {"Authorization": f"Bearer {token}"}
        )
        serialized = json.dumps(summary)
        self.assertIn("tenantId", serialized)
        self.assertIn("role", serialized)
        self.assertNotIn("person-42", serialized)
        self.assertNotIn("tenant-7", serialized)
        self.assertNotIn(token, serialized)
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "assessment"
            web_assessment.initialize(workspace, "https://portal.example.test")
            lease = web_runner.CredentialLease(
                "fixture", {"Authorization": f"Bearer {token}"}
            )
            web_assessment.append_event(workspace, lease.metadata("available"))
            web_assessment.compile_workspace(workspace)
            coverage = json.loads(
                (workspace / "coverage.json").read_text(encoding="utf-8")
            )
            persisted = json.dumps(
                coverage["runtime"]["credential_lease"]["token_claims"]
            )
            self.assertIn("tenantId", persisted)
            self.assertNotIn("tenant-7", persisted)
            self.assertNotIn(token, persisted)

    def test_request_template_key_includes_origin(self) -> None:
        first = web_runner.request_key("GET", "https://api-a.example.test/v1/items")
        second = web_runner.request_key("GET", "https://api-b.example.test/v1/items")
        self.assertNotEqual(first, second)

    def test_request_template_selection_rejects_ambiguous_query_shapes(self) -> None:
        requests = [
            web_runner.RawRequest(
                "GET",
                f"https://api.example.test/items?{query}",
                {},
                None,
                "fixture",
            )
            for query in ("ownerId=self", "tenantId=current")
        ]
        corpus = {}
        for request in requests:
            corpus.setdefault(
                web_runner.request_key(request.method, request.url), []
            ).append(request)
        self.assertIsNone(
            web_runner.select_template(
                {},
                {"method": "GET"},
                {"method": "GET", "url": "https://api.example.test/items"},
                corpus,
                web_runner.CredentialLease("fixture", {}),
            )
        )
        selected = web_runner.select_template(
            {},
            {"method": "GET"},
            {
                "method": "GET",
                "url": "https://api.example.test/items?ownerId=:value",
            },
            corpus,
            web_runner.CredentialLease("fixture", {}),
        )
        self.assertIsNotNone(selected)
        self.assertIn("ownerId=", selected.url)

    def test_mismatched_credential_lease_does_not_leave_runner_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lease = root / "lease.json"
            write_json(
                lease,
                {
                    "target_origin": "https://other.example.test",
                    "headers": {"Authorization": "fixture"},
                },
            )
            lease.chmod(0o600)
            workspace = root / "assessment"
            args = SimpleNamespace(
                workspace=workspace,
                target="https://portal.example.test",
                header_file=None,
                credential_lease=lease,
                consume_auth=False,
            )
            with self.assertRaises(ValueError):
                web_runner.execute(args)
            self.assertFalse((workspace / ".runner.lock").exists())

    def test_generic_subject_mutations_cover_unrelated_domains(self) -> None:
        for domain, field in (
            ("commerce", "ownerId"),
            ("healthcare", "patientUserId"),
            ("project-management", "accountId"),
        ):
            with self.subTest(domain=domain):
                original = {field: "self-42", "page": 1}
                omitted = web_runner.mutate_mapping(
                    original,
                    "omitted-subject",
                    "implicit-subject-binding",
                    [field],
                )
                nonexistent = web_runner.mutate_mapping(
                    original,
                    "nonexistent-subject",
                    "implicit-subject-binding",
                    [field],
                )
                self.assertNotIn(field, omitted)
                self.assertTrue(str(nonexistent[field]).startswith("blue-sec-nonexistent-"))
                self.assertEqual(original[field], "self-42")

    def test_response_summary_persists_shape_not_values(self) -> None:
        body = b'{"code":0,"items":[{"email":"person@example.test","token":"secret"}]}'
        summary = web_runner.response_summary(
            200,
            "https://portal.example.test/api/users",
            {"content-type": "application/json"},
            body,
            0.01,
        )
        serialized = json.dumps(summary)
        self.assertIn("items[].email", serialized)
        self.assertNotIn("person@example.test", serialized)
        self.assertNotIn('"secret"', serialized)

    def test_cors_summary_and_variant_preserve_policy_not_origin_value(self) -> None:
        origin = "https://private-origin.example.test/path?token=hidden"
        summary = web_runner.response_summary(
            200,
            "https://portal.example.test/api/profile",
            {
                "content-type": "application/json",
                "access-control-allow-origin": origin,
                "access-control-allow-credentials": "true",
                "vary": "Accept-Encoding, Origin",
            },
            b'{"email":"person@example.test"}',
            0.01,
        )
        serialized = json.dumps(summary)
        self.assertEqual("origin", summary["cors"]["allow_origin_kind"])
        self.assertTrue(summary["cors"]["allow_credentials"])
        self.assertTrue(summary["cors"]["vary_origin"])
        self.assertNotIn(origin, serialized)
        request, reason = web_runner.variant_request(
            web_runner.RawRequest(
                "GET",
                "https://portal.example.test/api/profile",
                {"Cookie": "session=private"},
                None,
                "fixture",
            ),
            "cors-origin-variant",
            None,
            [],
        )
        self.assertIsNone(reason)
        self.assertEqual(web_runner.CORS_TEST_ORIGIN, request.headers["Origin"])

    def test_cors_candidate_keeps_browser_prerequisite_open_across_domains(self) -> None:
        result = {
            "status": 200,
            "cors": {
                "allow_origin_kind": "origin",
                "allow_origin_sha256": web_runner.CORS_TEST_ORIGIN_SHA256,
                "allow_credentials": True,
            }
        }
        for domain, path, fields in (
            ("commerce", "/api/orders/current", ["items[].accountId"]),
            ("healthcare", "/api/appointments/current", ["items[].patientId"]),
        ):
            with self.subTest(domain=domain):
                dependencies = web_runner.cors_validation_dependencies(
                    web_runner.RawRequest(
                        "GET",
                        f"https://{domain}.example.test{path}",
                        {"Cookie": "session=private"},
                        None,
                        "fixture",
                    ),
                    {"sensitive_field_names": fields},
                    result,
                    f"{domain}-cors-evidence",
                )
                by_id = {item["id"]: item for item in dependencies}
                self.assertEqual(
                    "pending", by_id["ambient-credential-delivery"]["status"]
                )
                self.assertEqual(
                    "satisfied", by_id["concrete-endpoint"]["status"]
                )
        self.assertEqual(
            [],
            web_runner.cors_validation_dependencies(
                web_runner.RawRequest(
                    "GET",
                    "https://public.example.test/api/catalog",
                    {},
                    None,
                    "fixture",
                ),
                {"sensitive_field_names": []},
                result,
                "public-cors-evidence",
            ),
        )

    def test_cors_family_executes_baseline_and_concrete_origin_variant(self) -> None:
        executor, variants = web_assessment.family_executor(
            "platform-exposure.headers-cache-cors"
        )
        self.assertEqual("passive-response-review", executor)
        self.assertEqual(["baseline", "cors-origin-variant"], variants)

    def test_cors_runtime_signal_stays_candidate_until_browser_prerequisite(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), CorsFixture)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                workspace = root / "assessment"
                target = f"http://127.0.0.1:{server.server_port}/"
                web_assessment.initialize(workspace, target)
                source = root / "surface.json"
                write_json(
                    source,
                    {
                        "surfaces": [
                            {
                                "kind": "api",
                                "method": "GET",
                                "url": target.rstrip("/") + "/api/profile",
                                "validation_state": "runtime-observed",
                                "runtime_observed": True,
                            }
                        ]
                    },
                )
                web_assessment.compile_workspace(workspace, [("manual", source)])
                first_inventory = json.loads(
                    (workspace / "surface-inventory.json").read_text()
                )
                surface_ref = first_inventory["surfaces"][0]["id"]
                web_assessment.append_event(
                    workspace,
                    {
                        "type": "request-shape",
                        "surface_ref": surface_ref,
                        "method": "GET",
                        "path": "/api/profile",
                        "source": "runtime",
                        "semantics": "read",
                        "safety": "read-only",
                    },
                )
                web_assessment.compile_workspace(workspace)
                plan = json.loads((workspace / "test-plan.json").read_text())
                inventory = json.loads(
                    (workspace / "surface-inventory.json").read_text()
                )
                case = next(
                    item
                    for item in plan["executable_cases"]
                    if item.get("family")
                    == "platform-exposure.headers-cache-cors"
                    and item.get("automation_state") == "auto-ready"
                )
                web_runner.run_case(
                    workspace,
                    case,
                    plan,
                    inventory,
                    {},
                    web_runner.CredentialLease(
                        "fixture", {"Cookie": "session=private"}
                    ),
                    web_runner.RateLimiter(1000),
                )
                web_assessment.compile_workspace(workspace)
                coverage = json.loads((workspace / "coverage.json").read_text())
                candidate = next(
                    item
                    for item in coverage["candidates"]
                    if item["title"].startswith("Cross-origin policy signal")
                )
                dependencies = {
                    item["id"]: item for item in candidate["validation_dependencies"]
                }
                self.assertEqual(
                    "pending",
                    dependencies["ambient-credential-delivery"]["status"],
                )
                self.assertFalse(
                    coverage["stop_gates"]["candidate_prerequisites_resolved"]
                )
        finally:
            server.shutdown()
            server.server_close()

    def test_anonymous_boundary_oracle_confirms_only_vulnerable_fixture(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), AuthorizationFixture)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for path, expected_findings in (("/vulnerable/users", 1), ("/secure/users", 0)):
                with self.subTest(path=path), tempfile.TemporaryDirectory() as temporary:
                    workspace = Path(temporary) / "assessment"
                    target = f"http://127.0.0.1:{server.server_port}/"
                    web_assessment.initialize(workspace, target)
                    source = Path(temporary) / "surface.json"
                    write_json(
                        source,
                        {
                            "surfaces": [
                                {
                                    "kind": "api",
                                    "method": "GET",
                                    "url": target.rstrip("/") + path,
                                    "validation_state": "runtime-observed",
                                    "runtime_observed": True,
                                }
                            ]
                        },
                    )
                    web_assessment.append_event(
                        workspace,
                        {"type": "identity", "id": "current-authenticated", "status": "available"},
                    )
                    web_assessment.append_event(
                        workspace,
                        {"type": "authorization-capability", "id": "anonymous-boundary", "status": "available", "reason": "fixture identity"},
                    )
                    web_assessment.compile_workspace(workspace, [("manual", source)])
                    plan = json.loads((workspace / "test-plan.json").read_text(encoding="utf-8"))
                    inventory = json.loads((workspace / "surface-inventory.json").read_text(encoding="utf-8"))
                    case = next(
                        item
                        for item in plan["executable_cases"]
                        if item.get("authorization_mode") == "anonymous-boundary"
                    )
                    lease = web_runner.CredentialLease(
                        "fixture",
                        {"Authorization": "Bearer fixture"},
                    )
                    web_runner.run_case(
                        workspace,
                        case,
                        plan,
                        inventory,
                        {},
                        lease,
                        web_runner.RateLimiter(1000),
                    )
                    web_assessment.compile_workspace(workspace)
                    coverage = json.loads((workspace / "coverage.json").read_text(encoding="utf-8"))
                    self.assertEqual(expected_findings, len(coverage["findings"]))
                    evidence_text = "".join(
                        item.read_text(encoding="utf-8")
                        for item in (workspace / "evidence" / "runner").glob("*.json")
                    )
                    self.assertNotIn("Bearer fixture", evidence_text)
                    self.assertNotIn("person@example.test", evidence_text)
        finally:
            server.shutdown()
            server.server_close()

    def test_request_replay_does_not_follow_cross_site_redirects(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), AuthorizationFixture)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = web_runner.send_request(
                web_runner.RawRequest(
                    "GET",
                    f"http://127.0.0.1:{server.server_port}/redirect-external",
                    {},
                    None,
                    "fixture",
                ),
                web_runner.RateLimiter(1000),
            )
            self.assertEqual(302, result["status"])
            self.assertEqual("/redirect-external", result["final_path"])
        finally:
            server.shutdown()
            server.server_close()

    def test_browser_route_results_are_bound_to_each_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "assessment"
            web_assessment.initialize(workspace, "https://portal.example.test")
            web_assessment.append_event(
                workspace,
                {"type": "identity", "id": "current-authenticated", "status": "available"},
            )
            inventories = []
            for identity in ("anonymous", "current-authenticated"):
                path = Path(temporary) / f"{identity}.json"
                write_json(
                    path,
                    {
                        "routes": [
                            {
                                "path": "/dashboard",
                                "validation": {
                                    "state": "runtime-visited",
                                    "reason": "browser-navigation-and-render-confirmed",
                                    "evidence": {
                                        "render": {"state": "rendered"},
                                        "controlRefs": [],
                                        "runtimeApiRefs": [],
                                        "lazyChunkRefs": [],
                                    },
                                },
                            }
                        ]
                    },
                )
                inventories.append((identity, path))
            web_assessment.compile_workspace(
                workspace,
                [("spa", path) for _, path in inventories],
                replace_inputs=True,
            )
            web_runner.record_browser_route_results(workspace, inventories)
            web_assessment.compile_workspace(workspace)
            plan = json.loads((workspace / "test-plan.json").read_text(encoding="utf-8"))
            cases = [
                item
                for item in plan["executable_cases"]
                if item.get("case_kind") == "route-navigation"
            ]
            self.assertEqual(
                {"anonymous", "current-authenticated"},
                {item["identity"] for item in cases},
            )
            self.assertTrue(all(item["status"] == "tested" for item in cases))

    def test_auditor_rejects_unresolved_agent_actions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            write_json(
                workspace / "test-plan.json",
                {
                    "executable_cases": [
                        {
                            "id": "agent-case-1",
                            "automation_state": "needs-agent",
                            "status": "queued",
                        }
                    ]
                },
            )
            write_json(workspace / "route-inventory.json", {"routes": []})
            write_json(workspace / "coverage.json", {"candidates": []})
            write_json(workspace / "surface-inventory.json", {"blockers": []})
            audit = web_runner.audit_execution(workspace)
            self.assertEqual("blocked", audit["status"])
            self.assertEqual(1, audit["counts"]["needs_agent"])

    def test_reversible_transaction_restores_exact_prestate(self) -> None:
        TransactionFixture.value = "original-private-value"
        server = ThreadingHTTPServer(("127.0.0.1", 0), TransactionFixture)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary) / "assessment"
                web_assessment.initialize(workspace, "http://127.0.0.1")
                case = {
                    "id": "transaction-case",
                    "case_kind": "api-test",
                    "test_cell_id": "transaction-cell",
                    "variants": ["protected-field-empty"],
                    "authorization_mode": None,
                    "safety": "reversible",
                }
                write_json(
                    workspace / "test-plan.json",
                    {
                        "schema_version": 4,
                        "test_cells": [
                            {
                                "id": "transaction-cell",
                                "family": "authorization.property-level",
                                "safety": "reversible",
                            }
                        ],
                        "executable_cases": [case],
                    },
                )
                url = f"http://127.0.0.1:{server.server_port}/self/item"
                headers = {"Content-Type": "application/json"}
                transactions = {
                    "protected-field-empty": {
                        "prestate": web_runner.RawRequest(
                            "GET", url, {}, None, "fixture"
                        ),
                        "mutation": web_runner.RawRequest(
                            "PATCH",
                            url,
                            headers,
                            b'{"value":"changed-private-value"}',
                            "fixture",
                        ),
                        "rollback": web_runner.RawRequest(
                            "PATCH",
                            url,
                            headers,
                            b'{"value":"original-private-value"}',
                            "fixture",
                        ),
                        "verify": web_runner.RawRequest(
                            "GET", url, {}, None, "fixture"
                        ),
                    }
                }
                web_runner.run_transaction_case(
                    workspace,
                    case,
                    transactions,
                    web_runner.RateLimiter(1000),
                )
                self.assertEqual("original-private-value", TransactionFixture.value)
                events = web_assessment.read_events(workspace)
                result = next(item for item in events if item["type"] == "test-result")
                self.assertEqual("tested", result["status"])
                self.assertEqual("completed", result["cleanup"]["status"])
                evidence = "".join(
                    path.read_text(encoding="utf-8")
                    for path in (workspace / "evidence" / "runner").glob("*.json")
                )
                self.assertNotIn("original-private-value", evidence)
                self.assertNotIn("changed-private-value", evidence)
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
