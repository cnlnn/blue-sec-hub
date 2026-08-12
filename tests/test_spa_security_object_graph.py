from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPA_SCRIPTS = ROOT / "skills" / "spa-security-object-graph" / "scripts"
sys.path.insert(0, str(SPA_SCRIPTS))

from collect_browser_assets import (
    browser_storage_state_metadata,
    collect_browser_assets,
    control_disposition,
    network_request_decision,
    redact_route_value,
    redact_runtime_json,
    redact_url,
    runtime_route_candidates,
    tracked,
)
from collect_spa_assets import (
    discover,
    invalid_asset_response,
    load_headers,
    parse_header_file,
    valid_asset_ref,
)
from inspect_token_claims import inspect_header_file
from route_inventory import (
    build_route_inventory,
    route_candidates,
    route_is_safe_to_visit,
)
from semantic_lexicon import validate_lexicon
from surface_inventory import (
    UNSAFE_READ_PATH_RE,
    build_surface_inventory,
    classify_cors,
    classify_response,
    normalize_api_path,
)
from sanitize_browser_capture import sanitize_manifest


class SpaSecurityObjectGraphTest(unittest.TestCase):
    def run_graph(self, assets: Path, output: Path) -> dict:
        subprocess.run(
            [
                sys.executable,
                str(SPA_SCRIPTS / "build_object_graph.py"),
                str(assets),
                "--out",
                str(output),
            ],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return json.loads((output / "graph.json").read_text(encoding="utf-8"))

    def test_browser_route_limit_defaults_to_exhaustive(self) -> None:
        self.assertEqual(
            0,
            inspect.signature(collect_browser_assets)
            .parameters["max_pages"]
            .default,
        )

    def test_short_current_numeric_identifier_is_still_tracked(self) -> None:
        self.assertTrue(tracked("response.items[0].id", 1))
        self.assertTrue(tracked("response.ownerId", "7"))
        self.assertFalse(tracked("response.enabled", True))

    def test_header_file_supports_lines_and_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            line_file = root / "headers.txt"
            line_file.write_text(
                "# temporary session\nCookie: session=redacted\nX-Tenant: blue\n",
                encoding="utf-8",
            )
            line_file.chmod(0o600)
            json_file = root / "headers.json"
            json_file.write_text(
                json.dumps({"Authorization": "Bearer redacted"}),
                encoding="utf-8",
            )
            json_file.chmod(0o600)
            self.assertEqual(
                parse_header_file(line_file),
                {"Cookie": "session=redacted", "X-Tenant": "blue"},
            )
            self.assertEqual(
                load_headers(["X-Tenant: override"], json_file),
                {"Authorization": "Bearer redacted", "X-Tenant": "override"},
            )

    def test_token_claim_summary_keeps_names_without_values(self) -> None:
        def encoded(value: dict) -> str:
            raw = json.dumps(value, separators=(",", ":")).encode()
            return base64.urlsafe_b64encode(raw).decode().rstrip("=")

        for domain, claims in (
            (
                "commerce",
                {
                    "sub": "buyer-42",
                    "tenantId": "shop-7",
                    "roles": ["buyer"],
                    "email": "buyer@example.test",
                    "exp": 9999999999,
                },
            ),
            (
                "healthcare",
                {
                    "sub": "clinician-9",
                    "orgPath": "/hospital/unit",
                    "permissions": ["appointment:read"],
                    "phone": "00000000000",
                    "iat": 1,
                },
            ),
        ):
            with self.subTest(domain=domain), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                token = (
                    encoded({"alg": "none", "typ": "JWT"})
                    + "."
                    + encoded(claims)
                    + "."
                )
                header_file = root / "headers.json"
                header_file.write_text(
                    json.dumps(
                        {
                            "Authorization": f"Bearer {token}",
                            "X-Session": "opaque-secret-value",
                        }
                    ),
                    encoding="utf-8",
                )
                header_file.chmod(0o600)
                result = inspect_header_file(header_file)
                rendered = json.dumps(result)
                self.assertEqual(2, result["tokenCount"])
                self.assertFalse(result["rawValuesPersisted"])
                self.assertEqual(
                    sorted(claims),
                    result["tokens"][0]["claimNames"],
                )
                for secret in (
                    "buyer-42",
                    "shop-7",
                    "buyer@example.test",
                    "clinician-9",
                    "/hospital/unit",
                    "00000000000",
                    "opaque-secret-value",
                ):
                    self.assertNotIn(secret, rendered)

    def test_browser_storage_state_requires_private_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state_file = root / "storage-state.json"
            state_file.write_text(
                json.dumps(
                    {
                        "cookies": [],
                        "origins": [
                            {
                                "origin": "https://inventory.example",
                                "localStorage": [
                                    {"name": "session", "value": "redacted"}
                                ],
                            },
                            {
                                "origin": "https://training.example",
                                "localStorage": [
                                    {"name": "access-token", "value": "redacted"}
                                ],
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            state_file.chmod(0o600)
            metadata = browser_storage_state_metadata(state_file)
            self.assertTrue(metadata["applied"])
            self.assertEqual(metadata["originCount"], 2)
            self.assertEqual(metadata["cookieCount"], 0)
            self.assertNotIn("redacted", json.dumps(metadata))

            if os.name == "posix":
                state_file.chmod(0o644)
                with self.assertRaisesRegex(ValueError, "group/world"):
                    browser_storage_state_metadata(state_file)

    def test_runtime_json_redaction_keeps_schema_without_values(self) -> None:
        source = {
            "user": {
                "name": "Alice",
                "token": "secret-value",
                "active": True,
            },
            "items": [
                {"id": 42, "amount": 1.5},
                {"id": 43, "amount": 2.5},
            ],
        }
        redacted = redact_runtime_json(source)
        encoded = json.dumps(redacted)
        self.assertNotIn("Alice", encoded)
        self.assertNotIn("secret-value", encoded)
        self.assertEqual(redacted["user"]["name"]["length"], 5)
        self.assertEqual(redacted["items"]["count"], 2)
        self.assertEqual(
            redacted["items"]["itemShapes"][0]["id"]["$redactedType"],
            "integer",
        )

    def test_browser_capture_sanitizer_preserves_original_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            response_file = root / "profile.json"
            raw = b'{"name":"Alice","token":"secret-value","roles":["user"]}'
            response_file.write_bytes(raw)
            manifest_file = root / "browser-manifest.json"
            manifest_file.write_text(
                json.dumps(
                    {
                        "responses": [
                            {
                                "resourceType": "xhr",
                                "contentType": "application/json",
                                "localPath": str(response_file),
                                "bytes": len(raw),
                                "sha256": hashlib.sha256(raw).hexdigest(),
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            result = sanitize_manifest(manifest_file)
            self.assertEqual(result["rewritten"], 1)
            self.assertEqual(result["reconciled"], 0)
            stored = response_file.read_text(encoding="utf-8")
            self.assertNotIn("Alice", stored)
            self.assertNotIn("secret-value", stored)
            manifest = json.loads(
                manifest_file.read_text(encoding="utf-8")
            )
            record = manifest["responses"][0]
            self.assertEqual(
                record["sha256"],
                hashlib.sha256(raw).hexdigest(),
            )
            self.assertEqual(
                record["storedRepresentation"],
                "redacted-json-shape",
            )
            self.assertTrue(record["storedSourceMatchedResponseHash"])

    def test_browser_capture_sanitizer_reconciles_duplicate_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            response_file = root / "profile.json"
            raw = b'{"name":"Alice","token":"secret-value"}'
            response_file.write_bytes(raw)
            manifest_file = root / "browser-manifest.json"
            manifest_file.write_text(
                json.dumps(
                    {
                        "responses": [
                            {
                                "resourceType": "xhr",
                                "localPath": str(response_file),
                                "sha256": hashlib.sha256(raw).hexdigest(),
                            },
                            {
                                "resourceType": "xhr",
                                "localPath": str(response_file),
                                "sha256": "0" * 64,
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            result = sanitize_manifest(manifest_file)
            self.assertEqual(result["rewritten"], 1)
            self.assertEqual(result["reconciled"], 1)
            self.assertNotIn(
                "secret-value",
                response_file.read_text(encoding="utf-8"),
            )
            manifest = json.loads(
                manifest_file.read_text(encoding="utf-8")
            )
            self.assertTrue(
                all(
                    item["storedRepresentation"] == "redacted-json-shape"
                    for item in manifest["responses"]
                )
            )

    def test_browser_capture_sanitizer_does_not_follow_external_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = root / "capture"
            capture.mkdir()
            external = root / "external.json"
            external.write_text('{"token":"keep-me"}', encoding="utf-8")
            manifest_file = capture / "browser-manifest.json"
            manifest_file.write_text(
                json.dumps(
                    {
                        "responses": [
                            {
                                "resourceType": "xhr",
                                "localPath": str(external),
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            result = sanitize_manifest(manifest_file)
            self.assertEqual(result["rewritten"], 0)
            self.assertEqual(result["skipped"], 1)
            self.assertEqual(
                external.read_text(encoding="utf-8"),
                '{"token":"keep-me"}',
            )

    def test_mutation_named_routes_are_navigable_but_dynamic_routes_wait(self) -> None:
        routes = route_candidates(
            """
            const routes = [
              {path: "/account/updatePassword"},
              {path: "/reports/export"},
              {path: "/orders/:orderId"},
              {path: "/assets/app.js"},
            ];
            """
        )
        self.assertIn("/account/updatePassword", routes)
        self.assertIn("/reports/export", routes)
        self.assertIn("/orders/:orderId", routes)
        self.assertNotIn("/assets/app.js", routes)
        self.assertTrue(route_is_safe_to_visit("/account/updatePassword"))
        self.assertTrue(route_is_safe_to_visit("/reports/export"))
        self.assertFalse(route_is_safe_to_visit("/orders/:orderId"))

    def test_offline_inventory_keeps_sources_and_navigation_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "account.js").write_text(
                'const routes = [{path:"/account/updatePassword"}];',
                encoding="utf-8",
            )
            (root / "orders.js").write_text(
                'const routes = [{path:"/orders/:orderId"}];',
                encoding="utf-8",
            )
            inventory = build_route_inventory(root)
            self.assertEqual(inventory["totals"]["routes"], 2)
            by_path = {item["path"]: item for item in inventory["routes"]}
            self.assertEqual(
                by_path["/account/updatePassword"]["navigation"],
                "eligible",
            )
            self.assertEqual(
                by_path["/orders/:orderId"]["navigation"],
                "blocked-parameters",
            )
            self.assertEqual(
                ["orderId"],
                by_path["/orders/:orderId"]["parameterNames"],
            )
            self.assertTrue(
                by_path["/account/updatePassword"]["sources"][0].endswith(
                    "account.js"
                )
            )
            evidence = by_path["/account/updatePassword"]["evidence"][0]
            self.assertEqual(evidence["definitionType"], "path")
            self.assertIsInstance(evidence["offset"], int)

    def test_control_and_request_guards_separate_navigation_from_side_effects(self) -> None:
        self.assertEqual(
            "planned-unsafe",
            control_disposition({"text": "Delete order", "tag": "button"}),
        )
        self.assertEqual(
            "eligible",
            control_disposition({"text": "Search", "tag": "button"}),
        )
        self.assertEqual(
            ("blocked", "side-effect-like-safe-method-request"),
            network_request_decision("GET", "/account/reset", "xhr"),
        )
        self.assertEqual(
            ("allowed", "browser-resource"),
            network_request_decision("GET", "/account/reset", "document"),
        )
        self.assertEqual(
            ("allowed", "recognized-read-post"),
            network_request_decision("POST", "/orders/page", "xhr"),
        )
        self.assertEqual(
            ("blocked", "unclassified-side-effect-request"),
            network_request_decision("POST", "/orders/delete", "xhr"),
        )
        self.assertEqual(
            ("blocked", "unclassified-side-effect-request"),
            network_request_decision("POST", "/orders/delete/page", "xhr"),
        )
        self.assertEqual(
            ("blocked", "unclassified-side-effect-request"),
            network_request_decision("POST", "/orders/create", "document"),
        )
        self.assertEqual(
            ("blocked", "out-of-scope-side-effect-request"),
            network_request_decision("POST", "/telemetry", "fetch", False),
        )
        self.assertEqual(
            {"/admin/audit", "/orders/123"},
            runtime_route_candidates(
                {
                    "menus": [
                        {"routePath": "/admin/audit"},
                        {"path": "/orders/123"},
                        {"iconPath": "/assets/menu.svg"},
                    ]
                }
            ),
        )

    def test_asset_discovery_rejects_parser_tails_and_expressions(self) -> None:
        text = """
        import("/assets/lazy.123.js");
        import("./plain-lazy.js");
        //# sourceMappingURL=app.js.map
        const locale = "af.js";
        const broken = "widget.js',null)}};garbage.map";
        const unresolved = base + "/chunks/runtime.js";
        """
        self.assertEqual(
            discover(text, "application/javascript"),
            [
                "/assets/lazy.123.js",
                "./plain-lazy.js",
                "app.js.map",
            ],
        )
        self.assertTrue(valid_asset_ref("/chunks/account.js?v=1"))
        self.assertFalse(valid_asset_ref("base + '/chunks/account.js'"))
        self.assertEqual(
            invalid_asset_response(
                "https://portal.example/chunks/missing.js",
                "text/html",
                b"<html><div id=app></div></html>",
            ),
            "fake-200-html-fallback-for-script",
        )

    def test_asset_discovery_keeps_explicit_worker_and_html_assets(self) -> None:
        html = """
        <script src="/static/app.js"></script>
        <link rel="modulepreload" href="/assets/dashboard.mjs">
        """
        javascript = """
        const locale = "fr.js";
        const worker = new Worker("./processor.js");
        """
        self.assertEqual(
            discover(html, "text/html"),
            ["/static/app.js", "/assets/dashboard.mjs"],
        )
        self.assertEqual(
            discover(javascript, "application/javascript"),
            ["./processor.js"],
        )

    def test_api_path_resolution_never_guesses_relative_or_cross_origin(self) -> None:
        target = "https://portal.example/base/"
        self.assertEqual(
            normalize_api_path("/api/orders?state=open", target),
            ("/api/orders", None),
        )
        self.assertEqual(
            normalize_api_path("api/orders", target),
            (None, "relative-path-without-observed-base"),
        )
        self.assertEqual(
            normalize_api_path("https://other.example/api/orders", target),
            (None, "cross-origin"),
        )
        self.assertEqual(
            normalize_api_path(
                "https://portal.example/api/login;JSESSIONID=secret",
                target,
            ),
            ("/api/login", None),
        )
        self.assertEqual(
            redact_url(
                "https://portal.example/api/login;JSESSIONID=secret?next=/home"
            ),
            "https://portal.example/api/login?next=:value",
        )
        self.assertEqual(
            redact_url(
                "https://portal.example/#/orders/detail?orderId=secret&tab=events"
            ),
            "https://portal.example/#/orders/detail?orderId=:value&tab=:value",
        )
        self.assertEqual(
            redact_url("https://portal.example/orders/12345#/runs/aabbccddeeff0011"),
            "https://portal.example/orders/{id}#/runs/{id}",
        )
        self.assertEqual(
            redact_route_value("/orders/12345?view=full", "https://portal.example/"),
            "/orders/{id}?view=:value",
        )

    def test_response_classifier_rejects_real_and_fake_not_found(self) -> None:
        real = classify_response(
            {
                "status": 404,
                "url": "https://portal.example/api/missing",
                "contentType": "application/json",
                "body": b'{"message":"missing"}',
            }
        )
        fake_json = classify_response(
            {
                "status": 200,
                "url": "https://portal.example/api/missing",
                "contentType": "application/json",
                "body": b'{"code":404,"message":"resource not found"}',
            }
        )
        baseline = {
            "status": 200,
            "url": "https://portal.example/__missing",
            "contentType": "text/html",
            "body": b"<html><title>Portal</title><div id=app></div></html>",
        }
        fake_shell = classify_response(
            {
                **baseline,
                "url": "https://portal.example/api/not-real",
            },
            baseline,
        )
        valid = classify_response(
            {
                "status": 200,
                "url": "https://portal.example/api/orders",
                "contentType": "application/json",
                "body": b'{"items":[],"total":0}',
            },
            baseline,
        )
        redacted_runtime = classify_response(
            {
                "status": 200,
                "url": "https://portal.example/api/profile",
                "contentType": "application/json",
                "body": b'{"code":{"type":"integer"},"profile":{"accountId":{"type":"string"}}}',
            },
            baseline,
        )
        redirected = classify_response(
            {
                "status": 200,
                "requestedUrl": "https://portal.example/api/orders",
                "url": "https://portal.example/login",
                "contentType": "text/html",
                "body": b"<html>authentication required</html>",
            }
        )
        application_error = classify_response(
            {
                "status": 200,
                "url": "https://portal.example/api/orders",
                "contentType": "application/json",
                "body": b'{"returnCode":"500","returnMessage":"Internal Server Error"}',
            }
        )
        token_boundary = classify_response(
            {
                "status": 200,
                "url": "https://portal.example/api/tokenLogin",
                "contentType": "application/json",
                "body": '{"rtnCode":"-9999","rtnMsg":"token不存在"}'.encode(),
            }
        )
        self.assertEqual(real["state"], "rejected")
        self.assertEqual(fake_json["reason"], "fake-200-not-found-body")
        self.assertEqual(fake_shell["reason"], "fake-200-fallback-match")
        self.assertEqual(valid["state"], "reachable")
        self.assertEqual(redacted_runtime["state"], "reachable")
        self.assertEqual(redirected["reason"], "redirected-boundary")
        self.assertEqual(
            application_error["reason"],
            "application-server-error",
        )
        self.assertEqual(
            token_boundary["reason"],
            "application-authentication-boundary",
        )
        cors = classify_cors(
            {
                "status": 200,
                "url": "https://portal.example/api/customer",
                "responseHeaders": {
                    "access-control-allow-origin": [
                        "https://blue-sec.invalid"
                    ],
                    "access-control-allow-credentials": ["true"],
                },
            },
            "https://blue-sec.invalid",
        )
        self.assertEqual(
            cors["reason"],
            "credentialed-arbitrary-origin-reflection",
        )
        self.assertIsNotNone(
            UNSAFE_READ_PATH_RE.search("/api/account/resetPassword")
        )
        self.assertIsNone(UNSAFE_READ_PATH_RE.search("/api/account/detail"))

    def test_unified_surface_keeps_account_feature_and_runtime_only_api(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            body_path = root / "password.json"
            body_path.write_text('{"code":0}', encoding="utf-8")
            (root / "account.js").write_text(
                """
                const routes = [{
                  path: "/account/password",
                  name: "account-password",
                  meta: {title: "Change password"}
                }];
                const policy = {
                  resetCredential: {permission: "account:credential:reset"}
                };
                axios.post("/api/account/password/reset", {accountId});
                """,
                encoding="utf-8",
            )
            graph = {
                "endpoints": [
                    {
                        "path": "/api/account/password/reset",
                        "method": "POST",
                        "source": str(root / "account.js"),
                        "line": 10,
                        "offset": 330,
                        "directFields": ["accountId"],
                    }
                ]
            }
            browser = {
                "pagesVisited": ["https://portal.example/#/account/password"],
                "responses": [
                    {
                        "url": "https://portal.example/api/account/profile",
                        "method": "GET",
                        "status": 200,
                        "resourceType": "xhr",
                        "contentType": "application/json",
                        "localPath": str(body_path),
                        "requestFields": [],
                    }
                ],
                "uiControls": [
                    {
                        "id": "ui:account-name",
                        "page": "https://portal.example/#/account/password",
                        "tag": "input",
                        "type": "text",
                        "placeholder": "Account name",
                        "visible": True,
                        "disabled": False,
                        "exerciseState": "observed-only",
                        "value": "must-not-persist",
                    }
                ],
                "navigationFailures": [],
                "navigationQueueRemaining": 0,
            }
            collection = {"records": [], "queueRemaining": 0}
            inventory = build_surface_inventory(
                "https://portal.example/",
                [root],
                graph,
                browser,
                collection,
                coverage_context={
                    "expectedRoleIds": ["member"],
                    "observedRoleIds": ["member"],
                },
            )
            route = next(
                item
                for item in inventory["features"]
                if item["id"] == "route:/account/password"
            )
            permission = next(
                item
                for item in inventory["features"]
                if item["id"] == "permission:account:credential:reset"
            )
            runtime_api = next(
                item
                for item in inventory["apis"]
                if item["path"] == "/api/account/profile"
            )
            write_api = next(
                item
                for item in inventory["apis"]
                if item["path"] == "/api/account/password/reset"
            )
            self.assertEqual(route["name"], "account-password")
            self.assertEqual(permission["name"], "resetCredential")
            self.assertEqual(runtime_api["validation"]["state"], "runtime-observed")
            self.assertEqual(runtime_api["urlResolution"]["state"], "observed")
            self.assertEqual(write_api["validation"]["state"], "unverified")
            self.assertEqual(inventory["totals"]["validApis"], 1)
            self.assertEqual(inventory["assessmentState"], "interim")
            control = next(
                item
                for item in inventory["features"]
                if item["id"] == "ui:account-name"
            )
            self.assertEqual(control["control"]["placeholder"], "Account name")
            self.assertNotIn("value", control["control"])

    def test_runtime_not_found_api_is_not_counted_as_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing = root / "missing.json"
            missing.write_text(
                '{"status":404,"message":"not found"}',
                encoding="utf-8",
            )
            browser = {
                "pagesVisited": [],
                "responses": [
                    {
                        "url": "https://ops.example/api/jobs/missing",
                        "method": "GET",
                        "status": 200,
                        "resourceType": "fetch",
                        "contentType": "application/json",
                        "localPath": str(missing),
                    }
                ],
                "uiControls": [],
                "navigationFailures": [],
                "navigationQueueRemaining": 0,
            }
            inventory = build_surface_inventory(
                "https://ops.example/",
                [root],
                {"endpoints": []},
                browser,
                {"records": [], "queueRemaining": 0},
                coverage_context={
                    "expectedRoleIds": ["operator"],
                    "observedRoleIds": ["operator"],
                },
            )
            self.assertEqual(inventory["totals"]["validApis"], 0)
            self.assertEqual(
                inventory["apis"][0]["validation"]["reason"],
                "fake-200-not-found-body",
            )

    def test_spa_fallback_navigation_is_not_counted_as_rendered_route(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "routes.js").write_text(
                'const routes = [{path:"/admin/hidden"}];',
                encoding="utf-8",
            )
            browser = {
                "pagesVisited": [],
                "navigationAttempts": [
                    {
                        "requestedUrl": "https://portal.example/#/admin/hidden",
                        "effectiveUrl": "https://portal.example/#/admin/hidden",
                        "state": "visited",
                        "status": 200,
                        "render": {
                            "state": "rejected",
                            "reason": "spa-fallback-fingerprint",
                        },
                    }
                ],
                "responses": [],
                "uiControls": [],
                "navigationFailures": [],
                "navigationQueueRemaining": 0,
            }
            inventory = build_surface_inventory(
                "https://portal.example/",
                [root],
                {"endpoints": []},
                browser,
                {"records": [], "queueRemaining": 0},
                coverage_context={
                    "expectedRoleIds": ["member"],
                    "observedRoleIds": ["member"],
                },
            )
            route = next(
                item for item in inventory["routes"] if item["path"] == "/admin/hidden"
            )
            self.assertEqual("rejected", route["validation"]["state"])
            self.assertEqual(0, inventory["totals"]["renderedRoutes"])
            self.assertIn("/admin/hidden", inventory["unvisitedRoutes"])

    def test_observed_dynamic_route_satisfies_template_without_value_storage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.js").write_text(
                'const routes = [{path: "/orders/:orderId"}];',
                encoding="utf-8",
            )
            browser = {
                "pagesVisited": ["https://portal.example/orders/{id}"],
                "navigationAttempts": [
                    {
                        "requestedUrl": "https://portal.example/orders/{id}",
                        "state": "visited",
                        "status": 200,
                        "render": {"state": "rendered"},
                        "controlRefs": [],
                        "runtimeApiRefs": [],
                        "lazyChunkRefs": [],
                    }
                ],
                "responses": [],
                "uiControls": [],
                "navigationFailures": [],
                "navigationQueueRemaining": 0,
            }
            inventory = build_surface_inventory(
                "https://portal.example/",
                [root],
                {"endpoints": []},
                browser,
                {"records": [], "queueRemaining": 0},
                coverage_context={
                    "expectedRoleIds": ["member"],
                    "observedRoleIds": ["member"],
                },
            )
            self.assertEqual(1, len(inventory["routes"]))
            route = inventory["routes"][0]
            self.assertEqual("/orders/:orderId", route["path"])
            self.assertEqual("observed", route["parameterState"])
            self.assertEqual("runtime-visited", route["validation"]["state"])
            self.assertFalse(route["parameterSources"][0]["valuePersisted"])
            self.assertEqual([], inventory["unvisitedRoutes"])

    def test_runtime_spa_shell_fallback_is_not_counted_as_api(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shell = root / "index.html"
            shell.write_text(
                "<!doctype html><html><div id=app></div></html>",
                encoding="utf-8",
            )
            browser = {
                "pagesVisited": [],
                "responses": [
                    {
                        "url": "https://console.example/",
                        "method": "GET",
                        "status": 200,
                        "resourceType": "document",
                        "contentType": "text/html",
                        "localPath": str(shell),
                    },
                    {
                        "url": "https://console.example/api/invented",
                        "method": "GET",
                        "status": 200,
                        "resourceType": "xhr",
                        "contentType": "text/html",
                        "localPath": str(shell),
                    },
                ],
                "uiControls": [],
                "navigationFailures": [],
                "navigationQueueRemaining": 0,
            }
            inventory = build_surface_inventory(
                "https://console.example/",
                [root],
                {"endpoints": []},
                browser,
                {"records": [], "queueRemaining": 0},
                coverage_context={
                    "expectedRoleIds": ["analyst"],
                    "observedRoleIds": ["analyst"],
                },
            )
            self.assertEqual(inventory["totals"]["validApis"], 0)
            self.assertEqual(
                inventory["apis"][0]["validation"]["reason"],
                "fake-200-fallback-match",
            )

    def test_static_assets_produce_endpoint_graph(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = root / "assets"
            output = root / "analysis"
            assets.mkdir()
            (assets / "notebook.js").write_text(
                """
                export function createNotebook(projectId, imageVersionId, quota) {
                  return axios.post("/api/notebook/create", {
                    projectId, imageVersionId, quota
                  });
                }
                export function projectDetail(projectId) {
                  return axios.get("/api/project/detail", {
                    params: { projectId }
                  });
                }
                """,
                encoding="utf-8",
            )
            graph = self.run_graph(assets, output)
            paths = {item["path"] for item in graph["endpoints"]}
            self.assertIn("/api/notebook/create", paths)
            self.assertIn("/api/project/detail", paths)
            self.assertTrue((output / "report.md").is_file())

    def test_commerce_workflow_uses_structure_not_compute_terms(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = root / "assets"
            output = root / "analysis"
            assets.mkdir()
            (assets / "commerce.js").write_text(
                """
                export function orderDetail(orderId) {
                  return axios.get("/commerce/order/detail", {
                    params: { orderId }
                  });
                }
                export function createRefund(orderId, paymentId, amount) {
                  return axios.post("/finance/refund/create", {
                    orderId, paymentId, amount
                  });
                }
                export function refundStatus(orderId) {
                  return axios.get("/finance/refund/status", {
                    params: { orderId }
                  });
                }
                """,
                encoding="utf-8",
            )
            graph = self.run_graph(assets, output)
            creator = next(
                item
                for item in graph["endpoints"]
                if item["path"] == "/finance/refund/create"
            )
            self.assertIn("transaction", creator["tags"]["business_object"])
            self.assertIn("financial", creator["tags"]["sensitive_capability"])
            self.assertTrue(
                any(
                    chain["creator"]["path"] == "/finance/refund/create"
                    and any(
                        item["path"] == "/commerce/order/detail"
                        for item in chain["prerequisites"]
                    )
                    for chain in graph["chains"]
                )
            )

    def test_chinese_workflow_and_fields_are_semantically_tagged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = root / "assets"
            output = root / "analysis"
            assets.mkdir()
            (assets / "审批流程.js").write_text(
                """
                export function 查询申请(申请编号) {
                  return axios.get("/业务/申请/详情", {
                    params: {"申请编号": 申请编号}
                  });
                }
                export function 提交审批(申请编号, 部门编号) {
                  return axios.post("/业务/审批/提交", {
                    "申请编号": 申请编号,
                    "部门编号": 部门编号
                  });
                }
                export function 查询审批记录(申请编号) {
                  return axios.get("/业务/审批/记录", {
                    params: {"申请编号": 申请编号}
                  });
                }
                """,
                encoding="utf-8",
            )
            graph = self.run_graph(assets, output)
            creator = next(
                item
                for item in graph["endpoints"]
                if item["path"] == "/业务/审批/提交"
            )
            self.assertIn("submit", creator["tags"]["write_action"])
            self.assertIn("workflow", creator["tags"]["business_object"])
            self.assertIn("approval", creator["tags"]["gate"])
            self.assertIn("申请编号", creator["fields"])
            self.assertTrue(
                any(
                    chain["creator"]["path"] == "/业务/审批/提交"
                    for chain in graph["chains"]
                )
            )

    def test_shared_identifier_builds_chain_without_domain_keywords(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = root / "assets"
            output = root / "analysis"
            assets.mkdir()
            (assets / "neutral.js").write_text(
                """
                export function first(opaqueObjectKey) {
                  return axios.get("/svc/a/x", {
                    params: { opaqueObjectKey }
                  });
                }
                export function second(opaqueObjectKey) {
                  return axios.post("/svc/a/y", {
                    opaqueObjectKey
                  });
                }
                """,
                encoding="utf-8",
            )
            graph = self.run_graph(assets, output)
            creator = next(
                item for item in graph["endpoints"] if item["path"] == "/svc/a/y"
            )
            self.assertNotIn("business_object", creator["tags"])
            self.assertNotIn("resource", creator["tags"])
            self.assertTrue(
                any(
                    chain["creator"]["path"] == "/svc/a/y"
                    and any(
                        item["path"] == "/svc/a/x"
                        for item in chain["prerequisites"]
                    )
                    for chain in graph["chains"]
                )
            )

    def test_lexicon_rejects_target_specific_supplements(self) -> None:
        failures = validate_lexicon(
            {
                "schema_version": 1,
                "categories": {
                    "business_object": {
                        "target-object": [
                            "https://target.example/api/private",
                            "10.0.0.8",
                        ]
                    }
                },
            },
            "fixture",
        )
        self.assertTrue(any("target-specific alias" in item for item in failures))

    def test_lexicon_rejects_ad_hoc_taxonomy_categories(self) -> None:
        failures = validate_lexicon(
            {
                "schema_version": 1,
                "categories": {
                    "customer-specific-widget": {
                        "private-concept": ["internal widget"]
                    }
                },
            },
            "fixture",
        )
        self.assertTrue(
            any("unknown taxonomy category" in item for item in failures)
        )

    def test_active_skill_has_no_original_target_identifiers(self) -> None:
        skill = ROOT / "skills" / "spa-security-object-graph"
        active = [
            skill / "SKILL.md",
            skill / "references" / "heuristics.md",
            *sorted((skill / "scripts").glob("*.py")),
        ]
        material = "\n".join(path.read_text(encoding="utf-8") for path in active)
        for forbidden in (
            "ai." + "csg.cn",
            "/train/task",
            "jupyter-address",
            "hashrateId",
            "imageVersionId",
        ):
            self.assertNotIn(forbidden, material)


if __name__ == "__main__":
    unittest.main()
