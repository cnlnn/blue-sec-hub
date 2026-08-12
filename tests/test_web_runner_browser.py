from __future__ import annotations

import json
import io
import os
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import web_runner


class BrowserFixture(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/api/profile":
            body = b'{"code":0,"profile":{"accountId":"shape-only"}}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path not in {"/", "/dashboard"}:
            self.send_error(404)
            return
        marker = "home" if path == "/" else "dashboard"
        body = f"""<!doctype html>
<html><head><title>{marker}</title></head>
<body data-route=\"{marker}\">
  <a href=\"/dashboard\">Dashboard</a>
  <button role=\"tab\">Overview</button>
  <main>{marker}</main>
  <script>fetch('/api/profile')</script>
</body></html>""".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@unittest.skipUnless(
    os.environ.get("BLUE_SEC_BROWSER_TESTS") == "1",
    "real Chromium integration is enabled only in its dedicated CI job",
)
class WebRunnerBrowserTest(unittest.TestCase):
    def test_anonymous_browser_collection_exhausts_current_routes(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), BrowserFixture)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary) / "assessment"
                target = f"http://127.0.0.1:{server.server_port}/"
                raw_requests = []
                inventory_path = web_runner.browser_collection(
                    workspace,
                    target,
                    "anonymous",
                    {},
                    None,
                    True,
                    raw_requests,
                )
                self.assertIsNotNone(inventory_path)
                inventory = json.loads(
                    inventory_path.read_text(encoding="utf-8")
                )
                routes = {item["path"]: item for item in inventory["routes"]}
                self.assertIn("/dashboard", routes)
                self.assertEqual(
                    "runtime-visited",
                    routes["/dashboard"]["validation"]["state"],
                )
                self.assertFalse(
                    (workspace / ".runtime" / "runner-headers-anonymous.json").exists()
                )
                self.assertTrue(
                    any(item.url.endswith("/api/profile") for item in raw_requests)
                )
                self.assertFalse(
                    (workspace / ".runtime" / "request-corpus-anonymous.json").exists()
                )
                args = SimpleNamespace(
                    workspace=workspace,
                    target=target,
                    header_file=None,
                    credential_lease=None,
                    consume_auth=False,
                    storage_state=None,
                    har=None,
                    refresh=False,
                    requests_per_second=1000.0,
                )
                with redirect_stdout(io.StringIO()):
                    return_code = web_runner.execute(args)
                state = json.loads(
                    (workspace / "runner-state.json").read_text(encoding="utf-8")
                )
                self.assertEqual(2, return_code)
                self.assertEqual("needs-agent", state["status"])
                self.assertFalse((workspace / ".runner.lock").exists())
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
