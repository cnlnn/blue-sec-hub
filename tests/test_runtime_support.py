from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import executor_native  # noqa: E402
import executor_adapter  # noqa: E402
import runtime_support  # noqa: E402
import spa_graph  # noqa: E402
import install  # noqa: E402
import doctor  # noqa: E402


class RuntimeSupportTest(unittest.TestCase):
    def test_core_runtime_does_not_depend_on_uv(self) -> None:
        with mock.patch("runtime_support.shutil.which", return_value=None):
            value = runtime_support.runtime_status()
        self.assertEqual("ready", value["core_runtime"]["status"])
        self.assertEqual("stdlib", value["package_manager"])

    def test_native_executor_remains_ready_without_uv_or_browser(self) -> None:
        spec = executor_adapter.load_executor_specs()["blue-sec-native"]
        with (
            mock.patch("executor_native.browser_runtime_ready", return_value=False),
            mock.patch("executor_native.shutil.which", return_value=None),
        ):
            value = executor_native.NativeExecutorAdapter(spec).capability()
        self.assertEqual("runtime-ready", value["status"])
        self.assertFalse(value["capabilities"]["browser"])

    def test_bootstrap_without_options_does_not_create_venv(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "bootstrap.py")],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        self.assertIn("manager=stdlib", result.stdout)

    def test_spa_launcher_has_no_hardcoded_virtualenv_runtime(self) -> None:
        source = Path(spa_graph.__file__).read_text(encoding="utf-8")
        self.assertNotIn(".venv", source)
        self.assertIn("Path(sys.executable)", source)

    def test_installer_knowledge_sync_is_optional_and_nonfatal(self) -> None:
        failed = subprocess.CompletedProcess([], 1, "", "network unavailable")
        with mock.patch("install.subprocess.run", return_value=failed):
            value = install.synchronize_knowledge()
        self.assertEqual("degraded", value["status"])
        self.assertEqual("knowledge-sync-failed", value["reason"])
        self.assertEqual("skipped", install.synchronize_knowledge(disabled=True)["status"])

    def test_luna_eval_is_never_claimed_without_configuration(self) -> None:
        with mock.patch.object(doctor, "DATA_ROOT", Path("/definitely/missing")):
            self.assertEqual("not-installed", doctor.luna_eval_health("missing")["status"])

    def test_luna_only_receipt_does_not_break_baseline_health(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            revision = root / "eval-results" / "revision"
            revision.mkdir(parents=True)
            (revision / "luna.json").write_text(
                '{"hosts":[{"host":"luna","model":"gpt-5.6-luna","cases":[]}]}',
                encoding="utf-8",
            )
            with mock.patch.object(doctor, "DATA_ROOT", root):
                self.assertIn(doctor.baseline_eval_health("revision")["status"], {"not-installed", "ready"})


if __name__ == "__main__":
    unittest.main()
