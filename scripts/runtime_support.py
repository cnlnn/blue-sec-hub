#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIN_PYTHON = (3, 11)


def managed_python() -> Path:
    if os.name == "nt":
        return ROOT / ".venv" / "Scripts" / "python.exe"
    return ROOT / ".venv" / "bin" / "python"


def python_ready() -> bool:
    return sys.version_info >= MIN_PYTHON


def python_has_playwright(runtime: Path) -> bool:
    if not runtime.is_file():
        return False
    return subprocess.run(
        [str(runtime), "-c", "import playwright.sync_api"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def system_browser() -> str | None:
    for name in (
        "google-chrome-stable",
        "google-chrome",
        "chromium",
        "chromium-browser",
        "msedge",
    ):
        if path := shutil.which(name):
            return path
    candidates = [
        Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
    ]
    for variable in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
        if root := os.environ.get(variable):
            candidates.extend(
                (
                    Path(root) / "Google/Chrome/Application/chrome.exe",
                    Path(root) / "Chromium/Application/chrome.exe",
                    Path(root) / "Microsoft/Edge/Application/msedge.exe",
                )
            )
    return next((str(path) for path in candidates if path.is_file()), None)


def bundled_browser(runtime: Path) -> bool:
    if not python_has_playwright(runtime):
        return False
    return subprocess.run(
        [
            str(runtime),
            "-c",
            "from pathlib import Path; from playwright.sync_api import sync_playwright; "
            "p=sync_playwright().start(); x=p.chromium.executable_path; p.stop(); "
            "raise SystemExit(not Path(x).is_file())",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def playwright_runtime() -> Path | None:
    candidates = [Path(sys.executable), managed_python()]
    return next((runtime for runtime in candidates if python_has_playwright(runtime)), None)


def browser_status() -> dict[str, str | None]:
    runtime = playwright_runtime()
    browser = system_browser()
    if runtime and (browser or bundled_browser(runtime)):
        status = "ready"
    elif runtime:
        status = "broken"
    else:
        status = "not-installed"
    return {
        "status": status,
        "runtime": str(runtime) if runtime else None,
        "browser": browser,
    }


def runtime_status() -> dict[str, object]:
    return {
        "python_runtime": {
            "status": "ready" if python_ready() else "unsupported-version",
            "executable": sys.executable,
            "version": ".".join(str(item) for item in sys.version_info[:3]),
        },
        "core_runtime": {"status": "ready" if python_ready() else "unsupported-version"},
        "package_manager": "uv" if shutil.which("uv") else "stdlib",
        "optional_browser": browser_status(),
    }
