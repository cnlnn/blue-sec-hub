#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

import runtime_support


ROOT = Path(__file__).resolve().parents[1]


def venv_python() -> Path:
    return runtime_support.managed_python()


def system_browser_available() -> bool:
    if any(
        shutil.which(name)
        for name in (
            "google-chrome-stable",
            "google-chrome",
            "chromium",
            "chromium-browser",
            "msedge",
        )
    ):
        return True
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
    return any(path.is_file() for path in candidates)


def pip_bootstrap() -> None:
    runtime = venv_python()
    if not runtime.is_file():
        venv.EnvBuilder(with_pip=True, clear=False).create(ROOT / ".venv")
    subprocess.run(
        [
            str(runtime),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "playwright>=1.50,<2",
        ],
        cwd=ROOT,
        check=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare Blue Sec Hub Python runtime")
    parser.add_argument(
        "--with-spa-browser",
        action="store_true",
        help="Install the optional Python Playwright dependency",
    )
    parser.add_argument(
        "--install-browser-if-missing",
        action="store_true",
        help="Download Playwright Chromium only when no supported system browser exists",
    )
    parser.add_argument(
        "--install-browser",
        action="store_true",
        help="Also download Playwright Chromium; system Chrome is preferred otherwise",
    )
    args = parser.parse_args()

    with_browser = (
        args.with_spa_browser or args.install_browser or args.install_browser_if_missing
    )
    if sys.version_info < (3, 11):
        raise SystemExit("Blue Sec Hub requires Python 3.11+")
    if not with_browser:
        print(f"[ok] core=ready runtime={sys.executable} manager=stdlib browser=not-requested")
        return

    manager = "uv" if (uv := shutil.which("uv")) else "venv-pip"
    try:
        if uv:
            subprocess.run(
                [uv, "sync", "--locked", "--extra", "spa-browser"],
                cwd=ROOT,
                check=True,
            )
        else:
            pip_bootstrap()
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"[degraded] core=ready browser=not-installed manager={manager} error={error}")
        raise SystemExit(2) from error

    install_browser = args.install_browser or (
        args.install_browser_if_missing and not system_browser_available()
    )
    if install_browser:
        subprocess.run(
            [str(venv_python()), "-m", "playwright", "install", "chromium"],
            cwd=ROOT,
            check=True,
        )
    print(f"[ok] core=ready runtime={venv_python()} manager={manager} browser=ready")


if __name__ == "__main__":
    main()
