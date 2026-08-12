#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path

import runtime_support

ROOT = Path(__file__).resolve().parents[1]
ANALYZER = (
    ROOT
    / "skills"
    / "spa-security-object-graph"
    / "scripts"
    / "analyze_url.py"
)


def main() -> None:
    runtime = Path(sys.executable)
    if "--browser" in sys.argv:
        runtime = runtime_support.playwright_runtime() or runtime
    os.execv(str(runtime), [str(runtime), str(ANALYZER), *sys.argv[1:]])


if __name__ == "__main__":
    main()
