#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "skill_contracts.json"
ALL_PLATFORMS = [
    "codex",
    "claude",
    "gemini",
    "grok",
    "opencode",
    "openclaw",
    "hermes",
    "trae",
    "trae-cn",
]


def load_contract() -> dict[str, Any]:
    value = json.loads(CONTRACT.read_text(encoding="utf-8"))
    if value.get("schema_version") != 1:
        raise ValueError("unsupported skill contract schema")
    return value


def changed_paths(base: str, head: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", f"{base}...{head}"],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    return sorted({line for line in result.stdout.splitlines() if line})


def matches(path: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(path, pattern)


def classify(paths: list[str], contract: dict[str, Any] | None = None) -> dict[str, Any]:
    contract = contract or load_contract()
    levels = list(contract["levels"])
    selected_level = "content"
    platforms: set[str] = set()
    classifications = []
    unknown = []
    for path in paths:
        matched = [rule for rule in contract["rules"] if matches(path, str(rule["pattern"]))]
        if not matched:
            level = "core-runtime"
            unknown.append(path)
            rule_platforms = ALL_PLATFORMS
        else:
            rule = max(matched, key=lambda item: levels.index(str(item["level"])))
            level = str(rule["level"])
            rule_platforms = list(rule.get("platforms", []))
        if levels.index(level) > levels.index(selected_level):
            selected_level = level
        platforms.update(str(item) for item in rule_platforms)
        classifications.append({"path": path, "level": level, "platforms": rule_platforms})
    if selected_level == "core-runtime":
        platforms = set(ALL_PLATFORMS)
    gates = {
        "content": True,
        "unit": levels.index(selected_level) >= levels.index("functional-data"),
        "os_matrix": levels.index(selected_level) >= levels.index("executable"),
        "platform_matrix": selected_level in {"platform-runtime", "core-runtime"},
    }
    return {
        "schema_version": 1,
        "level": selected_level,
        "paths": paths,
        "classifications": classifications,
        "unknown_paths": unknown,
        "platforms": sorted(platforms),
        "gates": gates,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Select the minimum sufficient Blue Sec validation gates")
    parser.add_argument("--base")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--path", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    paths = args.path or changed_paths(args.base or f"{args.head}^", args.head)
    result = classify(paths)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
