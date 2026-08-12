#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CACHE_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_CACHE",
        Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "blue-sec-hub",
    )
)


def load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def run_sync(*arguments: str) -> int:
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts/sync_sources.py"), *arguments],
        cwd=ROOT,
        check=False,
    ).returncode


def diff() -> dict:
    active = load(ROOT / "sources.lock.json")
    candidate = load(CACHE_ROOT / "source-candidates/lock.json")
    if not candidate:
        return {
            "status": "not-refreshed",
            "instruction_authority": None,
            "required_checks": [],
            "changes": [],
        }
    changes = []
    names = sorted(set(active.get("sources", {})) | set(candidate.get("sources", {})))
    for name in names:
        before = active.get("sources", {}).get(name, {})
        after = candidate.get("sources", {}).get(name, {})
        changes.append(
            {
                "source": name,
                "from_commit": before.get("commit"),
                "to_commit": after.get("commit"),
                "changed": before.get("commit") != after.get("commit"),
                "trust": after.get("trust"),
                "content_policy": after.get("content_policy"),
            }
        )
    return {
        "status": candidate.get("review", {}).get("status", "not-refreshed"),
        "instruction_authority": candidate.get("review", {}).get("instruction_authority"),
        "required_checks": candidate.get("review", {}).get("required_checks", []),
        "changes": changes,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Review and activate security knowledge sources")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("refresh")
    commands.add_parser("diff")
    approve = commands.add_parser("approve")
    approve.add_argument(
        "--reviewed",
        action="store_true",
        help="Confirm that the candidate diff and required checks were reviewed",
    )
    commands.add_parser("status")
    args = parser.parse_args()
    if args.command == "refresh":
        raise SystemExit(run_sync("--refresh"))
    if args.command == "approve":
        if not args.reviewed:
            raise SystemExit("approval requires --reviewed after blue-sec-knowledge diff")
        raise SystemExit(run_sync("--approve", "--reviewed"))
    print(json.dumps(diff(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
