#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from security_terms import expand_query
from knowledge_index import build as build_index
from knowledge_index import search as indexed_search


ROOT = Path(__file__).resolve().parents[1]
CACHE_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_CACHE",
        Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
        / "blue-sec-hub",
    )
)
DATA_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_DATA",
        Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        / "blue-sec-hub",
    )
)


def python_search(
    roots: list[str],
    terms: list[str],
    regex: bool,
) -> list[str]:
    flags = re.IGNORECASE
    patterns = [
        re.compile(term if regex else re.escape(term), flags)
        for term in terms
    ]
    matches: list[str] = []
    for root in roots:
        for path in sorted(Path(root).rglob("*")):
            if not path.is_file():
                continue
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue
            for number, line in enumerate(lines, start=1):
                if any(pattern.search(line) for pattern in patterns):
                    matches.append(f"{path}:{number}:{line}")
    return matches


def main() -> None:
    parser = argparse.ArgumentParser(description="Search Blue Sec Hub knowledge")
    parser.add_argument("pattern")
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument(
        "--regex",
        action="store_true",
        help="Treat pattern as a regular expression and disable term expansion",
    )
    parser.add_argument(
        "--no-expand",
        action="store_true",
        help="Search the literal input without bilingual terminology expansion",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Print the machine-readable query expansion before matches",
    )
    parser.add_argument(
        "--source",
        choices=(
            "all",
            "upstreams",
            "vendored",
            "feeds",
            "overlays",
            "internal",
            "reports",
        ),
        default="all",
    )
    parser.add_argument("--rebuild", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    roots: list[tuple[str, Path]] = []
    if args.source in {"all", "overlays"}:
        roots.append(("overlays", DATA_ROOT / "overlays"))
        roots.append(("overlays", DATA_ROOT / "effective" / "current" / "knowledge"))
    if args.source in {"all", "upstreams", "vendored"}:
        roots.append(("upstreams", CACHE_ROOT / "upstreams"))
    if args.source in {"all", "vendored"}:
        roots.append(("vendored", ROOT / "knowledge"))
    if args.source in {"all", "feeds"}:
        roots.append(("feeds", CACHE_ROOT / "feeds"))
    if args.source in {"all", "internal"}:
        roots.append(("internal", DATA_ROOT / "internal" / "documents"))
    if args.source in {"all", "reports"}:
        roots.append(("reports", DATA_ROOT / "report-intelligence"))
    existing_roots = [(kind, path) for kind, path in roots if path.exists()]
    existing = [str(path) for _, path in existing_roots]
    if not existing:
        raise SystemExit("no indexed knowledge sources found")

    expansion = (
        {
            "query": args.pattern,
            "canonical": [],
            "matched_triggers": [],
            "candidate_matches": [],
            "search_terms": [args.pattern],
        }
        if args.regex or args.no_expand
        else expand_query(args.pattern)
    )
    if args.rebuild:
        build_index(existing_roots)
    if not args.regex:
        matches = indexed_search(expansion["search_terms"], existing_roots, args.limit)
        if args.explain:
            print(json.dumps(expansion, ensure_ascii=False, sort_keys=True))
        if args.json:
            print(json.dumps(matches, ensure_ascii=False, indent=2))
            return
        for match in matches:
            body = str(match["body"]).replace("\n", " ")
            print(
                f"{match['path']}:{match['line_start']}:{body} "
                f"[source={match['source_name']} commit={match['source_commit']} "
                f"trust={match['trust']} instruction_authority=false]"
            )
        return
    if shutil.which("rg"):
        command = [
            "rg",
            "-n",
            "-i",
            "--no-heading",
            "--color",
            "never",
        ]
        if not args.regex:
            command.append("--fixed-strings")
        for term in expansion["search_terms"]:
            command.extend(("-e", term))
        command.extend(existing)
        result = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode not in {0, 1}:
            raise SystemExit(result.stderr.strip())
        lines = result.stdout.splitlines()
    else:
        lines = python_search(existing, expansion["search_terms"], args.regex)
    if args.explain:
        print(json.dumps(expansion, ensure_ascii=False, sort_keys=True))
    for line in lines[: args.limit]:
        print(line)
    if len(lines) > args.limit:
        print(f"[truncated] {len(lines) - args.limit} more matches")


if __name__ == "__main__":
    main()
