#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any


SOURCE_SUFFIXES = {".go", ".java", ".kt", ".js", ".jsx", ".ts", ".tsx", ".py", ".rb", ".cs", ".php"}
ROUTE_PATTERNS = (
    re.compile(r"@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:value\s*=\s*)?[\"']([^\"']+)", re.I),
    re.compile(r"@(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)", re.I),
    re.compile(r"\b(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*[\"']([^\"']+)", re.I),
    re.compile(r"\.(GET|POST|PUT|PATCH|DELETE)\s*\(\s*[\"']([^\"']+)", re.I),
)
AUTH_RE = re.compile(r"authorize|permission|hasRole|hasAuthority|RequireAuth|middleware.*auth|currentUser|principal|鉴权|权限", re.I)
OBJECT_RE = re.compile(r"findById|where\s*\(|findOne|query|repository|owner|tenant|orgId|userId|对象|租户", re.I)


def stable_id(value: Any) -> str:
    return "source-route-" + hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:16]


def method_and_path(match: re.Match[str], text: str) -> tuple[str, str]:
    groups = match.groups()
    if len(groups) == 1:
        annotation = text[match.start() : match.start() + 24]
        method_match = re.search(r"@(Get|Post|Put|Patch|Delete)", annotation, re.I)
        return (method_match.group(1).upper() if method_match else "UNKNOWN", groups[0])
    return groups[0].upper(), groups[1]


def map_source(root: Path) -> dict[str, Any]:
    routes = []
    skipped = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.casefold() not in SOURCE_SUFFIXES:
            continue
        if any(part in {".git", "node_modules", "vendor", "dist", "build"} for part in path.parts):
            continue
        try:
            if path.stat().st_size > 4 * 1024 * 1024:
                skipped += 1
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped += 1
            continue
        lines = text.splitlines()
        for pattern in ROUTE_PATTERNS:
            for match in pattern.finditer(text):
                method, route = method_and_path(match, text)
                if not route.startswith("/"):
                    continue
                line = text.count("\n", 0, match.start()) + 1
                context = "\n".join(lines[max(0, line - 12) : min(len(lines), line + 30)])
                relative = path.relative_to(root).as_posix()
                routes.append(
                    {
                        "id": stable_id([relative, line, method, route]),
                        "method": method,
                        "path": route,
                        "source": {"file": relative, "line": line},
                        "control_signals": {
                            "authorization_check_nearby": bool(AUTH_RE.search(context)),
                            "object_query_nearby": bool(OBJECT_RE.search(context)),
                        },
                        "state": "static-source-candidate",
                    }
                )
    unique = {item["id"]: item for item in routes}
    ordered = sorted(unique.values(), key=lambda item: (item["path"], item["method"], item["id"]))
    return {
        "schema_version": 1,
        "source_root_hash": hashlib.sha256(str(root.resolve()).encode()).hexdigest(),
        "routes": ordered,
        "surfaces": [
            {
                "kind": "api",
                "method": item["method"],
                "url": item["path"],
                "validation_state": "documented",
                "profiles": ["source-correlated", "rest"],
                "source_refs": [f"source:{item['id']}"],
            }
            for item in ordered
        ],
        "skipped_files": skipped,
        "finding_policy": "source mapping is discovery and policy evidence, not runtime vulnerability proof",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Statically correlate source routes and nearby control signals")
    parser.add_argument("source_root", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    value = map_source(args.source_root.resolve())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if os.name != "nt":
        args.out.chmod(0o600)
    print(json.dumps({"routes": len(value["routes"]), "out": str(args.out)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
