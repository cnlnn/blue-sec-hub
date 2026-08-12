from __future__ import annotations

import argparse
from bisect import bisect_right
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path


ROUTE_RE = re.compile(
    r"(?P<kind>path|redirect)\s*:\s*['\"`](?P<value>[^'\"`]{1,180})['\"`]"
)
ROUTE_NAME_RE = re.compile(r"\bname\s*:\s*['\"`]([^'\"`]{1,180})['\"`]")
ROUTE_TITLE_RE = re.compile(r"\btitle\s*:\s*['\"`]([^'\"`]{1,180})['\"`]")
CHUNK_RE = re.compile(
    r"(?:\bn\.e|import)\s*\(\s*['\"`]([^'\"`]{1,180})['\"`]\s*\)"
)
ASSET_PATH_RE = re.compile(r"\.[A-Za-z0-9]{2,5}(?:\?|$)")
DYNAMIC_PARAM_RE = re.compile(r":([A-Za-z_$][\w$]*)")


def route_definitions(text: str) -> list[dict]:
    definitions = []
    newline_offsets = [
        index for index, character in enumerate(text) if character == "\n"
    ]
    for match in ROUTE_RE.finditer(text):
        value = match.group("value")
        if not value.startswith("/") or value.startswith("//"):
            continue
        if ASSET_PATH_RE.search(value):
            continue
        route = value
        next_match = ROUTE_RE.search(text, match.end())
        end = min(
            len(text),
            match.end() + 1200,
            next_match.start() if next_match else len(text),
        )
        context = text[match.end():end]
        name_match = ROUTE_NAME_RE.search(context)
        title_match = ROUTE_TITLE_RE.search(context)
        chunk_match = CHUNK_RE.search(context)
        definitions.append(
            {
                "path": route,
                "definitionType": match.group("kind"),
                "offset": match.start(),
                "line": bisect_right(newline_offsets, match.start()) + 1,
                "name": name_match.group(1) if name_match else None,
                "title": title_match.group(1) if title_match else None,
                "chunk": chunk_match.group(1) if chunk_match else None,
            }
        )
    return definitions


def route_candidates(text: str) -> set[str]:
    return {item["path"] for item in route_definitions(text)}


def route_parameter_names(route: str) -> list[str]:
    return sorted(set(DYNAMIC_PARAM_RE.findall(route)))


def route_is_safe_to_visit(route: str) -> bool:
    # A route name is not an HTTP mutation. Navigation is read-only and the
    # browser request guard decides whether page-initiated requests may run.
    return not route_parameter_names(route)


def route_id(route: str) -> str:
    digest = hashlib.sha256(route.encode()).hexdigest()[:16]
    return f"route-{digest}"


def build_route_inventory(asset_root: Path) -> dict:
    evidence: dict[str, list[dict]] = {}
    for path in sorted(asset_root.rglob("*")):
        if not path.is_file() or path.suffix.casefold() not in {".js", ".mjs", ".cjs"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for definition in route_definitions(text):
            item = {"source": str(path), **definition}
            if item not in evidence.setdefault(definition["path"], []):
                evidence[definition["path"]].append(item)
    routes = [
        {
            "id": route_id(route),
            "path": route,
            "pathTemplate": route,
            "parameterNames": route_parameter_names(route),
            "parameterState": (
                "unresolved" if route_parameter_names(route) else "not-required"
            ),
            "navigation": (
                "eligible" if route_is_safe_to_visit(route) else "blocked-parameters"
            ),
            "sources": sorted({item["source"] for item in evidence[route]}),
            "evidence": sorted(
                evidence[route],
                key=lambda item: (item["source"], item["offset"]),
            ),
        }
        for route in sorted(evidence)
    ]
    return {
        "schemaVersion": 1,
        "generatedAt": datetime.now(UTC).isoformat(),
        "assetRoot": str(asset_root.resolve()),
        "totals": {
            "routes": len(routes),
            "eligibleForVisit": sum(
                item["navigation"] == "eligible" for item in routes
            ),
            "skippedForSafety": sum(
                item["navigation"] == "blocked-parameters" for item in routes
            ),
            "blockedParameters": sum(
                item["navigation"] == "blocked-parameters" for item in routes
            ),
        },
        "routes": routes,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a complete offline SPA route inventory"
    )
    parser.add_argument("asset_root", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    inventory = build_route_inventory(args.asset_root)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(inventory, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    args.out.chmod(0o600)
    print(
        f"[ok] routes={inventory['totals']['routes']} "
        f"eligible={inventory['totals']['eligibleForVisit']} "
        f"skipped={inventory['totals']['skippedForSafety']} "
        f"out={args.out}"
    )


if __name__ == "__main__":
    main()
