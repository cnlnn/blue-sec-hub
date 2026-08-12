#!/usr/bin/env python3
"""Collect a SPA from one URL and build its security object graph."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from build_object_graph import extract_endpoints, write_report, EXTENSIONS
from collect_spa_assets import add_header_arguments, collect_site, load_headers
from surface_inventory import build_surface_inventory


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Starting domain or URL")
    parser.add_argument("--out", required=True, type=Path, help="Combined output directory")
    add_header_arguments(parser)
    parser.add_argument("--max-files", type=int, default=600)
    parser.add_argument("--max-mb", type=int, default=250)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--window", type=int, default=2400)
    parser.add_argument("--browser", action="store_true", help="Capture runtime lazy chunks with Chromium")
    parser.add_argument(
        "--browser-pages",
        type=int,
        default=0,
        help="Maximum browser route navigations; 0 exhausts the route queue",
    )
    parser.add_argument(
        "--browser-storage-state",
        type=Path,
        help="Playwright storage-state JSON; must be mode 0600 on POSIX",
    )
    parser.add_argument(
        "--verify-safe-reads",
        action="store_true",
        help="Validate discovered GET/HEAD APIs and reject real/fake not-found responses",
    )
    parser.add_argument("--probe-limit", type=int, default=200)
    parser.add_argument(
        "--coverage-context",
        type=Path,
        help="JSON with expected/observed role and business-state IDs",
    )
    parser.add_argument(
        "--request-corpus-out",
        type=Path,
        help="Private transient browser request corpus for the assessment runner",
    )
    parser.add_argument(
        "--seed-routes",
        type=Path,
        help="JSON route seed list; seeds require fresh browser validation",
    )
    args = parser.parse_args()

    asset_dir = args.out / "assets"
    analysis_dir = args.out / "analysis"
    headers = load_headers(args.header, args.header_file)
    collection_manifest = collect_site(
        args.url,
        asset_dir,
        headers,
        args.max_files,
        args.max_mb * 1024 * 1024,
        args.timeout,
    )
    roots = [asset_dir]
    runtime_flows = []
    browser_manifest = {}
    if args.browser:
        from collect_browser_assets import collect_browser_assets

        browser_dir = args.out / "browser-assets"
        browser_manifest = collect_browser_assets(
            args.url,
            browser_dir,
            headers,
            args.browser_pages,
            args.browser_storage_state,
            args.request_corpus_out,
            args.seed_routes,
        )
        runtime_flows = browser_manifest.get("dataFlows", [])
        roots.append(browser_dir)
    files = sorted({p for root in roots for p in root.rglob("*") if p.is_file() and p.suffix.lower() in EXTENSIONS})
    records = []
    seen_content = set()
    scanned = 0
    for path in files:
        try:
            body = path.read_bytes()
        except OSError:
            continue
        digest = hashlib.sha256(body).digest()
        if digest in seen_content:
            continue
        seen_content.add(digest)
        scanned += 1
        records.extend(extract_endpoints(path, body.decode("utf-8", errors="replace"), args.window))
    analysis_dir.mkdir(parents=True, exist_ok=True)
    write_report(records, analysis_dir, scanned, runtime_flows)
    graph = json.loads((analysis_dir / "graph.json").read_text(encoding="utf-8"))
    inventory = build_surface_inventory(
        args.url,
        roots,
        graph,
        browser_manifest,
        collection_manifest,
        args.verify_safe_reads,
        headers,
        args.timeout,
        args.probe_limit,
        coverage_context=(
            json.loads(args.coverage_context.read_text(encoding="utf-8"))
            if args.coverage_context
            else {}
        ),
    )
    inventory_path = analysis_dir / "surface-inventory.json"
    inventory_path.write_text(
        json.dumps(inventory, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    inventory_path.chmod(0o600)
    print(analysis_dir / "report.md")
    print(inventory_path)


if __name__ == "__main__":
    main()
