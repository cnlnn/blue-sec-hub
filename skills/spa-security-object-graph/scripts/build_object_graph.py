#!/usr/bin/env python3
"""Build a best-effort security object graph from generic SPA text assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from semantic_lexicon import load_lexicon, tag_text

EXTENSIONS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".html", ".map"}

FIELD_RE = re.compile(
    r"(?<![A-Za-z0-9_$-])([A-Za-z_$][A-Za-z0-9_$-]{1,63}"
    r"(?:Id|Ids|ID|IDs|Uuid|UUID|Key|Code|No|Number|Type|Level|State|Status|"
    r"Version|Size|Limit|Amount|Price|Balance|Duration|Quota|Role|Token|Count|"
    r"Name|Path|Url|URL))"
    r"(?![A-Za-z0-9_$])"
)
CJK_FIELD_RE = re.compile(r"['\"]([\u3400-\u9fff]{2,16})['\"]\s*:")
METHOD_RE = re.compile(r"method\s*:\s*['\"](get|post|put|patch|delete)['\"]", re.I)
CONST_RE_TEMPLATE = r"(?:const|let|var)\s+{name}\s*=\s*['\"]([^'\"]+)['\"]"

URL_PATTERNS = [
    re.compile(r"url\s*:\s*((?:[A-Za-z_$][\w$]*\s*\+\s*)?['\"`][^'\"`]{1,240}['\"`])"),
    re.compile(r"\bfetch\s*\(\s*(['\"`][^'\"`]{1,240}['\"`])"),
    re.compile(r"\b(?:axios\.)?(get|post|put|patch|delete)\s*\(\s*(['\"`][^'\"`]{1,240}['\"`])", re.I),
]

def normalize_expression(expr: str, text: str, offset: int) -> str:
    pieces = re.findall(r"['\"`]([^'\"`]*)['\"`]", expr)
    path = "".join(pieces)
    prefix_match = re.match(r"\s*([A-Za-z_$][\w$]*)\s*\+", expr)
    if prefix_match:
        name = re.escape(prefix_match.group(1))
        nearby = text[max(0, offset - 3000):offset]
        matches = list(re.finditer(CONST_RE_TEMPLATE.format(name=name), nearby))
        if matches:
            path = matches[-1].group(1) + path
    return path


def extract_endpoints(path: Path, text: str, window: int) -> list[dict]:
    records = []
    seen = set()
    lexicon = load_lexicon()
    for pattern_index, pattern in enumerate(URL_PATTERNS):
        for match in pattern.finditer(text):
            if pattern_index == 2:
                explicit_method, expr = match.group(1).lower(), match.group(2)
            elif pattern_index == 1:
                expr = match.group(1)
                fetch_tail = text[match.end():min(len(text), match.end() + 600)]
                options = re.match(r"\s*,\s*\{(.{0,500}?)\}\s*\)", fetch_tail, re.S)
                fetch_method = METHOD_RE.search(options.group(1)) if options else None
                explicit_method = fetch_method.group(1).lower() if fetch_method else "get"
            else:
                explicit_method, expr = None, match.group(1)
            resolved = normalize_expression(expr, text, match.start())
            if not resolved or not ("/" in resolved or resolved.startswith("http")):
                continue
            key = (match.start(), resolved)
            if key in seen:
                continue
            seen.add(key)
            local = text[max(0, match.start() - window):min(len(text), match.end() + window)]
            method_match = METHOD_RE.search(text[match.start():min(len(text), match.end() + 350)])
            method = explicit_method or (method_match.group(1).lower() if method_match else "unknown")
            fields = sorted(set(FIELD_RE.findall(local)) | set(CJK_FIELD_RE.findall(local)))
            direct = text[max(0, match.start() - 180):min(len(text), match.end() + 520)]
            direct_fields = sorted(
                set(FIELD_RE.findall(direct)) | set(CJK_FIELD_RE.findall(direct))
            )
            tags = tag_text(f"{path.stem}\n{resolved}\n{local}", lexicon)
            score = 0
            reasons = []
            if method in {"post", "put", "patch", "delete"}:
                score += 3
                reasons.append("state-changing method")
            if tags.get("write_action"):
                score += 3
                reasons.append("write/action semantics")
            if tags.get("read_action"):
                score += 1
                reasons.append("read/action semantics")
            if tags.get("lifecycle_action"):
                score += 2
                reasons.append("lifecycle semantics")
            if tags.get("business_object"):
                score += 2
                reasons.append("business-object semantics")
            if tags.get("resource"):
                score += 2
                reasons.append("resource semantics")
            if tags.get("gate"):
                score += 3
                reasons.append("control-gate semantics")
            if tags.get("public_boundary"):
                score += 1
                reasons.append("public-boundary semantics")
            if tags.get("sensitive_capability"):
                score += 3
                reasons.append("sensitive-capability semantics")
            if fields:
                score += min(4, len(fields))
                reasons.append("client object fields")
            semantic_dimensions = sum(
                bool(tags.get(category))
                for category in (
                    "business_object",
                    "resource",
                    "gate",
                    "public_boundary",
                    "sensitive_capability",
                )
            )
            if semantic_dimensions >= 2:
                score += min(3, semantic_dimensions)
                reasons.append("cross-domain semantics")
            hypotheses = []
            object_semantics = tags.get("business_object") or tags.get("resource")
            if tags.get("write_action") and object_semantics and tags.get("gate"):
                hypotheses.append("gated object state transition")
            if tags.get("public_boundary") and object_semantics:
                hypotheses.append("public-to-controlled object flow")
            if tags.get("lifecycle_action") and object_semantics:
                hypotheses.append("object lifecycle control")
            if tags.get("sensitive_capability"):
                hypotheses.append("sensitive capability boundary")
            if method in {"post", "put", "patch", "delete"} and direct_fields:
                hypotheses.append("client-selected object state change")
            records.append({
                "path": resolved,
                "method": method.upper(),
                "source": str(path),
                "line": text.count("\n", 0, match.start()) + 1,
                "offset": match.start(),
                "rawExpression": expr,
                "fields": fields[:40],
                "directFields": direct_fields[:20],
                "tags": tags,
                "score": score,
                "reasons": reasons,
                "hypotheses": hypotheses,
                "contextDigest": re.sub(r"\s+", " ", local[:600]).strip(),
            })
    return records


GENERIC_FIELDS = {
    "id",
    "data",
    "code",
    "msg",
    "message",
    "list",
    "total",
    "name",
    "status",
    "pageno",
    "pagesize",
}
MEANINGFUL_SUFFIXES = (
    "id",
    "ids",
    "uuid",
    "key",
    "code",
    "number",
    "type",
    "level",
    "state",
    "status",
    "version",
    "size",
    "limit",
    "amount",
    "price",
    "balance",
    "duration",
    "quota",
    "role",
    "token",
    "count",
    "path",
    "url",
)


def api_family(endpoint_path: str) -> str:
    clean = endpoint_path.split("?", 1)[0]
    segments = [segment for segment in clean.split("/") if segment]
    return "/" + "/".join(segments[:2]) if segments else clean


def meaningful_fields(item: dict) -> set[str]:
    result = set()
    for field in item.get("directFields", []):
        normalized = re.sub(r"[^a-z0-9]+", "", field.casefold())
        if normalized in GENERIC_FIELDS:
            continue
        if re.search(r"[\u3400-\u9fff]", field) or normalized.endswith(
            MEANINGFUL_SUFFIXES
        ):
            result.add(field)
    return result


def tag_values(item: dict, *categories: str) -> set[str]:
    return {
        value
        for category in categories
        for value in item.get("tags", {}).get(category, [])
    }


def build_relation_graph(records: list[dict]) -> dict[int, list[dict]]:
    """Build sparse evidence edges without creating a full same-file clique."""
    adjacency: dict[int, list[dict]] = defaultdict(list)

    def connect(left: int, right: int, evidence: str, weight: int, detail: str) -> None:
        if left == right:
            return
        edge = {"to": right, "evidence": evidence, "weight": weight, "detail": detail}
        reverse = {"to": left, "evidence": evidence, "weight": weight, "detail": detail}
        adjacency[left].append(edge)
        adjacency[right].append(reverse)

    by_source: dict[str, list[int]] = defaultdict(list)
    by_family: dict[str, list[int]] = defaultdict(list)
    by_field: dict[str, list[int]] = defaultdict(list)
    for index, item in enumerate(records):
        by_source[item["source"]].append(index)
        by_family[api_family(item["path"])].append(index)
        for field in meaningful_fields(item):
            by_field[field].append(index)

    for indexes in by_source.values():
        ordered = sorted(indexes, key=lambda index: records[index].get("offset", 0))
        for position, left in enumerate(ordered):
            for right in ordered[position + 1:]:
                distance = records[right].get("offset", 0) - records[left].get("offset", 0)
                if distance > 12_000:
                    break
                weight = 6 if distance <= 3_000 else 4 if distance <= 7_000 else 2
                connect(left, right, "same-feature-chunk", weight, f"offset-distance={distance}")

    for family, indexes in by_family.items():
        if len(indexes) > 120:
            continue
        for position, left in enumerate(indexes):
            for right in indexes[position + 1:]:
                connect(left, right, "same-api-family", 7, family)

    for field, indexes in by_field.items():
        # High-frequency identifiers create near-complete graphs in large bundles.
        if len(indexes) > 8:
            continue
        for position, left in enumerate(indexes):
            for right in indexes[position + 1:]:
                connect(left, right, "shared-object-field", 8, field)
    return adjacency


def reachable(adjacency: dict[int, list[dict]], start: int, max_hops: int = 2) -> dict[int, tuple[int, list[dict]]]:
    best: dict[int, tuple[int, list[dict]]] = {}
    frontier = [(start, 0, [])]
    while frontier:
        node, hops, evidence_path = frontier.pop(0)
        if hops >= max_hops:
            continue
        for edge in adjacency.get(node, []):
            candidate = edge["to"]
            new_path = evidence_path + [{key: value for key, value in edge.items() if key != "to"}]
            score = sum(item["weight"] for item in new_path)
            previous = best.get(candidate)
            if previous is None or score > previous[0]:
                best[candidate] = (score, new_path)
                frontier.append((candidate, hops + 1, new_path))
    best.pop(start, None)
    return best


def build_chains(records: list[dict], runtime_flows: list[dict] | None = None) -> list[dict]:
    adjacency = build_relation_graph(records)

    def runtime_path(value: str | None) -> str:
        if not value:
            return ""
        return "/" + value.split("://", 1)[-1].split("/", 1)[-1].split("?", 1)[0]

    runtime_pairs = {
        (runtime_path(flow.get("to", {}).get("url")), runtime_path(flow.get("from", {}).get("url")))
        for flow in runtime_flows or []
    }
    chains = []
    for creator_index, creator in enumerate(records):
        creator_fields = meaningful_fields(creator)
        creator_actions = tag_values(creator, "write_action", "lifecycle_action")
        creator_objects = tag_values(creator, "business_object", "resource")
        if creator["method"] not in {"POST", "PUT", "PATCH", "DELETE"}:
            continue
        if not (creator_actions or creator_objects or creator_fields):
            continue
        creator_semantics = tag_values(
            creator,
            "business_object",
            "resource",
            "gate",
            "sensitive_capability",
        )
        candidates = reachable(adjacency, creator_index)
        prereqs, controls = [], []
        for candidate_index, (relation_score, evidence_path) in candidates.items():
            candidate = records[candidate_index]
            if candidate["path"] == creator["path"]:
                continue
            candidate_fields = meaningful_fields(candidate)
            shared_fields = sorted(creator_fields & candidate_fields)
            candidate_semantics = tag_values(
                candidate,
                "business_object",
                "resource",
                "gate",
                "sensitive_capability",
            )
            semantic_overlap = sorted(candidate_semantics & creator_semantics)
            runtime_observed = (
                (creator["path"], candidate["path"]) in runtime_pairs
                or (candidate["path"], creator["path"]) in runtime_pairs
            )
            evidence = list(evidence_path)
            if runtime_observed:
                evidence.insert(
                    0,
                    {
                        "evidence": "observed-value-reuse",
                        "weight": 12,
                        "detail": "browser traffic",
                    },
                )
            object_terms = sorted(
                tag_values(candidate, "actor", "business_object", "resource", "gate")
            )
            entry = {
                "method": candidate["method"],
                "path": candidate["path"],
                "source": candidate["source"],
                "line": candidate["line"],
                "score": (
                    relation_score
                    + len(shared_fields) * 3
                    + len(semantic_overlap) * 4
                    + (8 if runtime_observed else 0)
                ),
                "sharedFields": shared_fields,
                "semanticOverlap": semantic_overlap,
                "objectTerms": object_terms,
                "evidence": evidence,
            }
            is_read = candidate["method"] == "GET" or bool(
                tag_values(candidate, "read_action")
            )
            has_relation = bool(
                shared_fields or semantic_overlap or runtime_observed
            )
            if is_read and has_relation and (
                object_terms
                or shared_fields
                or runtime_observed
                or tag_values(candidate, "public_boundary")
            ):
                if tag_values(candidate, "public_boundary"):
                    entry["score"] += 4
                prereqs.append(entry)
            candidate_controls = tag_values(
                candidate,
                "lifecycle_action",
                "sensitive_capability",
            )
            if candidate_controls and (
                has_relation
                or api_family(candidate["path"]) == api_family(creator["path"])
            ):
                controls.append(entry)

        def unique_best(items: list[dict], limit: int) -> list[dict]:
            result, seen = [], set()
            for item in sorted(items, key=lambda value: (-value["score"], value["path"])):
                key = (item["method"], item["path"])
                if key in seen:
                    continue
                seen.add(key)
                result.append(item)
                if len(result) == limit:
                    break
            return result

        selected_prereqs = unique_best(prereqs, 12)
        selected_controls = unique_best(controls, 8)
        selectors_by_term = {}
        for item in sorted(prereqs, key=lambda value: (-value["score"], value["path"])):
            for term in [*item["sharedFields"], *item["objectTerms"]]:
                selectors_by_term.setdefault(term, item)
        selected_selectors = [
            {**item, "selectorTerm": term}
            for term, item in sorted(selectors_by_term.items(), key=lambda pair: (-pair[1]["score"], pair[0]))
        ][:20]
        if selected_prereqs or selected_controls:
            evidence_types = {
                edge["evidence"]
                for item in selected_prereqs + selected_controls + selected_selectors
                for edge in item["evidence"]
            }
            confidence = (
                "runtime-observed"
                if "observed-value-reuse" in evidence_types
                else "strong-hypothesis"
                if selected_prereqs and selected_controls
                else "hypothesis"
            )
            chains.append(
                {
                    "score": (
                        creator["score"]
                        + min(8, len(selected_prereqs))
                        + min(6, len(selected_controls))
                    ),
                    "confidence": confidence,
                    "evidenceTypes": sorted(evidence_types),
                    "creator": {
                        "method": creator["method"],
                        "path": creator["path"],
                        "source": creator["source"],
                        "line": creator["line"],
                    },
                    "prerequisites": selected_prereqs,
                    "objectSelectors": selected_selectors,
                    "controls": selected_controls,
                    "requiredNextStep": (
                        "Confirm request-field provenance and the expected "
                        "server-side authorization rule."
                    ),
                }
            )
    return sorted(chains, key=lambda item: -item["score"])


def write_report(records: list[dict], out_dir: Path, scanned: int, runtime_flows: list[dict] | None = None) -> None:
    ranked = sorted(records, key=lambda item: (-item["score"], item["source"], item["line"]))
    runtime_flows = runtime_flows or []
    lexicon = load_lexicon()
    chains = build_chains(records, runtime_flows)
    sources = defaultdict(list)
    for item in ranked:
        sources[item["source"]].append(item)
    edges = []
    for item in ranked:
        endpoint = f'{item["method"]} {item["path"]}'
        for field in item["fields"]:
            edges.append({"from": endpoint, "to": field, "type": "nearby-field", "confidence": "hypothesis"})
        for category, tags in item["tags"].items():
            for tag in tags:
                edges.append({"from": endpoint, "to": tag, "type": category, "confidence": "hypothesis"})
    payload = {
        "summary": {
            "filesScanned": scanned,
            "endpoints": len(records),
            "sources": len(sources),
            "taxonomyVersion": lexicon["taxonomy_version"],
            "lexiconSources": lexicon["sources"],
        },
        "endpoints": ranked,
        "edges": edges,
        "chains": chains,
        "runtimeDataFlows": runtime_flows,
    }
    (out_dir / "graph.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = [
        "# SPA Security Object Graph", "",
        f"Scanned {scanned} files; extracted {len(records)} endpoint candidates from {len(sources)} sources.", "",
        f'Taxonomy version `{lexicon["taxonomy_version"]}`; lexicon layers `{len(lexicon["sources"])}`.', "",
        "## Candidate security chains", "",
    ]
    if not chains:
        lines.append("No cross-feature chain candidate was produced.")
    for chain in chains[:40]:
        creator = chain["creator"]
        lines.extend([
            f'### {chain["score"]}: `{creator["method"]} {creator["path"]}`', "",
            f'- Confidence: `{chain["confidence"]}`; creator: `{creator["source"]}:{creator["line"]}`',
            f'- Evidence types: `{", ".join(chain["evidenceTypes"])}`',
            "- Candidate prerequisites: " + (" -> ".join(f'`{x["method"]} {x["path"]}`' for x in chain["prerequisites"]) or "none"),
            "- Object selectors: " + ("; ".join(f'`{x["selectorTerm"]}` via `{x["method"]} {x["path"]}`' for x in chain["objectSelectors"]) or "none"),
            "- Candidate controls: " + (" -> ".join(f'`{x["method"]} {x["path"]}`' for x in chain["controls"]) or "none"),
            f'- Next: {chain["requiredNextStep"]}', "",
        ])
    if runtime_flows:
        lines.extend(["## Runtime field flows", ""])
        for flow in runtime_flows[:80]:
            lines.append(f'- `{flow["from"]["method"]} {flow["from"]["url"]}` field `{flow["from"]["field"]}` -> `{flow["to"]["method"]} {flow["to"]["url"]}` field `{flow["to"]["field"]}`')
        lines.append("")
    lines.extend([
        "## High-priority hypotheses", "",
    ])
    high = [item for item in ranked if item["score"] >= 11]
    if not high:
        lines.append("No endpoint reached the default high-priority threshold.")
    for item in high[:80]:
        lines.extend([
            f'### {item["score"]}: `{item["method"]} {item["path"]}`', "",
            f'- Source: `{item["source"]}:{item["line"]}`',
            f'- Tags: `{json.dumps(item["tags"], ensure_ascii=False)}`',
            f'- Fields: `{", ".join(item["fields"]) or "none found in proximity window"}`',
            f'- Hypotheses: `{", ".join(item["hypotheses"]) or "manual review required"}`', "",
        ])
    lines.extend(["## Feature clusters", ""])
    for source, items in sorted(sources.items(), key=lambda pair: -max(x["score"] for x in pair[1]))[:60]:
        tags = Counter(tag for item in items for values in item["tags"].values() for tag in values)
        lines.append(f'### `{source}`')
        lines.append(f'- Top terms: `{", ".join(term for term, _ in tags.most_common(15))}`')
        for item in items[:12]:
            lines.append(f'- {item["score"]:02d} `{item["method"]} {item["path"]}` (line {item["line"]})')
        lines.append("")
    (out_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, help="SPA files or directories")
    parser.add_argument("--out", required=True, type=Path, help="Output directory")
    parser.add_argument("--window", type=int, default=2400, help="Context characters on each side")
    args = parser.parse_args()

    files = []
    for value in args.inputs:
        if value.is_file() and value.suffix.lower() in EXTENSIONS:
            files.append(value)
        elif value.is_dir():
            files.extend(p for p in value.rglob("*") if p.is_file() and p.suffix.lower() in EXTENSIONS)
    files = sorted(set(files))
    args.out.mkdir(parents=True, exist_ok=True)
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
        text = body.decode("utf-8", errors="replace")
        records.extend(extract_endpoints(path, text, args.window))
    write_report(records, args.out, scanned)
    print(args.out / "report.md")


if __name__ == "__main__":
    main()
