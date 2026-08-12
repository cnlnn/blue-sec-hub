#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security_terms import canonicalize_term


DATA_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_DATA",
        Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        / "blue-sec-hub",
    )
)
STORE = DATA_ROOT / "report-intelligence"
FINDINGS = STORE / "findings"
REVISIONS = STORE / "revisions"
ANALYSIS = STORE / "analysis"
SCHEMA_VERSION = 1
VALID_EVIDENCE_STATES = {"historical", "current"}
VALID_STATUSES = {
    "reported",
    "confirmed-present",
    "fixed",
    "partially-fixed",
    "not-reproduced",
    "environment-mismatch",
    "insufficient-evidence",
    "rejected",
}
LIST_FIELDS = (
    "assets",
    "components",
    "versions",
    "channels",
    "entrypoints",
    "parameters",
    "objects",
    "roles",
    "root_causes",
    "cwes",
    "controls",
    "preconditions",
    "postconditions",
    "alternate_surfaces",
    "evidence_refs",
    "tags",
    "supersedes",
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def slug(value: str) -> str:
    result = re.sub(
        r"[^\w.-]+",
        "-",
        value.casefold(),
        flags=re.UNICODE,
    ).strip("-_")
    return result[:80] or "unknown"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def string_list(value: Any, field: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a string or list of strings")
    return sorted({item.strip() for item in value if item.strip()})


def normalize_source(value: Any) -> dict[str, Any]:
    if isinstance(value, str):
        value = {"path": value}
    if not isinstance(value, dict) or not value.get("path"):
        raise ValueError("source must contain a path")
    source = dict(value)
    path = Path(str(source["path"])).expanduser()
    source["path"] = str(path.resolve()) if path.exists() else str(path)
    if path.is_file() and not source.get("sha256"):
        source["sha256"] = digest(path)
    source.setdefault("sha256", None)
    source.setdefault("report_id", None)
    source.setdefault("report_date", None)
    source.setdefault("kind", "report")
    return source


def finding_fingerprint(value: dict[str, Any]) -> str:
    material = {
        "system_id": value["system_id"],
        "title": value["title"],
        "source_sha256": value["source"].get("sha256"),
        "source_report_id": value["source"].get("report_id"),
        "entrypoints": value["entrypoints"],
        "weakness_class": value["weakness_class"],
        "observed_at": value.get("observed_at"),
    }
    return hashlib.sha256(
        json.dumps(material, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def content_fingerprint(value: dict[str, Any]) -> str:
    excluded = {"content_sha256", "indexed_at"}
    material = {key: item for key, item in value.items() if key not in excluded}
    return hashlib.sha256(
        json.dumps(material, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def normalize_finding(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("each finding must be a JSON object")
    value = dict(raw)
    for field in ("system_id", "title", "weakness_class", "evidence_state", "status"):
        if not isinstance(value.get(field), str) or not value[field].strip():
            raise ValueError(f"{field} is required")
        value[field] = value[field].strip()
    value["system_id"] = slug(value["system_id"])
    original_weakness = value["weakness_class"]
    value["weakness_class"] = canonicalize_term(original_weakness)
    if value["weakness_class"] != original_weakness:
        value["weakness_class_original"] = original_weakness
    if value["evidence_state"] not in VALID_EVIDENCE_STATES:
        raise ValueError(
            f"evidence_state must be one of {sorted(VALID_EVIDENCE_STATES)}"
        )
    if value["status"] not in VALID_STATUSES:
        raise ValueError(f"status must be one of {sorted(VALID_STATUSES)}")
    value["source"] = normalize_source(value.get("source"))
    for field in LIST_FIELDS:
        value[field] = string_list(value.get(field), field)
    remediation = value.get("remediation") or {}
    if not isinstance(remediation, dict):
        raise ValueError("remediation must be an object")
    value["remediation"] = {
        "claim": str(remediation.get("claim") or "").strip(),
        "mechanism": str(remediation.get("mechanism") or "").strip(),
        "scope": string_list(remediation.get("scope"), "remediation.scope"),
    }
    value["observed_at"] = value.get("observed_at") or value["source"].get(
        "report_date"
    )
    value["notes"] = str(value.get("notes") or "").strip()
    value["schema_version"] = SCHEMA_VERSION
    value["fingerprint"] = finding_fingerprint(value)
    value["finding_id"] = value.get("finding_id") or (
        f"{value['system_id']}-{value['fingerprint'][:16]}"
    )
    value["finding_id"] = slug(str(value["finding_id"]))
    value["content_sha256"] = content_fingerprint(value)
    value["indexed_at"] = now()
    return value


def parse_input(path: str) -> list[Any]:
    text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    try:
        value = json.loads(text)
        return value if isinstance(value, list) else [value]
    except json.JSONDecodeError:
        result: list[Any] = []
        for number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise SystemExit(f"invalid JSON at line {number}: {error}") from error
        return result


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def load_findings(system_id: str | None = None) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if not FINDINGS.exists():
        return result
    for path in sorted(FINDINGS.glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise SystemExit(f"invalid finding {path}: {error}") from error
        if system_id and value.get("system_id") != slug(system_id):
            continue
        result.append(value)
    return result


def command_upsert(args: argparse.Namespace) -> None:
    added = updated = unchanged = 0
    for raw in parse_input(args.input):
        try:
            value = normalize_finding(raw)
        except ValueError as error:
            raise SystemExit(f"invalid finding: {error}") from error
        target = FINDINGS / f"{value['finding_id']}.json"
        if target.exists():
            previous = json.loads(target.read_text(encoding="utf-8"))
            if previous.get("content_sha256") == value["content_sha256"]:
                unchanged += 1
                print(f"[current] {value['finding_id']}")
                continue
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            revision = REVISIONS / value["finding_id"] / f"{stamp}.json"
            revision.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(target, revision)
            updated += 1
            print(f"[updated] {value['finding_id']} previous={revision}")
        else:
            added += 1
            print(f"[added] {value['finding_id']}")
        write_json(target, value)
    print(f"[ok] added={added} updated={updated} unchanged={unchanged}")


def values(finding: dict[str, Any], field: str) -> set[str]:
    return {str(item).casefold() for item in finding.get(field, [])}


def shared_dimensions(
    left: dict[str, Any], right: dict[str, Any]
) -> dict[str, list[str]]:
    fields = (
        "root_causes",
        "cwes",
        "components",
        "entrypoints",
        "objects",
        "controls",
        "channels",
        "parameters",
    )
    result: dict[str, list[str]] = {}
    for field in fields:
        common = values(left, field) & values(right, field)
        if common:
            result[field] = sorted(common)
    if left["weakness_class"].casefold() == right["weakness_class"].casefold():
        result["weakness_class"] = [left["weakness_class"]]
    return result


def similarity_score(shared: dict[str, list[str]]) -> int:
    weights = {
        "root_causes": 3,
        "cwes": 3,
        "weakness_class": 2,
        "components": 2,
        "objects": 2,
        "entrypoints": 2,
        "controls": 1,
        "channels": 1,
        "parameters": 1,
    }
    return sum(weights[field] for field in shared)


def confidence(score: int) -> str:
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def relation(
    kind: str,
    left: dict[str, Any],
    right: dict[str, Any] | None,
    reason: str,
    candidate_confidence: str,
    shared: dict[str, list[str]] | None = None,
    surface: str | None = None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "from": left["finding_id"],
        "to": right["finding_id"] if right else None,
        "surface": surface,
        "confidence": candidate_confidence,
        "reason": reason,
        "shared": shared or {},
        "evidence_state": (
            "current"
            if left["evidence_state"] == "current"
            and (right is None or right["evidence_state"] == "current")
            else "historical-candidate"
        ),
    }


def build_chains(
    findings: list[dict[str, Any]], relations: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_id = {item["finding_id"]: item for item in findings}
    adjacency: dict[str, list[dict[str, Any]]] = {}
    for item in relations:
        if item["kind"] == "postcondition-enables" and item.get("to"):
            adjacency.setdefault(item["from"], []).append(item)

    chains: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()

    def walk(path: list[str], edges: list[dict[str, Any]]) -> None:
        if edges:
            key = tuple(path)
            if key not in seen:
                seen.add(key)
                nodes = [by_id[item] for item in path]
                states = {item["evidence_state"] for item in nodes}
                all_confirmed = all(
                    item["evidence_state"] == "current"
                    and item["status"] == "confirmed-present"
                    for item in nodes
                )
                edge_confidence = [item["confidence"] for item in edges]
                chain_confidence = (
                    "high"
                    if all(value == "high" for value in edge_confidence)
                    else "medium"
                    if all(value in {"high", "medium"} for value in edge_confidence)
                    else "low"
                )
                chains.append(
                    {
                        "nodes": path.copy(),
                        "confidence": chain_confidence,
                        "state": (
                            "current-elements-candidate"
                            if all_confirmed
                            else "historical-or-unconfirmed-candidate"
                        ),
                        "mixed_temporal": states == {"historical", "current"},
                        "matched_conditions": [
                            item["shared"].get("capability", []) for item in edges
                        ],
                    }
                )
        if len(path) >= 4 or len(chains) >= 500:
            return
        for edge in adjacency.get(path[-1], []):
            target = str(edge["to"])
            if target in path:
                continue
            walk([*path, target], [*edges, edge])

    for start in sorted(adjacency):
        walk([start], [])
    chains.sort(
        key=lambda item: (
            {"high": 0, "medium": 1, "low": 2}[item["confidence"]],
            -len(item["nodes"]),
            item["nodes"],
        )
    )
    return chains


def build_analysis(findings: list[dict[str, Any]], system_id: str) -> dict[str, Any]:
    relations: list[dict[str, Any]] = []
    for index, left in enumerate(findings):
        for right in findings[index + 1 :]:
            if "rejected" in {left["status"], right["status"]}:
                continue
            shared = shared_dimensions(left, right)
            score = similarity_score(shared)
            different_surface = not (
                values(left, "entrypoints") & values(right, "entrypoints")
            )
            if score >= 4 and different_surface:
                relations.append(
                    relation(
                        "sibling-surface",
                        left,
                        right,
                        "共享根因、弱点、组件或对象，但入口不同；应检查同类控制是否一致。",
                        confidence(score),
                        shared,
                    )
                )

            left_post = values(left, "postconditions")
            right_pre = values(right, "preconditions")
            if left_post & right_pre:
                confirmed = (
                    left["evidence_state"] == "current"
                    and right["evidence_state"] == "current"
                    and left["status"] == "confirmed-present"
                    and right["status"] == "confirmed-present"
                )
                relations.append(
                    relation(
                        "postcondition-enables",
                        left,
                        right,
                        "前一漏洞获得的能力满足后一漏洞的前置条件。",
                        "high" if confirmed else "medium",
                        {"capability": sorted(left_post & right_pre)},
                    )
                )
            right_post = values(right, "postconditions")
            left_pre = values(left, "preconditions")
            if right_post & left_pre:
                confirmed = (
                    left["evidence_state"] == "current"
                    and right["evidence_state"] == "current"
                    and left["status"] == "confirmed-present"
                    and right["status"] == "confirmed-present"
                )
                relations.append(
                    relation(
                        "postcondition-enables",
                        right,
                        left,
                        "前一漏洞获得的能力满足后一漏洞的前置条件。",
                        "high" if confirmed else "medium",
                        {"capability": sorted(right_post & left_pre)},
                    )
                )

            fixed, other = (
                (left, right)
                if left["status"] == "fixed"
                else (right, left)
                if right["status"] == "fixed"
                else (None, None)
            )
            if (
                fixed
                and other
                and other["evidence_state"] == "current"
                and other["status"] not in {"fixed", "rejected", "not-reproduced"}
            ):
                fixed_shared = shared_dimensions(fixed, other)
                fixed_score = similarity_score(fixed_shared)
                if fixed_score >= 4:
                    same_entry = bool(
                        values(fixed, "entrypoints") & values(other, "entrypoints")
                    )
                    relations.append(
                        relation(
                            "fix-bypass-or-regression",
                            fixed,
                            other,
                            (
                                "修复后同一入口出现同源现象，优先检查修复回归。"
                                if same_entry
                                else "修复与同源弱点位于不同入口，优先检查修复范围绕过。"
                            ),
                            confidence(fixed_score + (2 if same_entry else 0)),
                            fixed_shared,
                        )
                    )

        if left["status"] == "rejected":
            continue
        remediation_scope = {
            str(item).casefold() for item in left["remediation"].get("scope", [])
        }
        known_entries = values(left, "entrypoints")
        for surface in left.get("alternate_surfaces", []):
            normalized = surface.casefold()
            if normalized in known_entries or normalized in remediation_scope:
                continue
            relations.append(
                relation(
                    "untested-alternate-surface",
                    left,
                    None,
                    "报告或当前资产图存在等价入口，但修复范围和验证证据未覆盖。",
                    "medium",
                    surface=surface,
                )
            )

    statuses = Counter(item["status"] for item in findings)
    weaknesses = Counter(item["weakness_class"] for item in findings)
    profile = {
        "finding_count": len(findings),
        "historical_count": sum(
            1 for item in findings if item["evidence_state"] == "historical"
        ),
        "current_count": sum(
            1 for item in findings if item["evidence_state"] == "current"
        ),
        "statuses": dict(statuses.most_common()),
        "weaknesses": dict(weaknesses.most_common()),
        "assets": sorted({value for item in findings for value in item["assets"]}),
        "components": sorted(
            {value for item in findings for value in item["components"]}
        ),
        "entrypoints": sorted(
            {value for item in findings for value in item["entrypoints"]}
        ),
        "objects": sorted({value for item in findings for value in item["objects"]}),
        "roles": sorted({value for item in findings for value in item["roles"]}),
    }
    relations.sort(
        key=lambda item: (
            {"high": 0, "medium": 1, "low": 2}[item["confidence"]],
            item["kind"],
            item["from"],
            item.get("to") or "",
        )
    )
    chains = build_chains(findings, relations)
    return {
        "schema_version": SCHEMA_VERSION,
        "system_id": slug(system_id),
        "generated_at": now(),
        "profile": profile,
        "relations": relations,
        "chains": chains,
        "rules": [
            "historical-candidate is not a current vulnerability",
            "a chain is confirmed only after every edge is validated in the current environment",
            "fix bypass candidates require direct comparison with the claimed remediation scope",
        ],
    }


def render_markdown(analysis: dict[str, Any]) -> str:
    profile = analysis["profile"]
    lines = [
        f"# Vulnerability Intelligence: {analysis['system_id']}",
        "",
        f"- Findings: {profile['finding_count']}",
        f"- Historical: {profile['historical_count']}",
        f"- Current: {profile['current_count']}",
        f"- Statuses: {json.dumps(profile['statuses'], ensure_ascii=False)}",
        f"- Weaknesses: {json.dumps(profile['weaknesses'], ensure_ascii=False)}",
        "",
        "## Candidate Relations",
        "",
    ]
    if not analysis["relations"]:
        lines.append("No candidate relations found.")
    for item in analysis["relations"]:
        target = item["to"] or item["surface"] or "unverified surface"
        lines.extend(
            [
                f"### {item['kind']}: {item['from']} -> {target}",
                "",
                f"- Confidence: `{item['confidence']}`",
                f"- Evidence: `{item['evidence_state']}`",
                f"- Reason: {item['reason']}",
                f"- Shared: `{json.dumps(item['shared'], ensure_ascii=False)}`",
                "",
            ]
        )
    lines.extend(["## Candidate Chains", ""])
    if not analysis["chains"]:
        lines.append("No candidate chains found.")
    for item in analysis["chains"]:
        lines.extend(
            [
                f"### {' -> '.join(item['nodes'])}",
                "",
                f"- Confidence: `{item['confidence']}`",
                f"- State: `{item['state']}`",
                f"- Mixed historical/current: `{str(item['mixed_temporal']).lower()}`",
                f"- Matched conditions: `{json.dumps(item['matched_conditions'], ensure_ascii=False)}`",
                "",
            ]
        )
    lines.extend(
        [
            "## Interpretation Rules",
            "",
            *[f"- {rule}" for rule in analysis["rules"]],
            "",
        ]
    )
    return "\n".join(lines)


def command_analyze(args: argparse.Namespace) -> None:
    system_id = slug(args.system)
    findings = load_findings(system_id)
    if not findings:
        raise SystemExit(f"no findings for system: {system_id}")
    analysis = build_analysis(findings, system_id)
    json_path = ANALYSIS / f"{system_id}.json"
    markdown_path = ANALYSIS / f"{system_id}.md"
    write_json(json_path, analysis)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.write_text(render_markdown(analysis), encoding="utf-8")
    if args.format == "json":
        print(json.dumps(analysis, ensure_ascii=False, indent=2))
    else:
        print(render_markdown(analysis))
    print(f"[saved] {json_path}")
    print(f"[saved] {markdown_path}")


def command_list(args: argparse.Namespace) -> None:
    findings = load_findings(args.system)
    for item in findings:
        if args.status and item["status"] != args.status:
            continue
        print(
            f"{item['finding_id']}\t{item['evidence_state']}\t"
            f"{item['status']}\t{item['title']}"
        )


def command_show(args: argparse.Namespace) -> None:
    path = FINDINGS / f"{slug(args.finding_id)}.json"
    if not path.exists():
        raise SystemExit(f"finding not found: {args.finding_id}")
    print(path.read_text(encoding="utf-8"), end="")


def command_audit(_: argparse.Namespace) -> None:
    failures: list[str] = []
    findings = load_findings()
    ids: set[str] = set()
    for value in findings:
        identifier = value.get("finding_id")
        if not identifier or identifier in ids:
            failures.append(f"duplicate or missing finding_id: {identifier}")
        ids.add(identifier)
        try:
            normalize_finding(value)
        except ValueError as error:
            failures.append(f"{identifier}: {error}")
    if failures:
        raise SystemExit("\n".join(failures))
    systems = len({item["system_id"] for item in findings})
    print(f"[ok] report findings={len(findings)} systems={systems}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build local vulnerability intelligence from security reports"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    upsert = commands.add_parser("upsert", help="insert normalized findings")
    upsert.add_argument("input", help="JSON/JSONL file or - for stdin")
    upsert.set_defaults(function=command_upsert)

    analyze = commands.add_parser("analyze", help="build system profile and relations")
    analyze.add_argument("--system", required=True)
    analyze.add_argument("--format", choices=("markdown", "json"), default="markdown")
    analyze.set_defaults(function=command_analyze)

    listing = commands.add_parser("list", help="list findings")
    listing.add_argument("--system")
    listing.add_argument("--status", choices=sorted(VALID_STATUSES))
    listing.set_defaults(function=command_list)

    show = commands.add_parser("show", help="show one finding")
    show.add_argument("finding_id")
    show.set_defaults(function=command_show)

    audit = commands.add_parser("audit", help="validate the local finding store")
    audit.set_defaults(function=command_audit)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
