#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = 1
CLAIM_KINDS = {
    "historical-claim",
    "risk-signal",
    "static-capability",
    "incident-observation",
    "vulnerability",
}
VALIDATION_STATES = {
    "observed",
    "historical",
    "candidate",
    "confirmed",
    "rejected",
    "blocked-external",
}
DEPENDENCY_STATES = {
    "pending",
    "searching",
    "satisfied",
    "exhausted-with-evidence",
    "blocked-external",
}
PREREQUISITE_SOURCES = {
    "attacker-public", "attacker-authenticated", "attacker-derived",
    "tester-provided", "historical-report", "internal-log", "source-code",
}
BLACKBOX_CLOSING_SOURCES = {
    "attacker-public", "attacker-authenticated", "attacker-derived",
}
PRIORITIES = {"critical", "high", "medium", "low", "informational"}
SEVERITIES = {"critical", "high", "medium", "low", "informational"}
BASE_VULNERABILITY_DEPENDENCIES = (
    "attacker-source",
    "controlled-input",
    "reachable-path",
    "consumer",
    "trigger-result",
    "observable-impact",
)
PRIVILEGED_IMPACT_DEPENDENCY = "privilege-bridge"
RCE_PATTERN = re.compile(r"\brce\b|remote\s+code\s+execution|远程代码执行", re.I)
CONFIRMED_TITLE_PATTERN = re.compile(
    r"(?:critical|high|高危|严重).*?(?:rce|remote\s+code\s+execution|远程代码执行)|"
    r"(?:rce|remote\s+code\s+execution|远程代码执行).*?(?:critical|high|高危|严重)",
    re.I,
)


def stable_id(value: dict[str, Any]) -> str:
    material = json.dumps(
        {
            "title": value.get("title"),
            "claim_kind": value.get("claim_kind"),
            "evidence_refs": value.get("evidence_refs", []),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return "claim-" + hashlib.sha256(material.encode()).hexdigest()[:16]


def required_dependency_ids(value: dict[str, Any]) -> set[str]:
    if value.get("claim_kind") != "vulnerability":
        return set()
    required = set(BASE_VULNERABILITY_DEPENDENCIES)
    impact = " ".join(
        str(value.get(key) or "")
        for key in ("potential_impact", "confirmed_impact", "title")
    )
    if RCE_PATTERN.search(impact):
        required.add(PRIVILEGED_IMPACT_DEPENDENCY)
    return required


def dependency_map(value: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("id")): item
        for item in value.get("validation_dependencies", [])
        if isinstance(item, dict) and item.get("id")
    }


def unresolved_dependencies(value: dict[str, Any]) -> list[str]:
    dependencies = dependency_map(value)
    required = required_dependency_ids(value)
    return sorted(
        dependency_id
        for dependency_id in required
        if dependencies.get(dependency_id, {}).get("status") != "satisfied"
    )


def validate(value: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    required_fields = (
        "schema_version",
        "claim_id",
        "claim_kind",
        "validation_state",
        "title",
        "evidence_refs",
        "attacker_prerequisites",
        "validation_dependencies",
        "potential_impact",
        "confirmed_impact",
        "investigation_priority",
        "formal_severity",
        "next_actions",
        "alternative_explanations",
        "coverage_effect",
    )
    for field in required_fields:
        if field not in value:
            failures.append(f"missing required field: {field}")
    if value.get("schema_version") != SCHEMA_VERSION:
        failures.append("schema_version must be 1")
    if not str(value.get("claim_id") or "").strip():
        failures.append("claim_id is required")
    if value.get("claim_kind") not in CLAIM_KINDS:
        failures.append("invalid claim_kind")
    if value.get("validation_state") not in VALIDATION_STATES:
        failures.append("invalid validation_state")
    if value.get("investigation_priority") not in PRIORITIES:
        failures.append("invalid investigation_priority")
    if value.get("formal_severity") not in SEVERITIES | {None}:
        failures.append("invalid formal_severity")
    for field in (
        "evidence_refs",
        "attacker_prerequisites",
        "validation_dependencies",
        "next_actions",
        "alternative_explanations",
    ):
        if not isinstance(value.get(field), list):
            failures.append(f"{field} must be an array")
    seen: set[str] = set()
    for item in value.get("validation_dependencies", []):
        if not isinstance(item, dict):
            failures.append("validation dependency must be an object")
            continue
        dependency_id = str(item.get("id") or "")
        if not dependency_id or dependency_id in seen:
            failures.append("validation dependency id is missing or duplicated")
        seen.add(dependency_id)
        status = item.get("status")
        if status not in DEPENDENCY_STATES:
            failures.append(f"invalid dependency state: {status}")
        refs = item.get("evidence_refs")
        if not isinstance(refs, list):
            failures.append(f"dependency {dependency_id}: evidence_refs must be an array")
        if status in {"satisfied", "exhausted-with-evidence"} and not refs:
            failures.append(f"dependency {dependency_id}: {status} requires evidence_refs")
        if status != "satisfied" and not str(item.get("reason") or "").strip():
            failures.append(f"dependency {dependency_id}: unresolved state requires reason")
        source = item.get("prerequisite_source")
        if source is not None and source not in PREREQUISITE_SOURCES:
            failures.append(f"dependency {dependency_id}: invalid prerequisite_source")
    state = value.get("validation_state")
    kind = value.get("claim_kind")
    if state == "confirmed":
        if not value.get("evidence_refs"):
            failures.append("confirmed conclusion requires evidence_refs")
        if kind == "vulnerability":
            gaps = unresolved_dependencies(value)
            if gaps:
                failures.append("confirmed vulnerability has unresolved prerequisites: " + ",".join(gaps))
            if not value.get("confirmed_impact"):
                failures.append("confirmed vulnerability requires confirmed_impact")
            if value.get("attacker_model", {}).get("kind") == "black-box":
                invalid_sources = sorted(
                    str(item.get("id"))
                    for item in value.get("validation_dependencies", [])
                    if item.get("status") == "satisfied"
                    and item.get("prerequisite_source") not in BLACKBOX_CLOSING_SOURCES
                )
                if invalid_sources:
                    failures.append(
                        "black-box vulnerability uses non-attacker prerequisite sources: "
                        + ",".join(invalid_sources)
                    )
            # A confirmed finding may intentionally omit scoring. Severity is
            # permitted only after confirmation, but it is not evidence itself.
    if kind != "vulnerability" or state != "confirmed":
        if value.get("formal_severity") is not None:
            failures.append("formal_severity is only allowed for confirmed vulnerabilities")
    if kind in {"historical-claim", "risk-signal", "static-capability"} and value.get(
        "confirmed_impact"
    ) is not None:
        failures.append(f"{kind} cannot set confirmed_impact")
    if state in {"candidate", "blocked-external"}:
        if value.get("confirmed_impact") is not None:
            failures.append(f"{state} conclusion cannot have confirmed_impact")
        if not value.get("validation_dependencies"):
            failures.append(f"{state} conclusion requires validation_dependencies")
        if not value.get("next_actions"):
            failures.append(f"{state} conclusion requires next_actions")
        if value.get("coverage_effect") not in {"continue", "interim", "blocked"}:
            failures.append(f"{state} conclusion cannot complete coverage")
    if kind == "historical-claim" and state != "historical":
        failures.append("historical-claim must use historical state")
    if state == "historical" and value.get("formal_severity") is not None:
        failures.append("historical claim cannot set formal_severity")
    return failures


def default_dependencies(value: dict[str, Any]) -> list[dict[str, Any]]:
    existing = dependency_map(value)
    dependencies = list(value.get("validation_dependencies", []))
    for dependency_id in sorted(required_dependency_ids(value)):
        if dependency_id in existing:
            continue
        dependencies.append(
            {
                "id": dependency_id,
                "status": "blocked-external"
                if value.get("validation_state") == "blocked-external"
                else "pending",
                "evidence_refs": [],
                "reason": "prerequisite has not been validated",
            }
        )
    if not dependencies and value.get("validation_state") in {"candidate", "blocked-external"}:
        dependencies.append(
            {
                "id": "claim-specific-prerequisite",
                "status": "pending",
                "evidence_refs": [],
                "reason": "claim-specific prerequisite has not been validated",
            }
        )
    return dependencies


def normalize(raw: dict[str, Any], *, source_type: str | None = None) -> dict[str, Any]:
    value = dict(raw)
    legacy = "claim_kind" not in value or "schema_version" not in value
    event_type = source_type or str(value.get("type") or "")
    if "claim_kind" not in value:
        value["claim_kind"] = "vulnerability" if event_type == "finding" else "risk-signal"
    if "validation_state" not in value:
        value["validation_state"] = "candidate"
    value.setdefault("schema_version", SCHEMA_VERSION)
    value.setdefault("claim_id", str(value.get("id") or ""))
    value.setdefault("title", "Unlabeled security conclusion")
    value.setdefault("evidence_refs", [])
    value.setdefault("attacker_prerequisites", [])
    value.setdefault("attacker_model", {})
    value.setdefault("potential_impact", None)
    value.setdefault("confirmed_impact", None)
    value.setdefault("investigation_priority", "medium")
    value.setdefault("formal_severity", None)
    value.setdefault("next_actions", [])
    value.setdefault("alternative_explanations", [])
    value.setdefault("coverage_effect", "continue")
    value.setdefault("policy_violations", [])
    if not value["claim_id"]:
        value["claim_id"] = stable_id(value)
    if legacy:
        value["policy_violations"] = [
            *value["policy_violations"],
            "legacy-unverifiable",
        ]
    value["validation_dependencies"] = default_dependencies(value)
    attempted_confirmation = value.get("validation_state") == "confirmed"
    if attempted_confirmation and validate(value):
        value["validation_state"] = "candidate"
        value["confirmed_impact"] = None
        value["formal_severity"] = None
        value["coverage_effect"] = "interim"
        value["policy_violations"] = [
            *value["policy_violations"],
            "invalid-confirmed-claim-downgraded",
        ]
        value.setdefault("next_actions", [])
        if not value["next_actions"]:
            value["next_actions"] = [
                f"resolve prerequisite: {item}"
                for item in unresolved_dependencies(value)
            ] or ["collect direct evidence for the claimed impact"]
    if value.get("validation_state") in {"candidate", "blocked-external"}:
        value["formal_severity"] = None
        value["confirmed_impact"] = None
        for legacy_rating in ("severity", "cvss", "cvss_score"):
            if value.get(legacy_rating) is not None:
                value[f"reported_{legacy_rating}"] = value[legacy_rating]
                value[legacy_rating] = None
                value["policy_violations"] = [
                    *value["policy_violations"],
                    f"unresolved-candidate-{legacy_rating}-removed",
                ]
        value["coverage_effect"] = (
            "interim" if value["validation_state"] == "blocked-external" else "continue"
        )
        if not value.get("next_actions"):
            value["next_actions"] = [
                f"resolve prerequisite: {item}"
                for item in unresolved_dependencies(value)
            ] or ["collect direct evidence for the claimed impact"]
        if RCE_PATTERN.search(str(value.get("title") or "")):
            value["original_title"] = value["title"]
            value["title"] = "Potential code-execution path (prerequisites unresolved)"
            value["policy_violations"] = [
                *value["policy_violations"],
                "confirmed-impact-title-on-unresolved-candidate",
            ]
    value["policy_violations"] = sorted(set(value["policy_violations"]))
    return value


def load_json_argument(reference: str) -> dict[str, Any]:
    text = sys.stdin.read() if reference == "-" else Path(reference).read_text(encoding="utf-8")
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("security conclusion must be a JSON object")
    return value


def iter_workspace_claims(workspace: Path) -> Iterable[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for filename in (
        "security-conclusion-events.jsonl",
        "security-conclusions.jsonl",
    ):
        ledger = workspace / filename
        if not ledger.is_file():
            continue
        for line in ledger.read_text(encoding="utf-8").splitlines():
            if line.strip():
                item = normalize(json.loads(line))
                latest[item["claim_id"]] = item
    if latest:
        yield from latest.values()
        return
    for filename, event_type in (
        ("confirmed-findings.json", "finding"),
        ("candidate-findings.json", "candidate"),
    ):
        path = workspace / filename
        if not path.is_file():
            continue
        value = json.loads(path.read_text(encoding="utf-8"))
        for item in value.get("findings", []):
            yield normalize(item, source_type=event_type)


def workspace_status(workspace: Path) -> dict[str, Any]:
    claims = list(iter_workspace_claims(workspace))
    invalid_confirmed = sum(
        item.get("validation_state") == "candidate"
        and bool(
            {"invalid-confirmed-claim-downgraded", "legacy-unverifiable"}
            & set(item.get("policy_violations", []))
        )
        for item in claims
    )
    unresolved_high = sum(
        item.get("validation_state") in {"candidate", "blocked-external"}
        and item.get("investigation_priority") in {"critical", "high"}
        for item in claims
    )
    counts: dict[str, int] = {}
    for item in claims:
        state = str(item.get("validation_state") or "unknown")
        counts[state] = counts.get(state, 0) + 1
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "degraded" if invalid_confirmed else "ready",
        "workspace": str(workspace.resolve()),
        "claims": len(claims),
        "states": dict(sorted(counts.items())),
        "invalid_confirmed_claims": invalid_confirmed,
        "unresolved_high_priority_candidates": unresolved_high,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate Blue Sec Hub security conclusions")
    commands = parser.add_subparsers(dest="command", required=True)
    validate_command = commands.add_parser("validate")
    validate_command.add_argument("json")
    validate_command.add_argument("--normalize", action="store_true")
    status_command = commands.add_parser("status")
    status_command.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "status":
        print(json.dumps(workspace_status(args.workspace), ensure_ascii=False, indent=2))
        return
    value = load_json_argument(args.json)
    if args.normalize:
        value = normalize(value)
    failures = validate(value)
    print(
        json.dumps(
            {"status": "ready" if not failures else "invalid", "failures": failures, "conclusion": value},
            ensure_ascii=False,
            indent=2,
        )
    )
    if failures:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
