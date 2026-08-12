#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections import Counter, deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

import operator_policy
import effective_skills
import security_conclusion


SCHEMA_VERSION = 3
MAX_CAPSULE_BYTES = 24 * 1024
CAPSULE_NAME = "context-capsule.json"
EVENTS_NAME = "context-events.jsonl"
CONCLUSIONS_NAME = "security-conclusion-events.jsonl"
JOURNAL_STATE_NAME = "context-journal-state.json"
BINDING_INDEX_NAME = "context-bindings.json"
CONVERSATION_LEARNING_NAME = "conversation-learning-events.jsonl"
DISTILLATION_QUEUE_NAME = "session-distillation-queue.jsonl"
DATA_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_DATA",
        Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        / "blue-sec-hub",
    )
)
EVENT_TYPES = {
    "fact",
    "hypothesis",
    "decision",
    "next-action",
    "blocker",
    "scope",
    "finding",
    "rejected",
    "evidence-anchor",
    "provisional",
    "session-boundary",
}
PRIORITIES = {"critical": 0, "high": 1, "normal": 2, "low": 3}
STATUSES = {"active", "resolved", "superseded"}
PREREQUISITE_SOURCES = {
    "attacker-public",
    "attacker-authenticated",
    "attacker-derived",
    "tester-provided",
    "historical-report",
    "internal-log",
    "source-code",
}
ATTACKER_CLOSING_SOURCES = {
    "attacker-public",
    "attacker-authenticated",
    "attacker-derived",
}
FORBIDDEN_KEYS = {
    "authorization",
    "cookie",
    "cookies",
    "token",
    "password",
    "passwd",
    "secret",
    "headers",
    "request_body",
    "response_body",
    "storage_state",
}
CANONICAL_FILES = (
    "task-context.json",
    "job.json",
    "agent-state.json",
    "runner-state.json",
    "coverage.json",
    "surface-inventory.json",
    "route-inventory.json",
    "test-plan.json",
    "prerequisite-graph.json",
    "object-provenance.json",
    "evidence-index.json",
    "candidate-findings.json",
    "confirmed-findings.json",
    "attack-chain-analysis.json",
    "tool-runs.json",
    "source-control-map.json",
    JOURNAL_STATE_NAME,
)
EVENT_LEDGER_FILES = (
    EVENTS_NAME,
    CONCLUSIONS_NAME,
    "assessment-events.jsonl",
    "events.jsonl",
)

IMPORTANT_TRANSCRIPT_RE = re.compile(
    r"(?:必须|需要|不要|不能|确认|发现|证据|假设|排除|阻塞|下一步|范围|决定|"
    r"must|need|do not|confirmed|finding|evidence|hypothesis|rejected|blocked|next|scope|decision)",
    re.I,
)


def now() -> str:
    return datetime.now(UTC).isoformat()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if os.name != "nt":
        temporary.chmod(0o600)
    temporary.replace(path)


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def file_sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def stable_id(prefix: str, value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True).encode()
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:16]}"


def sanitize_summary(value: str, limit: int = 1000) -> str:
    clean, _ = operator_policy.redact_text(value, limit)
    return clean


def forbidden_fields(value: Any, prefix: str = "") -> list[str]:
    result = []
    if isinstance(value, dict):
        for key, child in value.items():
            name = str(key).casefold()
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            if name in FORBIDDEN_KEYS:
                result.append(child_prefix)
            result.extend(forbidden_fields(child, child_prefix))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            result.extend(forbidden_fields(child, f"{prefix}[{index}]"))
    return result


def sanitize_conclusion_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): sanitize_conclusion_value(child) for key, child in value.items()}
    if isinstance(value, list):
        return [sanitize_conclusion_value(child) for child in value]
    if isinstance(value, str):
        return sanitize_summary(value, 2000)
    return value


def validate_context_event(event: dict[str, Any]) -> dict[str, Any]:
    event_type = event.get("type")
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unsupported context event type: {event_type}")
    if event.get("priority", "normal") not in PRIORITIES:
        raise ValueError("invalid context event priority")
    if event.get("status", "active") not in STATUSES:
        raise ValueError("invalid context event status")
    if not str(event.get("summary") or "").strip():
        raise ValueError("context event requires summary")
    forbidden = forbidden_fields(event)
    if forbidden:
        raise ValueError("context event contains forbidden secret-bearing fields: " + ", ".join(forbidden))
    normalized = {
        "id": str(event.get("id") or stable_id("context-event", {
            "type": event_type,
            "summary": event.get("summary"),
            "refs": event.get("refs", []),
        })),
        "type": event_type,
        "priority": event.get("priority", "normal"),
        "status": event.get("status", "active"),
        "summary": sanitize_summary(str(event["summary"])),
        "refs": sorted({str(item) for item in event.get("refs", []) if str(item).strip()})[:100],
        "replaces": sorted({str(item) for item in event.get("replaces", []) if str(item).strip()})[:100],
        "recorded_at": str(event.get("recorded_at") or now()),
    }
    if event.get("verification_state") in {"verified", "provisional"}:
        normalized["verification_state"] = event["verification_state"]
    if event.get("platform"):
        normalized["platform"] = str(event["platform"])
    if event.get("session_id"):
        normalized["session_id"] = stable_id("session", str(event["session_id"]))
    if event.get("trigger"):
        normalized["trigger"] = str(event["trigger"])
    if event.get("evidence_strength") in {"confirmed", "inferred", "hypothesis", "rejected"}:
        normalized["evidence_strength"] = event["evidence_strength"]
    prerequisite_source = event.get("prerequisite_source")
    if prerequisite_source is not None:
        if prerequisite_source not in PREREQUISITE_SOURCES:
            raise ValueError("invalid prerequisite_source")
        normalized["prerequisite_source"] = prerequisite_source
        normalized["closes_blackbox_prerequisite"] = (
            prerequisite_source in ATTACKER_CLOSING_SOURCES
        )
    return normalized


def append_context_event(workspace: Path, event: dict[str, Any]) -> dict[str, Any]:
    normalized = validate_context_event(event)
    path = workspace / EVENTS_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    existing_ids = {
        item.get("id")
        for item in read_jsonl(path)
        if isinstance(item, dict)
    }
    if normalized["id"] not in existing_ids:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(normalized, ensure_ascii=False, sort_keys=True) + "\n")
        if os.name != "nt":
            path.chmod(0o600)
    return normalized


def append_conversation_learning_event(event: dict[str, Any]) -> dict[str, Any]:
    forbidden = forbidden_fields(event)
    if forbidden:
        raise ValueError(
            "conversation learning event contains forbidden fields: "
            + ", ".join(forbidden)
        )
    event_type = str(event.get("type") or "correction")
    if event_type not in {"correction", "verification", "eval", "preference", "functional-change"}:
        raise ValueError("invalid conversation learning event type")
    summary = sanitize_summary(str(event.get("summary") or ""), 1000)
    if not summary:
        raise ValueError("conversation learning event requires summary")
    source_session = str(event.get("source_session") or "")
    normalized = {
        "schema_version": 1,
        "event_id": str(event.get("event_id") or stable_id("conversation-learning", event)),
        "type": event_type,
        "summary": summary,
        "source_platform": str(event.get("source_platform") or "unknown"),
        "source_session_hash": stable_id("session", source_session) if source_session else None,
        "source_turn_ref": str(event.get("source_turn_ref") or "") or None,
        "validation_state": str(event.get("validation_state") or "unverified"),
        "evidence_refs": sorted({stable_id("evidence", str(item)) for item in event.get("evidence_refs", [])}),
        "recorded_at": now(),
    }
    path = DATA_ROOT / CONVERSATION_LEARNING_NAME
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(normalized, ensure_ascii=False, sort_keys=True) + "\n")
    if os.name != "nt":
        path.chmod(0o600)
    return normalized


def queue_session_distillation(platform: str, session_id: str | None, transcript: str | None) -> None:
    value = {
        "schema_version": 1,
        "event_id": stable_id("distillation-queue", [platform, session_id, transcript]),
        "platform": platform,
        "session_ref": stable_id("session", session_id) if session_id else None,
        "transcript_ref": stable_id("transcript", transcript) if transcript else None,
        "queued_at": now(),
        "status": "pending",
    }
    path = DATA_ROOT / DISTILLATION_QUEUE_NAME
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    existing = {item.get("event_id") for item in read_jsonl(path)}
    if value["event_id"] not in existing:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")
    if os.name != "nt":
        path.chmod(0o600)


def append_security_conclusion(
    workspace: Path, conclusion: dict[str, Any]
) -> dict[str, Any]:
    forbidden = forbidden_fields(conclusion)
    if forbidden:
        raise ValueError(
            "security conclusion contains forbidden secret-bearing fields: "
            + ", ".join(forbidden)
        )
    normalized = security_conclusion.normalize(sanitize_conclusion_value(conclusion))
    failures = security_conclusion.validate(normalized)
    if failures:
        raise ValueError("invalid security conclusion: " + "; ".join(failures))
    path = workspace / CONCLUSIONS_NAME
    existing = [item for item in read_jsonl(path) if isinstance(item, dict)]
    if not existing or existing[-1] != normalized:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(normalized, ensure_ascii=False, sort_keys=True) + "\n")
        if os.name != "nt":
            path.chmod(0o600)
    state = normalized["validation_state"]
    event_type = (
        "finding"
        if state == "confirmed" and normalized["claim_kind"] == "vulnerability"
        else "blocker"
        if state == "blocked-external"
        else "hypothesis"
        if state == "candidate"
        else "fact"
    )
    conclusion_event_id = stable_id(
        f"conclusion-{normalized['claim_id']}",
        {
            "state": normalized["validation_state"],
            "dependencies": normalized["validation_dependencies"],
            "evidence_refs": normalized["evidence_refs"],
        },
    )
    prior_event_ids = [
        str(item.get("id"))
        for item in read_jsonl(workspace / EVENTS_NAME)
        if str(item.get("id", "")).startswith(
            f"conclusion-{normalized['claim_id']}-"
        )
    ]
    append_context_event(
        workspace,
        {
            "id": conclusion_event_id,
            "type": event_type,
            "priority": "critical"
            if normalized["investigation_priority"] == "critical"
            else "high"
            if normalized["investigation_priority"] == "high"
            else "normal",
            "summary": normalized["title"],
            "refs": normalized["evidence_refs"],
            "replaces": prior_event_ids,
            "evidence_strength": "confirmed"
            if state == "confirmed"
            else "rejected"
            if state == "rejected"
            else "hypothesis",
        },
    )
    return normalized


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    yield value
    except OSError:
        return


def current_context_events(workspace: Path) -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    replacement_ids = set()
    for event in read_jsonl(workspace / EVENTS_NAME):
        latest[str(event.get("id"))] = event
        replacement_ids.update(str(item) for item in event.get("replaces", []))
    active = [
        item
        for event_id, item in latest.items()
        if event_id not in replacement_ids
        and item.get("status", "active") == "active"
    ]
    return sorted(
        active,
        key=lambda item: (
            PRIORITIES.get(item.get("priority", "normal"), 2),
            item.get("recorded_at", ""),
            item.get("id", ""),
        ),
    )


def compact_records(values: Iterable[dict[str, Any]], limit: int = 100) -> tuple[list[dict[str, Any]], int]:
    result = []
    total = 0
    keys = (
        "id",
        "type",
        "title",
        "family",
        "severity",
        "priority",
        "status",
        "reason",
        "surface_ref",
        "work_unit_id",
        "test_cell_id",
        "test_case_id",
        "authorization_mode",
        "dependency_id",
        "owner_kind",
        "owner_id",
        "kind",
        "binding_slot_refs",
        "evidence_refs",
        "prerequisite_source",
        "closes_blackbox_prerequisite",
    )
    for value in values:
        if not isinstance(value, dict):
            continue
        total += 1
        if len(result) >= limit:
            continue
        item = {key: value[key] for key in keys if key in value and value[key] not in (None, [], {})}
        if item:
            result.append(item)
    return result, max(0, total - len(result))


def recent_security_events(workspace: Path, limit: int = 60) -> list[dict[str, Any]]:
    allowed = {
        "surface-discovered",
        "identity",
        "business-state",
        "authorization-capability",
        "candidate",
        "finding",
        "candidate-disposition",
        "candidate-dependency",
        "prerequisite-result",
        "missed-finding",
        "credential-state",
        "runtime-condition",
        "route-result",
        "control-result",
        "variant-result",
        "runner-checkpoint",
        "execution-audit",
    }
    selected: deque[dict[str, Any]] = deque(maxlen=limit)
    for event in read_jsonl(workspace / "events.jsonl"):
        if event.get("type") not in allowed:
            continue
        record, _ = compact_records([event], 1)
        if record:
            selected.append(record[0])
    return list(selected)


def canonical_sources(workspace: Path) -> list[dict[str, Any]]:
    result = []
    for name in CANONICAL_FILES:
        path = workspace / name
        if not path.is_file():
            continue
        result.append({
            "path": name,
            "sha256": file_sha256(path),
            "bytes": path.stat().st_size,
        })
    known = {str(item["path"]) for item in result}
    for name in EVENT_LEDGER_FILES:
        events = workspace / name
        if events.is_file() and name not in known:
            result.append({"path": name, "sha256": file_sha256(events), "bytes": events.stat().st_size})
    return result


def event_cursor(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    count = 0
    tail = None
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            count += 1
            tail = hashlib.sha256(line.rstrip("\n").encode("utf-8")).hexdigest()
    return {
        "records": count,
        "tail_sha256": tail,
        "file_sha256": file_sha256(path),
    }


def file_revision(path: Path) -> str | None:
    return file_sha256(path) if path.is_file() else None


def state_revisions(workspace: Path, coverage: dict[str, Any] | None = None) -> dict[str, Any]:
    coverage = coverage if coverage is not None else load_json(workspace / "coverage.json", {})
    finding_path = workspace / "confirmed-findings.json"
    if finding_path.is_file():
        finding_revision = file_sha256(finding_path)
    else:
        finding_revision = hashlib.sha256(
            json.dumps(
                coverage.get("findings", []), ensure_ascii=False, sort_keys=True
            ).encode("utf-8")
        ).hexdigest()
    job = load_json(workspace / "job.json", {})
    active_job_revision = None
    if job and job.get("status") not in {"complete", "completed", "resolved", "failed", "cancelled"}:
        active_job_revision = file_revision(workspace / "job.json")
    return {
        "event_cursor": {
            name: cursor
            for name in EVENT_LEDGER_FILES
            if (cursor := event_cursor(workspace / name)) is not None
        },
        "coverage_revision": file_revision(workspace / "coverage.json"),
        "finding_revision": finding_revision,
        "task_revision": file_revision(workspace / "task-context.json"),
        "active_job_revision": active_job_revision,
    }


def build_capsule(workspace: Path, state: dict[str, Any] | None = None) -> dict[str, Any]:
    workspace = workspace.resolve()
    agent = state if state is not None else load_json(workspace / "agent-state.json", {})
    coverage = load_json(workspace / "coverage.json", {})
    plan = load_json(workspace / "test-plan.json", {})
    inventory = load_json(workspace / "surface-inventory.json", {})
    routes = load_json(workspace / "route-inventory.json", {})
    prerequisites = load_json(
        workspace / "prerequisite-graph.json", {"prerequisites": []}
    )
    evidence = load_json(workspace / "evidence-index.json", {})
    generic_task = load_json(workspace / "task-context.json", {})
    context_events = current_context_events(workspace)
    operator_context = agent.get("task_context", {}).get("operator_policy", {})
    attacker_model = (
        generic_task.get("attacker_model")
        or coverage.get("attacker_model")
        or agent.get("task_context", {}).get("attacker_model")
        or {"kind": "black-box", "allowed_prerequisite_sources": sorted(ATTACKER_CLOSING_SOURCES)}
    )

    unresolved_actions = [
        item
        for item in agent.get("actions", [])
        if item.get("status") not in {"resolved", "blocked"}
    ]
    unresolved_actions.sort(
        key=lambda item: (
            int(str(item.get("priority", "P3"))[1:]) if str(item.get("priority", "P3"))[1:].isdigit() else 3,
            item.get("role", ""),
            item.get("id", ""),
        )
    )
    action_records = []
    for item in unresolved_actions[:120]:
        action_records.append({
            key: item[key]
            for key in (
                "id",
                "role",
                "source_id",
                "priority",
                "safety",
                "status",
                "instruction",
                "input_refs",
                "expected_events",
                "evidence_requirements",
                "invalidation_fingerprint",
            )
            if key in item
        })

    findings, findings_omitted = compact_records(coverage.get("findings", []), 100)
    candidates, candidates_omitted = compact_records(coverage.get("candidates", []), 120)
    cells, cells_omitted = compact_records(
        (
            item
            for item in plan.get("test_cells", [])
            if item.get("status") not in {"tested", "not-applicable"}
        ),
        160,
    )
    unresolved_prerequisites, prerequisites_omitted = compact_records(
        (
            item
            for item in prerequisites.get("prerequisites", [])
            if item.get("status") != "satisfied"
        ),
        160,
    )
    false_gates = sorted(
        key for key, passed in coverage.get("stop_gates", {}).items() if not passed
    )
    source_index = canonical_sources(workspace)
    revisions = state_revisions(workspace, coverage)
    identity_context = {
        "identities": coverage.get("identities", []),
        "business_states": coverage.get("business_states", []),
        "authorization_capabilities": coverage.get("authorization_capabilities", []),
        "credential_state": coverage.get("runtime", {}).get("credential_state"),
        "credential_reason": coverage.get("runtime", {}).get("credential_reason"),
    }
    capsule_core = {
        "schema_version": SCHEMA_VERSION,
        "task": {
            "task_id": generic_task.get("task_id"),
            "target": agent.get("target") or coverage.get("target") or generic_task.get("target"),
            "workflow": agent.get("task_context", {}).get("workflow") or generic_task.get("task_kind", "security-assessment"),
            "status": agent.get("status") or coverage.get("assessment_state", "interim"),
            "assessment_id": coverage.get("assessment_id"),
            "scope_policy": agent.get("task_context", {}).get("scope_policy") or coverage.get("scope", {}).get("mode") or generic_task.get("scope"),
            "safety": agent.get("task_context", {}).get("safety") or generic_task.get("safety", {}),
            "runner_checkpoint": coverage.get("runtime", {}).get("runner_checkpoint", {}),
            "operator_policy_digest": operator_context.get("policy_digest"),
            "platform_sessions": generic_task.get("platform_sessions", []),
            "effective_revision": generic_task.get("effective_revision"),
            "context_schema": generic_task.get("context_schema", SCHEMA_VERSION),
            "attacker_model": attacker_model,
        },
        "continuity_contract": {
            "purpose": "restore critical security investigation state after model context compaction or platform switch",
            "canonical_state_wins": True,
            "historical_evidence_does_not_satisfy_current_coverage": True,
            "do_not_downgrade": [
                "scope-and-safety-boundaries",
                "confirmed-findings-and-negative-controls",
                "unresolved-high-risk-actions",
                "identity-object-state-bindings",
                "surface-and-evidence-references",
                "cleanup-and-blocker-state",
            ],
        },
        "critical_clues": context_events[:80],
        "active_operator_policy": operator_context.get("rules", [])[:24],
        "confirmed_findings": findings,
        "active_candidates": candidates,
        "unresolved_candidates": candidates,
        "unresolved_actions": action_records,
        "unresolved_test_cells": cells,
        "unresolved_prerequisites": unresolved_prerequisites,
        "pending_prerequisites": unresolved_prerequisites,
        "coverage_debt": {
            "failed_stop_gates": false_gates,
            "queue_summary": coverage.get("queue_summary", {}),
            "route_summary": routes.get("summary", coverage.get("route_coverage", {})),
            "surface_summary": inventory.get("summary", {}),
            "inventory_blockers": inventory.get("blockers", [])[:200],
            "unmapped_controls": coverage.get("surface_execution_summary", {}).get("controls_unmapped"),
        },
        "identity_and_state": identity_context,
        "credential_state_refs": coverage.get("runtime", {}).get("credential_state_refs", []),
        "tool_state": {
            "runner_checkpoint": coverage.get("runtime", {}).get("runner_checkpoint", {}),
            "tool_runs_revision": file_revision(workspace / "tool-runs.json"),
        },
        "recent_machine_events": recent_security_events(workspace, 30),
        "evidence_summary": evidence.get("summary", {"count": len(evidence.get("evidence", []))}),
        "canonical_sources": source_index,
        **revisions,
        "overflow": {
            "context_clues_omitted": max(0, len(context_events) - 80),
            "findings_omitted": findings_omitted,
            "candidates_omitted": candidates_omitted,
            "actions_omitted": max(0, len(unresolved_actions) - 120),
            "test_cells_omitted": cells_omitted,
            "prerequisites_omitted": prerequisites_omitted,
            "full_state_retained_in_canonical_sources": True,
        },
        "restore_sequence": [
            "verify target, scope, safety policy, identity and business state",
            "verify canonical source hashes and rebuild the capsule if stale",
            "preserve confirmed findings, rejected explanations and evidence anchors",
            "resume leased or highest-priority unresolved action without repeating resolved work",
            "reconcile new evidence into inventory and plan before drawing conclusions",
            "run the independent auditor before claiming completion",
        ],
    }
    capsule_core["checkpoint_id"] = stable_id(
        "context-checkpoint",
        {
            "sources": source_index,
            "revisions": revisions,
            "clues": [item.get("id") for item in capsule_core["critical_clues"]],
            "actions": [item.get("id") for item in action_records],
        },
    )
    capsule_core["generated_at"] = now()
    enforce_capsule_budget(capsule_core)
    atomic_json(workspace / CAPSULE_NAME, capsule_core)
    task_id = str(generic_task.get("task_id") or "")
    if task_id:
        task_status, checkpoint_revision, _ = effective_skills.task_workspace_status(workspace)
        if task_status in {"complete", "completed", "resolved", "failed", "cancelled"}:
            effective_skills.release_task(task_id)
        else:
            effective_skills.pin_task(
                task_id,
                workspace,
                str(generic_task.get("effective_revision") or "") or None,
                checkpoint_revision=checkpoint_revision,
                task_status=task_status,
                task_revision=state_revisions(workspace, coverage).get("task_revision"),
            )
    return capsule_core


def capsule_size(value: dict[str, Any]) -> int:
    return len(json.dumps(value, ensure_ascii=False, sort_keys=True).encode())


def enforce_capsule_budget(capsule: dict[str, Any]) -> None:
    overflow = capsule["overflow"]
    collections = (
        ("recent_machine_events", 5, "recent_machine_events_omitted"),
        ("unresolved_test_cells", 12, "test_cells_omitted"),
        ("unresolved_prerequisites", 12, "prerequisites_omitted"),
        ("active_candidates", 12, "candidates_omitted"),
        ("active_operator_policy", 4, "operator_policy_omitted"),
    )
    while capsule_size(capsule) > MAX_CAPSULE_BYTES:
        changed = False
        blockers = capsule["coverage_debt"].get("inventory_blockers", [])
        if len(blockers) > 12:
            blockers.pop()
            overflow["inventory_blockers_omitted"] = int(overflow.get("inventory_blockers_omitted", 0)) + 1
            changed = True
        for key, minimum, counter in collections:
            values = capsule.get(key, [])
            if capsule_size(capsule) <= MAX_CAPSULE_BYTES:
                break
            if len(values) > minimum:
                values.pop()
                overflow[counter] = int(overflow.get(counter, 0)) + 1
                changed = True
        if capsule_size(capsule) <= MAX_CAPSULE_BYTES:
            break
        clues = capsule.get("critical_clues", [])
        removable = next(
            (
                index
                for index in range(len(clues) - 1, -1, -1)
                if clues[index].get("priority") in {"normal", "low"}
            ),
            None,
        )
        if removable is not None:
            clues.pop(removable)
            overflow["context_clues_omitted"] += 1
            changed = True
        actions = capsule.get("unresolved_actions", [])
        removable_action = next(
            (
                index
                for index in range(len(actions) - 1, -1, -1)
                if actions[index].get("priority") in {"P2", "P3"}
            ),
            None,
        )
        if capsule_size(capsule) > MAX_CAPSULE_BYTES and removable_action is not None:
            actions.pop(removable_action)
            overflow["actions_omitted"] += 1
            changed = True
        if not changed:
            break
    if capsule_size(capsule) > MAX_CAPSULE_BYTES:
        for action in capsule.get("unresolved_actions", []):
            instruction = action.get("instruction")
            if isinstance(instruction, dict):
                action["instruction"] = {
                    key: instruction[key]
                    for key in ("action", "case_id", "family", "reason")
                    if key in instruction
                }
        for clue in capsule.get("critical_clues", []):
            clue["summary"] = str(clue.get("summary") or "")[:240]
        overflow["hard_budget_compaction"] = True
    if capsule_size(capsule) > MAX_CAPSULE_BYTES:
        identity = capsule.get("identity_and_state", {})
        for key in ("identities", "business_states", "authorization_capabilities"):
            values = identity.get(key, [])
            if isinstance(values, list) and len(values) > 20:
                overflow[f"{key}_omitted"] = len(values) - 20
                identity[key] = values[:20]
        final_collections = (
            ("recent_machine_events", 0, "recent_machine_events_omitted"),
            ("unresolved_test_cells", 0, "test_cells_omitted"),
            ("unresolved_prerequisites", 0, "prerequisites_omitted"),
            ("active_candidates", 0, "candidates_omitted"),
            ("active_operator_policy", 4, "operator_policy_omitted"),
            ("critical_clues", 8, "context_clues_omitted"),
            ("confirmed_findings", 12, "findings_omitted"),
            ("unresolved_actions", 12, "actions_omitted"),
        )
        for key, minimum, counter in final_collections:
            values = capsule.get(key, [])
            while capsule_size(capsule) > MAX_CAPSULE_BYTES and len(values) > minimum:
                values.pop()
                overflow[counter] = int(overflow.get(counter, 0)) + 1
    if capsule_size(capsule) > MAX_CAPSULE_BYTES:
        identity = capsule.get("identity_and_state", {})
        capsule["identity_and_state"] = {
            "credential_state": identity.get("credential_state"),
            "credential_reason": identity.get("credential_reason"),
            "identities_count": len(identity.get("identities", [])),
            "business_states_count": len(identity.get("business_states", [])),
            "authorization_capabilities_count": len(identity.get("authorization_capabilities", [])),
            "full_state": "coverage.json",
        }
        overflow["identity_context_compacted"] = True
    if capsule_size(capsule) > MAX_CAPSULE_BYTES:
        emergency = {
            "schema_version": capsule["schema_version"],
            "checkpoint_id": capsule.get("checkpoint_id"),
            "generated_at": capsule.get("generated_at"),
            "task": capsule["task"],
            "continuity_contract": capsule["continuity_contract"],
            "critical_index": {
                "clue_ids": [item.get("id") for item in capsule.get("critical_clues", [])[:80]],
                "finding_ids": [item.get("id") for item in capsule.get("confirmed_findings", [])[:80]],
                "action_ids": [item.get("id") for item in capsule.get("unresolved_actions", [])[:80]],
                "failed_stop_gates": capsule.get("coverage_debt", {}).get("failed_stop_gates", []),
            },
            "canonical_sources": capsule["canonical_sources"],
            "overflow": {
                **overflow,
                "emergency_index_only": True,
                "full_state_retained_in_canonical_sources": True,
            },
            "restore_sequence": capsule["restore_sequence"],
        }
        capsule.clear()
        capsule.update(emergency)
        overflow = capsule["overflow"]
    overflow["capsule_bytes"] = capsule_size(capsule)
    overflow["capsule_budget_bytes"] = MAX_CAPSULE_BYTES
    index = capsule.get("critical_index", {})
    while capsule_size(capsule) > MAX_CAPSULE_BYTES and not index:
        changed = False
        for key, counter in (
            ("recent_machine_events", "recent_machine_events_omitted"),
            ("unresolved_test_cells", "test_cells_omitted"),
            ("unresolved_prerequisites", "prerequisites_omitted"),
            ("active_candidates", "candidates_omitted"),
        ):
            values = capsule.get(key, [])
            if values:
                values.pop()
                overflow[counter] = int(overflow.get(counter, 0)) + 1
                changed = True
                break
        if not changed:
            clues = capsule.get("critical_clues", [])
            removable = next(
                (
                    position
                    for position in range(len(clues) - 1, -1, -1)
                    if clues[position].get("priority") in {"normal", "low"}
                ),
                None,
            )
            if removable is not None:
                clues.pop(removable)
                overflow["context_clues_omitted"] += 1
                changed = True
        if not changed:
            break
    while capsule_size(capsule) > MAX_CAPSULE_BYTES and index:
        changed = False
        for key in ("clue_ids", "finding_ids", "action_ids", "failed_stop_gates"):
            values = index.get(key, [])
            if len(values) > 1:
                values.pop()
                changed = True
                if capsule_size(capsule) <= MAX_CAPSULE_BYTES:
                    break
        if not changed:
            break
    overflow["capsule_bytes"] = capsule_size(capsule)


def audit_capsule(workspace: Path) -> dict[str, Any]:
    capsule = load_json(workspace / CAPSULE_NAME, {})
    if not capsule:
        return {"status": "missing", "stale_sources": [CAPSULE_NAME]}
    reasons: list[str] = []
    if int(capsule.get("schema_version", 0)) < SCHEMA_VERSION or not all(
        key in capsule
        for key in ("event_cursor", "coverage_revision", "finding_revision", "task_revision")
    ):
        reasons.append("legacy-unverifiable")
    recorded = {
        str(source.get("path")): str(source.get("sha256"))
        for source in capsule.get("canonical_sources", [])
        if source.get("path")
    }
    current = {
        str(source.get("path")): str(source.get("sha256"))
        for source in canonical_sources(workspace)
        if source.get("path")
    }
    stale = sorted(
        path
        for path in recorded.keys() | current.keys()
        if recorded.get(path) != current.get(path)
    )
    revisions = state_revisions(workspace)
    recorded_cursor = capsule.get("event_cursor", {})
    if recorded_cursor != revisions["event_cursor"]:
        reasons.append("event-cursor-behind")
    if capsule.get("coverage_revision") != revisions["coverage_revision"]:
        reasons.append("event-cursor-behind")
    if capsule.get("finding_revision") != revisions["finding_revision"]:
        reasons.append("finding-ledger-diverged")
    if capsule.get("active_job_revision") != revisions["active_job_revision"]:
        reasons.append("unregistered-active-job")
    reasons = list(dict.fromkeys(reasons))
    return {
        "status": "current" if not stale and not reasons else "stale",
        "checkpoint_id": capsule.get("checkpoint_id"),
        "stale_sources": stale,
        "reasons": reasons,
        "generated_at": capsule.get("generated_at"),
    }


def command_build(args: argparse.Namespace) -> int:
    capsule = build_capsule(args.workspace)
    print(json.dumps(capsule, ensure_ascii=False, indent=2))
    return 0


def command_init(args: argparse.Namespace) -> int:
    workspace = args.workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    task_path = workspace / "task-context.json"
    current = load_json(task_path, {})
    created_at = current.get("created_at") or now()
    effective_revision = current.get("effective_revision") or effective_skills.current_revision()
    task = {
        "schema_version": SCHEMA_VERSION,
        "task_id": current.get("task_id") or stable_id(
            "security-task",
            {
                "workspace": str(workspace),
                "created_at": created_at,
            },
        ),
        "task_kind": args.task_kind,
        "target": args.target,
        "scope": args.scope,
        "safety": {
            "policy": args.safety,
            "credentials_persisted": False,
            "raw_evidence_in_capsule": False,
        },
        "created_at": created_at,
        "updated_at": now(),
        "platform_sessions": current.get("platform_sessions", []),
        "effective_revision": effective_revision,
        "status": current.get("status", "active"),
        "context_schema": SCHEMA_VERSION,
        "attacker_model": current.get("attacker_model") or {
            "kind": getattr(args, "attacker_model", "black-box"),
            "allowed_prerequisite_sources": sorted(ATTACKER_CLOSING_SOURCES),
        },
    }
    atomic_json(task_path, task)
    effective_skills.pin_task(task["task_id"], workspace, effective_revision)
    capsule = build_capsule(workspace)
    print(json.dumps({"task": task, "checkpoint_id": capsule["checkpoint_id"]}, ensure_ascii=False, indent=2))
    return 0


def command_show(args: argparse.Namespace) -> int:
    capsule = load_json(args.workspace / CAPSULE_NAME, {})
    if not capsule:
        capsule = build_capsule(args.workspace)
    print(json.dumps(capsule, ensure_ascii=False, indent=2))
    return 0


def command_record(args: argparse.Namespace) -> int:
    event = load_json(args.event, {})
    normalized = append_context_event(args.workspace, event)
    capsule = checkpoint(args.workspace, trigger="context-event")
    print(json.dumps({"event": normalized, "checkpoint_id": capsule["checkpoint_id"]}, ensure_ascii=False, indent=2))
    return 0


def update_journal_state(
    workspace: Path,
    *,
    trigger: str,
    platform: str | None = None,
    session_id: str | None = None,
    transcript_key: str | None = None,
    transcript_offset: int | None = None,
) -> dict[str, Any]:
    path = workspace / JOURNAL_STATE_NAME
    state = load_json(path, {"schema_version": 1, "transcripts": {}})
    state["schema_version"] = 1
    state["last_trigger"] = trigger
    state["last_checkpoint_at"] = now()
    if platform:
        state["platform"] = platform
    if session_id:
        state["session_ref"] = stable_id("session", session_id)
    if transcript_key and transcript_offset is not None:
        state.setdefault("transcripts", {})[transcript_key] = {
            "offset": transcript_offset,
            "updated_at": now(),
        }
    atomic_json(path, state)
    return state


def bind_platform_session(
    workspace: Path, platform: str | None, session_id: str | None
) -> None:
    if not platform or not session_id:
        return
    path = workspace / "task-context.json"
    task = load_json(path, {})
    if not task:
        return
    session_ref = stable_id("session", session_id)
    sessions = [
        item
        for item in task.get("platform_sessions", [])
        if not (item.get("platform") == platform and item.get("session_ref") == session_ref)
    ]
    sessions.append({"platform": platform, "session_ref": session_ref, "bound_at": now()})
    task["platform_sessions"] = sessions[-40:]
    task["updated_at"] = now()
    atomic_json(path, task)
    binding_path = DATA_ROOT / BINDING_INDEX_NAME
    bindings = load_json(binding_path, {"schema_version": 1, "bindings": {}})
    bindings.setdefault("bindings", {})[session_ref] = {
        "workspace": str(workspace.resolve()),
        "task_id": task.get("task_id"),
        "platform": platform,
        "updated_at": now(),
    }
    atomic_json(binding_path, bindings)


def resolve_bound_workspace(session_id: str | None) -> Path | None:
    if not session_id:
        return None
    session_ref = stable_id("session", session_id)
    bindings = load_json(DATA_ROOT / BINDING_INDEX_NAME, {}).get("bindings", {})
    value = bindings.get(session_ref, {})
    workspace = Path(str(value.get("workspace") or ""))
    if workspace.is_dir() and (workspace / "task-context.json").is_file():
        return workspace.resolve()
    return None


def checkpoint(
    workspace: Path,
    *,
    trigger: str = "manual",
    platform: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    workspace = workspace.resolve()
    bind_platform_session(workspace, platform, session_id)
    update_journal_state(
        workspace,
        trigger=trigger,
        platform=platform,
        session_id=session_id,
    )
    return build_capsule(workspace)


def restore_context(workspace: Path) -> dict[str, Any]:
    workspace = workspace.resolve()
    initial_audit = audit_capsule(workspace)
    audit = initial_audit
    if initial_audit["status"] != "current":
        build_capsule(workspace)
        audit = audit_capsule(workspace)
    capsule = load_json(workspace / CAPSULE_NAME, {})
    task = load_json(workspace / "task-context.json", {})
    pinned_revision = task.get("effective_revision")
    active_revision = effective_skills.current_revision()
    provisional = [
        item
        for item in capsule.get("critical_clues", [])
        if item.get("verification_state") == "provisional"
        or item.get("type") == "provisional"
    ]
    return {
        "status": "ready" if audit["status"] == "current" else "degraded",
        "audit": audit,
        "requires_reconciliation": bool(provisional),
        "provisional_clue_ids": [item.get("id") for item in provisional],
        "effective_revision": pinned_revision,
        "active_effective_revision": active_revision,
        "effective_revision_changed": bool(
            pinned_revision and active_revision and pinned_revision != active_revision
        ),
        "reconciled_from": (
            initial_audit.get("reasons", [])
            if initial_audit["status"] != "current"
            else []
        ),
        "capsule": capsule,
    }


def context_status(workspace: Path) -> dict[str, Any]:
    """Report checkpoint freshness without mutating or rebuilding task state."""
    workspace = workspace.resolve()
    audit = audit_capsule(workspace)
    capsule = load_json(workspace / CAPSULE_NAME, {})
    task = load_json(workspace / "task-context.json", {})
    pinned_revision = task.get("effective_revision")
    active_revision = effective_skills.current_revision()
    provisional = [
        item
        for item in capsule.get("critical_clues", [])
        if item.get("verification_state") == "provisional"
        or item.get("type") == "provisional"
    ]
    return {
        "status": "ready" if audit["status"] == "current" else "degraded",
        "audit": audit,
        "requires_reconciliation": audit["status"] != "current" or bool(provisional),
        "provisional_clue_ids": [item.get("id") for item in provisional],
        "effective_revision": pinned_revision,
        "active_effective_revision": active_revision,
        "effective_revision_changed": bool(
            pinned_revision and active_revision and pinned_revision != active_revision
        ),
    }


def visible_transcript_messages(path: Path, offset: int = 0) -> tuple[list[str], int]:
    messages: list[str] = []
    with path.open("rb") as handle:
        size = path.stat().st_size
        if offset < 0 or offset > size:
            offset = 0
        handle.seek(offset)
        for raw in handle:
            try:
                event = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            payload = event.get("payload", event)
            if payload.get("type") != "message" or payload.get("role") not in {"user", "assistant"}:
                continue
            parts = payload.get("content", [])
            text = "\n".join(
                str(item.get("text", ""))
                for item in parts
                if isinstance(item, dict)
                and item.get("type") in {"input_text", "output_text", "text"}
            ).strip()
            if text:
                messages.append(text)
        return messages, handle.tell()


def reconcile_transcript(
    workspace: Path,
    transcript: Path,
    *,
    platform: str | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    workspace = workspace.resolve()
    transcript = transcript.expanduser().resolve()
    if not transcript.is_file():
        raise ValueError(f"transcript does not exist: {transcript}")
    key = stable_id("transcript", str(transcript))
    journal = load_json(workspace / JOURNAL_STATE_NAME, {"transcripts": {}})
    offset = int(journal.get("transcripts", {}).get(key, {}).get("offset", 0))
    messages, new_offset = visible_transcript_messages(transcript, offset)
    relevant = [message for message in messages if IMPORTANT_TRANSCRIPT_RE.search(message)]
    recorded = []
    for message in relevant[-8:]:
        event = append_context_event(
            workspace,
            {
                "type": "provisional",
                "priority": "high",
                "summary": message[:1000],
                "verification_state": "provisional",
                "platform": platform,
                "session_id": session_id,
                "trigger": "transcript-reconcile",
                "refs": [key],
            },
        )
        recorded.append(event["id"])
    bind_platform_session(workspace, platform, session_id)
    update_journal_state(
        workspace,
        trigger="transcript-reconcile",
        platform=platform,
        session_id=session_id,
        transcript_key=key,
        transcript_offset=new_offset,
    )
    capsule = build_capsule(workspace)
    return {
        "status": "reconciled",
        "messages_seen": len(messages),
        "provisional_clues_recorded": len(recorded),
        "provisional_clue_ids": recorded,
        "checkpoint_id": capsule["checkpoint_id"],
    }


def command_checkpoint(args: argparse.Namespace) -> int:
    capsule = checkpoint(
        args.workspace,
        trigger=args.trigger,
        platform=args.platform,
        session_id=args.session_id,
    )
    print(json.dumps(capsule, ensure_ascii=False, indent=2))
    return 0


def command_restore(args: argparse.Namespace) -> int:
    print(json.dumps(restore_context(args.workspace), ensure_ascii=False, indent=2))
    return 0


def command_reconcile(args: argparse.Namespace) -> int:
    result = reconcile_transcript(
        args.workspace,
        args.transcript,
        platform=args.platform,
        session_id=args.session_id,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def command_status(args: argparse.Namespace) -> int:
    result = context_status(args.workspace)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "ready" else 2


def command_audit(args: argparse.Namespace) -> int:
    result = audit_capsule(args.workspace)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "current" else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build bounded security-task context checkpoints")
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init")
    initialize.add_argument("--workspace", required=True, type=Path)
    initialize.add_argument("--task-kind", required=True)
    initialize.add_argument("--target")
    initialize.add_argument("--scope", default="current-authorized-task-scope")
    initialize.add_argument("--safety", default="minimally-disruptive")
    initialize.add_argument("--attacker-model", default="black-box")
    initialize.set_defaults(function=command_init)
    for name, function in (
        ("build", command_build),
        ("show", command_show),
        ("audit", command_audit),
        ("restore", command_restore),
        ("status", command_status),
    ):
        item = commands.add_parser(name)
        item.add_argument("--workspace", required=True, type=Path)
        item.set_defaults(function=function)
    record = commands.add_parser("record")
    record.add_argument("--workspace", required=True, type=Path)
    record.add_argument("--event", required=True, type=Path)
    record.set_defaults(function=command_record)
    checkpoint_parser = commands.add_parser("checkpoint")
    checkpoint_parser.add_argument("--workspace", required=True, type=Path)
    checkpoint_parser.add_argument("--trigger", default="manual")
    checkpoint_parser.add_argument("--platform")
    checkpoint_parser.add_argument("--session-id")
    checkpoint_parser.set_defaults(function=command_checkpoint)
    reconcile = commands.add_parser("reconcile")
    reconcile.add_argument("--workspace", required=True, type=Path)
    reconcile.add_argument("--transcript", required=True, type=Path)
    reconcile.add_argument("--platform")
    reconcile.add_argument("--session-id")
    reconcile.set_defaults(function=command_reconcile)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        raise SystemExit(args.function(args))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=os.sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
