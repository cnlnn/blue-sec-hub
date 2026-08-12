#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    import effective_skills
    import learning_store
    from web_assessment import registrable_domain
except ModuleNotFoundError:
    from scripts import effective_skills, learning_store
    from scripts.web_assessment import registrable_domain


def data_root() -> Path:
    return Path(
        os.environ.get(
            "BLUE_SEC_DATA",
            Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
            / "blue-sec-hub",
        )
    )


def cluster_root() -> Path:
    return data_root() / "assessment-learning" / "clusters"


def now() -> str:
    return datetime.now(UTC).isoformat()


def stable_id(prefix: str, value: Any) -> str:
    body = json.dumps(value, ensure_ascii=False, sort_keys=True).encode()
    return f"{prefix}-{hashlib.sha256(body).hexdigest()[:16]}"


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def atomic_json(path: Path, value: Any) -> None:
    learning_store.atomic_json(path, value)


def write_jsonl(path: Path, values: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        "".join(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n" for value in values),
        encoding="utf-8",
    )
    if os.name != "nt":
        temporary.chmod(0o600)
    temporary.replace(path)


def read_events(workspace: Path) -> list[dict[str, Any]]:
    path = workspace / "assessment-events.jsonl"
    if not path.is_file():
        return []
    values = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            values.append(value)
    return values


def technique_for(finding: dict[str, Any]) -> str:
    for key in ("technique_ref", "family", "authorization_mode", "weakness_id"):
        value = str(finding.get(key) or "").strip().casefold()
        if value:
            return re.sub(r"[^a-z0-9.-]+", "-", value).strip("-")[:96]
    title = str(finding.get("title") or "validated-security-boundary")
    if re.search(r"anonymous|without credentials|未授权", title, re.I):
        return "authorization.anonymous-boundary"
    return "evidence.validated-security-boundary"


def generic_pattern(technique: str) -> tuple[str, str, str]:
    if "anonymous" in technique:
        return (
            "Compare a stable authenticated baseline with a credential-free replay and repeat the variant before confirming equivalent protected response structure.",
            "Applies to read-like operations with a current authenticated baseline; public resources and nonexistent-object responses are excluded.",
            "Require two repeatable variants, equivalent protected response structure, impact-bearing fields, and a negative control.",
        )
    if "authorization" in technique or "object" in technique:
        return (
            "Vary one subject, object, parent, role, or lifecycle binding at a time while retaining a self-owned baseline.",
            "Applies when current identity, ownership, and normal lifecycle evidence are available; unrelated-object access is excluded.",
            "Require a normal baseline, a single-variable variant, repeatability, and explicit impact or a rejected alternative explanation.",
        )
    return (
        "Reproduce the validated behavior from a stable baseline, change one security-relevant variable, and compare a negative control.",
        "Applies when the input, processing boundary, and observable result are current and repeatable.",
        "Require current evidence, one changed variable, repeatability, and an impact-bearing oracle before confirmation.",
    )


def target_fingerprint(target: str) -> str:
    parsed = urlsplit(target if "://" in target else "https://" + target)
    boundary = registrable_domain((parsed.hostname or "").casefold())
    return hashlib.sha256(boundary.encode()).hexdigest()


def candidate_for(finding: dict[str, Any], target_hash: str) -> dict[str, Any]:
    technique = technique_for(finding)
    procedure, conditions, oracle = generic_pattern(technique)
    evidence = sorted(
        stable_id("evidence-ref", str(value))
        for value in finding.get("evidence_refs", [])
        if value
    )
    candidate_id = stable_id(
        "learning-candidate",
        {"technique": technique, "procedure": procedure, "oracle": oracle},
    )
    return {
        "schema_version": 1,
        "id": candidate_id,
        "state": "candidate",
        "destination": "blue-vulnerability-patterns",
        "technique": technique,
        "procedure": procedure,
        "conditions": conditions,
        "oracle": oracle,
        "source_evidence_hashes": evidence,
        "observation_hash": stable_id("observation", [target_hash, finding.get("id")]),
        "created_at": now(),
    }


def update_cluster(candidate: dict[str, Any], target_hash: str) -> dict[str, Any]:
    root = cluster_root()
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{candidate['id']}.json"
    cluster = load_json(
        path,
        {
            "schema_version": 1,
            "candidate_id": candidate["id"],
            "technique": candidate["technique"],
            "target_fingerprints": [],
            "regression_scenarios": [],
            "promotion_state": "candidate",
        },
    )
    cluster["target_fingerprints"] = sorted(
        set(cluster.get("target_fingerprints", [])) | {target_hash}
    )
    independent = len(cluster["target_fingerprints"])
    regressions = len(set(cluster.get("regression_scenarios", [])))
    cluster["promotion_state"] = "ready" if independent >= 2 or regressions >= 2 else "candidate"
    cluster["updated_at"] = now()
    atomic_json(path, cluster)
    return cluster


def approve_candidate(candidate: dict[str, Any], cluster: dict[str, Any]) -> dict[str, Any]:
    if cluster.get("promotion_state") != "ready":
        return {"status": "candidate", "reason": "two independent scenarios required"}
    seed = {
        "id": candidate["id"],
        "semantic_id": candidate["technique"],
        "kind": "knowledge-entry",
        "skill": "blue-vulnerability-patterns",
        "ownership": "local",
        "source": "assessment-learning",
        "task": f"Validate reusable {candidate['technique']} behavior",
        "failure": "A confirmed behavior remained isolated to one assessment and could not guide comparable validation.",
        "correction": candidate["procedure"],
        "successful_pattern": f"{candidate['procedure']} {candidate['oracle']}",
        "conditions": candidate["conditions"],
        "confidence": "high",
        "sensitivity": "internal",
        "evidence_refs": [candidate["observation_hash"], *candidate["source_evidence_hashes"]],
        "created_at": candidate["created_at"],
    }
    value = learning_store.make_object(seed)
    with learning_store.store_lock():
        records = learning_store.state_index()
        existing = records.get(candidate["id"])
        if existing and existing.get("state") == "approved":
            return {"status": "approved", "record_id": candidate["id"]}
        sha256, _ = learning_store.write_object(value)
        if not existing:
            learning_store.append_event(
                {"event": "recorded", "record_id": candidate["id"], "object_sha256": sha256}
            )
        failures = learning_store.validate_for_approval(value)
        if failures:
            return {"status": "blocked", "reason": "; ".join(failures)}
        prospective = [*learning_store.approved_objects(), value]
        manifest = learning_store.manifest_for_objects(prospective)
        snapshot = effective_skills.compile_snapshot(manifest=manifest)
        learning_store.append_event(
            {
                "event": "approved",
                "record_id": candidate["id"],
                "object_sha256": sha256,
                "approval_basis": "two-independent-assessments",
                "independent_scenarios": len(cluster.get("target_fingerprints", [])),
            }
        )
        committed = learning_store.rebuild_manifest()
        if committed["revision"] != manifest["revision"]:
            raise ValueError("learning state changed during assessment approval")
        effective_skills.activate_revision(str(snapshot["revision"]))
    return {"status": "approved", "record_id": candidate["id"], "effective_revision": snapshot["revision"]}


def distill(workspace: Path, promote: bool = True) -> dict[str, Any]:
    workspace = workspace.resolve()
    coverage = load_json(workspace / "coverage.json", {})
    state = load_json(workspace / "agent-state.json", {})
    target = str(state.get("target") or coverage.get("target") or "")
    if not target:
        raise ValueError("assessment target is unavailable")
    findings = [
        item for item in coverage.get("findings", []) if item.get("validation_state") == "confirmed"
    ]
    missed = [item for item in read_events(workspace) if item.get("type") == "missed-finding"]
    target_hash = target_fingerprint(target)
    candidates: list[dict[str, Any]] = []
    promotions = []
    for finding in findings:
        candidate = candidate_for(finding, target_hash)
        cluster = update_cluster(candidate, target_hash)
        candidate["universality"] = {
            "independent_scenarios": len(cluster.get("target_fingerprints", [])),
            "state": cluster["promotion_state"],
        }
        candidates.append(candidate)
        if promote:
            promotions.append({"id": candidate["id"], **approve_candidate(candidate, cluster)})
    for item in missed:
        cause = re.sub(r"[^a-z0-9.-]+", "-", str(item.get("cause") or "unknown").casefold()).strip("-")
        candidates.append(
            {
                "schema_version": 1,
                "id": stable_id("missed-finding-learning", cause),
                "state": "candidate",
                "destination": "blue-web-patrol",
                "technique": f"coverage-gap.{cause}",
                "procedure": "Add a target-independent collection or validation step without weakening evidence gates.",
                "conditions": "Applies when the same generic coverage cause is evidenced; target and interface details are excluded.",
                "oracle": "Require a reproduced missed baseline and a positive regression.",
                "source_evidence_hashes": [],
                "created_at": now(),
            }
        )
    candidates = sorted({item["id"]: item for item in candidates}.values(), key=lambda item: item["id"])
    write_jsonl(workspace / "learning-candidates.jsonl", candidates)
    summary = {
        "schema_version": 2,
        "generated_at": now(),
        "confirmed_findings": len(findings),
        "missed_findings": len(missed),
        "candidates": len(candidates),
        "ready": sum(item.get("universality", {}).get("state") == "ready" for item in candidates),
        "promotions": promotions,
        "target_material_persisted": False,
        "git_branch_created": False,
    }
    atomic_json(workspace / "learning-summary.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Distill target-independent learning from an assessment")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("distill")
    command.add_argument("--workspace", required=True, type=Path)
    command.add_argument("--auto-promote", action=argparse.BooleanOptionalAction, default=True)
    args = parser.parse_args()
    print(json.dumps(distill(args.workspace, args.auto_promote), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
