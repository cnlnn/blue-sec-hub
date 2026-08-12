#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import install
import platforms
import effective_skills
import learning_store
import platform_certify
import report_ingestion
import runtime_support
import security_conclusion
import context_checkpoint
import knowledge_index
from executor_adapter import get_adapter, load_executor_specs


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
BASELINE_REQUIRED_CASES = {
    "regression-burp-damaged-history",
    "regression-random-id-negative",
    "regression-internal-log-provenance",
    "incomplete-chain-spa",
    "incomplete-chain-web",
    "regression-interim-completion",
    "regression-revoked-finding",
}


def upstream_knowledge_health() -> dict[str, object]:
    lock_path = ROOT / "sources.lock.json"
    upstreams = CACHE_ROOT / "upstreams"
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"status": "corrupt", "reason": "source-lock-missing-or-invalid", "sources": {}}
    sources: dict[str, dict[str, object]] = {}
    for name, expected in lock.get("sources", {}).items():
        path = upstreams / name
        item: dict[str, object] = {"expected_commit": expected.get("commit")}
        if "payload_records" in expected:
            try:
                summary = json.loads((path / "summary.json").read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                item.update(status="not-built", reason="payload-catalog-missing")
            else:
                current = int(summary.get("payloads", 0)) == int(expected["payload_records"])
                current = current and summary.get("source", {}).get("commit") == expected.get("commit")
                item.update(status="ready" if current else "stale", records=int(summary.get("payloads", 0)))
        else:
            count = sum(1 for candidate in path.rglob("*") if candidate.is_file() and candidate.suffix.casefold() in {".md", ".markdown"}) if path.is_dir() else 0
            expected_count = int(expected.get("markdown_files", 0))
            item.update(status="ready" if count == expected_count else ("not-built" if not path.exists() else "stale"), documents=count)
        sources[name] = item
    states = {str(item["status"]) for item in sources.values()}
    status = "ready" if states <= {"ready"} else ("not-built" if states <= {"not-built"} else "degraded")
    return {"status": status, "sources": sources, "locked_sources": len(sources)}


def baseline_eval_health(active_revision: str | None) -> dict[str, object]:
    configured = bool(os.environ.get("BLUE_SEC_BASELINE_MODEL"))
    root = DATA_ROOT / "eval-results" / str(active_revision or "")
    reports = []
    if root.is_dir():
        for path in root.glob("*.json"):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            baseline = next(
                (item for item in value.get("hosts", []) if item.get("host") == "baseline"),
                None,
            )
            case_ids = {str(item.get("id")) for item in (baseline or {}).get("cases", [])}
            if baseline and BASELINE_REQUIRED_CASES <= case_ids:
                reports.append((str(value.get("generated_at") or ""), path, value, baseline))
    if reports:
        _, path, value, baseline = max(reports, key=lambda item: (item[0], str(item[1])))
        return {
            "status": "ready" if value.get("passed") and baseline.get("passed") else "degraded",
            "host": "codex",
            "model": baseline.get("model"),
            "model_configured": configured,
            "effective_revision": active_revision,
            "behavior_consistency": value.get("behavior_consistency"),
            "safety_contract_passed": value.get("safety_contract_passed"),
            "result_sha256": value.get("result_sha256"),
            "result_path": str(path),
            "required_cases": len(BASELINE_REQUIRED_CASES),
        }
    return {
        "status": "ready" if configured and shutil.which("codex") else "not-installed",
        "host": "codex",
        "model_configured": configured,
    }


def luna_eval_health(active_revision: str | None) -> dict[str, object]:
    root = DATA_ROOT / "eval-results" / str(active_revision or "")
    reports = []
    if root.is_dir():
        for path in root.glob("*.json"):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            luna = next(
                (item for item in value.get("hosts", []) if "luna" in str(item.get("model", "")).casefold()),
                None,
            )
            case_ids = {str(item.get("id")) for item in (luna or {}).get("cases", [])}
            if luna and BASELINE_REQUIRED_CASES <= case_ids:
                reports.append((str(value.get("generated_at") or ""), path, value, luna))
    if reports:
        _, path, value, luna = max(reports, key=lambda item: (item[0], str(item[1])))
        return {
            "status": "ready" if value.get("passed") and luna.get("passed") else "degraded",
            "host": "luna",
            "model": luna.get("model"),
            "effective_revision": active_revision,
            "behavior_consistency": value.get("behavior_consistency"),
            "safety_contract_passed": value.get("safety_contract_passed"),
            "result_path": str(path),
            "required_cases": len(BASELINE_REQUIRED_CASES),
        }
    return {"status": "not-installed", "host": "luna", "reason": "no complete Luna eval receipt for the active revision"}


def installed_skill_capability(entry: dict, skills: list[Path]) -> tuple[str, list[str]]:
    target = platforms.skill_root(entry)
    manifest = install.load_json(target / install.MANIFEST_NAME)
    records = {item.get("name"): item for item in manifest.get("skills", [])}
    missing = []
    for source in skills:
        destination = target / source.parent.name
        record = records.get(source.parent.name, {})
        linked = install.same_link(destination, source.parent)
        managed = (
            destination.is_dir()
            and not destination.is_symlink()
            and record.get("mode") == "managed-copy"
            and record.get("sha256") == install.tree_hash(destination)
        )
        if not linked and not managed:
            missing.append(source.parent.name)
    return ("ready" if not missing else "degraded", missing)


def mcp_capability(entry: dict) -> str:
    mode = str(entry["mcp"]["mode"])
    config = platforms.resolve_path(entry, str(entry["mcp"]["config"]))
    if mode.endswith("if-present") and not config.exists():
        config = platforms.resolve_path(entry, str(entry["mcp"]["snippet"]))
    if mode.startswith("json-") or mode == "generated-snippet":
        current = install.load_json(config)
        key, expected = install.json_server(mode)
        return "ready" if current.get(key, {}).get(install.SERVER_NAME) == expected else "degraded"
    executable = platforms.executable(entry)
    if not executable:
        return "not-installed"
    get, _, _, environment = install.mcp_cli_commands(entry, executable)
    result = subprocess.run(get, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return "ready" if result.returncode == 0 and install.SERVER_NAME in result.stdout else "degraded"


def subagent_capability(entry: dict) -> tuple[str, list[str]]:
    contract = entry["agents"]
    if contract["status"] != "supported":
        return "not-exposed", []
    target = platforms.resolve_path(entry, str(contract["path"]))
    manifest = install.load_json(target / install.AGENT_MANIFEST_NAME)
    records = {item.get("name"): item for item in manifest.get("agents", [])}
    missing = []
    for source in sorted((ROOT / "agents").glob("*.md")):
        destination = target / source.name
        record = records.get(source.name, {})
        linked = install.same_link(destination, source)
        managed = (
            destination.is_file()
            and not destination.is_symlink()
            and record.get("mode") == "managed-copy"
            and record.get("sha256") == install.file_hash(destination)
        )
        if not linked and not managed:
            missing.append(source.name)
    return ("ready" if not missing else "degraded"), missing


def platform_capability_matrix(selected: list[dict], skills: list[Path]) -> dict[str, dict]:
    matrix = {}
    for entry in selected:
        detected = platforms.is_detected(entry)
        version = platforms.probe_version(entry)
        skills_status, missing = installed_skill_capability(entry, skills)
        subagents_status, missing_agents = subagent_capability(entry)
        session_status = "ready" if entry["sessions"]["status"] == "supported" else "not-exposed"
        hook_manifest = install.load_json(install.hook_manifest_path(entry))
        if hook_manifest.get("platform") == entry["id"] and hook_manifest.get("active"):
            hook_status = "ready"
        elif hook_manifest.get("platform") == entry["id"]:
            hook_status = "contract-ready"
        else:
            hook_status = "degraded" if detected else "contract-ready"
        capabilities = {
            "skills": skills_status,
            "mcp": mcp_capability(entry),
            "hooks": hook_status,
            "checkpoint": "contract-ready",
            "restore": "contract-ready",
            "session-import": session_status,
            "subagents": subagents_status,
        }
        certification = platform_certify.validate_receipt(entry) if detected else {
            "status": "not-installed",
            "reasons": ["runtime not detected"],
        }
        if certification["status"] == "runtime-certified":
            capabilities["mcp"] = "runtime-certified"
            capabilities["hooks"] = "runtime-certified"
            capabilities["checkpoint"] = "runtime-certified"
            capabilities["restore"] = "runtime-certified"
        if not detected:
            overall = "not-installed"
        elif version["status"] == "degraded":
            overall = "unsupported-version"
        elif certification["status"] == "runtime-certified":
            overall = "runtime-certified"
        elif (
            entry.get("kind") == "ide"
            and not platforms.executable(entry)
            and all(
                value in {"ready", "contract-ready", "not-exposed"}
                for value in capabilities.values()
            )
        ):
            overall = "contract-ready"
        elif all(value in {"ready", "contract-ready", "not-exposed"} for value in capabilities.values()):
            overall = "contract-ready"
        else:
            overall = "degraded"
        matrix[str(entry["id"])] = {
            "status": overall,
            "detected": detected,
            "version": version,
            "certification": certification,
            "capabilities": capabilities,
            "missing_skills": missing,
            "missing_agents": missing_agents,
            "contract": platforms.contract_summary(entry),
        }
    return matrix


def session_distillation_health() -> dict:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "session_distill.py"), "status"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        return {
            "status": "not-built",
            "reason": result.stderr.strip() or "session distillation run not found",
        }
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"status": "degraded", "reason": "invalid session distillation status"}
    return {
        "status": "ready" if value.get("state") == "complete" else "degraded",
        "run_id": value.get("run_id"),
        "generated_at": value.get("generated_at"),
        "state": value.get("state"),
        "distiller_version": value.get("distiller_version"),
        "recent_runs": value.get("recent_runs", {}),
        "session_coverage": value.get("session_coverage", {}),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate Blue Sec Hub installation and runtime")
    parser.add_argument("--platform", choices=("auto", "all", *platforms.platform_ids()), default="auto")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    failures: list[str] = []
    warnings: list[str] = []
    effective_status = effective_skills.status()
    effective_source = effective_skills.current_skills_root()
    skill_source = effective_source if effective_source.is_dir() else ROOT / "skills"
    skills = sorted(skill_source.glob("*/SKILL.md"))

    nested = [
        path
        for path in (ROOT / "skills").rglob("SKILL.md")
        if path.parent.parent != ROOT / "skills"
    ]
    if nested:
        failures.append("nested upstream SKILL.md found inside local skills")

    selected = platforms.select_platforms(args.platform)
    platform_matrix = platform_capability_matrix(selected, skills)
    runtime = runtime_support.runtime_status()
    runtime["optional_executors"] = {
        name: get_adapter(name).capability()["status"] for name in load_executor_specs()
    }
    learning_status = learning_store.audit_store()
    report_index_status = report_ingestion.audit_state()
    distillation_status = session_distillation_health()
    distillation_queue = DATA_ROOT / context_checkpoint.DISTILLATION_QUEUE_NAME
    learning_events = DATA_ROOT / context_checkpoint.CONVERSATION_LEARNING_NAME
    learning_backlog = {
        "status": "ready",
        "pending_distillation": sum(1 for item in context_checkpoint.read_jsonl(distillation_queue) if item.get("status") == "pending"),
        "conversation_events": sum(1 for _ in context_checkpoint.read_jsonl(learning_events)),
    }
    baseline_host_eval = baseline_eval_health(effective_status.get("active_revision"))
    upstream_knowledge = upstream_knowledge_health()
    search_roots = [
        (kind, path)
        for kind, path in (
            ("overlays", DATA_ROOT / "overlays"),
            ("overlays", DATA_ROOT / "effective" / "current" / "knowledge"),
            ("upstreams", CACHE_ROOT / "upstreams"),
            ("vendored", ROOT / "knowledge"),
            ("feeds", CACHE_ROOT / "feeds"),
            ("internal", DATA_ROOT / "internal" / "documents"),
            ("reports", DATA_ROOT / "report-intelligence"),
        )
        if path.exists()
    ]
    knowledge_index_status = {
        "status": "ready" if upstream_knowledge["status"] == "ready" and knowledge_index.is_current(search_roots) else "not-built",
        "path": str(knowledge_index.index_path()),
    }
    contract_schema = ROOT / "contracts" / "security-conclusion.schema.json"
    contract_policy = ROOT / "policies" / "security-conclusion.md"
    conclusion_contract = {
        "status": "ready"
        if contract_schema.is_file()
        and contract_policy.is_file()
        and effective_skills.GLOBAL_POLICY_MARKER
        in contract_policy.read_text(encoding="utf-8")
        else "degraded",
        "schema_version": security_conclusion.SCHEMA_VERSION,
        "schema": str(contract_schema),
        "policy_sha256": effective_skills.global_policy_sha256()
        if contract_policy.is_file()
        else None,
    }
    conclusion_workspace = os.environ.get("BLUE_SEC_WORKSPACE")
    conclusion_health = (
        security_conclusion.workspace_status(Path(conclusion_workspace))
        if conclusion_workspace
        else {
            "status": "not-exposed",
            "invalid_confirmed_claims": 0,
            "unresolved_high_priority_candidates": 0,
        }
    )
    health_status = (
        "ready"
        if learning_status["status"] == "ready"
        and effective_status["status"] != "degraded"
        and conclusion_contract["status"] == "ready"
        else "degraded"
    )
    repository_head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ).stdout.strip() or None
    workspace_drift = bool(
        subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ).stdout.strip()
    )
    if args.json:
        print(
            json.dumps(
                {
                    "schema_version": 2,
                    "status": health_status,
                    "repository": {
                        "head": repository_head,
                        "workspace_drift": workspace_drift,
                    },
                    "learning": learning_status,
                    "effective": effective_status,
                    "task_pin_health": effective_status.get("task_pin_health", {}),
                    "report_index": report_index_status,
                    "distillation_run": distillation_status,
                    "session_coverage": distillation_status.get("session_coverage", {}),
                    "learning_backlog": learning_backlog,
                    "baseline_host_eval": baseline_host_eval,
                    "luna_host_eval": luna_eval_health(effective_status.get("active_revision")),
                    "upstream_knowledge": upstream_knowledge,
                    "offline_knowledge": {
                        "status": "ready" if (ROOT / "knowledge" / "offline-core.md").is_file() else "not-built",
                        "path": str(ROOT / "knowledge" / "offline-core.md"),
                    },
                    "payload_catalog": upstream_knowledge.get("sources", {}).get("payloads-all-the-things", {"status": "not-built"}),
                    "knowledge_index": knowledge_index_status,
                    "context_durability": {"status": "ready", "schema_version": context_checkpoint.SCHEMA_VERSION},
                    "effective_revision_pin": effective_status.get("task_pin_health", {}),
                    "learning_reconciliation": learning_status.get("base_reconciliation", {}),
                    "conclusion_contract": conclusion_contract,
                    "invalid_confirmed_claims": conclusion_health["invalid_confirmed_claims"],
                    "unresolved_high_priority_candidates": conclusion_health["unresolved_high_priority_candidates"],
                    "runtime": runtime,
                    "platforms": platform_matrix,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return
    if effective_status["status"] == "degraded":
        failures.extend(effective_status.get("failures", ["effective snapshot is degraded"]))
    for platform, item in platform_matrix.items():
        if item["detected"] and item["capabilities"]["skills"] != "ready":
            failures.append(f"{platform} skills are not installed: {', '.join(item['missing_skills'][:5])}")
        if item["detected"] and item["capabilities"]["mcp"] == "degraded":
            failures.append(f"{platform} blue-sec-hub MCP is not configured")

    source_lock = ROOT / "sources.lock.json"
    upstreams = CACHE_ROOT / "upstreams"
    if not source_lock.exists():
        failures.append("sources.lock.json is missing")
    elif not upstreams.exists():
        warnings.append(f"upstream cache is absent: {upstreams}")
    else:
        lock = json.loads(source_lock.read_text(encoding="utf-8"))
        for name, metadata in lock.get("sources", {}).items():
            path = upstreams / name
            if "payload_records" in metadata:
                try:
                    summary = json.loads(
                        (path / "summary.json").read_text(encoding="utf-8")
                    )
                except (OSError, json.JSONDecodeError):
                    failures.append(f"upstream payload catalog missing or invalid: {name}")
                    continue
                if int(summary.get("payloads", 0)) != int(metadata["payload_records"]):
                    failures.append(
                        f"upstream payload cache mismatch {name}: expected "
                        f"{metadata['payload_records']}, found {summary.get('payloads', 0)}"
                    )
                if summary.get("source", {}).get("commit") != metadata.get("commit"):
                    failures.append(f"upstream payload commit mismatch: {name}")
                continue
            count = (
                sum(
                    1
                    for item in path.rglob("*")
                    if item.is_file() and item.suffix.casefold() in {".md", ".markdown"}
                )
                if path.exists()
                else 0
            )
            expected = int(metadata.get("markdown_files", 0))
            if count != expected:
                failures.append(
                    f"upstream cache mismatch {name}: expected {expected}, found {count}"
                )

    old_references = ROOT / "skills" / "blue-security-knowledge" / "references"
    if old_references.exists():
        failures.append(f"legacy vendored knowledge remains in repository: {old_references}")

    learning = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "learning.py"), "audit"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if learning.returncode:
        failures.append(learning.stderr.strip() or learning.stdout.strip())
    else:
        print(learning.stdout.strip())

    learning_policy = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "learning_policy.py")],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if learning_policy.returncode:
        failures.append(
            learning_policy.stderr.strip() or learning_policy.stdout.strip()
        )
    else:
        print("[ok] hub-wide learning policy")

    reports = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "report_intelligence.py"), "audit"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if reports.returncode:
        failures.append(reports.stderr.strip() or reports.stdout.strip())
    else:
        print(reports.stdout.strip())

    report_ingestion_audit = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "report_ingestion.py"), "audit"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if report_ingestion_audit.returncode:
        failures.append(
            report_ingestion_audit.stderr.strip() or report_ingestion_audit.stdout.strip()
        )
    else:
        print(report_ingestion_audit.stdout.strip())

    config = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "hub_config.py"), "audit"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if config.returncode:
        failures.append(config.stderr.strip() or config.stdout.strip())
    else:
        print(config.stdout.strip())

    terms = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "term_learning.py"), "audit"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if terms.returncode:
        failures.append(terms.stderr.strip() or terms.stdout.strip())
    else:
        print(terms.stdout.strip())

    spa_lexicon = subprocess.run(
        [
            sys.executable,
            str(
                ROOT
                / "skills"
                / "spa-security-object-graph"
                / "scripts"
                / "semantic_lexicon.py"
            ),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if spa_lexicon.returncode:
        failures.append(spa_lexicon.stderr.strip() or spa_lexicon.stdout.strip())
    else:
        print("[ok] SPA semantic lexicon")

    browser = runtime["optional_browser"]
    print(f"[runtime] python={runtime['python_runtime']['status']} core={runtime['core_runtime']['status']} manager={runtime['package_manager']}")
    print(f"[spa] static-ready={str(runtime_support.python_ready()).lower()}")
    print(
        "[spa] browser-runtime="
        f"{browser['runtime'] or 'optional-missing'} "
        f"system-browser={browser['browser'] or 'not-found'} status={browser['status']}"
    )

    print(f"[skills] local={len(skills)}")
    print(
        f"[effective] status={effective_status['status']} "
        f"active={effective_status.get('active_revision') or 'none'} "
        f"previous={effective_status.get('previous_revision') or 'none'} "
        f"task-pins={len(effective_status.get('active_task_pins', []))}"
    )
    pin_counts = effective_status.get("task_pin_health", {}).get("counts", {})
    print(
        f"[task-pins] active={pin_counts.get('active', 0)} "
        f"recoverable={pin_counts.get('recoverable', 0)} "
        f"orphaned={pin_counts.get('orphaned', 0)}"
    )
    budget = effective_status.get("budget_summary", {})
    print(
        f"[skill-budget] base-max={budget.get('max_base_tokens', 0)} "
        f"rules-max={budget.get('max_rule_tokens', 0)} "
        f"global-policy={budget.get('global_policy_tokens', 0)} "
        f"references={budget.get('reference_tokens', 0)} "
        f"prompt-max={budget.get('max_total_tokens', 0)} "
        f"warnings={budget.get('warnings', 0)}"
    )
    print(
        f"[learning] candidate={learning_status['candidate']} "
        f"approved={learning_status['approved']} "
        f"manifest={learning_status.get('manifest_revision') or 'none'}"
    )
    print(
        f"[learning-reconciliation] "
        f"status={learning_status.get('base_reconciliation', {}).get('status', 'unknown')} "
        f"deterministic={learning_status.get('base_reconciliation', {}).get('deterministic', 0)}"
    )
    print(
        f"[session-distillation] status={distillation_status['status']} "
        f"run={distillation_status.get('run_id') or 'none'}"
    )
    print(f"[repository] head={repository_head or 'unknown'} drift={str(workspace_drift).lower()}")
    print(f"[agent] command={shutil.which('blue-sec-agent') or 'not-installed'} schema=1")
    print(f"[context] command={shutil.which('blue-sec-context') or 'not-installed'} schema={context_checkpoint.SCHEMA_VERSION} budget=24576")
    print(
        f"[conclusion-contract] status={conclusion_contract['status']} "
        f"invalid-confirmed={conclusion_health['invalid_confirmed_claims']} "
        f"unresolved-high-priority={conclusion_health['unresolved_high_priority_candidates']}"
    )
    print("[web-runtime] native-static-http-protocol=ready")
    for platform, status in platform_matrix.items():
        print(f"[platform] {platform}={status['status']} capabilities={json.dumps(status['capabilities'], sort_keys=True)}")
    print(f"[cache] upstreams={upstreams}")
    print(f"[data] overlays={DATA_ROOT / 'overlays'}")
    print(f"[data] report-ingestion={DATA_ROOT / 'report-ingestion'}")
    print(f"[data] report-intelligence={DATA_ROOT / 'report-intelligence'}")
    for warning in warnings:
        print(f"[warning] {warning}")
    if failures:
        raise SystemExit("\n".join(failures))
    print("[ok] ownership boundaries, links, cache and learning state are healthy")


if __name__ == "__main__":
    main()
