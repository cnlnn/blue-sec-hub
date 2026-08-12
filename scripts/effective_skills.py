#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import learning_store
from skill_validation import validate_skill


ROOT = Path(__file__).resolve().parents[1]
BASE_SKILLS = ROOT / "skills"
GLOBAL_POLICY = ROOT / "policies" / "security-conclusion.md"
SCHEMA_VERSION = 1
MAX_SKILL_BYTES = 32 * 1024
MAX_RULE_BYTES = 8 * 1024
MAX_SKILL_TOKENS = 6_000
RECOMMENDED_SKILL_TOKENS = 4_500
KEEP_REVISIONS = 3
GENERATED_MARKER = "<!-- blue-sec-effective-rules -->"
GLOBAL_POLICY_MARKER = "<!-- blue-sec-global-security-conclusion-policy -->"


def now() -> str:
    return datetime.now(UTC).isoformat()


def estimated_tokens(content: str) -> int:
    tokens = 0
    for match in re.finditer(r"[\u3400-\u9fff]|[A-Za-z0-9_]+|[^\s]", content):
        value = match.group()
        if len(value) == 1 or ord(value[0]) > 127:
            tokens += 1
        else:
            tokens += max(1, (len(value) + 3) // 4)
    return tokens


def enforce_token_budget(label: str, tokens: int) -> bool:
    if tokens > MAX_SKILL_TOKENS:
        raise ValueError(f"{label} exceeds token budget: {tokens}")
    return tokens > RECOMMENDED_SKILL_TOKENS


def reference_budget(skill: Path) -> dict[str, int]:
    root = skill / "references"
    paths = sorted(path for path in root.rglob("*") if path.is_file()) if root.is_dir() else []
    contents = [path.read_text(encoding="utf-8", errors="replace") for path in paths]
    return {
        "reference_files": len(paths),
        "reference_bytes": sum(len(content.encode("utf-8")) for content in contents),
        "reference_tokens": sum(estimated_tokens(content) for content in contents),
    }


def effective_root() -> Path:
    return learning_store.data_root() / "effective"


def state_path() -> Path:
    return effective_root() / "state.json"


def current_link() -> Path:
    return effective_root() / "current"


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def atomic_json(path: Path, value: Any) -> None:
    learning_store.atomic_json(path, value)


def repository_revision() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        value = hashlib.sha256()
        for path in sorted(BASE_SKILLS.rglob("*")):
            if path.is_file():
                value.update(path.relative_to(BASE_SKILLS).as_posix().encode())
                value.update(path.read_bytes())
        return f"tree-{value.hexdigest()}"


def repository_tree_sha256() -> str:
    """Hash runtime and compilation inputs, independent of rewritten Git history."""
    digest = hashlib.sha256()
    roots = [ROOT / name for name in ("skills", "policies", "contracts", "scripts", "platform-packages")]
    paths = [
        path for root in roots if root.exists()
        for path in root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    ]
    paths.extend(
        path for path in (
            ROOT / "platforms.json",
            ROOT / "learning_policy.json",
            ROOT / "skill_contracts.json",
            ROOT / "base-capabilities.json",
            ROOT / "security_terms.json",
        ) if path.is_file()
    )
    for path in sorted(set(paths)):
        relative = path.relative_to(ROOT).as_posix()
        if not path.is_file():
            continue
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def policy_version() -> int:
    value = load_json(ROOT / "learning_policy.json", {})
    return int(value.get("policy_version", 0))


def global_policy_content() -> str:
    content = GLOBAL_POLICY.read_text(encoding="utf-8").strip()
    if GLOBAL_POLICY_MARKER not in content:
        raise ValueError("global security conclusion policy marker is missing")
    return content + "\n"


def global_policy_sha256() -> str:
    return hashlib.sha256(global_policy_content().encode("utf-8")).hexdigest()


def revision_for(manifest: dict[str, Any]) -> str:
    return learning_store.digest(
        {
            "schema_version": SCHEMA_VERSION,
            "source_tree_sha256": repository_tree_sha256(),
            "knowledge_revision": manifest.get("revision"),
            "policy_version": policy_version(),
            "global_policy_sha256": global_policy_sha256(),
        }
    )


def active_objects(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        learning_store.load_object(str(item["object_sha256"]))
        for item in manifest.get("objects", [])
    ]


def render_rules(values: list[dict[str, Any]]) -> str:
    lines = ["", GENERATED_MARKER, "", "## Validated Local Rules", ""]
    for value in sorted(values, key=lambda item: (item["semantic_id"], item["id"])):
        lines.extend(
            [
                f"- **{value['semantic_id']}**: {value['successful_pattern']}",
                f"  Applies when: {value['conditions']}",
            ]
        )
    return "\n".join(lines) + "\n"


def knowledge_markdown(value: dict[str, Any]) -> str:
    return "\n".join(
        (
            f"# {value['semantic_id']}",
            "",
            f"- Skill: `{value['skill']}`",
            f"- Conditions: {value['conditions']}",
            f"- Confidence: `{value['confidence']}`",
            "",
            "## Validated Knowledge",
            "",
            value["successful_pattern"],
            "",
            "## Avoided Failure",
            "",
            value["failure"],
            "",
        )
    )


def file_hashes(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "manifest.json"
    }


def snapshot_failures(revision: str, root: Path | None = None) -> list[str]:
    snapshot = root or effective_root() / revision
    manifest = load_json(snapshot / "manifest.json", {})
    failures: list[str] = []
    if manifest.get("revision") != revision:
        failures.append("snapshot manifest revision mismatch")
        return failures
    expected = manifest.get("files")
    if not isinstance(expected, dict):
        failures.append("snapshot file manifest is missing")
        return failures
    actual = file_hashes(snapshot)
    for path in sorted(set(expected) | set(actual)):
        if path not in expected:
            failures.append(f"unexpected snapshot file: {path}")
        elif path not in actual:
            failures.append(f"missing snapshot file: {path}")
        elif expected[path] != actual[path]:
            failures.append(f"snapshot file hash mismatch: {path}")
    return failures


def compile_snapshot(
    *, activate: bool = False, manifest: dict[str, Any] | None = None
) -> dict[str, Any]:
    manifest = manifest or learning_store.load_manifest(rebuild=True)
    revision = revision_for(manifest)
    root = effective_root()
    destination = root / revision
    values = active_objects(manifest)
    if not destination.exists():
        root.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=f".{revision}.", dir=root))
        try:
            skills_root = temporary / "skills"
            shutil.copytree(
                BASE_SKILLS,
                skills_root,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"),
            )
            grouped: dict[str, list[dict[str, Any]]] = {}
            for value in values:
                if value["kind"] == "instruction-rule":
                    grouped.setdefault(value["skill"], []).append(value)
            budgets: dict[str, dict[str, int]] = {}
            global_policy = "\n" + global_policy_content()
            global_policy_bytes = len(global_policy.encode("utf-8"))
            global_policy_tokens = estimated_tokens(global_policy)
            for skill in sorted(path for path in skills_root.iterdir() if path.is_dir()):
                entry = skill / "SKILL.md"
                base_content = entry.read_text(encoding="utf-8")
                base_bytes = len(base_content.encode("utf-8"))
                base_tokens = estimated_tokens(base_content)
                if base_bytes > MAX_SKILL_BYTES:
                    raise ValueError(f"base skill exceeds budget for {skill.name}: {base_bytes}")
                compiled = base_content.rstrip() + "\n" + global_policy
                total_bytes = len(compiled.encode("utf-8"))
                total_tokens = estimated_tokens(compiled)
                if total_bytes > MAX_SKILL_BYTES:
                    raise ValueError(f"effective skill exceeds budget for {skill.name}: {total_bytes}")
                warning = enforce_token_budget(f"effective skill {skill.name}", total_tokens)
                entry.write_text(compiled, encoding="utf-8")
                budgets[skill.name] = {
                    "base": base_bytes,
                    "rules": 0,
                    "global_policy": global_policy_bytes,
                    "total": total_bytes,
                    "base_tokens": base_tokens,
                    "rule_tokens": 0,
                    "global_policy_tokens": global_policy_tokens,
                    "total_tokens": total_tokens,
                    "prompt_tokens": total_tokens,
                    **reference_budget(skill),
                    "recommended_exceeded": warning,
                }
            for skill, rules in grouped.items():
                entry = skills_root / skill / "SKILL.md"
                if not entry.is_file():
                    raise ValueError(f"approved instruction targets missing skill: {skill}")
                addition = render_rules(rules)
                addition_bytes = len(addition.encode("utf-8"))
                if addition_bytes > MAX_RULE_BYTES:
                    raise ValueError(f"effective rules exceed budget for {skill}: {addition_bytes}")
                original = entry.read_text(encoding="utf-8").rstrip() + "\n"
                compiled = original + addition
                total_bytes = len(compiled.encode("utf-8"))
                total_tokens = estimated_tokens(compiled)
                if total_bytes > MAX_SKILL_BYTES:
                    raise ValueError(f"effective skill exceeds budget for {skill}: {total_bytes}")
                warning = enforce_token_budget(f"effective skill {skill}", total_tokens)
                entry.write_text(compiled, encoding="utf-8")
                rule_tokens = estimated_tokens(addition)
                budgets[skill] = {
                    **budgets[skill],
                    "rules": addition_bytes,
                    "total": total_bytes,
                    "rule_tokens": rule_tokens,
                    "total_tokens": total_tokens,
                    "prompt_tokens": total_tokens,
                    **reference_budget(skills_root / skill),
                    "recommended_exceeded": warning,
                }

            knowledge_root = temporary / "knowledge"
            for value in values:
                if value["kind"] != "knowledge-entry":
                    continue
                path = knowledge_root / value["skill"] / f"{learning_store.digest(value)}.md"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(knowledge_markdown(value), encoding="utf-8")

            routing = [
                {
                    "id": value["id"],
                    "semantic_id": value["semantic_id"],
                    "skill": value["skill"],
                    "term": value["successful_pattern"],
                    "conditions": value["conditions"],
                }
                for value in values
                if value["kind"] == "routing-term"
            ]
            atomic_json(temporary / "routing-terms.json", {"schema_version": 1, "terms": routing})

            failures = []
            for skill in sorted(path for path in skills_root.iterdir() if path.is_dir()):
                failures.extend(f"{skill.name}: {item}" for item in validate_skill(skill))
            if failures:
                raise ValueError("effective skill validation failed:\n" + "\n".join(failures))

            metadata = {
                "schema_version": SCHEMA_VERSION,
                "revision": revision,
                "code_revision": repository_revision(),
                "source_tree_sha256": repository_tree_sha256(),
                "knowledge_revision": manifest.get("revision"),
                "policy_version": policy_version(),
                "global_policy_sha256": global_policy_sha256(),
                "global_policy_tokens": global_policy_tokens,
                "generated_at": now(),
                "skills": len([path for path in skills_root.iterdir() if path.is_dir()]),
                "active_objects": len(values),
                "prompt_budgets": budgets,
                "files": file_hashes(temporary),
            }
            atomic_json(temporary / "manifest.json", metadata)
            temporary.replace(destination)
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
    metadata = load_json(destination / "manifest.json", {})
    failures = snapshot_failures(revision)
    if failures:
        raise ValueError("effective snapshot integrity failed:\n" + "\n".join(failures))
    if activate:
        activate_revision(revision)
    return metadata


def link_current(revision: str) -> str:
    root = effective_root()
    destination = root / revision
    if not (destination / "skills").is_dir():
        raise ValueError(f"effective revision does not exist: {revision}")
    link = current_link()
    temporary = root / f".current.{os.getpid()}"
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink() if temporary.is_symlink() else shutil.rmtree(temporary)
    try:
        temporary.symlink_to(destination, target_is_directory=True)
        os.replace(temporary, link)
        return "symlink"
    except (OSError, NotImplementedError):
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink() if temporary.is_symlink() else shutil.rmtree(temporary)
        staging = root / f".current-copy.{os.getpid()}"
        shutil.copytree(destination, staging)
        previous = root / f".current-old.{os.getpid()}"
        if link.exists():
            os.replace(link, previous)
        os.replace(staging, link)
        if previous.is_symlink() or previous.is_file():
            previous.unlink(missing_ok=True)
        else:
            shutil.rmtree(previous, ignore_errors=True)
        return "managed-copy"


def activate_revision(revision: str) -> dict[str, Any]:
    root = effective_root()
    root.mkdir(parents=True, exist_ok=True)
    failures = snapshot_failures(revision)
    if failures:
        raise ValueError("cannot activate corrupt effective snapshot:\n" + "\n".join(failures))
    state = load_json(state_path(), {"schema_version": SCHEMA_VERSION, "history": []})
    active = state.get("active_revision")
    if active == revision and current_skills_root().is_dir():
        return state
    mode = link_current(revision)
    history = [item for item in state.get("history", []) if item != revision]
    if active:
        history.insert(0, active)
    state = {
        "schema_version": SCHEMA_VERSION,
        "active_revision": revision,
        "previous_revision": active,
        "history": history[:KEEP_REVISIONS],
        "activation_mode": mode,
        "activated_at": now(),
    }
    atomic_json(state_path(), state)
    pinned = {
        str(item["effective_revision"])
        for item in task_pins()
        if item.get("effective_revision")
    }
    prune_revisions({revision, *state["history"][: KEEP_REVISIONS - 1], *pinned})
    return state


def prune_revisions(retain: set[str]) -> None:
    root = effective_root()
    for path in root.iterdir() if root.exists() else []:
        if (
            not path.is_dir()
            or path.is_symlink()
            or path.name.startswith(".")
            or path.name in {"current", "task-pins"}
        ):
            continue
        if path.name not in retain and (path / "manifest.json").is_file():
            shutil.rmtree(path)


def current_revision() -> str | None:
    return load_json(state_path(), {}).get("active_revision")


def current_skills_root() -> Path:
    link = current_link()
    return link / "skills"


def task_pins_root() -> Path:
    return effective_root() / "task-pins"


def task_registry_path() -> Path:
    return effective_root() / "task-registry.json"


def workspace_digest(workspace: Path) -> str:
    return hashlib.sha256(str(workspace.resolve()).encode("utf-8")).hexdigest()


def pin_task(
    task_id: str,
    workspace: Path,
    revision: str | None = None,
    *,
    checkpoint_revision: str | None = None,
    task_status: str = "active",
    task_revision: str | None = None,
) -> dict[str, Any]:
    selected = revision or current_revision()
    value = {
        "schema_version": 2,
        "task_id": task_id,
        "effective_revision": selected,
        "workspace_hash": workspace_digest(workspace),
        "checkpoint_revision": checkpoint_revision,
        "task_revision": task_revision,
        "task_status": task_status,
        "updated_at": now(),
    }
    if not selected:
        return value
    atomic_json(task_pins_root() / f"{task_id}.json", value)
    registry = load_json(task_registry_path(), {"schema_version": 1, "tasks": {}})
    registry.setdefault("tasks", {})[task_id] = {
        "workspace": str(workspace.resolve()),
        "workspace_hash": value["workspace_hash"],
        "updated_at": value["updated_at"],
    }
    atomic_json(task_registry_path(), registry)
    return value


def release_task(task_id: str) -> None:
    (task_pins_root() / f"{task_id}.json").unlink(missing_ok=True)
    registry = load_json(task_registry_path(), {"schema_version": 1, "tasks": {}})
    tasks = registry.get("tasks", {})
    if isinstance(tasks, dict) and task_id in tasks:
        tasks.pop(task_id, None)
        atomic_json(task_registry_path(), registry)


def task_pins() -> list[dict[str, Any]]:
    return [
        value
        for path in sorted(task_pins_root().glob("*.json"))
        if isinstance((value := load_json(path, {})), dict) and value.get("task_id")
    ] if task_pins_root().exists() else []


def task_workspace_status(workspace: Path) -> tuple[str, str | None, str | None]:
    task = load_json(workspace / "task-context.json", {})
    agent = load_json(workspace / "agent-state.json", {})
    job = load_json(workspace / "job.json", {})
    capsule = load_json(workspace / "context-capsule.json", {})
    statuses = [
        str(value.get("status") or "")
        for value in (task, agent, job)
        if isinstance(value, dict)
    ]
    terminal = next(
        (
            status
            for status in statuses
            if status in {"complete", "completed", "resolved", "failed", "cancelled"}
        ),
        None,
    )
    status = terminal or next((item for item in statuses if item), "active")
    return status, capsule.get("checkpoint_id"), task.get("task_id")


def gc_task_pins(*, apply: bool = False) -> dict[str, Any]:
    registry = load_json(task_registry_path(), {"schema_version": 1, "tasks": {}})
    registered = registry.get("tasks", {}) if isinstance(registry.get("tasks", {}), dict) else {}
    items: list[dict[str, Any]] = []
    orphaned: list[str] = []
    for pin in task_pins():
        task_id = str(pin.get("task_id"))
        classification = "recoverable"
        reason = "legacy-unverifiable"
        record = registered.get(task_id, {}) if isinstance(registered, dict) else {}
        workspace_value = record.get("workspace") if isinstance(record, dict) else None
        migrated_pin: dict[str, Any] | None = None
        if int(pin.get("schema_version", 0)) < 2 and workspace_value:
            workspace = Path(str(workspace_value))
            if workspace.is_dir() and (workspace / "task-context.json").is_file():
                status, checkpoint_revision, workspace_task_id = task_workspace_status(workspace)
                if workspace_task_id == task_id:
                    classification = (
                        "active"
                        if status not in {"complete", "completed", "resolved", "failed", "cancelled"}
                        else "recoverable"
                    )
                    reason = "legacy-pin-migratable"
                    migrated_pin = {
                        **pin,
                        "schema_version": 2,
                        "workspace_hash": workspace_digest(workspace),
                        "checkpoint_revision": checkpoint_revision,
                        "task_revision": load_json(workspace / "task-context.json", {}).get("task_revision"),
                        "task_status": status,
                        "updated_at": now(),
                    }
        if int(pin.get("schema_version", 0)) < 2 and migrated_pin is None:
            reason = "legacy-pin-quarantined"
            migrated_pin = {
                **pin,
                "schema_version": 2,
                "checkpoint_revision": None,
                "task_revision": None,
                "task_status": "unknown",
                "migration_state": "quarantined-unverifiable",
                "updated_at": now(),
            }
        if int(pin.get("schema_version", 0)) >= 2 and workspace_value:
            workspace = Path(str(workspace_value))
            if not workspace.is_dir():
                classification, reason = "orphaned", "workspace-missing"
            elif workspace_digest(workspace) != pin.get("workspace_hash"):
                classification, reason = "orphaned", "workspace-hash-mismatch"
            elif not (workspace / "task-context.json").is_file():
                classification, reason = "orphaned", "task-record-missing"
            else:
                status, checkpoint_revision, workspace_task_id = task_workspace_status(workspace)
                if workspace_task_id != task_id:
                    classification, reason = "orphaned", "task-id-mismatch"
                elif status in {"complete", "completed", "resolved", "failed", "cancelled"}:
                    if checkpoint_revision and checkpoint_revision == pin.get("checkpoint_revision"):
                        classification, reason = "orphaned", "terminal-task-checkpointed"
                    else:
                        classification, reason = "recoverable", "terminal-checkpoint-mismatch"
                elif checkpoint_revision and checkpoint_revision == pin.get("checkpoint_revision"):
                    classification, reason = "active", "current-checkpoint"
                else:
                    classification, reason = "recoverable", "checkpoint-mismatch"
        if classification == "orphaned":
            orphaned.append(task_id)
        items.append(
            {
                "task_id": task_id,
                "effective_revision": pin.get("effective_revision"),
                "workspace_hash": pin.get("workspace_hash"),
                "classification": classification,
                "reason": reason,
                "migratable": migrated_pin is not None,
                "migrated_pin": migrated_pin,
            }
        )
    if apply:
        for item in items:
            migrated_pin = item.pop("migrated_pin", None)
            if migrated_pin:
                atomic_json(task_pins_root() / f"{item['task_id']}.json", migrated_pin)
        for task_id in orphaned:
            release_task(task_id)
        for item in items:
            if item["task_id"] in orphaned:
                item["classification"] = "released"
        state = load_json(state_path(), {})
        active = state.get("active_revision")
        retained = {
            str(item["effective_revision"])
            for item in task_pins()
            if item.get("effective_revision")
        }
        if active:
            retained.add(str(active))
        retained.update(str(item) for item in state.get("history", [])[: KEEP_REVISIONS - 1])
        prune_revisions(retained)
    for item in items:
        item.pop("migrated_pin", None)
    counts = {
        state: sum(item["classification"] == state for item in items)
        for state in ("active", "recoverable", "orphaned", "released")
    }
    return {
        "status": "degraded" if counts["orphaned"] else "ready",
        "mode": "apply" if apply else "dry-run",
        "counts": counts,
        "items": items,
    }


def rollback() -> dict[str, Any]:
    state = load_json(state_path(), {})
    previous = state.get("previous_revision") or next(iter(state.get("history", [])), None)
    if not previous:
        raise ValueError("no previous effective revision is available")
    return activate_revision(str(previous))


def status() -> dict[str, Any]:
    state = load_json(state_path(), {})
    active = state.get("active_revision")
    manifest = load_json(effective_root() / str(active) / "manifest.json", {}) if active else {}
    current = current_skills_root()
    failures: list[str] = []
    budgets = manifest.get("prompt_budgets", {})
    if active:
        failures.extend(snapshot_failures(str(active)))
        current_tree = repository_tree_sha256()
        if manifest.get("source_tree_sha256") != current_tree:
            failures.append("active snapshot was compiled from a different source tree")
        current_knowledge = learning_store.load_manifest(rebuild=True).get("revision")
        if manifest.get("knowledge_revision") != current_knowledge:
            failures.append("active snapshot was compiled from a different knowledge revision")
        if manifest.get("global_policy_sha256") != global_policy_sha256():
            failures.append("active snapshot was compiled with a different global policy")
        for skill, budget in budgets.items():
            if int(budget.get("total_tokens", 0)) > MAX_SKILL_TOKENS:
                failures.append(f"active skill exceeds token budget: {skill}")
        current_root = current_link()
        if current_root.exists() and not current_root.is_symlink():
            failures.extend(
                f"current: {failure}"
                for failure in snapshot_failures(str(active), current_root)
            )
    if not active or not current.is_dir():
        state_status = "not-built"
    elif failures:
        state_status = "degraded"
    else:
        state_status = "ready"
    return {
        "status": state_status,
        "active_revision": active,
        "previous_revision": state.get("previous_revision"),
        "activation_mode": state.get("activation_mode"),
        "code_revision": manifest.get("code_revision"),
        "current_code_revision": repository_revision(),
        "source_tree_sha256": manifest.get("source_tree_sha256"),
        "current_source_tree_sha256": repository_tree_sha256(),
        "effective_tree_match": bool(
            manifest.get("source_tree_sha256")
            and manifest.get("source_tree_sha256") == repository_tree_sha256()
        ),
        "knowledge_revision": manifest.get("knowledge_revision"),
        "global_policy_sha256": manifest.get("global_policy_sha256"),
        "prompt_budgets": budgets,
        "budget_limits": {
            "warning_tokens": RECOMMENDED_SKILL_TOKENS,
            "maximum_tokens": MAX_SKILL_TOKENS,
        },
        "budget_summary": {
            "skills": len(budgets),
            "warnings": sum(
                1 for budget in budgets.values() if budget.get("recommended_exceeded")
            ),
            "max_base_tokens": max(
                (int(budget.get("base_tokens", 0)) for budget in budgets.values()),
                default=0,
            ),
            "max_rule_tokens": max(
                (int(budget.get("rule_tokens", 0)) for budget in budgets.values()),
                default=0,
            ),
            "global_policy_tokens": max(
                (int(budget.get("global_policy_tokens", 0)) for budget in budgets.values()),
                default=0,
            ),
            "reference_tokens": sum(
                int(budget.get("reference_tokens", 0)) for budget in budgets.values()
            ),
            "max_total_tokens": max(
                (int(budget.get("total_tokens", 0)) for budget in budgets.values()),
                default=0,
            ),
        },
        "skills_root": str(current),
        "active_task_pins": task_pins(),
        "task_pin_health": gc_task_pins(),
        "legacy_task_pins": sum(
            int(item.get("schema_version", 0)) < 2 for item in task_pins()
        ),
        "failures": failures,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compile and activate Effective Skills")
    commands = parser.add_subparsers(dest="command", required=True)
    compile_parser = commands.add_parser("compile")
    compile_parser.add_argument("--activate", action="store_true")
    activate_parser = commands.add_parser("activate")
    activate_parser.add_argument("revision", nargs="?")
    commands.add_parser("rollback")
    commands.add_parser("status")
    commands.add_parser("eval")
    gc = commands.add_parser("gc", help="classify and release provably orphaned task pins")
    mode = gc.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    return parser


def main() -> None:
    parser = build_parser()
    args, remaining = parser.parse_known_args()
    if remaining and args.command != "eval":
        parser.error("unrecognized arguments: " + " ".join(remaining))
    if args.command == "compile":
        result = compile_snapshot(activate=args.activate)
    elif args.command == "activate":
        if args.revision:
            result = activate_revision(args.revision)
        else:
            metadata = compile_snapshot()
            result = activate_revision(str(metadata["revision"]))
    elif args.command == "rollback":
        result = rollback()
    elif args.command == "eval":
        import skill_eval

        skill_eval.main(remaining)
        return
    elif args.command == "gc":
        result = gc_task_pins(apply=args.apply)
    else:
        result = status()
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
