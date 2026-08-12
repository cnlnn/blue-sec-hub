#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tomllib
from datetime import datetime
from pathlib import Path

import platforms
import effective_skills


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
MANIFEST_NAME = ".blue-sec-install.json"
COMMAND_MANIFEST_NAME = ".blue-sec-hub-commands.json"
AGENT_MANIFEST_NAME = ".blue-sec-agents-install.json"
SERVER_NAME = "blue-sec-hub"
SERVER_COMMAND = "blue-sec-agent"
SERVER_ARGS = ["serve", "--stdio"]

COMMANDS = {
    "blue-sec": "blue_sec.py",
    "blue-sec-update": "update.py",
    "blue-sec-feeds-update": "update_feeds.py",
    "blue-sec-search": "search_knowledge.py",
    "blue-sec-terms": "security_terms.py",
    "blue-sec-term-learning": "term_learning.py",
    "blue-sec-ingest": "ingest_internal.py",
    "blue-sec-report-ingest": "report_ingestion.py",
    "blue-sec-executors": "executor_status.py",
    "blue-sec-exec": "executor_control.py",
    "blue-sec-learn": "learning.py",
    "blue-sec-doctor": "doctor.py",
    "blue-sec-report": "report_intelligence.py",
    "blue-sec-config": "hub_config.py",
    "blue-sec-bootstrap": "bootstrap.py",
    "blue-sec-spa-graph": "spa_graph.py",
    "blue-sec-web-assessment": "web_assessment.py",
    "blue-sec-web-runner": "web_runner.py",
    "blue-sec-agent": "agent.py",
    "blue-sec-context": "context_checkpoint.py",
    "blue-sec-context-hook": "context_hook.py",
    "blue-sec-knowledge-runtime": "knowledge_runtime.py",
    "blue-sec-source-map": "source_mapper.py",
    "blue-sec-install": "install.py",
    "blue-sec-knowledge-session": "knowledge_session.py",
    "blue-sec-knowledge-distill": "knowledge_distill.py",
    "blue-sec-session-distill": "session_distill.py",
    "blue-sec-payload-catalog": "payload_catalog.py",
    "blue-sec-skill": "effective_skills.py",
    "blue-sec-assessment-learning": "assessment_learning.py",
    "blue-sec-quality-gate": "quality_gate.py",
    "blue-sec-benchmark": "benchmark_suite.py",
    "blue-sec-skill-eval": "skill_eval.py",
    "blue-sec-knowledge": "knowledge_sources.py",
    "blue-sec-platform-certify": "platform_certify.py",
    "blue-sec-branch-audit": "branch_audit.py",
    "blue-sec-conclusion": "security_conclusion.py",
}


def tree_hash(path: Path) -> str:
    value = hashlib.sha256()
    for item in sorted(path.rglob("*")):
        if item.is_file():
            value.update(item.relative_to(path).as_posix().encode())
            value.update(item.read_bytes())
    return value.hexdigest()


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def same_link(path: Path, source: Path) -> bool:
    return path.is_symlink() and path.resolve() == source.resolve()


def copy_or_link(source: Path, destination: Path) -> str:
    try:
        destination.symlink_to(source, target_is_directory=True)
        return "symlink"
    except (OSError, NotImplementedError):
        shutil.copytree(source, destination)
        return "managed-copy"


def backup_config(path: Path, stamp: str) -> None:
    if path.exists():
        shutil.copy2(path, path.with_name(f"{path.name}.blue-sec-backup.{stamp}"))


def load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def skill_source_root(dry_run: bool = False) -> tuple[Path, str | None]:
    if dry_run:
        return SKILLS, effective_skills.current_revision()
    metadata = effective_skills.compile_snapshot(activate=True)
    return effective_skills.current_skills_root(), str(metadata["revision"])


def synchronize_knowledge(dry_run: bool = False, disabled: bool = False) -> dict:
    """Install the pinned, reviewed knowledge set without making it a core dependency."""
    if disabled:
        return {"status": "skipped", "reason": "disabled-by-user"}
    if dry_run:
        return {"status": "dry-run", "mode": "pinned"}
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "sync_sources.py")],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode:
        return {
            "status": "degraded",
            "mode": "pinned",
            "reason": "knowledge-sync-failed",
            "detail": (result.stderr.strip() or result.stdout.strip())[-1000:],
        }
    return {"status": "ready", "mode": "pinned"}


def install_skills(platform: str, target: Path, stamp: str, dry_run: bool = False) -> dict:
    source_root, effective_revision = skill_source_root(dry_run)
    sources = sorted(path for path in source_root.iterdir() if path.is_dir())
    if dry_run:
        return {"platform": platform, "skill_root": str(target), "status": "dry-run", "skills": len(sources)}
    target.mkdir(parents=True, exist_ok=True)
    manifest_path = target / MANIFEST_NAME
    previous = load_json(manifest_path)
    backup_root = target.parent / "skill-backups" / stamp
    records = []
    changed = 0
    for source in sources:
        destination = target / source.name
        digest = tree_hash(source)
        prior = next((item for item in previous.get("skills", []) if item.get("name") == source.name), {})
        current_copy = (
            destination.is_dir()
            and not destination.is_symlink()
            and prior.get("mode") == "managed-copy"
            and prior.get("sha256") == tree_hash(destination)
        )
        if same_link(destination, source) or (current_copy and prior.get("source_sha256") == digest):
            mode = "symlink" if destination.is_symlink() else "managed-copy"
            records.append({"name": source.name, "mode": mode, "sha256": tree_hash(destination), "source_sha256": digest})
            continue
        if destination.exists() or destination.is_symlink():
            backup_root.mkdir(parents=True, exist_ok=True)
            shutil.move(str(destination), backup_root / destination.name)
        mode = copy_or_link(source, destination)
        records.append({"name": source.name, "mode": mode, "sha256": tree_hash(destination), "source_sha256": digest})
        changed += 1
    manifest = {
        "schema_version": 3,
        "platform": platform,
        "repository": str(ROOT),
        "effective_revision": effective_revision,
        "skill_source": str(source_root),
        "installed_at": stamp,
        "skills": records,
    }
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"platform": platform, "skill_root": str(target), "status": "ready", "changed": changed, "skills": len(records)}


def uninstall_skills(platform: str, target: Path, dry_run: bool = False) -> dict:
    if dry_run:
        return {"platform": platform, "skill_root": str(target), "status": "dry-run"}
    manifest_path = target / MANIFEST_NAME
    manifest = load_json(manifest_path)
    removed = 0
    retained = []
    source_root = Path(str(manifest.get("skill_source") or SKILLS))
    for item in manifest.get("skills", []):
        destination = target / item["name"]
        source = source_root / item["name"]
        managed = same_link(destination, source)
        if destination.is_dir() and not destination.is_symlink():
            managed = item.get("mode") == "managed-copy" and item.get("sha256") == tree_hash(destination)
        if managed:
            destination.unlink() if destination.is_symlink() else shutil.rmtree(destination)
            removed += 1
        elif destination.exists() or destination.is_symlink():
            retained.append(item["name"])
    manifest_path.unlink(missing_ok=True)
    return {"platform": platform, "skill_root": str(target), "status": "removed", "removed": removed, "retained_modified": retained}


def install_agents(entry: dict, stamp: str, dry_run: bool = False) -> dict:
    contract = entry["agents"]
    if contract["status"] != "supported":
        return {"status": "not-exposed"}
    target = platforms.resolve_path(entry, str(contract["path"]))
    sources = sorted((ROOT / "agents").glob("*.md"))
    if dry_run:
        return {"status": "dry-run", "agent_root": str(target), "agents": len(sources)}
    target.mkdir(parents=True, exist_ok=True)
    manifest_path = target / AGENT_MANIFEST_NAME
    previous = load_json(manifest_path)
    prior = {item.get("name"): item for item in previous.get("agents", [])}
    records = []
    changed = 0
    for source in sources:
        destination = target / source.name
        old = prior.get(source.name, {})
        managed_copy = (
            destination.is_file()
            and not destination.is_symlink()
            and old.get("mode") == "managed-copy"
            and old.get("sha256") == file_hash(destination)
        )
        if same_link(destination, source) or (managed_copy and old.get("source_sha256") == file_hash(source)):
            mode = "symlink" if destination.is_symlink() else "managed-copy"
        else:
            if destination.exists() or destination.is_symlink():
                backup = target.parent / "agent-backups" / stamp
                backup.mkdir(parents=True, exist_ok=True)
                shutil.move(str(destination), backup / destination.name)
            try:
                destination.symlink_to(source)
                mode = "symlink"
            except (OSError, NotImplementedError):
                shutil.copy2(source, destination)
                mode = "managed-copy"
            changed += 1
        records.append(
            {
                "name": source.name,
                "mode": mode,
                "sha256": file_hash(destination),
                "source_sha256": file_hash(source),
            }
        )
    manifest_path.write_text(
        json.dumps({"schema_version": 1, "platform": entry["id"], "agents": records}, indent=2) + "\n",
        encoding="utf-8",
    )
    return {"status": "ready", "agent_root": str(target), "agents": len(records), "changed": changed}


def uninstall_agents(entry: dict, dry_run: bool = False) -> dict:
    contract = entry["agents"]
    if contract["status"] != "supported":
        return {"status": "not-exposed"}
    target = platforms.resolve_path(entry, str(contract["path"]))
    manifest_path = target / AGENT_MANIFEST_NAME
    manifest = load_json(manifest_path)
    if dry_run:
        return {"status": "dry-run", "agent_root": str(target)}
    removed = 0
    retained = []
    for item in manifest.get("agents", []):
        destination = target / item["name"]
        source = ROOT / "agents" / item["name"]
        managed = same_link(destination, source) or (
            destination.is_file()
            and not destination.is_symlink()
            and item.get("mode") == "managed-copy"
            and item.get("sha256") == file_hash(destination)
        )
        if managed:
            destination.unlink()
            removed += 1
        elif destination.exists() or destination.is_symlink():
            retained.append(item["name"])
    manifest_path.unlink(missing_ok=True)
    return {"status": "removed", "agent_root": str(target), "removed": removed, "retained_modified": retained}


def install_commands(stamp: str, dry_run: bool = False) -> dict:
    bin_dir = Path(os.environ.get("BLUE_SEC_BIN", Path.home() / ".local" / "bin"))
    if dry_run:
        return {"bin": str(bin_dir), "commands": len(COMMANDS), "status": "dry-run"}
    bin_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = bin_dir / COMMAND_MANIFEST_NAME
    previous = load_json(manifest_path)
    prior_entries = {item["name"]: item for item in previous.get("commands", [])}
    removed_stale = 0
    for name, item in prior_entries.items():
        if name in COMMANDS:
            continue
        path = bin_dir / item.get("path", name)
        managed = path.is_symlink() and path.resolve().is_relative_to((ROOT / "scripts").resolve())
        if path.is_file() and not path.is_symlink():
            managed = item.get("installed_sha256") == file_hash(path)
        if managed:
            path.unlink()
            removed_stale += 1
    records = []
    for name, script in COMMANDS.items():
        command = bin_dir / (f"{name}.cmd" if os.name == "nt" else name)
        source = ROOT / "scripts" / script
        prior = prior_entries.get(name, {})
        managed = same_link(command, source) or (
            command.is_file() and not command.is_symlink() and prior.get("installed_sha256") == file_hash(command)
        )
        if command.exists() or command.is_symlink():
            if managed:
                command.unlink()
            else:
                backup = bin_dir / "blue-sec-backups" / stamp
                backup.mkdir(parents=True, exist_ok=True)
                shutil.move(str(command), backup / command.name)
        mode = "managed-copy"
        if os.name == "nt":
            command.write_text(f'@"{sys.executable}" "{source}" %*\r\n', encoding="utf-8")
        else:
            try:
                command.symlink_to(source)
                mode = "symlink"
            except (OSError, NotImplementedError):
                shutil.copy2(source, command)
                command.chmod(command.stat().st_mode | 0o111)
        records.append({
            "name": name,
            "path": command.name,
            "mode": mode,
            "source_sha256": file_hash(source),
            "installed_sha256": file_hash(command) if command.is_file() else None,
        })
    manifest_path.write_text(json.dumps({"schema_version": 2, "repository": str(ROOT), "commands": records}, indent=2) + "\n", encoding="utf-8")
    return {"bin": str(bin_dir), "commands": len(records), "removed_stale_managed_commands": removed_stale}


def uninstall_commands(dry_run: bool = False) -> dict:
    bin_dir = Path(os.environ.get("BLUE_SEC_BIN", Path.home() / ".local" / "bin"))
    if dry_run:
        return {"bin": str(bin_dir), "status": "dry-run"}
    manifest_path = bin_dir / COMMAND_MANIFEST_NAME
    manifest = load_json(manifest_path)
    removed = 0
    for item in manifest.get("commands", []):
        path = bin_dir / item["path"]
        managed = path.is_symlink() and path.resolve().is_relative_to((ROOT / "scripts").resolve())
        if path.is_file() and not path.is_symlink():
            managed = item.get("installed_sha256") == file_hash(path)
        if managed:
            path.unlink()
            removed += 1
    manifest_path.unlink(missing_ok=True)
    return {"bin": str(bin_dir), "removed": removed}


def json_server(mode: str) -> tuple[str, dict]:
    if mode == "json-opencode":
        return "mcp", {"type": "local", "command": [SERVER_COMMAND, *SERVER_ARGS], "enabled": True}
    return "mcpServers", {"command": SERVER_COMMAND, "args": SERVER_ARGS}


def merge_json_mcp(path: Path, mode: str, stamp: str, dry_run: bool = False) -> dict:
    if path.exists():
        try:
            current = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            return {"status": "error", "config": str(path), "detail": f"invalid JSON: {error}"}
    else:
        current = {}
    key, server = json_server(mode)
    if current.get(key, {}).get(SERVER_NAME) == server:
        return {"status": "current", "config": str(path)}
    if dry_run:
        return {"status": "dry-run", "config": str(path)}
    backup_config(path, stamp)
    current.setdefault(key, {})[SERVER_NAME] = server
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(current, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"status": "configured", "config": str(path)}


def remove_json_mcp(path: Path, mode: str, stamp: str, dry_run: bool = False) -> dict:
    if not path.exists():
        return {"status": "absent", "config": str(path)}
    try:
        current = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        return {"status": "error", "config": str(path), "detail": f"invalid JSON: {error}"}
    key, server = json_server(mode)
    existing = current.get(key, {}).get(SERVER_NAME)
    if existing is None:
        return {"status": "absent", "config": str(path)}
    if existing != server:
        return {"status": "retained-modified", "config": str(path)}
    if dry_run:
        return {"status": "dry-run", "config": str(path)}
    backup_config(path, stamp)
    current[key].pop(SERVER_NAME, None)
    path.write_text(json.dumps(current, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"status": "removed", "config": str(path)}


def mcp_cli_commands(entry: dict, executable: str) -> tuple[list[str], list[str], list[str], dict[str, str]]:
    mode = entry["mcp"]["mode"]
    environment = dict(os.environ)
    if mode == "codex-cli":
        environment["CODEX_HOME"] = str(platforms.platform_home(entry))
        return (
            [executable, "mcp", "get", SERVER_NAME],
            [executable, "mcp", "add", SERVER_NAME, "--", SERVER_COMMAND, *SERVER_ARGS],
            [executable, "mcp", "remove", SERVER_NAME],
            environment,
        )
    if mode == "claude-cli":
        if entry.get("home_env") in os.environ:
            environment["CLAUDE_CONFIG_DIR"] = str(platforms.platform_home(entry))
        return (
            [executable, "mcp", "get", SERVER_NAME],
            [executable, "mcp", "add", "--scope", "user", SERVER_NAME, "--", SERVER_COMMAND, *SERVER_ARGS],
            [executable, "mcp", "remove", "--scope", "user", SERVER_NAME],
            environment,
        )
    if mode == "hermes-cli":
        return (
            [executable, "mcp", "list"],
            [executable, "mcp", "add", SERVER_NAME, "--command", SERVER_COMMAND, "--args", *SERVER_ARGS],
            [executable, "mcp", "remove", SERVER_NAME],
            environment,
        )
    return (
        [executable, "mcp", "get", SERVER_NAME],
        [executable, "mcp", "add", SERVER_NAME, "--", SERVER_COMMAND, *SERVER_ARGS],
        [executable, "mcp", "remove", SERVER_NAME],
        environment,
    )


def cli_mcp_is_current(mode: str, result: subprocess.CompletedProcess[str]) -> bool:
    if result.returncode != 0:
        return False
    if mode == "hermes-cli":
        return SERVER_NAME in result.stdout and "enabled" in result.stdout.casefold()
    if mode == "claude-cli" and "Scope: User" not in result.stdout:
        return False
    return SERVER_COMMAND in result.stdout


def configure_mcp(entry: dict, stamp: str, dry_run: bool = False) -> dict:
    platform = str(entry["id"])
    mode = str(entry["mcp"]["mode"])
    config = platforms.resolve_path(entry, str(entry["mcp"]["config"]))
    if mode.startswith("json-") or mode == "generated-snippet":
        if mode.endswith("if-present") and not config.exists():
            config = platforms.resolve_path(entry, str(entry["mcp"]["snippet"]))
            result = merge_json_mcp(config, mode, stamp, dry_run)
            result["status"] = "contract-ready" if result["status"] == "configured" else result["status"]
            result["detail"] = "host config not detected; generated importable snippet"
            return {"platform": platform, **result}
        return {"platform": platform, **merge_json_mcp(config, mode, stamp, dry_run)}
    executable = platforms.executable(entry)
    if not executable:
        return {"platform": platform, "status": "not-installed"}
    get, add, remove, environment = mcp_cli_commands(entry, executable)
    if dry_run:
        return {"platform": platform, "status": "dry-run", "config": str(config)}
    current = subprocess.run(get, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if cli_mcp_is_current(mode, current):
        return {"platform": platform, "status": "current"}
    backup_config(config, stamp)
    if current.returncode == 0 and SERVER_NAME in current.stdout:
        subprocess.run(remove, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    result = subprocess.run(
        add,
        env=environment,
        input="\n" if mode == "hermes-cli" else None,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    verified = subprocess.run(get, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    success = result.returncode == 0 and cli_mcp_is_current(mode, verified)
    detail = (result.stdout + "\n" + verified.stdout)[-500:]
    return {"platform": platform, "status": "configured" if success else "error", "detail": detail}


def remove_mcp(entry: dict, stamp: str, dry_run: bool = False) -> dict:
    platform = str(entry["id"])
    mode = str(entry["mcp"]["mode"])
    config = platforms.resolve_path(entry, str(entry["mcp"]["config"]))
    if mode.startswith("json-") or mode == "generated-snippet":
        if mode.endswith("if-present") and not config.exists():
            config = platforms.resolve_path(entry, str(entry["mcp"]["snippet"]))
        return {"platform": platform, **remove_json_mcp(config, mode, stamp, dry_run)}
    executable = platforms.executable(entry)
    if not executable:
        return {"platform": platform, "status": "not-installed"}
    _, _, remove, environment = mcp_cli_commands(entry, executable)
    if dry_run:
        return {"platform": platform, "status": "dry-run"}
    backup_config(config, stamp)
    result = subprocess.run(remove, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return {"platform": platform, "status": "removed" if result.returncode == 0 else "absent-or-error", "detail": result.stdout[-500:]}


def hook_manifest_path(entry: dict) -> Path:
    return platforms.platform_home(entry) / "blue-sec-hub-hooks.json"


def hook_command(platform: str, event: str) -> str:
    return f"blue-sec-context-hook --platform {platform} --event {event}"


def hook_manifest(entry: dict, active: bool) -> dict:
    platform = str(entry["id"])
    return {
        "schema_version": 1,
        "platform": platform,
        "mode": entry["hooks"]["mode"],
        "active": active,
        "events": [
            {"event": event, "command": hook_command(platform, str(event))}
            for event in entry["hooks"].get("events", [])
        ],
    }


def merge_native_json_hooks(path: Path, entry: dict, stamp: str, dry_run: bool) -> dict:
    try:
        current = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except json.JSONDecodeError as error:
        return {"status": "error", "detail": f"invalid hook JSON: {error}", "config": str(path)}
    platform = str(entry["id"])
    hooks = current.setdefault("hooks", {})
    changed = False
    for event in entry["hooks"].get("events", []):
        managed = {
            "matcher": "*",
            "hooks": [{"type": "command", "command": hook_command(platform, str(event))}],
        }
        values = hooks.setdefault(str(event), [])
        if managed not in values:
            values.append(managed)
            changed = True
    if not changed:
        return {"status": "ready", "config": str(path)}
    if dry_run:
        return {"status": "dry-run", "config": str(path)}
    backup_config(path, stamp)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(current, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"status": "ready", "config": str(path)}


def remove_native_json_hooks(path: Path, entry: dict, stamp: str, dry_run: bool) -> dict:
    if not path.exists():
        return {"status": "absent", "config": str(path)}
    try:
        current = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        return {"status": "error", "detail": f"invalid hook JSON: {error}", "config": str(path)}
    platform = str(entry["id"])
    changed = False
    hooks = current.get("hooks", {})
    for event in entry["hooks"].get("events", []):
        managed = {
            "matcher": "*",
            "hooks": [{"type": "command", "command": hook_command(platform, str(event))}],
        }
        values = hooks.get(str(event), [])
        if managed in values:
            values.remove(managed)
            changed = True
        if not values:
            hooks.pop(str(event), None)
    if not changed:
        return {"status": "absent-or-modified", "config": str(path)}
    if dry_run:
        return {"status": "dry-run", "config": str(path)}
    backup_config(path, stamp)
    path.write_text(json.dumps(current, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"status": "removed", "config": str(path)}


CODEX_HOOK_BEGIN = "# BEGIN BLUE SEC HUB MANAGED HOOKS"
CODEX_HOOK_END = "# END BLUE SEC HUB MANAGED HOOKS"


def codex_hook_block(entry: dict) -> str:
    lines = [CODEX_HOOK_BEGIN, "[hooks]"]
    for event in entry["hooks"].get("events", []):
        command = hook_command(str(entry["id"]), str(event)).replace('"', '\\"')
        lines.append(f'{event} = [{{ type = "command", command = "{command}" }}]')
    lines.append(CODEX_HOOK_END)
    return "\n".join(lines)


def merge_codex_hooks(path: Path, entry: dict, stamp: str, dry_run: bool) -> dict:
    text = path.read_text(encoding="utf-8") if path.exists() else ""
    block = codex_hook_block(entry)
    if block in text:
        return {"status": "ready", "config": str(path)}
    try:
        parsed = tomllib.loads(text) if text.strip() else {}
    except tomllib.TOMLDecodeError as error:
        return {"status": "error", "detail": f"invalid TOML: {error}", "config": str(path)}
    if "hooks" in parsed:
        return {"status": "contract-ready", "detail": "existing hooks table retained; managed snippet generated", "config": str(path)}
    if dry_run:
        return {"status": "dry-run", "config": str(path)}
    backup_config(path, stamp)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + ("\n\n" if text.strip() else "") + block + "\n", encoding="utf-8")
    return {"status": "ready", "config": str(path)}


def remove_codex_hooks(path: Path, entry: dict, stamp: str, dry_run: bool) -> dict:
    if not path.exists():
        return {"status": "absent", "config": str(path)}
    text = path.read_text(encoding="utf-8")
    block = codex_hook_block(entry)
    if block not in text:
        return {"status": "absent-or-modified", "config": str(path)}
    if dry_run:
        return {"status": "dry-run", "config": str(path)}
    backup_config(path, stamp)
    updated = text.replace(block + "\n", "").replace(block, "").rstrip() + "\n"
    path.write_text(updated, encoding="utf-8")
    return {"status": "removed", "config": str(path)}


def configure_hooks(entry: dict, stamp: str, dry_run: bool = False) -> dict:
    platform = str(entry["id"])
    if platform == "codex":
        result = merge_codex_hooks(platforms.resolve_path(entry, entry["mcp"]["config"]), entry, stamp, dry_run)
    elif platform == "claude":
        result = merge_native_json_hooks(platforms.platform_home(entry) / "settings.json", entry, stamp, dry_run)
    elif platform == "gemini":
        result = merge_native_json_hooks(platforms.resolve_path(entry, entry["mcp"]["config"]), entry, stamp, dry_run)
    elif entry["hooks"]["mode"] == "event-checkpoint":
        result = {"status": "ready", "detail": "state writes and MCP restore provide lifecycle continuity"}
    else:
        result = {"status": "contract-ready", "detail": "native hook bundle generated; host activation requires a detected runtime"}
    if not dry_run:
        manifest = hook_manifest(entry, result["status"] == "ready")
        atomic = hook_manifest_path(entry)
        atomic.parent.mkdir(parents=True, exist_ok=True)
        atomic.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {"platform": platform, **result}


def remove_hooks(entry: dict, stamp: str, dry_run: bool = False) -> dict:
    platform = str(entry["id"])
    if platform == "codex":
        result = remove_codex_hooks(platforms.resolve_path(entry, entry["mcp"]["config"]), entry, stamp, dry_run)
    elif platform == "claude":
        result = remove_native_json_hooks(platforms.platform_home(entry) / "settings.json", entry, stamp, dry_run)
    elif platform == "gemini":
        result = remove_native_json_hooks(platforms.resolve_path(entry, entry["mcp"]["config"]), entry, stamp, dry_run)
    else:
        result = {"status": "removed"}
    if not dry_run:
        hook_manifest_path(entry).unlink(missing_ok=True)
    return {"platform": platform, **result}


def main() -> None:
    parser = argparse.ArgumentParser(description="Install Blue Sec Hub for supported agent platforms")
    parser.add_argument("--platform", choices=("auto", "all", *platforms.platform_ids()), default="auto")
    parser.add_argument("--no-configure-mcp", action="store_true")
    parser.add_argument("--no-hooks", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument(
        "--no-knowledge-sync",
        action="store_true",
        help="Skip installation of the reviewed, pinned upstream knowledge cache",
    )
    args = parser.parse_args()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    selected = platforms.select_platforms(args.platform)
    results = []
    if args.uninstall:
        for entry in selected:
            item = uninstall_skills(str(entry["id"]), platforms.skill_root(entry), args.dry_run)
            item["agents"] = uninstall_agents(entry, args.dry_run)
            item["mcp"] = {"status": "skipped"} if args.no_configure_mcp else remove_mcp(entry, stamp, args.dry_run)
            item["hooks"] = {"status": "skipped"} if args.no_hooks else remove_hooks(entry, stamp, args.dry_run)
            results.append(item)
        commands = uninstall_commands(args.dry_run) if args.platform == "all" else {"status": "retained-for-other-platforms"}
        print(f"[ok] uninstalled Blue Sec Hub from {', '.join(str(item['id']) for item in selected)}")
        print(json.dumps({"schema_version": 2, "results": results, "commands": commands}, ensure_ascii=False, indent=2))
        return
    commands = install_commands(stamp, args.dry_run)
    knowledge = synchronize_knowledge(args.dry_run, args.no_knowledge_sync)
    for entry in selected:
        item = install_skills(str(entry["id"]), platforms.skill_root(entry), stamp, args.dry_run)
        item["agents"] = install_agents(entry, stamp, args.dry_run)
        item["detected"] = platforms.is_detected(entry)
        item["mcp"] = {"status": "skipped"} if args.no_configure_mcp else configure_mcp(entry, stamp, args.dry_run)
        item["hooks"] = {"status": "skipped"} if args.no_hooks else configure_hooks(entry, stamp, args.dry_run)
        results.append(item)
    print(f"[ok] installed Blue Sec Hub for {', '.join(str(item['id']) for item in selected)}")
    print(json.dumps({"schema_version": 2, "results": results, "commands": commands, "knowledge": knowledge}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
