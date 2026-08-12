#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import effective_skills
import install
import platforms
import platform_observations


ROOT = Path(__file__).resolve().parents[1]
DATA_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_DATA",
        Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        / "blue-sec-hub",
    )
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def repository_revision() -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    return result.stdout.strip() or None


def receipt_path(platform_id: str) -> Path:
    return DATA_ROOT / "platform-certifications" / f"{platform_id}.json"


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def mcp_smoke() -> dict[str, Any]:
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ]
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "agent.py"), "serve", "--stdio"],
        input="".join(json.dumps(item) + "\n" for item in requests),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    responses = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    initialized = next((item for item in responses if item.get("id") == 1), {})
    listed = next((item for item in responses if item.get("id") == 2), {})
    names = sorted(item.get("name") for item in listed.get("result", {}).get("tools", []))
    ready = (
        result.returncode == 0
        and initialized.get("result", {}).get("serverInfo", {}).get("name") == install.SERVER_NAME
        and {"checkpoint_security_context", "restore_security_context"}.issubset(names)
    )
    evidence = json.dumps(responses, ensure_ascii=False, sort_keys=True).encode()
    return {"status": "ready" if ready else "degraded", "tools": len(names), "evidence_sha256": sha256_bytes(evidence)}


def lifecycle_smoke(platform_id: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as temporary:
        workspace = Path(temporary) / "task"
        environment = os.environ.copy()
        environment["BLUE_SEC_DATA"] = str(Path(temporary) / "data")
        commands = [
            [sys.executable, str(ROOT / "scripts/context_checkpoint.py"), "init", "--workspace", str(workspace), "--task-kind", "platform-certification"],
            [sys.executable, str(ROOT / "scripts/context_checkpoint.py"), "checkpoint", "--workspace", str(workspace), "--trigger", "certification", "--platform", platform_id],
            [sys.executable, str(ROOT / "scripts/context_checkpoint.py"), "restore", "--workspace", str(workspace)],
        ]
        outputs: list[str] = []
        statuses: list[int] = []
        for command in commands:
            result = subprocess.run(command, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
            statuses.append(result.returncode)
            outputs.append(result.stdout)
        try:
            restored = json.loads(outputs[-1])
        except json.JSONDecodeError:
            restored = {}
        ready = all(status == 0 for status in statuses) and restored.get("status") == "ready"
        return {
            "status": "ready" if ready else "degraded",
            "checkpoint": statuses[1] == 0,
            "restore": restored.get("status") == "ready",
            "evidence_sha256": sha256_bytes("\n".join(outputs).encode()),
        }


def configured_mcp_status(entry: dict[str, Any]) -> str:
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
    result = subprocess.run(get, env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
    return "ready" if install.cli_mcp_is_current(mode, result) else "degraded"


def configuration_status(entry: dict[str, Any]) -> dict[str, str]:
    skill_manifest = install.load_json(platforms.skill_root(entry) / install.MANIFEST_NAME)
    hook_manifest = install.load_json(install.hook_manifest_path(entry))
    skills = "ready" if skill_manifest.get("platform") == entry["id"] else "degraded"
    hooks = "ready" if hook_manifest.get("platform") == entry["id"] and hook_manifest.get("active") else "degraded"
    agents = "not-exposed"
    if entry["agents"]["status"] == "supported":
        target = platforms.resolve_path(entry, str(entry["agents"]["path"]))
        manifest = install.load_json(target / install.AGENT_MANIFEST_NAME)
        agents = "ready" if len(manifest.get("agents", [])) == len(list((ROOT / "agents").glob("*.md"))) else "degraded"
    return {"skills": skills, "hooks": hooks, "mcp": configured_mcp_status(entry), "agents": agents}


def certify(entry: dict[str, Any]) -> dict[str, Any]:
    platform_id = str(entry["id"])
    version = platforms.probe_version(entry)
    if version["status"] == "not-installed":
        return {"platform": platform_id, "status": "not-installed", "version": version}
    if version["status"] != "ready":
        return {"platform": platform_id, "status": "unsupported-version", "version": version}
    configured = configuration_status(entry)
    hook_observation = platform_observations.status(entry)
    mcp = mcp_smoke()
    lifecycle = lifecycle_smoke(platform_id)
    checks = {
        **configured,
        "hook-observation": hook_observation["status"],
        "mcp-initialize": mcp["status"],
        "checkpoint": lifecycle["status"],
        "restore": lifecycle["status"],
    }
    if any(value not in {"ready", "not-exposed"} for value in checks.values()):
        failed = [
            name
            for name, value in checks.items()
            if value not in {"ready", "not-exposed"}
        ]
        return {
            "platform": platform_id,
            "status": "degraded",
            "version": version,
            "checks": checks,
            "detail": "runtime certification is waiting for: " + ", ".join(failed),
            "hook_observation": hook_observation,
        }
    executable = Path(str(version["executable"])).resolve()
    receipt = {
        "schema_version": 1,
        "platform": platform_id,
        "status": "runtime-certified",
        "certified_at": datetime.now(UTC).isoformat(),
        "repository_revision": repository_revision(),
        "effective_revision": effective_skills.current_revision(),
        "runtime": {
            "executable": str(executable),
            "executable_sha256": sha256_file(executable),
            "version": version["version"],
            "version_evidence_sha256": sha256_bytes(str(version["raw"]).encode()),
        },
        "checks": checks,
        "evidence": {"mcp": mcp, "lifecycle": lifecycle},
        "hook_observation": hook_observation,
    }
    atomic_json(receipt_path(platform_id), receipt)
    return receipt


def validate_receipt(entry: dict[str, Any]) -> dict[str, Any]:
    path = receipt_path(str(entry["id"]))
    try:
        receipt = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"status": "contract-ready", "receipt": str(path), "reasons": ["missing certification receipt"]}
    reasons = []
    version = platforms.probe_version(entry)
    if receipt.get("platform") != entry["id"] or receipt.get("status") != "runtime-certified":
        reasons.append("invalid receipt identity")
    if receipt.get("repository_revision") != repository_revision():
        reasons.append("code revision changed")
    if receipt.get("effective_revision") != effective_skills.current_revision():
        reasons.append("Effective Skill revision changed")
    runtime = receipt.get("runtime", {})
    if version.get("status") != "ready" or runtime.get("version") != version.get("version"):
        reasons.append("runtime version changed or unavailable")
    executable = Path(str(version.get("executable") or ""))
    if executable.is_file() and runtime.get("executable_sha256") != sha256_file(executable.resolve()):
        reasons.append("runtime executable changed")
    if any(value not in {"ready", "not-exposed"} for value in receipt.get("checks", {}).values()):
        reasons.append("receipt contains failed checks")
    if platform_observations.status(entry)["status"] != "ready":
        reasons.append("required host hook events have not been observed recently")
    return {
        "status": "contract-ready" if reasons else "runtime-certified",
        "receipt": str(path),
        "certified_at": receipt.get("certified_at"),
        "reasons": reasons,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run real Blue Sec Hub platform runtime certification")
    parser.add_argument("--platform", choices=("auto", "all", *platforms.platform_ids()), default="auto")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    results = [certify(entry) for entry in platforms.select_platforms(args.platform)]
    payload = {"schema_version": 1, "results": results}
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for item in results:
            print(f"{item['platform']}: {item['status']}")
    raise SystemExit(0 if all(item["status"] in {"runtime-certified", "not-installed"} for item in results) else 2)


if __name__ == "__main__":
    main()
