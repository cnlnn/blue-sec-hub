#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "platforms.json"
PLATFORM_STATUSES = {
    "ready",
    "runtime-certified",
    "contract-ready",
    "degraded",
    "not-installed",
    "unsupported-version",
    "not-exposed",
    "skipped",
    "error",
}


def load_registry(path: Path = REGISTRY_PATH) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema_version") != 1:
        raise ValueError("unsupported platform registry schema")
    entries = value.get("platforms")
    if not isinstance(entries, list) or not entries:
        raise ValueError("platform registry requires platforms")
    ids: set[str] = set()
    aliases: set[str] = set()
    required = {
        "id",
        "kind",
        "executables",
        "version_probe",
        "default_home",
        "skill_path",
        "mcp",
        "hooks",
        "agents",
        "sessions",
    }
    for entry in entries:
        missing = required - set(entry)
        if missing:
            raise ValueError(f"platform entry missing fields: {', '.join(sorted(missing))}")
        platform_id = str(entry["id"])
        if platform_id in ids or platform_id in aliases:
            raise ValueError(f"duplicate platform id: {platform_id}")
        ids.add(platform_id)
        for alias in entry.get("aliases", []):
            alias = str(alias)
            if alias in ids or alias in aliases:
                raise ValueError(f"duplicate platform alias: {alias}")
            aliases.add(alias)
        if entry["sessions"].get("status") not in {"supported", "not-exposed"}:
            raise ValueError(f"invalid session status for {platform_id}")
    return value


def platform_ids() -> tuple[str, ...]:
    return tuple(str(item["id"]) for item in load_registry()["platforms"])


def _entry_map() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for entry in load_registry()["platforms"]:
        result[str(entry["id"])] = entry
        for alias in entry.get("aliases", []):
            result[str(alias)] = entry
    return result


def get_platform(name: str) -> dict[str, Any]:
    try:
        return _entry_map()[name]
    except KeyError as error:
        raise ValueError(f"unsupported platform: {name}") from error


def path_variables(entry: dict[str, Any]) -> dict[str, str]:
    home = Path(os.environ.get("HOME", str(Path.home()))).expanduser()
    xdg_config = Path(os.environ.get("XDG_CONFIG_HOME", home / ".config")).expanduser()
    appdata = Path(
        os.environ.get(
            "APPDATA",
            home / "Library" / "Application Support" if sys.platform == "darwin" else xdg_config,
        )
    ).expanduser()
    variables = {"home": str(home), "xdg_config": str(xdg_config), "appdata": str(appdata)}
    default = str(entry["default_home"]).format(**variables)
    override = os.environ.get(str(entry.get("home_env") or ""))
    platform_home = Path(override or default).expanduser()
    return {**variables, "platform_home": str(platform_home)}


def resolve_path(entry: dict[str, Any], template: str) -> Path:
    return Path(template.format(**path_variables(entry))).expanduser()


def platform_home(entry: dict[str, Any]) -> Path:
    return Path(path_variables(entry)["platform_home"])


def skill_root(entry: dict[str, Any]) -> Path:
    return resolve_path(entry, str(entry["skill_path"]))


def executable(entry: dict[str, Any]) -> str | None:
    return next((path for name in entry["executables"] if (path := shutil.which(name))), None)


def is_detected(entry: dict[str, Any]) -> bool:
    if executable(entry):
        return True
    if entry.get("kind") == "cli":
        return False
    paths = [platform_home(entry)] + [resolve_path(entry, item) for item in entry.get("detect_paths", [])]
    return any(path.exists() for path in paths)


def probe_version(entry: dict[str, Any], timeout: float = 10.0) -> dict[str, Any]:
    path = executable(entry)
    if not path:
        return {"status": "not-installed", "executable": None, "version": None, "raw": None}
    probe = entry.get("version_probe", {})
    arguments = [str(item) for item in probe.get("args", ["--version"])]
    try:
        result = subprocess.run(
            [path, *arguments],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"status": "degraded", "executable": path, "version": None, "raw": str(error)}
    raw = result.stdout.strip()[:1000]
    pattern = str(probe.get("pattern") or r"(?P<version>\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?)")
    match = re.search(pattern, raw)
    version = match.groupdict().get("version") if match else None
    status = "ready" if result.returncode == 0 and version else "degraded"
    return {"status": status, "executable": path, "version": version, "raw": raw}


def select_platforms(value: str) -> list[dict[str, Any]]:
    if value == "all":
        return [get_platform(item) for item in platform_ids()]
    if value == "auto":
        detected = [get_platform(item) for item in platform_ids() if is_detected(get_platform(item))]
        return detected or [get_platform("codex")]
    return [get_platform(value)]


def session_roots(entry: dict[str, Any]) -> list[Path]:
    return [resolve_path(entry, item) for item in entry["sessions"].get("paths", [])]


def iter_supported_session_roots(names: Iterable[str]) -> Iterable[tuple[str, str, Path]]:
    for name in names:
        entry = get_platform(name)
        if entry["sessions"].get("status") != "supported":
            continue
        for root in session_roots(entry):
            if root.is_dir():
                yield str(entry["id"]), str(entry["sessions"]["format"]), root


def contract_summary(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "platform": entry["id"],
        "detected": is_detected(entry),
        "executable": executable(entry),
        "version_probe": entry["version_probe"],
        "home": str(platform_home(entry)),
        "skill_root": str(skill_root(entry)),
        "package": entry["package"],
        "mcp_mode": entry["mcp"]["mode"],
        "hook_mode": entry["hooks"]["mode"],
        "hook_events": entry["hooks"].get("events", []),
        "session_import": entry["sessions"]["status"],
        "subagents": entry["agents"]["status"],
    }
