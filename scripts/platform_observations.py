#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


DATA_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_DATA",
        Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "blue-sec-hub",
    )
)
PRE_EVENTS = {"precompact", "precompress", "session_before_compact", "on_pre_compress", "session.compaction.started"}
RESTORE_EVENTS = {"postcompact", "sessionstart", "session_after_compact", "on_session_start", "session.compaction.completed"}


def path_for(platform: str) -> Path:
    return DATA_ROOT / "platform-certifications" / "hook-observations" / f"{platform}.json"


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if os.name != "nt":
        temporary.chmod(0o600)
    temporary.replace(path)


def record(platform: str, event: str, payload: dict[str, Any]) -> dict[str, Any]:
    path = path_for(platform)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        value = {"schema_version": 1, "platform": platform, "events": {}}
    normalized = event.casefold()
    value.setdefault("events", {})[normalized] = {
        "observed_at": datetime.now(UTC).isoformat(),
        "payload_sha256": hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode()).hexdigest(),
    }
    atomic_json(path, value)
    return value


def status(entry: dict[str, Any], max_age_days: int = 30) -> dict[str, Any]:
    events = {str(item).casefold() for item in entry["hooks"].get("events", [])}
    groups = []
    if events & PRE_EVENTS:
        groups.append(("pre-compact", PRE_EVENTS))
    if events & RESTORE_EVENTS:
        groups.append(("restore", RESTORE_EVENTS))
    if not groups:
        return {"status": "not-exposed", "required": [], "observed": [], "missing": []}
    try:
        value = json.loads(path_for(str(entry["id"])).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        value = {}
    observations = value.get("events", {}) if isinstance(value, dict) else {}
    cutoff = datetime.now(UTC) - timedelta(days=max_age_days)
    fresh = set()
    for event, observation in observations.items():
        try:
            observed_at = datetime.fromisoformat(str(observation["observed_at"]))
        except (KeyError, TypeError, ValueError):
            continue
        if observed_at.astimezone(UTC) >= cutoff:
            fresh.add(str(event).casefold())
    missing = [name for name, candidates in groups if not fresh & candidates]
    return {
        "status": "ready" if not missing else "contract-ready",
        "required": [name for name, _ in groups],
        "observed": sorted(fresh),
        "missing": missing,
        "path": str(path_for(str(entry["id"]))),
    }
