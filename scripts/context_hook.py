#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import context_checkpoint
import effective_skills
import platform_observations


PRE_EVENTS = {"precompact", "precompress", "session_before_compact", "on_pre_compress"}
RESTORE_EVENTS = {"postcompact", "sessionstart", "session_after_compact", "on_session_start"}


def read_payload() -> dict[str, Any]:
    try:
        value = json.load(sys.stdin)
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def find_workspace(payload: dict[str, Any]) -> Path | None:
    explicit = os.environ.get("BLUE_SEC_WORKSPACE") or payload.get("workspace")
    if explicit:
        path = Path(str(explicit)).expanduser().resolve()
        if path.is_dir():
            return path
    session_id = str(payload.get("session_id") or payload.get("sessionId") or "")
    if bound := context_checkpoint.resolve_bound_workspace(session_id):
        return bound
    start = Path(str(payload.get("cwd") or os.getcwd())).expanduser().resolve()
    for path in (start, *start.parents):
        if (path / "task-context.json").is_file() or (path / "agent-state.json").is_file():
            return path
    return None


def compact_restore_text(result: dict[str, Any]) -> str:
    capsule = result.get("capsule", {})
    value = {
        "blue_sec_context_restore": result.get("status"),
        "checkpoint_id": capsule.get("checkpoint_id"),
        "task": capsule.get("task", {}),
        "critical_clues": capsule.get("critical_clues", []),
        "confirmed_findings": capsule.get("confirmed_findings", []),
        "unresolved_actions": capsule.get("unresolved_actions", []),
        "coverage_debt": capsule.get("coverage_debt", {}),
        "restore_sequence": capsule.get("restore_sequence", []),
        "requires_reconciliation": result.get("requires_reconciliation", False),
    }
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Blue Sec Hub context lifecycle hook")
    parser.add_argument("--platform", required=True)
    parser.add_argument("--event")
    args = parser.parse_args()
    payload = read_payload()
    platform = args.platform
    if platform == "auto":
        platform = str(payload.get("platform") or "")
        if not platform:
            platform = next(
                (
                    name
                    for name, variable in (
                        ("codex", "CODEX_HOME"),
                        ("claude", "CLAUDE_CONFIG_DIR"),
                        ("grok", "GROK_PLUGIN_ROOT"),
                    )
                    if os.environ.get(variable)
                ),
                "generic",
            )
    workspace = find_workspace(payload)
    event = str(args.event or payload.get("hook_event_name") or payload.get("eventName") or "").casefold()
    if event:
        platform_observations.record(platform, event, payload)
    session_id = str(payload.get("session_id") or payload.get("sessionId") or "") or None
    transcript_value = payload.get("transcript_path") or payload.get("transcriptPath")
    if event == "sessionend":
        context_checkpoint.queue_session_distillation(
            platform,
            session_id,
            str(transcript_value) if transcript_value else None,
        )
    if workspace is None:
        return
    try:
        if event in PRE_EVENTS and transcript_value:
            transcript = Path(str(transcript_value)).expanduser()
            if transcript.is_file():
                context_checkpoint.reconcile_transcript(
                    workspace,
                    transcript,
                    platform=platform,
                    session_id=session_id,
                )
        if event in PRE_EVENTS or event in {"sessionend", "afteragent", "stop"}:
            context_checkpoint.checkpoint(
                workspace,
                trigger=event or "hook",
                platform=platform,
                session_id=session_id,
            )
        if event == "sessionend":
            task = context_checkpoint.load_json(workspace / "task-context.json", {})
            if task.get("task_id"):
                effective_skills.release_task(str(task["task_id"]))
        if event in RESTORE_EVENTS:
            print(compact_restore_text(context_checkpoint.restore_context(workspace)))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"blue-sec context hook degraded: {error}", file=sys.stderr)


if __name__ == "__main__":
    main()
