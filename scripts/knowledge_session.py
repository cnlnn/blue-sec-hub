#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CACHE_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_CACHE",
        Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
        / "blue-sec-hub",
    )
)
SESSIONS = CACHE_ROOT / "sessions"
SCHEMA_VERSION = 1
DEFAULT_TTL_HOURS = 24


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(path)


def manifest_path(session_id: str) -> Path:
    return SESSIONS / session_id / "session.json"


def load_manifest(session_id: str) -> dict[str, Any]:
    path = manifest_path(session_id)
    if not path.exists():
        raise SystemExit(f"knowledge session not found: {session_id}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schema_version") != SCHEMA_VERSION:
        raise SystemExit(f"unsupported knowledge session: {session_id}")
    return value


def active_manifests() -> list[tuple[Path, dict[str, Any]]]:
    if not SESSIONS.exists():
        return []
    result: list[tuple[Path, dict[str, Any]]] = []
    for path in sorted(SESSIONS.glob("*/session.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if value.get("state") == "active":
            result.append((path, value))
    return result


def cleanup_expired(ttl_hours: int = DEFAULT_TTL_HOURS) -> int:
    cutoff = time.time() - ttl_hours * 3600
    removed = 0
    for path, value in active_manifests():
        directory = path.parent
        touched = float(value.get("touched_epoch") or directory.stat().st_mtime)
        if touched >= cutoff:
            continue
        shutil.rmtree(directory)
        removed += 1
    return removed


def source_key(path: Path) -> str:
    return hashlib.sha256(str(path).encode("utf-8")).hexdigest()[:16]


def command_open(args: argparse.Namespace) -> None:
    cleanup_expired(args.ttl_hours)
    source = args.path.expanduser().resolve()
    if not source.is_dir():
        raise SystemExit(f"session knowledge root is not a directory: {source}")
    for manifest, value in active_manifests():
        if value.get("source_path") == str(source):
            value["touched_at"] = now()
            value["touched_epoch"] = time.time()
            atomic_json(manifest, value)
            print(f"[current] {value['session_id']}")
            print(manifest.parent)
            return
    session_id = args.session_id or f"ks-{uuid.uuid4().hex[:16]}"
    directory = SESSIONS / session_id
    if directory.exists():
        raise SystemExit(f"session already exists: {session_id}")
    directory.mkdir(parents=True, mode=0o700)
    directory.chmod(0o700)
    value = {
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id,
        "state": "active",
        "source_path": str(source),
        "source_key": source_key(source),
        "opened_at": now(),
        "touched_at": now(),
        "touched_epoch": time.time(),
        "ttl_hours": args.ttl_hours,
        "distillation_runs": [],
    }
    atomic_json(directory / "session.json", value)
    print(f"[opened] {session_id}")
    print(directory)


def command_status(args: argparse.Namespace) -> None:
    cleanup_expired(args.ttl_hours)
    if args.session_id:
        values = [(manifest_path(args.session_id), load_manifest(args.session_id))]
    else:
        values = active_manifests()
    for path, value in values:
        output = dict(value)
        output["session_dir"] = str(path.parent)
        output["permissions"] = oct(stat.S_IMODE(path.parent.stat().st_mode))
        print(json.dumps(output, ensure_ascii=False, sort_keys=True))
    print(f"[total] {len(values)}")


def command_close(args: argparse.Namespace) -> None:
    directory = manifest_path(args.session_id).parent
    if not directory.exists():
        print(f"[absent] {args.session_id}")
        return
    if args.keep:
        value = load_manifest(args.session_id)
        value["state"] = "closed"
        value["closed_at"] = now()
        atomic_json(directory / "session.json", value)
        print(f"[closed:retained] {args.session_id}")
        return
    shutil.rmtree(directory)
    print(f"[closed:removed] {args.session_id}")


def command_cleanup(args: argparse.Namespace) -> None:
    removed = cleanup_expired(args.ttl_hours)
    print(f"[ok] removed={removed}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage temporary, local-only Blue Sec knowledge sessions"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    opening = commands.add_parser("open")
    opening.add_argument("path", type=Path)
    opening.add_argument("--session-id")
    opening.add_argument("--ttl-hours", type=int, default=DEFAULT_TTL_HOURS)
    opening.set_defaults(function=command_open)

    status = commands.add_parser("status")
    status.add_argument("session_id", nargs="?")
    status.add_argument("--ttl-hours", type=int, default=DEFAULT_TTL_HOURS)
    status.set_defaults(function=command_status)

    close = commands.add_parser("close")
    close.add_argument("session_id")
    close.add_argument("--keep", action="store_true")
    close.set_defaults(function=command_close)

    cleanup = commands.add_parser("cleanup")
    cleanup.add_argument("--ttl-hours", type=int, default=DEFAULT_TTL_HOURS)
    cleanup.set_defaults(function=command_cleanup)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if getattr(args, "ttl_hours", DEFAULT_TTL_HOURS) < 1:
        raise SystemExit("ttl-hours must be positive")
    args.function(args)


if __name__ == "__main__":
    main()
