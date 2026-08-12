#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "feeds.json"
CACHE_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_CACHE",
        Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
        / "blue-sec-hub",
    )
)
FEEDS = CACHE_ROOT / "feeds"
LOCK = CACHE_ROOT / "feeds.lock.json"


def run(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(
        args,
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.strip()


def fresh_enough(max_age_hours: int) -> bool:
    if not LOCK.exists():
        return False
    try:
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        if not lock.get("complete"):
            return False
        configured = json.loads(CONFIG.read_text(encoding="utf-8"))
        required = {
            name for name, source in configured.items() if source["type"] != "live"
        }
        if not required.issubset(lock.get("sources", {})):
            return False
        synced_at = lock["synced_at"]
        timestamp = datetime.fromisoformat(synced_at)
    except (KeyError, ValueError, json.JSONDecodeError):
        return False
    return datetime.now(timezone.utc) - timestamp < timedelta(hours=max_age_hours)


def update_git(name: str, config: dict[str, object]) -> dict[str, object]:
    destination = FEEDS / name
    paths = [str(path) for path in config["paths"]]
    if not (destination / ".git").exists():
        destination.parent.mkdir(parents=True, exist_ok=True)
        run(
            "git",
            "clone",
            "--depth",
            "1",
            "--filter=blob:none",
            "--sparse",
            str(config["url"]),
            str(destination),
        )
    sparse_args = ["git", "sparse-checkout", "set"]
    if config.get("cone") is False:
        sparse_args.append("--no-cone")
    sparse_args.extend(paths)
    run(*sparse_args, cwd=destination)
    run("git", "pull", "--ff-only", cwd=destination)
    return {
        "type": "git-sparse",
        "url": config["url"],
        "commit": run("git", "rev-parse", "HEAD", cwd=destination),
        "paths": paths,
        "path": str(destination),
    }


def update_http(config: dict[str, object]) -> dict[str, object]:
    destination = FEEDS / str(config["target"])
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(
        str(config["url"]),
        headers={"User-Agent": "blue-sec-hub/1.0"},
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        limit = int(config.get("max_bytes", 100 * 1024 * 1024))
        content = response.read(limit + 1)
    if len(content) > limit:
        raise OSError(f"feed exceeds max_bytes={limit}: {config['url']}")
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    temporary.replace(destination)
    return {
        "type": "http",
        "url": config["url"],
        "sha256": hashlib.sha256(content).hexdigest(),
        "bytes": len(content),
        "path": str(destination),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Update authoritative security feeds")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--max-age-hours", type=int, default=24)
    args = parser.parse_args()

    if not args.force and fresh_enough(args.max_age_hours):
        print(f"[current] authoritative feeds: {LOCK}")
        return

    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    result: dict[str, object] = {
        "synced_at": datetime.now(timezone.utc).isoformat(),
        "sources": {},
    }
    failures: list[str] = []
    for name, source in config.items():
        try:
            if source["type"] == "git-sparse":
                metadata = update_git(name, source)
            elif source["type"] == "http":
                metadata = update_http(source)
            else:
                metadata = {
                    "type": "live",
                    "url": source["url"],
                    "note": "query live; not mirrored",
                }
            result["sources"][name] = metadata
            print(f"[updated] {name}")
        except (OSError, subprocess.CalledProcessError, urllib.error.URLError) as error:
            failures.append(f"{name}: {error}")
            print(f"[failed] {name}: {error}")

    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    result["complete"] = not failures
    LOCK.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    if failures:
        raise SystemExit("\n".join(failures))
    print(f"[ok] authoritative feeds: {LOCK}")


if __name__ == "__main__":
    main()
