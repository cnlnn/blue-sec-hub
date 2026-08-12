#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def update_code() -> str:
    if not (ROOT / ".git").exists() and not subprocess.run(
        ["git", "rev-parse", "--git-dir"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0:
        return "not-a-worktree"
    branch = subprocess.run(
        ["git", "branch", "--show-current"],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    if branch != "main" or dirty:
        return "blocked-worktree-drift"
    remotes = subprocess.run(
        ["git", "remote"], cwd=ROOT, check=True, text=True, stdout=subprocess.PIPE
    ).stdout.split()
    if "origin" not in remotes:
        return "no-origin"
    subprocess.run(["git", "fetch", "origin", "main"], cwd=ROOT, check=True)
    current = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    target = subprocess.run(
        ["git", "rev-parse", "origin/main"],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout.strip()
    if current == target:
        return "current"
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", current, target],
        cwd=ROOT,
    )
    if ancestor.returncode:
        return "blocked-non-fast-forward"
    temporary = Path(tempfile.mkdtemp(prefix="blue-sec-update-"))
    candidate = temporary / "candidate"
    try:
        subprocess.run(
            ["git", "worktree", "add", "--detach", str(candidate), target],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            [sys.executable, str(candidate / "scripts" / "validate.py"), "--offline"],
            cwd=candidate,
            check=True,
        )
    finally:
        subprocess.run(
            ["git", "worktree", "remove", "--force", str(candidate)],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        shutil.rmtree(temporary, ignore_errors=True)
    subprocess.run(["git", "merge", "--ff-only", "origin/main"], cwd=ROOT, check=True)
    return "updated"


def main() -> None:
    parser = argparse.ArgumentParser(description="Update Blue Sec Hub")
    parser.add_argument("--skip-feeds", action="store_true")
    parser.add_argument("--force-feeds", action="store_true")
    parser.add_argument("--skip-code", action="store_true")
    args = parser.parse_args()

    if not args.skip_code:
        code_status = update_code()
        print(f"[code] {code_status}")

    scripts = ["sync_sources.py"]
    if not args.skip_feeds:
        feed_args = [sys.executable, str(ROOT / "scripts" / "update_feeds.py")]
        if args.force_feeds:
            feed_args.append("--force")
        print("\n== update_feeds.py ==")
        result = subprocess.run(feed_args)
        if result.returncode:
            print("[warning] authoritative feed update failed; keeping available cache")
    scripts.extend(("term_learning.py", "validate.py"))
    for script in scripts:
        print(f"\n== {script} ==")
        command = [sys.executable, str(ROOT / "scripts" / script)]
        if script == "term_learning.py":
            command.append("discover")
        subprocess.run(command, check=True)

    print("\n== session_distill.py ==")
    distillation = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "session_distill.py"),
            "run",
            "--source",
            "all",
            "--incremental",
        ]
    )
    if distillation.returncode:
        print("[warning] session distillation backlog remains pending; current Effective Skill is unchanged")

    previous = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "effective_skills.py"), "status"],
        text=True,
        stdout=subprocess.PIPE,
        check=True,
    )
    previous_revision = json.loads(previous.stdout).get("active_revision")
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "effective_skills.py"), "compile"],
        check=True,
    )
    try:
        subprocess.run([sys.executable, str(ROOT / "scripts" / "install.py")], check=True)
        subprocess.run([sys.executable, str(ROOT / "scripts" / "doctor.py")], check=True)
    except subprocess.CalledProcessError:
        if previous_revision:
            subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "effective_skills.py"),
                    "activate",
                    str(previous_revision),
                ],
                check=False,
            )
            subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "install.py")],
                check=False,
            )
        raise


if __name__ == "__main__":
    main()
