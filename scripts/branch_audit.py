#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def git(repo: Path, *arguments: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.strip()


def resolve_base(repo: Path, requested: str) -> str:
    candidates = [requested]
    if requested == "main":
        candidates.insert(0, "origin/main")
    for candidate in candidates:
        if git(repo, "rev-parse", "--verify", "--quiet", candidate, check=False):
            return candidate
    raise ValueError(f"base branch does not exist: {requested}")


def github_prs(repo: Path) -> dict[str, dict[str, Any]]:
    if not shutil.which("gh"):
        return {}
    result = subprocess.run(
        ["gh", "pr", "list", "--state", "all", "--limit", "200", "--json", "headRefName,url,state,updatedAt"],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=30,
    )
    if result.returncode:
        return {}
    return {str(item["headRefName"]): item for item in json.loads(result.stdout)}


def branch_config(repo: Path, name: str, key: str) -> str | None:
    value = git(repo, "config", "--get", f"branch.{name}.{key}", check=False)
    return value or None


def worktrees(repo: Path) -> list[dict[str, Any]]:
    output = git(repo, "worktree", "list", "--porcelain")
    records: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    for line in [*output.splitlines(), ""]:
        if not line:
            if current:
                records.append(current)
                current = {}
            continue
        key, _, value = line.partition(" ")
        current[key] = value or True
    return records


def audit(repo: Path, requested_base: str = "main", include_github: bool = False) -> dict[str, Any]:
    repo = repo.resolve()
    base = resolve_base(repo, requested_base)
    now = datetime.now(UTC)
    prs = github_prs(repo) if include_github else {}
    checked_out = {
        str(item.get("branch", "")).removeprefix("refs/heads/"): item.get("worktree")
        for item in worktrees(repo)
        if item.get("branch")
    }
    format_string = "%00".join(
        ("%(refname)", "%(refname:short)", "%(objectname)", "%(committerdate:iso-strict)", "%(upstream:short)")
    )
    output = git(repo, "for-each-ref", f"--format={format_string}", "refs/heads", "refs/remotes")
    branches = []
    for line in output.splitlines():
        refname, short, commit, committed_at, upstream = line.split("\x00")
        if refname.endswith("/HEAD"):
            continue
        if refname in {"refs/heads/main", "refs/remotes/origin/main"}:
            continue
        behind_text, ahead_text = git(repo, "rev-list", "--left-right", "--count", f"{base}...{refname}").split()
        ahead = int(ahead_text)
        behind = int(behind_text)
        timestamp = datetime.fromisoformat(committed_at)
        age_days = max(0, int((now - timestamp.astimezone(UTC)).total_seconds() // 86400))
        local_name = short if refname.startswith("refs/heads/") else short.split("/", 1)[-1]
        pr = prs.get(local_name)
        configured_pr = branch_config(repo, local_name, "blue-sec-pr")
        blocking_reason = branch_config(repo, local_name, "blue-sec-blocked") if refname.startswith("refs/heads/") else None
        pr_url = str(pr.get("url")) if pr else configured_pr
        commits = []
        if ahead:
            for value in git(repo, "log", "--format=%H%x00%s", f"{base}..{refname}").splitlines():
                sha, _, subject = value.partition("\x00")
                commits.append({"sha": sha, "subject": subject})
        stale = ahead > 0 and age_days >= 7
        expired = stale and age_days >= 14 and not pr_url
        if ahead == 0:
            status = "merged-or-behind"
        elif expired:
            status = "archive-candidate"
        elif stale:
            status = "stale"
        elif pr_url:
            status = "ahead-with-pr"
        else:
            status = "ahead-without-pr"
        branches.append(
            {
                "ref": refname,
                "name": short,
                "scope": "local" if refname.startswith("refs/heads/") else "remote",
                "commit": commit,
                "committed_at": committed_at,
                "age_days": age_days,
                "ahead": ahead,
                "behind": behind,
                "upstream": upstream or None,
                "worktree": checked_out.get(local_name),
                "pr": {"url": pr_url, "state": pr.get("state") if pr else ("configured" if pr_url else "unknown")},
                "blocking_reason": blocking_reason,
                "stale": stale,
                "archive_candidate": expired,
                "status": status,
                "unmerged_commits": commits,
            }
        )
    branches.sort(key=lambda item: (item["scope"], item["name"]))
    summary = {
        "branches": len(branches),
        "ahead": sum(item["ahead"] > 0 for item in branches),
        "without_pr": sum(item["ahead"] > 0 and not item["pr"]["url"] for item in branches),
        "stale": sum(item["stale"] for item in branches),
        "archive_candidates": sum(item["archive_candidate"] for item in branches),
    }
    return {
        "schema_version": 1,
        "repository": str(repo),
        "base": base,
        "base_commit": git(repo, "rev-parse", base),
        "generated_at": now.isoformat(),
        "summary": summary,
        "branches": branches,
        "worktrees": worktrees(repo),
    }


def print_human(value: dict[str, Any]) -> None:
    summary = value["summary"]
    print(
        f"base={value['base']} branches={summary['branches']} ahead={summary['ahead']} "
        f"without-pr={summary['without_pr']} stale={summary['stale']} archive={summary['archive_candidates']}"
    )
    for branch in value["branches"]:
        pr = branch["pr"]["url"] or "no-pr"
        print(
            f"{branch['name']}\t{branch['status']}\tahead={branch['ahead']}\tbehind={branch['behind']}\t"
            f"age={branch['age_days']}d\t{pr}"
        )
        for commit in branch["unmerged_commits"]:
            print(f"  {commit['sha'][:12]} {commit['subject']}")
        if branch["blocking_reason"]:
            print(f"  blocked: {branch['blocking_reason']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Report every branch and worktree relative to stable main")
    parser.add_argument("--repo", type=Path, default=ROOT)
    parser.add_argument("--base", default="main")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--github", action="store_true", help="query PR metadata with the authenticated gh CLI")
    parser.add_argument("--fail-on-stale", action="store_true")
    args = parser.parse_args()
    try:
        result = audit(args.repo, args.base, args.github)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=subprocess.sys.stderr)
        raise SystemExit(2) from error
    print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else "", end="" if args.json else "")
    if not args.json:
        print_human(result)
    elif result:
        print()
    raise SystemExit(3 if args.fail_on_stale and result["summary"]["stale"] else 0)


if __name__ == "__main__":
    main()
