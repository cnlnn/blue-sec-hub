#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from executor_adapter import (
    ExecutionRequest,
    create_task,
    get_adapter,
    load_executor_specs,
    load_task,
    request_from_task,
    save_task,
    task_root,
    transition_task,
)


def command_plan(args: argparse.Namespace) -> int:
    request = ExecutionRequest(
        engine=args.engine,
        target=args.target,
        scope=tuple(args.scope),
        source_root=str(args.source.resolve()) if args.source else None,
        credential_lease=args.credential_lease,
        mode=args.mode,
        max_seconds=args.max_seconds,
        max_turns=args.max_turns,
        max_cost_usd=args.max_cost_usd,
        allow_network=args.allow_network,
        instructions=tuple(args.instruction),
    )
    task = create_task(request)
    print(json.dumps(task, ensure_ascii=False, indent=2))
    return 0


def command_status(args: argparse.Namespace) -> int:
    print(json.dumps(load_task(args.task_id), ensure_ascii=False, indent=2))
    return 0


def finish_task(task_id: str, result: object) -> int:
    value = asdict(result)
    state = str(value["status"])
    task = load_task(task_id)
    task["result"] = value
    save_task(task)
    transition_task(
        task_id,
        state,
        "executor-finished",
        exit_code=value.get("exit_code"),
        artifact_hashes=[item.get("sha256") for item in value.get("artifacts", [])],
    )
    print(json.dumps(load_task(task_id), ensure_ascii=False, indent=2))
    return 0 if state in {"completed", "paused"} else 1


def command_run(args: argparse.Namespace) -> int:
    task = load_task(args.task_id)
    if not args.authorized:
        raise ValueError("execution requires --authorized after confirming the recorded scope")
    if task["state"] not in {"planned", "paused", "failed"}:
        raise ValueError(f"task cannot run from state: {task['state']}")
    request = request_from_task(task)
    if request.target.startswith(("http://", "https://")) and not request.allow_network:
        raise ValueError("task was not planned with --allow-network")
    adapter = get_adapter(request.engine)
    transition_task(args.task_id, "running", "executor-started", engine=request.engine)
    result = adapter.resume(task, task_root(args.task_id)) if args.resume else adapter.run(request, task_root(args.task_id))
    return finish_task(args.task_id, result)


def command_collect(args: argparse.Namespace) -> int:
    task = load_task(args.task_id)
    adapter = get_adapter(str(task["request"]["engine"]))
    result = adapter.collect(task, task_root(args.task_id))
    print(json.dumps(asdict(result), ensure_ascii=False, indent=2))
    return 0 if result.status == "completed" else 1


def command_cancel(args: argparse.Namespace) -> int:
    task = load_task(args.task_id)
    if task["state"] == "running":
        raise ValueError("running task cannot be cancelled out-of-process; interrupt its owning terminal first")
    if task["state"] in {"completed", "cancelled"}:
        raise ValueError(f"task cannot be cancelled from state: {task['state']}")
    transition_task(args.task_id, "cancelled", "executor-cancelled")
    print(json.dumps(load_task(args.task_id), ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Plan and control policy-bound security executors")
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("--engine", choices=tuple(load_executor_specs()), required=True)
    plan.add_argument("--target", required=True)
    plan.add_argument("--scope", action="append", required=True)
    plan.add_argument("--source", type=Path)
    plan.add_argument("--credential-lease")
    plan.add_argument("--mode", choices=("quick", "standard", "deep"), default="standard")
    plan.add_argument("--max-seconds", type=int, default=3600)
    plan.add_argument("--max-turns", type=int, default=30)
    plan.add_argument("--max-cost-usd", type=float, default=0.0)
    plan.add_argument("--allow-network", action="store_true")
    plan.add_argument("--instruction", action="append", default=[])
    plan.set_defaults(function=command_plan)
    status = commands.add_parser("status")
    status.add_argument("task_id")
    status.set_defaults(function=command_status)
    run = commands.add_parser("run")
    run.add_argument("task_id")
    run.add_argument("--authorized", action="store_true")
    run.set_defaults(function=command_run, resume=False)
    resume = commands.add_parser("resume")
    resume.add_argument("task_id")
    resume.add_argument("--authorized", action="store_true")
    resume.set_defaults(function=command_run, resume=True)
    collect = commands.add_parser("collect")
    collect.add_argument("task_id")
    collect.set_defaults(function=command_collect)
    cancel = commands.add_parser("cancel")
    cancel.add_argument("task_id")
    cancel.set_defaults(function=command_cancel)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        raise SystemExit(args.function(args))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()
