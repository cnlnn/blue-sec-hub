#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import platforms


ROOT = Path(__file__).resolve().parents[1]


def run_script(name: str, arguments: list[str]) -> int:
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / name), *arguments],
        cwd=ROOT,
        check=False,
    ).returncode


def command_install(args: argparse.Namespace) -> int:
    values = ["--platform", args.platform]
    if args.no_configure_mcp:
        values.append("--no-configure-mcp")
    if args.no_hooks:
        values.append("--no-hooks")
    if args.dry_run:
        values.append("--dry-run")
    return run_script("install.py", values)


def command_update(args: argparse.Namespace) -> int:
    values = []
    for enabled, flag in (
        (args.skip_feeds, "--skip-feeds"),
        (args.force_feeds, "--force-feeds"),
        (args.skip_code, "--skip-code"),
    ):
        if enabled:
            values.append(flag)
    return run_script("update.py", values)


def command_doctor(args: argparse.Namespace) -> int:
    values = ["--platform", args.platform]
    if args.json:
        values.append("--json")
    return run_script("doctor.py", values)


def command_uninstall(args: argparse.Namespace) -> int:
    values = ["--platform", args.platform, "--uninstall"]
    if args.no_configure_mcp:
        values.append("--no-configure-mcp")
    if args.no_hooks:
        values.append("--no-hooks")
    return run_script("install.py", values)


def command_pentest(args: argparse.Namespace) -> int:
    values = [
        "run",
        "--target",
        args.target,
        "--platform",
        args.platform,
        "--requests-per-second",
        str(args.requests_per_second),
    ]
    for flag, value in (
        ("--workspace", args.workspace),
        ("--source-root", args.source),
        ("--header-file", args.header_file),
        ("--credential-lease", args.auth),
        ("--storage-state", args.storage_state),
        ("--har", args.har),
    ):
        if value:
            values.extend((flag, str(value)))
    return run_script("agent.py", values)


def command_workspace(args: argparse.Namespace) -> int:
    return run_script("agent.py", [args.action, "--workspace", str(args.workspace)])


def command_report(args: argparse.Namespace) -> int:
    path = args.workspace.resolve() / "results.md"
    if not path.is_file():
        print(f"error: report does not exist: {path}", file=sys.stderr)
        return 1
    print(path.read_text(encoding="utf-8"))
    return 0


def command_assessment_learn(args: argparse.Namespace) -> int:
    values = ["distill", "--workspace", str(args.workspace)]
    if not args.auto_promote:
        values.append("--no-auto-promote")
    return run_script("assessment_learning.py", values)


def command_passthrough(args: argparse.Namespace) -> int:
    return run_script(args.script, args.arguments)


def add_platform(parser: argparse.ArgumentParser, default: str) -> None:
    parser.add_argument(
        "--platform",
        choices=("auto", "all", *platforms.platform_ids()),
        default=default,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blue-sec",
        description="Install, operate, learn, and recover Blue Sec Hub tasks",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    install_parser = commands.add_parser("install")
    add_platform(install_parser, "auto")
    install_parser.add_argument("--no-configure-mcp", action="store_true")
    install_parser.add_argument("--no-hooks", action="store_true")
    install_parser.add_argument("--dry-run", action="store_true")
    install_parser.set_defaults(function=command_install)

    update = commands.add_parser("update")
    update.add_argument("--skip-feeds", action="store_true")
    update.add_argument("--force-feeds", action="store_true")
    update.add_argument("--skip-code", action="store_true")
    update.set_defaults(function=command_update)

    doctor = commands.add_parser("doctor")
    add_platform(doctor, "auto")
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(function=command_doctor)

    uninstall = commands.add_parser("uninstall")
    add_platform(uninstall, "all")
    uninstall.add_argument("--no-configure-mcp", action="store_true")
    uninstall.add_argument("--no-hooks", action="store_true")
    uninstall.set_defaults(function=command_uninstall)

    pentest = commands.add_parser("pentest")
    pentest.add_argument("target")
    pentest.add_argument("--workspace", type=Path)
    pentest.add_argument("--source", type=Path)
    pentest.add_argument("--auth", type=Path)
    pentest.add_argument("--header-file", type=Path)
    pentest.add_argument("--storage-state", type=Path)
    pentest.add_argument("--har", type=Path)
    pentest.add_argument("--platform", choices=("generic", "mcp", *platforms.platform_ids()), default="generic")
    pentest.add_argument("--requests-per-second", type=float, default=2.0)
    pentest.set_defaults(function=command_pentest)

    for name in ("status", "resume"):
        item = commands.add_parser(name)
        item.add_argument("workspace", type=Path)
        item.set_defaults(function=command_workspace, action=name)

    report = commands.add_parser("report")
    report.add_argument("workspace", type=Path)
    report.set_defaults(function=command_report)

    assessment = commands.add_parser("assessment-learn")
    assessment.add_argument("workspace", type=Path)
    assessment.add_argument("--auto-promote", action=argparse.BooleanOptionalAction, default=True)
    assessment.set_defaults(function=command_assessment_learn)

    for name, script in (
        ("learn", "learning.py"),
        ("skill", "effective_skills.py"),
        ("context", "context_checkpoint.py"),
        ("branch-audit", "branch_audit.py"),
        ("exec", "executor_control.py"),
    ):
        item = commands.add_parser(name)
        item.add_argument("arguments", nargs=argparse.REMAINDER)
        item.set_defaults(function=command_passthrough, script=script)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    raise SystemExit(args.function(args))


if __name__ == "__main__":
    main()
