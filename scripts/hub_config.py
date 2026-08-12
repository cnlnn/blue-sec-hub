#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any


CONFIG_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_CONFIG",
        Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        / "blue-sec-hub",
    )
)
CONFIG_PATH = CONFIG_ROOT / "config.json"
SCHEMA_VERSION = 2
REPORT_ROOT_MODES = {"all", "documents", "security-reports"}


def default_config() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "report_roots": [],
        "report_root_modes": {},
    }


def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        return default_config()
    try:
        value = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise SystemExit(f"invalid config {CONFIG_PATH}: {error}") from error
    if not isinstance(value, dict):
        raise SystemExit(f"invalid config object: {CONFIG_PATH}")
    value.setdefault("schema_version", SCHEMA_VERSION)
    value.setdefault("report_roots", [])
    value.setdefault("report_root_modes", {})
    if not isinstance(value["report_roots"], list) or not all(
        isinstance(item, str) for item in value["report_roots"]
    ):
        raise SystemExit("report_roots must be a list of paths")
    if not isinstance(value["report_root_modes"], dict) or not all(
        isinstance(path, str)
        and isinstance(mode, str)
        and mode in REPORT_ROOT_MODES
        for path, mode in value["report_root_modes"].items()
    ):
        raise SystemExit(
            "report_root_modes must map paths to all or documents"
        )
    return value


def save_config(value: dict[str, Any]) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = CONFIG_PATH.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(CONFIG_PATH)


def configured_report_roots(existing_only: bool = False) -> list[Path]:
    roots = [Path(item).expanduser() for item in load_config()["report_roots"]]
    if existing_only:
        roots = [path for path in roots if path.exists()]
    return roots


def configured_report_sources(
    existing_only: bool = False,
) -> list[tuple[Path, str]]:
    value = load_config()
    modes = value["report_root_modes"]
    sources = [
        (Path(item).expanduser(), modes.get(item, "all"))
        for item in value["report_roots"]
    ]
    if existing_only:
        sources = [(path, mode) for path, mode in sources if path.exists()]
    return sources


def command_add(args: argparse.Namespace) -> None:
    path = args.path.expanduser().resolve()
    if not path.exists():
        raise SystemExit(f"report root does not exist: {path}")
    value = load_config()
    roots = list(value["report_roots"])
    modes = dict(value["report_root_modes"])
    mode = args.mode or modes.get(str(path), "all")
    if str(path) not in roots:
        roots.append(str(path))
        value["report_roots"] = sorted(roots)
        print(f"[added] {path}")
    else:
        print(f"[current] {path}")
    modes[str(path)] = mode
    value["report_root_modes"] = modes
    value["schema_version"] = SCHEMA_VERSION
    save_config(value)
    print(f"[mode] {mode}")
    print(f"[config] {CONFIG_PATH}")


def command_remove(args: argparse.Namespace) -> None:
    path = str(args.path.expanduser().resolve())
    value = load_config()
    roots = list(value["report_roots"])
    modes = dict(value["report_root_modes"])
    if path in roots:
        roots.remove(path)
        value["report_roots"] = roots
        modes.pop(path, None)
        value["report_root_modes"] = modes
        save_config(value)
        print(f"[removed] {path}")
    else:
        print(f"[absent] {path}")


def command_list(_: argparse.Namespace) -> None:
    sources = configured_report_sources()
    for path, mode in sources:
        state = "available" if path.exists() else "missing"
        print(f"{state}\t{mode}\t{path}")
    print(f"[total] {len(sources)}")
    print(f"[config] {CONFIG_PATH}")


def command_audit(args: argparse.Namespace) -> None:
    roots = configured_report_roots()
    missing = [path for path in roots if not path.exists()]
    if missing:
        message = "configured report roots are missing:\n" + "\n".join(
            str(path) for path in missing
        )
        if args.strict:
            raise SystemExit(message)
        print(f"[warning] {message}")
    print(f"[ok] configured report roots={len(roots)}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Configure Blue Sec Hub")
    commands = parser.add_subparsers(dest="command", required=True)

    add = commands.add_parser("add-report-root")
    add.add_argument("path", type=Path)
    add.add_argument(
        "--mode",
        choices=sorted(REPORT_ROOT_MODES),
        default=None,
        help=(
            "all supported evidence files, only modern office/PDF documents, "
            "or security-report candidates including legacy documents and archives"
        ),
    )
    add.set_defaults(function=command_add)

    remove = commands.add_parser("remove-report-root")
    remove.add_argument("path", type=Path)
    remove.set_defaults(function=command_remove)

    listing = commands.add_parser("list")
    listing.set_defaults(function=command_list)

    audit = commands.add_parser("audit")
    audit.add_argument("--strict", action="store_true")
    audit.set_defaults(function=command_audit)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
