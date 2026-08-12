#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path


ALLOWED_FRONTMATTER = {
    "name",
    "description",
    "license",
    "allowed-tools",
    "compatibility",
    "metadata",
}
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
FRONTMATTER_RE = re.compile(r"^---\r?\n(.*?)\r?\n---(?:\r?\n|$)", re.DOTALL)
TOP_LEVEL_RE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):(?:[ \t]*(.*))?$")
QUOTED_VALUE_RE = re.compile(r"^(['\"])(.*)\1$")


def scalar(value: str) -> str:
    value = value.strip()
    if match := QUOTED_VALUE_RE.fullmatch(value):
        return match.group(2)
    return value


def parse_frontmatter(content: str) -> tuple[dict[str, str], list[str]]:
    match = FRONTMATTER_RE.match(content)
    if not match:
        return {}, ["missing or invalid YAML frontmatter"]
    values: dict[str, str] = {}
    failures: list[str] = []
    for number, line in enumerate(match.group(1).splitlines(), start=2):
        if not line.strip() or line.startswith((" ", "\t")):
            continue
        parsed = TOP_LEVEL_RE.fullmatch(line)
        if not parsed:
            failures.append(f"frontmatter line {number} is not a key/value")
            continue
        key, value = parsed.group(1), parsed.group(2) or ""
        if key in values:
            failures.append(f"duplicate frontmatter key: {key}")
        values[key] = scalar(value)
    return values, failures


def openai_interface_failures(skill: Path, skill_name: str) -> list[str]:
    path = skill / "agents" / "openai.yaml"
    if not path.exists():
        return []
    content = path.read_text(encoding="utf-8")
    failures = []
    for key in ("display_name", "short_description", "default_prompt"):
        match = re.search(
            rf"^[ \t]+{re.escape(key)}:[ \t]*(['\"])(.*?)\1[ \t]*$",
            content,
            re.MULTILINE,
        )
        if not match or not match.group(2).strip():
            failures.append(f"agents/openai.yaml needs quoted interface.{key}")
    prompt = re.search(
        r"^[ \t]+default_prompt:[ \t]*(['\"])(.*?)\1[ \t]*$",
        content,
        re.MULTILINE,
    )
    if prompt and f"${skill_name}" not in prompt.group(2):
        failures.append(
            f"agents/openai.yaml default_prompt must mention ${skill_name}"
        )
    return failures


def validate_skill(skill: Path) -> list[str]:
    entry = skill / "SKILL.md"
    if not entry.exists():
        return ["missing SKILL.md"]
    content = entry.read_text(encoding="utf-8")
    frontmatter, failures = parse_frontmatter(content)
    unexpected = set(frontmatter) - ALLOWED_FRONTMATTER
    if unexpected:
        failures.append(f"unexpected frontmatter keys: {sorted(unexpected)}")
    name = frontmatter.get("name", "").strip()
    description = frontmatter.get("description", "").strip()
    if not name:
        failures.append("missing frontmatter name")
    elif not NAME_RE.fullmatch(name) or len(name) > 64:
        failures.append("name must be hyphen-case and at most 64 characters")
    elif name != skill.name:
        failures.append(f"frontmatter name {name!r} does not match directory")
    if not description:
        failures.append("missing frontmatter description")
    elif len(description) > 1024 or "<" in description or ">" in description:
        failures.append(
            "description must be at most 1024 characters without angle brackets"
        )
    if "TODO" in content:
        failures.append("contains TODO")
    failures.extend(openai_interface_failures(skill, name))
    return failures


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Validate one local Skill")
    parser.add_argument("skill", type=Path)
    args = parser.parse_args()
    problems = validate_skill(args.skill)
    if problems:
        raise SystemExit("\n".join(problems))
    print(f"[ok] {args.skill.name}")
