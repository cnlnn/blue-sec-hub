#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from learning_policy import validate_policy
from privacy_scan import scan_repository
from skill_validation import validate_skill
from skill_eval import load_cases, validate_cases


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    failures = validate_policy()
    failures.extend(scan_repository(ROOT))
    for skill in sorted(path for path in (ROOT / "skills").iterdir() if path.is_dir()):
        failures.extend(f"{skill.name}: {item}" for item in validate_skill(skill))
    failures.extend(validate_cases(load_cases()))
    archive = ROOT / "knowledge-packs" / "approved.jsonl"
    if archive.exists():
        seen = set()
        for number, line in enumerate(archive.read_text(encoding="utf-8").splitlines(), start=1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                failures.append(f"{archive}:{number}: {error}")
                continue
            sha256 = str(value.get("object_sha256") or "")
            if len(sha256) != 64 or sha256 in seen:
                failures.append(f"{archive}:{number}: invalid or duplicate object_sha256")
            seen.add(sha256)
    if failures:
        raise SystemExit("\n".join(failures))
    print("[ok] content, privacy, and Skill contracts")


if __name__ == "__main__":
    main()
