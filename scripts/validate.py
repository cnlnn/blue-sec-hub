#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from privacy_scan import scan_repository
from security_terms import validate_glossary
from skill_validation import validate_skill


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
SOURCE_CONFIG = ROOT / "sources.json"
CACHE_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_CACHE",
        Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
        / "blue-sec-hub",
    )
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate Blue Sec Hub")
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip checks that require synchronized upstream caches",
    )
    args = parser.parse_args()
    failures: list[str] = []
    for skill in sorted(path for path in SKILLS.iterdir() if path.is_dir()):
        problems = validate_skill(skill)
        if problems:
            failures.extend(f"{skill.name}: {problem}" for problem in problems)
        else:
            print(f"[skill] {skill.name}")

    nested_entries = [
        path
        for path in SKILLS.rglob("SKILL.md")
        if path.parent.parent != SKILLS
    ]
    if nested_entries:
        failures.append(
            "local skills expose nested skill entries: "
            + ", ".join(str(path.relative_to(ROOT)) for path in nested_entries[:5])
        )
    legacy_references = SKILLS / "blue-security-knowledge" / "references"
    if legacy_references.exists():
        failures.append(
            "upstream knowledge must not be stored inside the active skill tree"
        )
    conclusion_policy = ROOT / "policies" / "security-conclusion.md"
    conclusion_schema = ROOT / "contracts" / "security-conclusion.schema.json"
    if not conclusion_policy.is_file() or "blue-sec-global-security-conclusion-policy" not in conclusion_policy.read_text(encoding="utf-8"):
        failures.append("global security conclusion policy is missing or invalid")
    if not conclusion_schema.is_file():
        failures.append("security conclusion schema is missing")

    if args.offline:
        print("[skip] synchronized upstream cache checks")
    else:
        references = CACHE_ROOT / "upstreams"
        source_names = json.loads(SOURCE_CONFIG.read_text(encoding="utf-8"))
        for name, source in source_names.items():
            if source.get("kind") == "payload-corpus":
                summary_path = references / name / "summary.json"
                try:
                    summary = json.loads(summary_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    failures.append(f"knowledge source {name}: payload catalog missing")
                    continue
                if not summary.get("payloads") or not summary.get("files"):
                    failures.append(f"knowledge source {name}: payload catalog empty")
                else:
                    print(
                        f"[knowledge] {name}: {summary['payloads']} payloads "
                        f"from {summary['files']} files"
                    )
                continue
            count = sum(
                1
                for path in (references / name).rglob("*")
                if path.is_file() and path.suffix.casefold() in {".md", ".markdown"}
            )
            if count == 0:
                failures.append(f"knowledge source {name}: no Markdown files")
            else:
                print(f"[knowledge] {name}: {count} Markdown files")

    for name in (
        "update.py",
        "blue_sec.py",
        "update_feeds.py",
        "search_knowledge.py",
        "security_terms.py",
        "term_learning.py",
        "ingest_internal.py",
        "report_ingestion.py",
        "executor_status.py",
        "executor_adapter.py",
        "executor_control.py",
        "executor_shannon.py",
        "executor_cai.py",
        "executor_strix.py",
        "executor_native.py",
        "learning.py",
        "effective_skills.py",
        "assessment_learning.py",
        "benchmark_suite.py",
        "quality_gate.py",
        "change_impact.py",
        "validate_content.py",
        "doctor.py",
        "report_intelligence.py",
        "hub_config.py",
        "bootstrap.py",
        "spa_graph.py",
        "web_assessment.py",
        "web_runner.py",
        "knowledge_session.py",
        "knowledge_distill.py",
        "session_distill.py",
        "payload_catalog.py",
        "agent.py",
        "context_checkpoint.py",
        "context_hook.py",
        "platform_observations.py",
        "platforms.py",
        "privacy_scan.py",
        "knowledge_runtime.py",
        "source_mapper.py",
        "security_conclusion.py",
    ):
        script = ROOT / "scripts" / name
        if not script.exists() or (
            os.name != "nt" and not os.access(script, os.X_OK)
        ):
            failures.append(f"script is missing or not executable: {script}")

    failures.extend(validate_glossary())
    privacy_findings = scan_repository(ROOT)
    if privacy_findings:
        failures.extend(privacy_findings)
    else:
        print("[ok] repository privacy scan")

    learning = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "learning.py"), "audit"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if learning.returncode:
        failures.append(learning.stderr.strip() or learning.stdout.strip())
    else:
        print(learning.stdout.strip())

    learning_policy = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "learning_policy.py")],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if learning_policy.returncode:
        failures.append(
            learning_policy.stderr.strip() or learning_policy.stdout.strip()
        )
    else:
        print("[ok] hub-wide learning policy")

    reports = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "report_intelligence.py"), "audit"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if reports.returncode:
        failures.append(reports.stderr.strip() or reports.stdout.strip())
    else:
        print(reports.stdout.strip())

    report_ingestion = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "report_ingestion.py"), "audit"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if report_ingestion.returncode:
        failures.append(
            report_ingestion.stderr.strip() or report_ingestion.stdout.strip()
        )
    else:
        print(report_ingestion.stdout.strip())

    terms = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "term_learning.py"), "audit"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if terms.returncode:
        failures.append(terms.stderr.strip() or terms.stdout.strip())
    else:
        print(terms.stdout.strip())

    spa_lexicon = subprocess.run(
        [
            sys.executable,
            str(
                ROOT
                / "skills"
                / "spa-security-object-graph"
                / "scripts"
                / "semantic_lexicon.py"
            ),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if spa_lexicon.returncode:
        failures.append(spa_lexicon.stderr.strip() or spa_lexicon.stdout.strip())
    else:
        print("[ok] SPA semantic lexicon")

    if not (ROOT / "ownership.json").exists():
        failures.append("ownership.json is missing")
    if not (ROOT / "learning_policy.json").exists():
        failures.append("learning_policy.json is missing")
    if not (ROOT / "report_profiles.json").exists():
        failures.append("report_profiles.json is missing")

    with tempfile.TemporaryDirectory(prefix="blue-sec-tests-") as temporary:
        test_environment = os.environ.copy()
        test_root = Path(temporary)
        test_environment.update(
            {
                "BLUE_SEC_DATA": str(test_root / "data"),
                "BLUE_SEC_CACHE": str(test_root / "cache"),
                "BLUE_SEC_CONFIG": str(test_root / "config"),
            }
        )
        tests = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", str(ROOT / "tests")],
            cwd=ROOT,
            env=test_environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    if tests.returncode:
        failures.append(tests.stderr.strip() or tests.stdout.strip())
    else:
        print("[ok] unit tests")

    if failures:
        raise SystemExit("\n".join(failures))
    print(f"[ok] validated {sum(1 for p in SKILLS.iterdir() if p.is_dir())} skills")


if __name__ == "__main__":
    main()
