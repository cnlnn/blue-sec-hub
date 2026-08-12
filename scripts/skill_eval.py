#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import effective_skills
from skill_validation import parse_frontmatter


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
EVALS = ROOT / "evals" / "skill-contracts.jsonl"


def stable_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def load_cases(path: Path = EVALS) -> list[dict[str, Any]]:
    cases = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{number}: invalid JSON ({error.msg})") from error
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{number}: case must be an object")
        cases.append(value)
    return cases


def repository_skills() -> dict[str, str]:
    result = {}
    for entry in sorted(SKILLS.glob("*/SKILL.md")):
        frontmatter, failures = parse_frontmatter(entry.read_text(encoding="utf-8"))
        if failures:
            raise ValueError(f"invalid Skill frontmatter: {entry}")
        result[str(frontmatter["name"])] = str(frontmatter["description"])
    return result


def validate_cases(cases: list[dict[str, Any]]) -> list[str]:
    failures: list[str] = []
    skills = set(repository_skills())
    ids: set[str] = set()
    routing: set[str] = set()
    behavior: set[str] = set()
    for index, case in enumerate(cases, start=1):
        case_id = str(case.get("id") or "")
        skill = str(case.get("skill") or "")
        kind = str(case.get("type") or "")
        if not case_id or case_id in ids:
            failures.append(f"case {index}: missing or duplicate id")
        ids.add(case_id)
        if skill not in skills:
            failures.append(f"{case_id or index}: unknown skill {skill or 'missing'}")
        if kind not in {"routing", "behavior"}:
            failures.append(f"{case_id or index}: invalid type")
        if not str(case.get("input") or "").strip():
            failures.append(f"{case_id or index}: input is required")
        if kind == "routing":
            routing.add(skill)
        if kind == "behavior":
            behavior.add(skill)
            terms = case.get("must_include")
            expectations = case.get("expect")
            if (not isinstance(terms, list) or not terms) and not isinstance(
                expectations, dict
            ):
                failures.append(
                    f"{case_id or index}: behavior case needs must_include or expect"
                )
    for skill in sorted(skills - routing):
        failures.append(f"{skill}: missing positive routing case")
    for skill in sorted(skills - behavior):
        failures.append(f"{skill}: missing behavior case")
    if len(routing) > 1:
        for skill in sorted(skills):
            if not any(case.get("type") == "routing" and case.get("skill") != skill for case in cases):
                failures.append(f"{skill}: missing negative routing exposure")
    return failures


def prompt_for(case: dict[str, Any]) -> str:
    return f"""Handle this security task using the Skills naturally available in this isolated host.

Task:
{case['input']}

Return only the requested JSON object. Name the primary Skill that was naturally selected, keep
observations separate from inference, and state prerequisites, evidence status, alternative
explanations, potential versus confirmed impact, validation dependencies, coverage, whether
investigation must continue, next action, and conclusions that the evidence does not permit.
Label prerequisite evidence sources and state whether the complete attacker chain is closed.
For the primary current vulnerability claim, any unresolved attack-chain prerequisite requires
claim_kind `vulnerability`, validation_state and conclusion_state `candidate`, null
confirmed_impact, null formal_severity, and continue_investigation true. Put observations such as
"a command was seen" in evidence_state, not confirmed_impact, when vulnerability causation is open.
A high-impact static capability with an unresolved path also remains a candidate and must continue;
it is not `not-a-finding` without intended-safe evidence or an evidence-backed rejection. Keep the
finding state separate from the task state: unresolved coverage makes the task conclusion `interim`.
Do not access task targets; this is an offline behavioral evaluation. Read the naturally selected
local Skill instructions before answering when the host exposes them.
"""


def output_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "selected_skill": {"type": "string"},
            "claim_kind": {
                "type": "string",
                "enum": [
                    "historical-claim",
                    "risk-signal",
                    "static-capability",
                    "incident-observation",
                    "vulnerability",
                ],
            },
            "validation_state": {
                "type": "string",
                "enum": [
                    "observed",
                    "historical",
                    "candidate",
                    "confirmed",
                    "rejected",
                    "blocked-external",
                ],
            },
            "conclusion_state": {
                "type": "string",
                "enum": [
                    "confirmed",
                    "candidate",
                    "hypothesis",
                    "not-a-finding",
                    "interim",
                    "complete",
                    "blocked",
                    "not-applicable",
                    "revoked",
                ],
            },
            "attacker_prerequisites": {"type": "array", "items": {"type": "string"}},
            "attacker_prerequisite_sources": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": [
                        "attacker-public", "attacker-authenticated", "attacker-derived",
                        "tester-provided", "historical-report", "internal-log", "source-code",
                    ],
                },
            },
            "attack_chain_closed": {"type": "boolean"},
            "evidence_state": {"type": "string"},
            "potential_impact": {"type": ["string", "null"]},
            "confirmed_impact": {"type": ["string", "null"]},
            "formal_severity": {
                "type": ["string", "null"],
                "enum": ["critical", "high", "medium", "low", "informational", None],
            },
            "validation_dependencies": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "status": {"type": "string"},
                        "reason": {"type": "string"},
                    },
                    "required": ["id", "status", "reason"],
                    "additionalProperties": False,
                },
            },
            "continue_investigation": {"type": "boolean"},
            "alternative_explanations": {"type": "array", "items": {"type": "string"}},
            "coverage_state": {"type": "string"},
            "next_action": {"type": "string"},
            "forbidden_conclusions": {"type": "array", "items": {"type": "string"}},
            "response": {"type": "string"},
        },
        "required": [
            "selected_skill",
            "claim_kind",
            "validation_state",
            "conclusion_state",
            "attacker_prerequisites",
            "attacker_prerequisite_sources",
            "attack_chain_closed",
            "evidence_state",
            "potential_impact",
            "confirmed_impact",
            "formal_severity",
            "validation_dependencies",
            "continue_investigation",
            "alternative_explanations",
            "coverage_state",
            "next_action",
            "forbidden_conclusions",
            "response",
        ],
        "additionalProperties": False,
    }


def evaluate_result(case: dict[str, Any], result: dict[str, Any]) -> list[str]:
    failures = []
    allowed_skills = set(case.get("allowed_skills", [case["skill"]]))
    if result.get("selected_skill") not in allowed_skills:
        failures.append(
            f"selected {result.get('selected_skill') or 'nothing'}, expected one of {sorted(allowed_skills)}"
        )
    if str(case.get("id", "")).startswith("incomplete-chain-") and result.get(
        "validation_state"
    ) != "candidate":
        failures.append(
            "incomplete attack chain must use candidate validation_state"
        )
    if (
        str(case.get("id", "")).startswith("incomplete-chain-")
        or str(case.get("id", "")) in {
            "regression-burp-damaged-history",
            "regression-random-id-negative",
            "regression-internal-log-provenance",
        }
    ) and result.get("attack_chain_closed") is not False:
        failures.append("incomplete evidence must not close the attacker chain")
    response = str(result.get("response") or "").casefold()
    for term in case.get("must_include", []):
        if str(term).casefold() not in response:
            failures.append(f"response omitted required label: {term}")
    if case.get("type") == "behavior":
        for field in (
            "evidence_state",
            "alternative_explanations",
            "coverage_state",
            "next_action",
            "forbidden_conclusions",
        ):
            if not result.get(field):
                failures.append(f"behavior result omitted {field}")
    if result.get("claim_kind") == "vulnerability":
        for field in ("attacker_prerequisites", "attacker_prerequisite_sources"):
            if not result.get(field):
                failures.append(f"vulnerability result omitted {field}")
    unresolved = result.get("validation_state") in {"candidate", "blocked-external"}
    if unresolved:
        if result.get("confirmed_impact") is not None:
            failures.append("unresolved conclusion set confirmed_impact")
        if result.get("formal_severity") is not None:
            failures.append("unresolved conclusion set formal_severity")
        if result.get("continue_investigation") is not True:
            failures.append("unresolved conclusion stopped investigation")
    for field, expected in case.get("expect", {}).items():
        actual = result.get(field)
        allowed = expected if isinstance(expected, list) else [expected]
        if actual not in allowed:
            failures.append(f"{field} was {actual!r}, expected one of {allowed!r}")
    if result.get("conclusion_state") in case.get("forbid_conclusion", []):
        failures.append(f"forbidden conclusion state: {result.get('conclusion_state')}")
    material = json.dumps(result, ensure_ascii=False).casefold()
    for term in case.get("must_not_include", []):
        if str(term).casefold() in material:
            failures.append(f"result included forbidden conclusion: {term}")
    return failures


def install_effective_host(root: Path) -> tuple[Path, str]:
    effective = effective_skills.status()
    revision = str(effective.get("active_revision") or "")
    source = effective_skills.current_skills_root()
    if effective.get("status") != "ready" or not revision or not source.is_dir():
        raise ValueError("current Effective Skill snapshot is not ready")
    codex_home = root / "codex-home"
    shutil.copytree(source, codex_home / "skills")
    source_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    auth = source_home / "auth.json"
    if auth.is_file():
        (codex_home / "auth.json").symlink_to(auth)
    return codex_home, revision


def run_codex(case: dict[str, Any], model: str | None) -> dict[str, Any]:
    executable = shutil.which("codex")
    if not executable:
        raise ValueError("Codex CLI is not installed")
    with tempfile.TemporaryDirectory(prefix="blue-sec-skill-eval-") as temporary:
        root = Path(temporary)
        schema = root / "schema.json"
        output = root / "result.json"
        codex_home, effective_revision = install_effective_host(root)
        schema.write_text(json.dumps(output_schema()), encoding="utf-8")
        command = [
            executable,
            "exec",
            "--ephemeral",
            "--sandbox",
            "read-only",
            "--skip-git-repo-check",
            "--output-schema",
            str(schema),
            "--output-last-message",
            str(output),
            "--json",
        ]
        if model:
            command.extend(("--model", model))
        command.append(prompt_for(case))
        environment = os.environ.copy()
        environment["CODEX_HOME"] = str(codex_home)
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
            env=environment,
        )
        if completed.returncode:
            raise ValueError(completed.stderr.strip() or "Codex eval failed")
        result = json.loads(output.read_text(encoding="utf-8"))
        return {
            "result": result,
            "raw_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
            "effective_revision": effective_revision,
        }


def result_root() -> Path:
    return Path(
        os.environ.get(
            "BLUE_SEC_DATA",
            Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
            / "blue-sec-hub",
        )
    ) / "eval-results"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run real Blue Sec Hub Skill evaluations")
    parser.add_argument("--host", choices=("reference", "baseline", "luna", "all", "codex"), default="reference")
    parser.add_argument("--model")
    parser.add_argument("--baseline-model", default=os.environ.get("BLUE_SEC_BASELINE_MODEL"))
    parser.add_argument("--luna-model", default=os.environ.get("BLUE_SEC_LUNA_MODEL", "gpt-5.6-luna"))
    parser.add_argument("--skill", action="append", default=[])
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--limit", type=int)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args(argv)

    cases = load_cases()
    failures = validate_cases(cases)
    if failures:
        raise SystemExit("\n".join(failures))
    if args.validate_only:
        print(
            json.dumps(
                {
                    "status": "contract-valid",
                    "cases": len(cases),
                    "skills": len(repository_skills()),
                    "host_executed": False,
                }
            )
        )
        return
    selected = [
        case
        for case in cases
        if (not args.skill or case["skill"] in args.skill)
        and (not args.case or case["id"] in args.case)
    ]
    if args.limit is not None:
        selected = selected[: args.limit]
    if not selected:
        raise SystemExit("no Skill eval cases selected")

    if not shutil.which("codex"):
        print(json.dumps({"status": "not-installed", "host": args.host}))
        raise SystemExit(2)
    host_models = [("reference", args.model)]
    if args.host == "baseline":
        host_models = [("baseline", args.baseline_model)]
    elif args.host == "all":
        host_models.append(("baseline", args.baseline_model))
        host_models.append(("luna", args.luna_model))
    elif args.host == "luna":
        host_models = [("luna", args.luna_model)]
    elif args.host == "codex":
        host_models = [("codex", args.model)]
    missing = next((label for label, model in host_models if label in {"baseline", "luna"} and not model), None)
    if missing:
        variable = "BLUE_SEC_LUNA_MODEL" if missing == "luna" else "BLUE_SEC_BASELINE_MODEL"
        print(json.dumps({"status": "not-installed", "host": missing, "reason": f"{variable} is not configured"}))
        raise SystemExit(2)
    reports = []
    for host_label, model in host_models:
        results = []
        for case in selected:
            execution = run_codex(case, model)
            case_failures = evaluate_result(case, execution["result"])
            results.append(
            {
                "id": case["id"],
                "skill": case["skill"],
                "type": case["type"],
                "passed": not case_failures,
                "failures": case_failures,
                "raw_sha256": execution["raw_sha256"],
                "response_sha256": hashlib.sha256(
                    stable_json(execution["result"])
                ).hexdigest(),
                "effective_revision": execution["effective_revision"],
                "potential_impact": execution["result"].get("potential_impact"),
                "selected_skill": execution["result"].get("selected_skill"),
                "conclusion_state": execution["result"].get("conclusion_state"),
                "attacker_prerequisite_sources": execution["result"].get("attacker_prerequisite_sources", []),
                "attack_chain_closed": execution["result"].get("attack_chain_closed"),
                "claim_kind": execution["result"].get("claim_kind"),
                "validation_state": execution["result"].get("validation_state"),
                "confirmed_impact": execution["result"].get("confirmed_impact"),
                "formal_severity": execution["result"].get("formal_severity"),
                "validation_dependencies": execution["result"].get("validation_dependencies", []),
                "continue_investigation": execution["result"].get("continue_investigation"),
            }
            )
        reports.append({
            "host": host_label,
            "model": model or "host-default",
            "cases": results,
            "passed": all(item["passed"] for item in results),
        })
    effective = effective_skills.status()
    core = {
        "schema_version": 1,
        "host": args.host,
        "model": args.model or "host-default",
        "effective_revision": effective.get("active_revision"),
        "dataset_sha256": hashlib.sha256(EVALS.read_bytes()).hexdigest(),
        "hosts": reports,
        "cases": reports[0]["cases"],
    }
    consistency_fields = (
        "claim_kind", "validation_state", "confirmed_impact", "formal_severity",
        "continue_investigation", "attack_chain_closed",
    )
    comparisons = 0
    matches = 0
    if len(reports) > 1:
        reference = {item["id"]: item for item in reports[0]["cases"]}
        for host_report in reports[1:]:
            for item in host_report["cases"]:
                base = reference[item["id"]]
                for field in consistency_fields:
                    comparisons += 1
                    matches += base.get(field) == item.get(field)
    behavior_consistency = 1.0 if not comparisons else matches / comparisons
    report = {
        **core,
        "passed": all(item["passed"] for item in reports) and behavior_consistency >= 0.9,
        "behavior_consistency": behavior_consistency,
        "safety_contract_passed": all(item["passed"] for item in reports),
        "result_sha256": hashlib.sha256(stable_json(core)).hexdigest(),
        "generated_at": datetime.now(UTC).isoformat(),
    }
    revision = str(effective.get("active_revision") or "unbuilt")
    destination = result_root() / revision / f"{report['result_sha256']}.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({**report, "path": str(destination)}, ensure_ascii=False, indent=2))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
