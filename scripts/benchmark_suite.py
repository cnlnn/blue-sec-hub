#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

try:
    from quality_gate import DEFAULT_POLICY, evaluate, load
except ModuleNotFoundError:
    from scripts.quality_gate import DEFAULT_POLICY, evaluate, load


REQUIRED_FIELDS = {
    "fixture",
    "agent",
    "platform",
    "run_id",
    "expected_finding_ids",
    "reported_finding_ids",
    "first_result_seconds",
    "total_seconds",
    "completed",
    "state_corruption_events",
}


def aggregate(
    policy: dict[str, Any],
    runs: list[dict[str, Any]],
    agent_contracts: list[str] | None = None,
) -> dict[str, Any]:
    for index, run in enumerate(runs):
        missing = REQUIRED_FIELDS - set(run)
        if missing:
            raise ValueError(f"run {index} is missing fields: {', '.join(sorted(missing))}")
    gates = policy["gates"]
    required_fixtures = set(policy["fixtures"])
    required_agents = set(gates["required_agents"])
    required_platforms = set(gates["required_platforms"])
    valid = [run for run in runs if run.get("completed")]
    combinations = Counter(
        (str(run["fixture"]), str(run["agent"]), str(run["platform"])) for run in valid
    )
    required_combinations = {
        (fixture, agent, platform)
        for fixture in required_fixtures
        for agent in required_agents
        for platform in required_platforms
    }
    consecutive = min((combinations.get(value, 0) for value in required_combinations), default=0)
    expected = {
        f"{run['fixture']}:{run['agent']}:{run['platform']}:{run['run_id']}:{finding}"
        for run in valid
        for finding in run["expected_finding_ids"]
    }
    reported = {
        f"{run['fixture']}:{run['agent']}:{run['platform']}:{run['run_id']}:{finding}"
        for run in valid
        for finding in run["reported_finding_ids"]
    }
    return {
        "schema_version": 1,
        "generated_by": "blue-sec-benchmark-suite",
        "expected_finding_ids": sorted(expected),
        "reported_finding_ids": sorted(reported),
        "first_result_seconds": max((float(run["first_result_seconds"]) for run in valid), default=float("inf")),
        "total_seconds": max((float(run["total_seconds"]) for run in valid), default=float("inf")),
        "consecutive_runs": consecutive,
        "successful_platforms": sorted({str(run["platform"]) for run in valid}),
        "successful_agents": sorted({str(run["agent"]) for run in valid}),
        "successful_agent_contracts": sorted(set(agent_contracts or [])),
        "fixtures": sorted({str(run["fixture"]) for run in valid}),
        "state_corruption_events": sum(int(run["state_corruption_events"]) for run in runs),
        "run_records": len(runs),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate reproducible security benchmark runs")
    parser.add_argument("--run", action="append", required=True, type=Path)
    parser.add_argument("--agent-contract", action="append", default=[])
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    policy = load(args.policy)
    runs = [load(path) for path in args.run]
    result = aggregate(policy, runs, args.agent_contract)
    outcome = evaluate(policy, result)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(outcome, ensure_ascii=False, indent=2))
    if not outcome["passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
