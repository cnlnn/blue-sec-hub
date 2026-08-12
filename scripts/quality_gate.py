#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "benchmarks" / "quality-gates.json"


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate(policy: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    gates = policy["gates"]
    required_fixtures = set(policy.get("fixtures", []))
    required_run_records = (
        len(required_fixtures)
        * len(gates["required_agents"])
        * len(gates["required_platforms"])
        * int(gates["minimum_consecutive_runs"])
    )
    expected = set(result.get("expected_finding_ids", []))
    reported = set(result.get("reported_finding_ids", []))
    true_positive = len(expected & reported)
    recall = true_positive / len(expected) if expected else 1.0
    precision = true_positive / len(reported) if reported else (1.0 if not expected else 0.0)
    checks = {
        "recall": recall >= float(gates["minimum_recall"]),
        "precision": precision >= float(gates["minimum_precision"]),
        "first_result_seconds": float(result.get("first_result_seconds", float("inf")))
        <= float(gates["maximum_first_result_seconds"]),
        "total_seconds": float(result.get("total_seconds", float("inf")))
        <= float(gates["maximum_total_seconds"]),
        "consecutive_runs": int(result.get("consecutive_runs", 0))
        >= int(gates["minimum_consecutive_runs"]),
        "platforms": set(gates["required_platforms"]) <= set(result.get("successful_platforms", [])),
        "agents": set(gates["required_agents"]) <= set(result.get("successful_agents", [])),
        "agent_contracts": set(gates.get("required_agent_contracts", []))
        <= set(result.get("successful_agent_contracts", [])),
        "fixtures": required_fixtures <= set(result.get("fixtures", [])),
        "run_records": int(result.get("run_records", 0)) >= required_run_records,
        "trusted_aggregator": not required_fixtures or result.get("generated_by") == "blue-sec-benchmark-suite",
        "state_corruption": int(result.get("state_corruption_events", 0)) == 0,
    }
    return {
        "schema_version": 1,
        "passed": all(checks.values()),
        "metrics": {
            "recall": round(recall, 4),
            "precision": round(precision, 4),
            "first_result_seconds": result.get("first_result_seconds"),
            "total_seconds": result.get("total_seconds"),
        },
        "checks": checks,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Blue Sec Hub release quality gates")
    parser.add_argument("result", type=Path)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    args = parser.parse_args()
    outcome = evaluate(load(args.policy), load(args.result))
    print(json.dumps(outcome, ensure_ascii=False, indent=2))
    if not outcome["passed"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
