from __future__ import annotations

import unittest

from scripts import benchmark_suite, quality_gate


AGENTS = ["codex", "claude"]
CONTRACTS = [
    "codex", "claude", "gemini", "grok", "opencode", "openclaw", "hermes", "trae", "trae-cn"
]


class QualityGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = {
            "gates": {
                "minimum_recall": 0.8,
                "minimum_precision": 0.98,
                "maximum_first_result_seconds": 600,
                "maximum_total_seconds": 5400,
                "minimum_consecutive_runs": 3,
                "required_platforms": ["linux", "macos", "windows"],
                "required_agents": AGENTS,
                "required_agent_contracts": CONTRACTS,
            }
        }

    def result(self) -> dict:
        return {
            "expected_finding_ids": ["a", "b", "c", "d", "e"],
            "reported_finding_ids": ["a", "b", "c", "d"],
            "first_result_seconds": 500,
            "total_seconds": 5000,
            "consecutive_runs": 3,
            "successful_platforms": ["linux", "macos", "windows"],
            "successful_agents": list(AGENTS),
            "successful_agent_contracts": list(CONTRACTS),
            "state_corruption_events": 0,
        }

    def test_strict_release_result_passes(self) -> None:
        self.assertTrue(quality_gate.evaluate(self.policy, self.result())["passed"])

    def test_missing_platform_contract_blocks_release(self) -> None:
        value = self.result()
        value["successful_agent_contracts"].remove("gemini")
        self.assertFalse(quality_gate.evaluate(self.policy, value)["checks"]["agent_contracts"])

    def test_aggregate_requires_three_runs_for_every_combination(self) -> None:
        policy = {**self.policy, "fixtures": ["fixture-a"]}
        runs = []
        for agent in AGENTS:
            for platform in ("linux", "macos", "windows"):
                for number in range(3):
                    runs.append(
                        {
                            "fixture": "fixture-a",
                            "agent": agent,
                            "platform": platform,
                            "run_id": f"{agent}-{platform}-{number}",
                            "expected_finding_ids": ["a"],
                            "reported_finding_ids": ["a"],
                            "first_result_seconds": 100,
                            "total_seconds": 1000,
                            "completed": True,
                            "state_corruption_events": 0,
                        }
                    )
        result = benchmark_suite.aggregate(policy, runs, CONTRACTS)
        self.assertEqual(3, result["consecutive_runs"])
        self.assertTrue(quality_gate.evaluate(policy, result)["passed"])


if __name__ == "__main__":
    unittest.main()
