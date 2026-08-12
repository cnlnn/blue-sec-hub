from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "session_distill.py"


def event(event_type: str, payload: dict) -> str:
    return json.dumps({"type": event_type, "payload": payload}, ensure_ascii=False)


def message(role: str, text: str) -> str:
    return event(
        "response_item",
        {
            "type": "message",
            "role": role,
            "content": [
                {
                    "type": "input_text" if role == "user" else "output_text",
                    "text": text,
                }
            ],
        },
    )


class SessionDistillationTest(unittest.TestCase):
    def environment(self, root: Path) -> dict[str, str]:
        value = os.environ.copy()
        value["BLUE_SEC_DATA"] = str(root / "data")
        value["BLUE_SEC_CONFIG"] = str(root / "config")
        return value

    def run_tool(self, root: Path, sessions: Path, run_id: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "run",
                "--sessions",
                str(sessions),
                "--run-id",
                run_id,
            ],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment(root),
        )

    def status(self, root: Path, run_id: str | None = None) -> dict:
        command = [sys.executable, str(SCRIPT), "status"]
        if run_id:
            command.append(run_id)
        result = subprocess.run(
            command,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment(root),
        )
        return json.loads(result.stdout)

    def test_status_selects_latest_completed_generated_at_and_reports_other_states(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runs = root / "data" / "session-distillation" / "runs"
            fixtures = {
                "z-older": ("2026-08-01T10:00:00+00:00", "complete"),
                "a-newer": ("2026-08-02T10:00:00+00:00", "complete"),
                "failed-last": ("2026-08-02T11:00:00+00:00", "failed"),
                "interrupted-last": ("2026-08-02T12:00:00+00:00", "interrupted"),
            }
            for run_id, (generated_at, state) in fixtures.items():
                path = runs / run_id
                path.mkdir(parents=True)
                (path / "summary.json").write_text(
                    json.dumps(
                        {
                            "schema_version": 2,
                            "distiller_version": "fixture",
                            "run_id": run_id,
                            "generated_at": generated_at,
                            "state": state,
                        }
                    ),
                    encoding="utf-8",
                )

            value = self.status(root)

            self.assertEqual("a-newer", value["run_id"])
            self.assertEqual("latest-complete-generated-at", value["selected_by"])
            self.assertEqual("failed-last", value["recent_runs"]["failed"]["run_id"])
            self.assertEqual(
                "interrupted-last",
                value["recent_runs"]["interrupted"]["run_id"],
            )

    def test_explicit_legacy_status_is_marked_unverifiable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run = root / "data" / "session-distillation" / "runs" / "legacy"
            run.mkdir(parents=True)
            (run / "summary.json").write_text(
                json.dumps({"schema_version": 1, "run_id": "legacy"}),
                encoding="utf-8",
            )

            value = self.status(root, "legacy")

            self.assertEqual("legacy-unverifiable", value["state"])
            self.assertIn("lacks generated_at", value["status_reason"])

    def test_accounts_for_sessions_and_excludes_hidden_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            security = sessions / "security.jsonl"
            lines = [
                event("session_meta", {"id": "session-security", "parent_thread_id": "parent"}),
                message("user", "这个渗透测试遗漏了很多接口和越权漏洞"),
                message("assistant", "已改为全路由采集并增加授权正负对照，回归测试通过。"),
                message("user", "现在可以了，" + "Cook" + "ie: TEST_COOKIE_VALUE"),
                event(
                    "response_item",
                    {
                        "type": "reasoning",
                        "encrypted_content": "hidden-secret-reasoning",
                    },
                ),
                event(
                    "response_item",
                    {
                        "type": "function_call",
                        "name": "exec_command",
                        "arguments": json.dumps(
                            {"cmd": "curl -H '" + "Author" + "ization: TEST_AUTH_VALUE' https://target.example"}
                        ),
                    },
                ),
                event(
                    "response_item",
                    {
                        "type": "function_call_output",
                        "output": json.dumps({"exit_code": 0, "output": "token=secret"}),
                    },
                ),
            ]
            security.write_text("\n".join(lines + [lines[0]]) + "\n", encoding="utf-8")
            (sessions / "ordinary.jsonl").write_text(
                "\n".join(
                    [
                        event("session_meta", {"id": "ordinary"}),
                        message("user", "帮我把这句话翻译成英文"),
                        message("assistant", "Here is the translation."),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (sessions / "security-copy.jsonl").write_text(
                security.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            (sessions / "broken.jsonl").write_text("not-json\n", encoding="utf-8")
            self.run_tool(root, sessions, "sd-fixture")
            run = root / "data" / "session-distillation" / "runs" / "sd-fixture"
            summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(4, summary["source_files"])
            self.assertEqual(2, summary["classifications"]["security"])
            self.assertEqual(1, summary["classifications"]["non-security"])
            self.assertEqual(1, summary["classifications"]["error"])
            self.assertEqual(1, summary["duplicate_session_sources"])
            self.assertEqual(1, summary["duplicate_content_sources"])
            self.assertGreater(summary["cross_file_duplicate_events"], 0)
            combined = "\n".join(
                path.read_text(encoding="utf-8") for path in run.iterdir() if path.is_file()
            )
            self.assertNotIn("TEST_COOKIE_VALUE", combined)
            self.assertNotIn("hidden-secret-reasoning", combined)
            self.assertNotIn("TEST_AUTH_VALUE", combined)
            self.assertNotIn("target.example", combined)
            candidates = [
                json.loads(line)
                for line in (run / "learning-candidates.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(1, len(candidates))
            self.assertEqual("validated", candidates[0]["validation_state"])
            self.assertEqual("coverage-gap", candidates[0]["candidate_type"])
            cards = [
                json.loads(line)
                for line in (run / "review-cards.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(1, len(cards))
            self.assertIn("遗漏了很多接口", cards[0]["user_correction"])
            self.assertIn("reconstruct the relevant scope", cards[0]["improved_method"])
            self.assertEqual("blocked", cards[0]["approval_state"])
            self.assertIn("already-covered-by-base", cards[0]["block_reasons"])
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(run.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(run.parent.parent.stat().st_mode), 0o700)
                self.assertTrue(
                    all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in run.iterdir())
                )

    def test_assistant_self_assertion_does_not_validate_learning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            (sessions / "self-asserted.jsonl").write_text(
                "\n".join(
                    [
                        event("session_meta", {"id": "self-asserted"}),
                        message("user", "这个渗透测试遗漏了接口，必须补齐路由覆盖"),
                        message("assistant", "已经修复并且回归测试通过。"),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            self.run_tool(root, sessions, "self-asserted")
            run = root / "data" / "session-distillation" / "runs" / "self-asserted"
            candidates = [
                json.loads(line)
                for line in (run / "learning-candidates.jsonl").read_text().splitlines()
            ]
            self.assertEqual("unverified", candidates[0]["validation_state"])

    def test_target_specific_candidate_withholds_assistant_method_excerpt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            (sessions / "target-specific.jsonl").write_text(
                "\n".join(
                    [
                        event("session_meta", {"id": "target-specific"}),
                        message(
                            "user",
                            "https://target.example 的渗透测试漏了接口，必须继续检查登录态。",
                        ),
                        message(
                            "assistant",
                            "收到，先确认 gp 登录态，再回顾 gp 的接口记录。",
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            self.run_tool(root, sessions, "target-specific")
            run = root / "data" / "session-distillation" / "runs" / "target-specific"
            combined = "\n".join(
                path.read_text(encoding="utf-8") for path in run.iterdir() if path.is_file()
            )

            self.assertNotIn("target.example", combined)
            self.assertNotIn("gp 登录态", combined)
            candidate = json.loads(
                (run / "learning-candidates.jsonl").read_text(encoding="utf-8").splitlines()[0]
            )
            self.assertTrue(candidate["target_specific"])
            self.assertEqual(
                "reconstruct the relevant scope and evidence state; validate the corrected behavior with tool evidence or explicit acceptance; preserve unresolved prerequisites and continue the investigation",
                candidate["lesson_bundle"]["successful_method"],
            )

    def test_review_command_hides_blocked_cards_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            (sessions / "review.jsonl").write_text(
                "\n".join(
                    [
                        event("session_meta", {"id": "review"}),
                        message("user", "这个渗透测试遗漏接口，必须补齐路由覆盖"),
                        message("assistant", "改为先建立完整路由清单，再逐项验证。"),
                    ]
                ) + "\n",
                encoding="utf-8",
            )
            self.run_tool(root, sessions, "review")
            command = [sys.executable, str(SCRIPT), "review", "review", "--json"]
            hidden = subprocess.run(
                command, check=True, text=True, stdout=subprocess.PIPE,
                env=self.environment(root),
            )
            self.assertEqual([], json.loads(hidden.stdout)["cards"])
            shown = subprocess.run(
                [*command, "--include-blocked"], check=True, text=True,
                stdout=subprocess.PIPE, env=self.environment(root),
            )
            card = json.loads(shown.stdout)["cards"][0]
            self.assertEqual("blocked", card["approval_state"])
            self.assertIn("missing-independent-validation", card["block_reasons"])

    def test_generic_api_and_internal_goal_corrections_are_not_security_lessons(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            (sessions / "generic.jsonl").write_text(
                "\n".join(
                    [
                        event("session_meta", {"id": "generic"}),
                        message("user", "API 模式不对，应该改成另外四种协议名称"),
                        message("assistant", "已经统一配置值和前端选项。"),
                        message("user", '<codex_internal_context source="goal">需要继续优化文件架构</codex_internal_context>'),
                        message("assistant", "继续拆分文件。"),
                    ]
                ) + "\n",
                encoding="utf-8",
            )
            self.run_tool(root, sessions, "generic")
            run = root / "data" / "session-distillation" / "runs" / "generic"
            self.assertEqual("", (run / "learning-candidates.jsonl").read_text())

    def test_extracts_operator_requirements_and_safely_classified_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            (sessions / "requirements.jsonl").write_text(
                "\n".join(
                    [
                        event("session_meta", {"id": "requirements"}),
                        message("user", "以后渗透测试必须先完整收集路由和接口，再分批验证，不能拿发现数量冒充已测试数量。"),
                        message("assistant", "已按完整采集与覆盖门槛更新，回归测试通过。"),
                        message("user", "安全验证请使用这个惰性 payload:\n```html\n<span data-blue-sec-probe=\"marker\"></span>\n```"),
                        message("assistant", "浏览器无网络标记验证通过。"),
                        message(
                            "user",
                            "分析 OAuth 和越权测试，"
                            + "github_"
                            + "pat_abcdefghijklmnopqrstuvwxyz1234567890 不得写入结果。",
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            self.run_tool(root, sessions, "requirements")
            run = root / "data" / "session-distillation" / "runs" / "requirements"
            summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
            self.assertEqual(0, summary["active_operator_policies"])
            policies = json.loads((root / "config" / "operator-policy.json").read_text(encoding="utf-8"))
            self.assertFalse(policies["active"])
            reviewed = [
                json.loads(line)
                for line in (run / "operator-policy-candidates.jsonl").read_text().splitlines()
            ]
            self.assertIn(
                "collect-before-batched-validation",
                {item["policy_key"] for item in reviewed},
            )
            payloads = [
                json.loads(line)
                for line in (run / "session-payload-candidates.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(1, len(payloads))
            self.assertEqual("safe-auto", payloads[0]["payload_policy"])
            combined = "\n".join(path.read_text(encoding="utf-8") for path in run.iterdir())
            self.assertNotIn("github_pat_", combined)

    def test_unchanged_sources_are_reused_and_resume_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            (sessions / "one.jsonl").write_text(
                "\n".join(
                    [
                        event("session_meta", {"id": "one"}),
                        message("user", "分析这个 PCAP 攻击流量"),
                        message("user", "根据告警还原攻击路径"),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            self.run_tool(root, sessions, "first")
            self.run_tool(root, sessions, "second")
            second = root / "data" / "session-distillation" / "runs" / "second"
            ledger = json.loads(
                (second / "session-source-ledger.jsonl").read_text(encoding="utf-8").splitlines()[0]
            )
            self.assertTrue(ledger["reused"])
            before = (second / "summary.json").read_bytes()
            subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "run",
                    "--sessions",
                    str(sessions),
                    "--run-id",
                    "second",
                    "--resume",
                ],
                check=True,
                env=self.environment(root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(before, (second / "summary.json").read_bytes())

    def test_claude_visible_messages_and_subagent_links_are_safely_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "projects"
            subagents = sessions / "project" / "parent-session" / "subagents"
            subagents.mkdir(parents=True)
            value = [
                {
                    "type": "system",
                    "content": "hidden system secret",
                    "sessionId": "claude-session",
                },
                {
                    "type": "user",
                    "sessionId": "claude-session",
                    "message": {"role": "user", "content": "渗透测试遗漏了越权接口"},
                },
                {
                    "type": "assistant",
                    "sessionId": "claude-session",
                    "message": {
                        "role": "assistant",
                        "content": [
                            {"type": "text", "text": "已增加授权回归并验证通过"},
                            {"type": "tool_use", "id": "call-1", "name": "Bash", "input": {"command": "pytest"}},
                        ],
                    },
                },
                {
                    "type": "user",
                    "sessionId": "claude-session",
                    "message": {"role": "user", "content": "现在可以了，token=SHOULD_NOT_PERSIST"},
                },
            ]
            path = subagents / "agent-one.jsonl"
            path.write_text("\n".join(json.dumps(item, ensure_ascii=False) for item in value) + "\n", encoding="utf-8")
            subprocess.run(
                [sys.executable, str(SCRIPT), "run", "--source", "claude", "--sessions", str(sessions), "--run-id", "claude-fixture"],
                check=True,
                env=self.environment(root),
                stdout=subprocess.PIPE,
            )
            run = root / "data" / "session-distillation" / "runs" / "claude-fixture"
            summary = json.loads((run / "summary.json").read_text())
            self.assertEqual({"claude": 1}, summary["source_platforms"])
            ledger = json.loads((run / "session-source-ledger.jsonl").read_text().splitlines()[0])
            self.assertEqual("claude", ledger["source_platform"])
            self.assertEqual(1, summary["parent_links"])
            combined = "\n".join(item.read_text() for item in run.iterdir() if item.is_file())
            self.assertNotIn("SHOULD_NOT_PERSIST", combined)
            self.assertNotIn("hidden system secret", combined)

    def test_hermes_json_sessions_are_supported_without_request_dumps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sessions = root / "sessions"
            sessions.mkdir()
            (sessions / "session_security.json").write_text(
                json.dumps(
                    {
                        "session_id": "hermes-session",
                        "session_start": "2026-08-02T00:00:00Z",
                        "messages": [
                            {"role": "user", "content": "分析这个 PCAP 攻击流量"},
                            {"role": "assistant", "content": "已建立攻击路径假设"},
                            {"role": "user", "content": "根据告警继续还原攻击路径"},
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "run",
                    "--source",
                    "hermes",
                    "--sessions",
                    str(sessions),
                    "--run-id",
                    "hermes-fixture",
                ],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.environment(root),
            )
            self.assertIn('"hermes": 1', result.stdout)
            summary = json.loads(
                (root / "data/session-distillation/runs/hermes-fixture/summary.json").read_text()
            )
            self.assertEqual(1, summary["source_platforms"]["hermes"])
            self.assertEqual(1, summary["classifications"]["security"])

    def test_unexposed_session_source_reports_capability_without_guessing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "run", "--source", "trae-cn"],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.environment(root),
            )
            value = json.loads(result.stdout)
            self.assertEqual("not-exposed", value["status"])


if __name__ == "__main__":
    unittest.main()
