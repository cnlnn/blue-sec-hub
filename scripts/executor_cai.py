#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from executor_adapter import ExecutionPlan, ExecutionRequest, ExecutionResult, ExecutorAdapter, sha256_file


def task_prompt(request: ExecutionRequest) -> str:
    source = f"\nRead-only source context: {request.source_root}" if request.source_root else ""
    instructions = "\n".join(f"- {item}" for item in request.instructions)
    extra = f"\nOperator constraints:\n{instructions}" if instructions else ""
    return (
        "Execute this explicitly authorized Blue Sec Hub security task using the orchestration agent and "
        "specialists as tools. Stay inside the exact scope, prefer minimally disruptive validation, and "
        "separate confirmed evidence from inference. Do not access unrelated systems.\n"
        f"Target: {request.target}\n"
        f"Exact scope: {', '.join(request.scope)}"
        f"{source}{extra}\n"
        "Return a concise evidence-backed result with unresolved blockers and cleanup status."
    )


class CAIAdapter(ExecutorAdapter):
    id = "cai"

    def capability(self) -> dict[str, object]:
        value = super().capability()
        value["status"] = "runtime-ready" if self.executable else "not-installed"
        value["orchestration"] = {
            "agent_type": "orchestration_agent",
            "agent_as_tool": "run_specialist",
            "parallel": "run_parallel_specialists",
            "guardrails": True,
        }
        return value

    def plan(self, request: ExecutionRequest, task_root: Path) -> ExecutionPlan:
        request.validate()
        limitations = []
        if request.target.startswith(("http://", "https://")) and not request.allow_network:
            limitations.append("network execution requires --allow-network")
        if not self.executable:
            limitations.append("CAI executable is not installed")
        status = "runtime-ready" if not limitations else ("not-installed" if not self.executable else "degraded")
        command = (self.executable, "--prompt", task_prompt(request)) if self.executable else ()
        return ExecutionPlan(
            engine=self.id,
            status=status,
            command=command,
            environment_names=(
                "CAI_AGENT_TYPE",
                "CAI_WORKSPACE",
                "CAI_WORKSPACE_DIR",
                "CAI_MAX_TURNS",
                "CAI_PRICE_LIMIT",
                "CAI_GUARDRAILS",
            ),
            output_paths=(str(task_root / "output"), str(task_root / "executor.log")),
            limitations=tuple(limitations),
        )

    def environment(self, request: ExecutionRequest, task_root: Path) -> dict[str, str]:
        environment = os.environ.copy()
        environment.update(
            {
                "CAI_AGENT_TYPE": "orchestration_agent",
                "CAI_WORKSPACE": task_root.name,
                "CAI_WORKSPACE_DIR": str((task_root / "output").resolve()),
                "CAI_MAX_TURNS": str(request.max_turns),
                "CAI_GUARDRAILS": "true",
                "CAI_STATE": "true",
                "CAI_STREAM": "false",
                "CAI_TRACING": "true",
                "CAI_SKIP_UPDATE_CHECK": "1",
                "PROMPT_TOOLKIT_NO_CPR": "1",
            }
        )
        if request.max_cost_usd > 0:
            environment["CAI_PRICE_LIMIT"] = str(request.max_cost_usd)
        return environment

    def run(self, request: ExecutionRequest, task_root: Path) -> ExecutionResult:
        plan = self.plan(request, task_root)
        if plan.status != "runtime-ready":
            return ExecutionResult(status="failed", detail="; ".join(plan.limitations))
        task_root.mkdir(parents=True, exist_ok=True)
        (task_root / "output").mkdir(exist_ok=True)
        log_path = task_root / "executor.log"
        try:
            with log_path.open("ab") as log:
                if os.name != "nt":
                    log_path.chmod(0o600)
                result = subprocess.run(
                    list(plan.command),
                    cwd=request.source_root or task_root,
                    env=self.environment(request, task_root),
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=request.max_seconds,
                    check=False,
                )
        except subprocess.TimeoutExpired:
            return ExecutionResult(status="paused", detail=f"time budget reached after {request.max_seconds}s")
        except KeyboardInterrupt:
            return ExecutionResult(status="paused", detail="operator interrupted CAI; workspace state is retained")
        artifacts = []
        for path in sorted(task_root.rglob("*")):
            if path.is_file() and path.name not in {"task.json", "events.jsonl"}:
                artifacts.append({"path": path.relative_to(task_root).as_posix(), "sha256": sha256_file(path), "bytes": path.stat().st_size})
        return ExecutionResult(
            status="completed" if result.returncode == 0 else "failed",
            exit_code=result.returncode,
            artifacts=artifacts,
            detail="CAI orchestration completed" if result.returncode == 0 else "CAI returned a non-zero exit code",
        )

    def resume(self, task: dict[str, object], task_root: Path) -> ExecutionResult:
        from executor_adapter import request_from_task

        return self.run(request_from_task(task), task_root)

    def collect(self, task: dict[str, object], task_root: Path) -> ExecutionResult:
        artifacts = []
        for path in sorted(task_root.rglob("*")):
            if path.is_file() and path.name not in {"task.json", "events.jsonl"}:
                artifacts.append({"path": path.relative_to(task_root).as_posix(), "sha256": sha256_file(path), "bytes": path.stat().st_size})
        return ExecutionResult(status="completed", artifacts=artifacts, detail="CAI artifact inventory refreshed")
