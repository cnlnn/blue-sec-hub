#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from executor_adapter import ExecutionPlan, ExecutionRequest, ExecutionResult, ExecutorAdapter, sha256_file


def instruction_text(request: ExecutionRequest) -> str:
    lines = [
        "Blue Sec Hub authorized task constraints:",
        f"Target: {request.target}",
        "Exact scope:",
        *(f"- {item}" for item in request.scope),
        "Use minimally disruptive validation. Separate confirmed evidence from inference.",
        "Do not access unrelated systems. Preserve cleanup status and unresolved blockers.",
    ]
    if request.source_root:
        lines.append(f"Source root: {request.source_root}")
    if request.instructions:
        lines.extend(("Operator constraints:", *(f"- {item}" for item in request.instructions)))
    return "\n".join(lines) + "\n"


class StrixAdapter(ExecutorAdapter):
    id = "strix"

    def capability(self) -> dict[str, object]:
        value = super().capability()
        value["status"] = "runtime-ready" if self.executable else "not-installed"
        value["capabilities"] = {
            "browser": True,
            "terminal": True,
            "dynamic_testing": True,
            "headless": True,
        }
        return value

    def plan(self, request: ExecutionRequest, task_root: Path) -> ExecutionPlan:
        request.validate()
        limitations = []
        if request.target.startswith(("http://", "https://")) and not request.allow_network:
            limitations.append("network execution requires --allow-network")
        if not self.executable:
            limitations.append("Strix executable is not installed")
        status = "runtime-ready" if not limitations else ("not-installed" if not self.executable else "degraded")
        command: list[str] = []
        if self.executable:
            command = [
                self.executable,
                "-n",
                "--target",
                request.target,
                "--scan-mode",
                request.mode,
                "--instruction-file",
                str((task_root / "instructions.txt").resolve()),
            ]
            if request.source_root and str(Path(request.source_root).resolve()) != request.target:
                command.extend(("--target", str(Path(request.source_root).resolve()), "--scope-mode", "full"))
        return ExecutionPlan(
            engine=self.id,
            status=status,
            command=tuple(command),
            environment_names=("STRIX_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"),
            output_paths=(str(task_root), str(task_root / "executor.log")),
            limitations=tuple(limitations),
        )

    def run(self, request: ExecutionRequest, task_root: Path) -> ExecutionResult:
        plan = self.plan(request, task_root)
        if plan.status != "runtime-ready":
            return ExecutionResult(status="failed", detail="; ".join(plan.limitations))
        task_root.mkdir(parents=True, exist_ok=True)
        instruction_path = task_root / "instructions.txt"
        instruction_path.write_text(instruction_text(request), encoding="utf-8")
        log_path = task_root / "executor.log"
        if os.name != "nt":
            instruction_path.chmod(0o600)
        try:
            with log_path.open("ab") as log:
                if os.name != "nt":
                    log_path.chmod(0o600)
                result = subprocess.run(
                    list(plan.command),
                    cwd=task_root,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=request.max_seconds,
                    check=False,
                )
        except subprocess.TimeoutExpired:
            return ExecutionResult(status="paused", detail=f"time budget reached after {request.max_seconds}s")
        except KeyboardInterrupt:
            return ExecutionResult(status="paused", detail="operator interrupted Strix")
        artifacts = []
        for path in sorted(task_root.rglob("*")):
            if path.is_file() and path.name not in {"task.json", "events.jsonl"}:
                artifacts.append({"path": path.relative_to(task_root).as_posix(), "sha256": sha256_file(path), "bytes": path.stat().st_size})
        success = result.returncode in {0, 2}
        detail = "Strix completed with findings" if result.returncode == 2 else "Strix completed without findings"
        if not success:
            detail = "Strix returned an unsupported exit code"
        return ExecutionResult(
            status="completed" if success else "failed",
            exit_code=result.returncode,
            artifacts=artifacts,
            detail=detail,
        )

    def resume(self, task: dict[str, object], task_root: Path) -> ExecutionResult:
        from executor_adapter import request_from_task

        return self.run(request_from_task(task), task_root)

    def collect(self, task: dict[str, object], task_root: Path) -> ExecutionResult:
        artifacts = []
        for path in sorted(task_root.rglob("*")):
            if path.is_file() and path.name not in {"task.json", "events.jsonl"}:
                artifacts.append({"path": path.relative_to(task_root).as_posix(), "sha256": sha256_file(path), "bytes": path.stat().st_size})
        return ExecutionResult(status="completed", artifacts=artifacts, detail="Strix artifact inventory refreshed")
