#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from executor_adapter import ExecutionPlan, ExecutionRequest, ExecutionResult, ExecutorAdapter, sha256_file


class ShannonAdapter(ExecutorAdapter):
    id = "shannon"

    def capability(self) -> dict[str, object]:
        value = super().capability()
        value["status"] = "runtime-ready" if self.executable else "not-installed"
        value["requirements"] = {
            "source_root": True,
            "network_authorization": True,
            "runtime": "Docker",
        }
        return value

    def plan(self, request: ExecutionRequest, task_root: Path) -> ExecutionPlan:
        request.validate()
        limitations = []
        if not request.source_root:
            limitations.append("Shannon requires a source root")
        if not request.allow_network:
            limitations.append("network execution requires --allow-network")
        if not self.executable:
            limitations.append("Shannon executable is not installed")
        status = "runtime-ready" if not limitations else ("not-installed" if not self.executable else "degraded")
        command: tuple[str, ...] = ()
        if self.executable and request.source_root:
            command = (
                self.executable,
                "start",
                "-u",
                request.target,
                "-r",
                str(Path(request.source_root).resolve()),
                "-o",
                str((task_root / "output").resolve()),
                "-w",
                task_root.name,
            )
        return ExecutionPlan(
            engine=self.id,
            status=status,
            command=command,
            environment_names=("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "AWS_REGION"),
            output_paths=(str(task_root / "output"), str(task_root / "executor.log")),
            limitations=tuple(limitations),
        )

    def run(self, request: ExecutionRequest, task_root: Path) -> ExecutionResult:
        plan = self.plan(request, task_root)
        if plan.status != "runtime-ready":
            return ExecutionResult(status="failed", detail="; ".join(plan.limitations))
        task_root.mkdir(parents=True, exist_ok=True)
        log_path = task_root / "executor.log"
        try:
            with log_path.open("ab") as log:
                if os.name != "nt":
                    log_path.chmod(0o600)
                result = subprocess.run(
                    list(plan.command),
                    cwd=request.source_root,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=request.max_seconds,
                    check=False,
                )
        except subprocess.TimeoutExpired:
            return ExecutionResult(status="paused", detail=f"time budget reached after {request.max_seconds}s")
        except KeyboardInterrupt:
            return ExecutionResult(status="paused", detail="operator interrupted; rerun resume with the same workspace")
        artifacts = []
        output = task_root / "output"
        for path in sorted(output.rglob("*")) if output.is_dir() else []:
            if path.is_file():
                artifacts.append(
                    {
                        "path": path.relative_to(task_root).as_posix(),
                        "sha256": sha256_file(path),
                        "bytes": path.stat().st_size,
                    }
                )
        if log_path.is_file():
            artifacts.append({"path": log_path.name, "sha256": sha256_file(log_path), "bytes": log_path.stat().st_size})
        return ExecutionResult(
            status="completed" if result.returncode == 0 else "failed",
            exit_code=result.returncode,
            artifacts=artifacts,
            detail="Shannon completed" if result.returncode == 0 else "Shannon returned a non-zero exit code",
        )

    def resume(self, task: dict[str, object], task_root: Path) -> ExecutionResult:
        from executor_adapter import request_from_task

        return self.run(request_from_task(task), task_root)

    def collect(self, task: dict[str, object], task_root: Path) -> ExecutionResult:
        artifacts = []
        for path in sorted(task_root.rglob("*")):
            if path.is_file() and path.name not in {"task.json", "events.jsonl"}:
                artifacts.append({"path": path.relative_to(task_root).as_posix(), "sha256": sha256_file(path), "bytes": path.stat().st_size})
        return ExecutionResult(status="completed", artifacts=artifacts, detail="artifact inventory refreshed")
