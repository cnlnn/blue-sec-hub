#!/usr/bin/env python3
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from executor_adapter import ROOT, ExecutionPlan, ExecutionRequest, ExecutionResult, ExecutorAdapter, sha256_file
import runtime_support


def browser_runtime_ready() -> bool:
    return runtime_support.browser_status()["status"] == "ready"


def artifact_inventory(task_root: Path) -> list[dict[str, object]]:
    artifacts = []
    for path in sorted((task_root / "output").rglob("*")) if (task_root / "output").is_dir() else []:
        if path.is_file():
            artifacts.append({"path": path.relative_to(task_root).as_posix(), "sha256": sha256_file(path), "bytes": path.stat().st_size})
    log = task_root / "executor.log"
    if log.is_file():
        artifacts.append({"path": log.name, "sha256": sha256_file(log), "bytes": log.stat().st_size})
    return artifacts


class NativeExecutorAdapter(ExecutorAdapter):
    id = "blue-sec-native"

    def capability(self) -> dict[str, object]:
        value = super().capability()
        ready = browser_runtime_ready()
        value.update(
            {
                "status": "runtime-ready",
                "executable": sys.executable,
                "capabilities": {
                    "same_site_outbound_policy": True,
                    "evidence_events": True,
                    "checkpoint_restore": True,
                    "request_rate_limit": True,
                    "browser": ready,
                },
            }
        )
        return value

    def plan(self, request: ExecutionRequest, task_root: Path) -> ExecutionPlan:
        request.validate()
        limitations = []
        if not request.target.startswith(("http://", "https://")):
            limitations.append("native executor currently requires an HTTP(S) target")
        if not request.allow_network:
            limitations.append("network execution requires --allow-network")
        ready = browser_runtime_ready()
        if not ready:
            limitations.append("optional browser collection will be bootstrapped on demand")
        status = "degraded" if any(
            item for item in limitations if not item.startswith("optional browser")
        ) else "runtime-ready"
        workspace = task_root / "output" / "assessment"
        command = [
            sys.executable,
            str(ROOT / "scripts" / "agent.py"),
            "run",
            "--target",
            request.target,
            "--workspace",
            str(workspace),
            "--platform",
            "generic",
            "--requests-per-second",
            "2.0",
            "--no-refresh-knowledge",
        ]
        if request.source_root:
            command.extend(("--source-root", str(Path(request.source_root).resolve())))
        return ExecutionPlan(
            engine=self.id,
            status=status,
            command=tuple(command),
            output_paths=(str(workspace), str(task_root / "executor.log")),
            limitations=tuple(limitations),
        )

    def execute(self, command: list[str], request: ExecutionRequest, task_root: Path) -> ExecutionResult:
        task_root.mkdir(parents=True, exist_ok=True)
        log_path = task_root / "executor.log"
        try:
            with log_path.open("ab") as log:
                if os.name != "nt":
                    log_path.chmod(0o600)
                result = subprocess.run(
                    command,
                    cwd=ROOT,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=request.max_seconds,
                    check=False,
                )
        except subprocess.TimeoutExpired:
            return ExecutionResult(status="paused", detail=f"time budget reached after {request.max_seconds}s")
        except KeyboardInterrupt:
            return ExecutionResult(status="paused", detail="operator interrupted; native workspace is checkpointed")
        status = "completed" if result.returncode == 0 else ("paused" if result.returncode == 2 else "failed")
        detail = {
            "completed": "native assessment reached evidence and coverage closure",
            "paused": "native assessment is interim and can be resumed from machine state",
            "failed": "native assessment runner failed",
        }[status]
        return ExecutionResult(status=status, exit_code=result.returncode, artifacts=artifact_inventory(task_root), detail=detail)

    def run(self, request: ExecutionRequest, task_root: Path) -> ExecutionResult:
        plan = self.plan(request, task_root)
        if plan.status == "degraded":
            return ExecutionResult(status="failed", detail="; ".join(plan.limitations))
        return self.execute(list(plan.command), request, task_root)

    def resume(self, task: dict[str, object], task_root: Path) -> ExecutionResult:
        from executor_adapter import request_from_task

        request = request_from_task(task)
        workspace = task_root / "output" / "assessment"
        command = [
            sys.executable,
            str(ROOT / "scripts" / "agent.py"),
            "resume",
            "--workspace",
            str(workspace),
            "--requests-per-second",
            "2.0",
        ]
        if request.source_root:
            command.extend(("--source-root", str(Path(request.source_root).resolve())))
        return self.execute(command, request, task_root)

    def collect(self, task: dict[str, object], task_root: Path) -> ExecutionResult:
        return ExecutionResult(status="completed", artifacts=artifact_inventory(task_root), detail="native evidence inventory refreshed")
