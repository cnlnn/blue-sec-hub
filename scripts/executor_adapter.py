#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import operator_policy


ROOT = Path(__file__).resolve().parents[1]
DATA_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_DATA",
        Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        / "blue-sec-hub",
    )
)
TASK_STATES = {"planned", "running", "paused", "completed", "failed", "cancelled"}


def now() -> str:
    return datetime.now(UTC).isoformat()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if os.name != "nt":
        temporary.chmod(0o600)
    temporary.replace(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_executor_specs() -> dict[str, dict[str, Any]]:
    value = json.loads((ROOT / "executors.json").read_text(encoding="utf-8"))
    if value.get("schema_version") != 2 or not isinstance(value.get("executors"), dict):
        raise ValueError("unsupported executor registry schema")
    for name, spec in value["executors"].items():
        missing = {"commands", "role", "url", "adapter"} - set(spec)
        if missing:
            raise ValueError(f"executor {name} missing fields: {', '.join(sorted(missing))}")
    return value["executors"]


def find_command(spec: dict[str, Any]) -> str | None:
    return next((path for command in spec["commands"] if (path := shutil.which(command))), None)


@dataclass(frozen=True)
class ExecutionRequest:
    engine: str
    target: str
    scope: tuple[str, ...]
    source_root: str | None = None
    credential_lease: str | None = None
    mode: str = "standard"
    max_seconds: int = 3600
    max_turns: int = 30
    max_cost_usd: float = 0.0
    allow_network: bool = False
    instructions: tuple[str, ...] = ()

    def validate(self) -> None:
        if self.engine not in load_executor_specs():
            raise ValueError(f"unsupported executor: {self.engine}")
        if not self.target.strip():
            raise ValueError("target is required")
        if not self.scope or self.target not in self.scope:
            raise ValueError("scope must explicitly contain the target")
        parsed = urlsplit(self.target)
        if parsed.scheme and parsed.scheme not in {"http", "https"}:
            raise ValueError("only HTTP(S) URLs or local paths are supported")
        if self.source_root:
            source = Path(self.source_root).expanduser().resolve()
            if not source.is_dir():
                raise ValueError(f"source root does not exist: {source}")
        if self.max_seconds <= 0 or self.max_seconds > 86400:
            raise ValueError("max_seconds must be between 1 and 86400")
        if self.max_turns <= 0 or self.max_turns > 1000:
            raise ValueError("max_turns must be between 1 and 1000")
        if self.max_cost_usd < 0:
            raise ValueError("max_cost_usd cannot be negative")
        if any(len(value) > 2000 for value in self.instructions):
            raise ValueError("executor instruction exceeds 2000 characters")

    def persisted(self) -> dict[str, Any]:
        self.validate()
        value = asdict(self)
        lease = value.pop("credential_lease")
        value["credential_lease_hash"] = sha256_text(str(lease)) if lease else None
        safe_instructions = []
        for instruction in value["instructions"]:
            clean = instruction
            for pattern in operator_policy.SECRET_PATTERNS:
                clean = pattern.sub("[REDACTED_SECRET]", clean)
            safe_instructions.append(clean)
        value["instructions"] = safe_instructions
        return value


@dataclass(frozen=True)
class ExecutionPlan:
    engine: str
    status: str
    command: tuple[str, ...] = ()
    environment_names: tuple[str, ...] = ()
    output_paths: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass
class ExecutionResult:
    status: str
    exit_code: int | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    detail: str | None = None


class ExecutorAdapter(ABC):
    id: str

    def __init__(self, spec: dict[str, Any]):
        self.spec = spec
        self.executable = find_command(spec)

    def capability(self) -> dict[str, Any]:
        return {
            "engine": self.id,
            "status": "not-installed" if not self.executable else "contract-ready",
            "executable": self.executable,
            "adapter": self.spec["adapter"],
            "role": self.spec["role"],
            "url": self.spec["url"],
        }

    @abstractmethod
    def plan(self, request: ExecutionRequest, task_root: Path) -> ExecutionPlan:
        raise NotImplementedError

    def run(self, request: ExecutionRequest, task_root: Path) -> ExecutionResult:
        return ExecutionResult(status="failed", detail=f"{self.id} adapter does not implement run")

    def resume(self, task: dict[str, Any], task_root: Path) -> ExecutionResult:
        return ExecutionResult(status="failed", detail=f"{self.id} adapter does not implement resume")

    def cancel(self, task: dict[str, Any], task_root: Path) -> ExecutionResult:
        return ExecutionResult(status="failed", detail=f"{self.id} adapter does not implement cancel")

    def collect(self, task: dict[str, Any], task_root: Path) -> ExecutionResult:
        return ExecutionResult(status="failed", detail=f"{self.id} adapter does not implement collect")

    def cleanup(self, task: dict[str, Any], task_root: Path) -> ExecutionResult:
        return ExecutionResult(status="completed", detail="no managed runtime resources")


class ContractOnlyAdapter(ExecutorAdapter):
    def __init__(self, executor_id: str, spec: dict[str, Any]):
        super().__init__(spec)
        self.id = executor_id

    def plan(self, request: ExecutionRequest, task_root: Path) -> ExecutionPlan:
        request.validate()
        return ExecutionPlan(
            engine=self.id,
            status="not-installed" if not self.executable else "contract-ready",
            limitations=("runtime adapter is not implemented; no command will be executed",),
        )


ADAPTERS: dict[str, type[ExecutorAdapter]] = {}


def register_adapter(name: str, adapter: type[ExecutorAdapter]) -> None:
    ADAPTERS[name] = adapter


def get_adapter(name: str) -> ExecutorAdapter:
    spec = load_executor_specs().get(name)
    if spec is None:
        raise ValueError(f"unsupported executor: {name}")
    adapter = ADAPTERS.get(name)
    configured = str(spec.get("adapter") or "pending")
    if adapter is None and configured != "pending":
        module_name, separator, class_name = configured.partition(":")
        if not separator:
            raise ValueError(f"invalid adapter entry for {name}: {configured}")
        module = importlib.import_module(module_name)
        adapter = getattr(module, class_name)
    return adapter(spec) if adapter else ContractOnlyAdapter(name, spec)


def create_task(request: ExecutionRequest) -> dict[str, Any]:
    request.validate()
    task_id = f"exec-{uuid.uuid4().hex}"
    root = DATA_ROOT / "executions" / "tasks" / task_id
    persisted_request = request.persisted()
    safe_request = request_from_value(persisted_request)
    adapter = get_adapter(safe_request.engine)
    plan = adapter.plan(safe_request, root)
    task = {
        "schema_version": 1,
        "task_id": task_id,
        "state": "planned",
        "created_at": now(),
        "updated_at": now(),
        "request": persisted_request,
        "plan": asdict(plan),
        "event_head": None,
    }
    atomic_json(root / "task.json", task)
    append_event(root, {"type": "planned", "status": plan.status})
    return load_task(task_id)


def task_root(task_id: str) -> Path:
    if not task_id.startswith("exec-") or any(character not in "0123456789abcdef" for character in task_id[5:]):
        raise ValueError("invalid task id")
    return DATA_ROOT / "executions" / "tasks" / task_id


def load_task(task_id: str) -> dict[str, Any]:
    path = task_root(task_id) / "task.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"executor task not found: {task_id}") from error
    if value.get("state") not in TASK_STATES:
        raise ValueError("executor task has invalid state")
    return value


def save_task(task: dict[str, Any]) -> dict[str, Any]:
    if task.get("state") not in TASK_STATES:
        raise ValueError("executor task has invalid state")
    task["updated_at"] = now()
    atomic_json(task_root(str(task["task_id"])) / "task.json", task)
    return task


def transition_task(task_id: str, state: str, event_type: str, **event: Any) -> dict[str, Any]:
    if state not in TASK_STATES:
        raise ValueError(f"invalid executor task state: {state}")
    task = load_task(task_id)
    task["state"] = state
    save_task(task)
    append_event(task_root(task_id), {"type": event_type, "state": state, **event})
    return load_task(task_id)


def request_from_value(value: dict[str, Any]) -> ExecutionRequest:
    return ExecutionRequest(
        engine=str(value["engine"]),
        target=str(value["target"]),
        scope=tuple(value["scope"]),
        source_root=value.get("source_root"),
        mode=str(value.get("mode") or "standard"),
        max_seconds=int(value.get("max_seconds") or 3600),
        max_turns=int(value.get("max_turns") or 30),
        max_cost_usd=float(value.get("max_cost_usd") or 0.0),
        allow_network=bool(value.get("allow_network")),
        instructions=tuple(value.get("instructions", [])),
    )


def request_from_task(task: dict[str, Any]) -> ExecutionRequest:
    return request_from_value(task["request"])


def append_event(root: Path, event: dict[str, Any]) -> dict[str, Any]:
    task = json.loads((root / "task.json").read_text(encoding="utf-8"))
    record = {"recorded_at": now(), "previous_sha256": task.get("event_head"), **event}
    record["sha256"] = sha256_text(json.dumps(record, ensure_ascii=False, sort_keys=True))
    with (root / "events.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    task["event_head"] = record["sha256"]
    task["updated_at"] = now()
    atomic_json(root / "task.json", task)
    return record
