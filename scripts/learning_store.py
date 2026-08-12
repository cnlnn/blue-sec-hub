#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterator

import operator_policy
from learning_policy import promotion_failures


SCHEMA_VERSION = 2
OBJECT_KINDS = {
    "instruction-rule",
    "knowledge-entry",
    "routing-term",
    "operator-policy",
    "functional-change",
}
ACTIVE_STATES = {"approved"}
LEDGER_EVENTS = {
    "recorded",
    "observed",
    "approved",
    "superseded",
    "revoked",
    "archived",
    "imported-base",
    "covered-by-base",
}
LEGACY_STATES = {"candidate", "promoted", "dismissed"}
ROOT = Path(__file__).resolve().parents[1]
BASE_CAPABILITIES = ROOT / "base-capabilities.json"


def now() -> str:
    return datetime.now(UTC).isoformat()


def data_root() -> Path:
    return Path(
        os.environ.get(
            "BLUE_SEC_DATA",
            Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
            / "blue-sec-hub",
        )
    )


def learning_root() -> Path:
    return data_root() / "learning"


def ledger_path() -> Path:
    return learning_root() / "ledger.jsonl"


def objects_root() -> Path:
    return learning_root() / "objects"


def manifest_path() -> Path:
    return learning_root() / "active-manifest.json"


def legacy_records_root() -> Path:
    return learning_root() / "records"


def migration_receipt_path() -> Path:
    return learning_root() / "migration-receipt.json"


def base_reconciliation_receipt_path() -> Path:
    return learning_root() / "base-reconciliation.json"


def stable_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(stable_json(value)).hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(stable_json(value) + b"\n")
    if os.name != "nt":
        temporary.chmod(0o600)
    temporary.replace(path)


@contextmanager
def store_lock(timeout: float = 10.0) -> Iterator[None]:
    root = learning_root()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = root / ".lock"
    deadline = time.monotonic() + timeout
    while True:
        try:
            lock.mkdir()
            break
        except FileExistsError:
            try:
                stale = time.time() - lock.stat().st_mtime > 60
            except OSError:
                stale = False
            if stale:
                shutil.rmtree(lock, ignore_errors=True)
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError("learning store is locked")
            time.sleep(0.05)
    try:
        yield
    finally:
        shutil.rmtree(lock, ignore_errors=True)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for number, line in enumerate(lines, start=1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"ledger line {number}: invalid JSON ({error.msg})"
            ) from error
        if not isinstance(value, dict):
            raise ValueError(f"ledger line {number}: event must be an object")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"ledger line {number}: invalid schema_version")
        if value.get("event") not in LEDGER_EVENTS:
            raise ValueError(f"ledger line {number}: invalid event")
        values.append(value)
    return values


def ledger_diagnostics(path: Path) -> list[str]:
    failures: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return failures
    for number, line in enumerate(lines, start=1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            failures.append(f"ledger line {number}: invalid JSON ({error.msg})")
            continue
        if not isinstance(value, dict):
            failures.append(f"ledger line {number}: event must be an object")
            continue
        if value.get("schema_version") != SCHEMA_VERSION:
            failures.append(f"ledger line {number}: invalid schema_version")
        if value.get("event") not in LEDGER_EVENTS:
            failures.append(f"ledger line {number}: invalid event")
    return failures


def append_event(event: dict[str, Any]) -> dict[str, Any]:
    kind = str(event.get("event") or "")
    if kind not in LEDGER_EVENTS:
        raise ValueError(f"unsupported learning ledger event: {kind}")
    normalized = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(event.get("event_id") or f"event-{secrets.token_hex(10)}"),
        "event": kind,
        "record_id": str(event["record_id"]),
        "object_sha256": event.get("object_sha256"),
        "recorded_at": str(event.get("recorded_at") or now()),
    }
    for key in (
        "supersedes",
        "reason",
        "archive_commit",
        "occurrences",
        "approval_basis",
        "independent_scenarios",
        "eval_result_sha256",
        "capability_id",
        "base_commit",
        "coverage_match",
    ):
        if event.get(key) is not None:
            normalized[key] = event[key]
    path = ledger_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    existing = {item.get("event_id") for item in read_jsonl(path)}
    if normalized["event_id"] not in existing:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(normalized, ensure_ascii=False, sort_keys=True) + "\n")
        if os.name != "nt":
            path.chmod(0o600)
    return normalized


def object_path(sha256: str) -> Path:
    return objects_root() / sha256[:2] / f"{sha256}.json"


def write_object(value: dict[str, Any]) -> tuple[str, Path]:
    sha256 = digest(value)
    path = object_path(sha256)
    if path.exists():
        current = json.loads(path.read_text(encoding="utf-8"))
        if digest(current) != sha256:
            raise ValueError(f"content object hash mismatch: {path}")
        return sha256, path
    atomic_json(path, value)
    return sha256, path


def load_object(sha256: str) -> dict[str, Any]:
    path = object_path(sha256)
    value = json.loads(path.read_text(encoding="utf-8"))
    if digest(value) != sha256:
        raise ValueError(f"content object hash mismatch: {path}")
    return value


def sanitized_text(value: str, *, limit: int = 2000) -> str:
    clean, redactions = operator_policy.redact_text(value, limit)
    if redactions:
        raise ValueError("learning content contains a secret or deployment-specific identifier")
    return clean


def evidence_hashes(values: list[str]) -> list[str]:
    return sorted(
        {
            hashlib.sha256(str(value).encode("utf-8")).hexdigest()
            for value in values
            if str(value).strip()
        }
    )


def make_object(record: dict[str, Any]) -> dict[str, Any]:
    kind = str(record.get("kind") or "")
    if kind not in OBJECT_KINDS:
        raise ValueError(f"unsupported learning object kind: {kind}")
    skill = sanitized_text(str(record.get("skill") or ""), limit=128)
    if not skill:
        raise ValueError("learning object requires a skill")
    fields = {
        key: sanitized_text(str(record.get(key) or ""))
        for key in ("task", "failure", "correction", "successful_pattern", "conditions")
    }
    if not all(fields.values()):
        raise ValueError("learning object requires task, failure, correction, success, and conditions")
    semantic_material = {
        "kind": kind,
        "skill": skill,
        "conditions": fields["conditions"],
        "correction": fields["correction"],
    }
    fingerprint = digest(
        {
            "kind": kind,
            "skill": skill,
            "task": fields["task"],
            "correction": fields["correction"],
            "conditions": fields["conditions"],
        }
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "id": str(record["id"]),
        "semantic_id": str(record.get("semantic_id") or f"learning-{digest(semantic_material)[:20]}"),
        "fingerprint": fingerprint,
        "kind": kind,
        "skill": skill,
        "ownership": str(record.get("ownership") or "local"),
        "source": sanitized_text(str(record.get("source") or "local"), limit=128),
        **fields,
        "confidence": str(record.get("confidence") or "medium"),
        "sensitivity": str(record.get("sensitivity") or "internal"),
        "evidence_hashes": evidence_hashes(list(record.get("evidence_refs") or [])),
        "created_at": str(record.get("created_at") or now()),
    }


def legacy_record_object(value: dict[str, Any]) -> dict[str, Any]:
    target = value.get("target")
    if not isinstance(target, dict):
        raise ValueError("legacy learning record requires a target object")
    ownership = str(target.get("ownership") or "local")
    result = make_object(
        {
            "id": value["id"],
            "kind": "knowledge-entry" if ownership == "upstream" else "instruction-rule",
            "skill": target.get("skill"),
            "ownership": ownership,
            "source": target.get("source") or "legacy-learning-v1",
            "task": value.get("task"),
            "failure": value.get("failure"),
            "correction": value.get("correction"),
            "successful_pattern": value.get("successful_pattern"),
            "conditions": value.get("conditions"),
            "confidence": value.get("confidence"),
            "sensitivity": value.get("sensitivity"),
            "created_at": value.get("created_at"),
            "evidence_refs": value.get("evidence_refs", []),
        }
    )
    result["evidence_hashes"] = sorted(
        {
            item.casefold()
            if len(item) == 64 and all(character in "0123456789abcdefABCDEF" for character in item)
            else hashlib.sha256(item.encode("utf-8")).hexdigest()
            for raw in value.get("evidence_refs", [])
            if (item := str(raw).strip())
        }
    )
    return result


def legacy_records() -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    root = legacy_records_root()
    for path in sorted(root.glob("*.json")) if root.is_dir() else []:
        raw = path.read_bytes()
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ValueError(f"legacy record {path.name}: invalid JSON ({error.msg})") from error
        if not isinstance(value, dict):
            raise ValueError(f"legacy record {path.name}: record must be an object")
        state = str(value.get("state") or "")
        if state not in LEGACY_STATES:
            raise ValueError(f"legacy record {path.name}: unsupported state {state or 'missing'}")
        if not value.get("id"):
            raise ValueError(f"legacy record {path.name}: missing id")
        records.append(
            {
                "filename": path.name,
                "file_sha256": hashlib.sha256(raw).hexdigest(),
                "state": state,
                "value": value,
                "object": legacy_record_object(value),
            }
        )
    return records


def load_migration_receipt() -> dict[str, Any]:
    path = migration_receipt_path()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError:
        return {"schema_version": 1, "records": []}
    except json.JSONDecodeError as error:
        raise ValueError(f"migration receipt: invalid JSON ({error.msg})") from error
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("migration receipt: invalid schema")
    return value


def migration_status() -> dict[str, Any]:
    records = legacy_records()
    receipt = load_migration_receipt()
    imported = {
        (str(item.get("legacy_id")), str(item.get("legacy_file_sha256")))
        for item in receipt.get("records", [])
        if isinstance(item, dict)
    }
    pending = [
        item
        for item in records
        if (str(item["value"]["id"]), item["file_sha256"]) not in imported
    ]
    return {
        "legacy_records": len(records),
        "migrated_records": len(records) - len(pending),
        "pending_records": len(pending),
        "receipt_revision": receipt.get("revision"),
    }


def state_index() -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for event in read_jsonl(ledger_path()):
        record_id = str(event.get("record_id") or "")
        if not record_id:
            continue
        current = result.setdefault(
            record_id,
            {
                "id": record_id,
                "state": "candidate",
                "occurrences": 0,
                "object_sha256": None,
                "events": [],
            },
        )
        kind = event.get("event")
        if kind == "recorded":
            current["object_sha256"] = event.get("object_sha256")
            current["state"] = "candidate"
            current["occurrences"] = max(1, int(current.get("occurrences", 0)))
        elif kind == "observed":
            current["occurrences"] = int(current.get("occurrences", 0)) + int(event.get("occurrences", 1))
        elif kind == "approved":
            current["state"] = "approved"
        elif kind == "superseded":
            current["state"] = "superseded"
        elif kind == "revoked":
            current["state"] = "revoked"
        elif kind == "imported-base":
            current["object_sha256"] = event.get("object_sha256")
            current["state"] = "archived-in-base"
            current["occurrences"] = max(
                1, int(event.get("occurrences", current.get("occurrences", 0) or 1))
            )
        elif kind == "covered-by-base":
            current["state"] = "archived-in-base"
            current["base_capability"] = event.get("capability_id")
            current["base_commit"] = event.get("base_commit")
        elif kind == "archived":
            current["archive_commit"] = event.get("archive_commit")
        current["events"].append(event)
    for value in result.values():
        sha256 = value.get("object_sha256")
        if sha256:
            value["object"] = load_object(str(sha256))
    return result


def load_base_capabilities() -> list[dict[str, Any]]:
    value = json.loads(BASE_CAPABILITIES.read_text(encoding="utf-8"))
    if value.get("schema_version") != 1 or not isinstance(value.get("capabilities"), list):
        raise ValueError("base-capabilities.json has an unsupported schema")
    identifiers: set[str] = set()
    result: list[dict[str, Any]] = []
    for capability in value["capabilities"]:
        identifier = str(capability.get("id") or "")
        skill = str(capability.get("skill") or "")
        terms = capability.get("match_terms")
        anchors = capability.get("anchors")
        if (
            not identifier
            or identifier in identifiers
            or not skill
            or not isinstance(terms, list)
            or not terms
            or not all(isinstance(item, str) and item.strip() for item in terms)
            or not isinstance(anchors, list)
            or not anchors
        ):
            raise ValueError(f"invalid base capability: {identifier or 'missing-id'}")
        for anchor in anchors:
            path = (ROOT / str(anchor.get("path") or "")).resolve()
            expected = str(anchor.get("contains") or "")
            if not path.is_relative_to(ROOT) or not path.is_file() or not expected:
                raise ValueError(f"invalid base capability anchor: {identifier}")
            if expected not in path.read_text(encoding="utf-8"):
                raise ValueError(f"base capability anchor is stale: {identifier}")
        identifiers.add(identifier)
        result.append(dict(capability))
    return result


def base_capability_matches(value: dict[str, Any]) -> list[dict[str, Any]]:
    material = " ".join(
        str(value.get(key) or "")
        for key in ("task", "failure", "correction", "successful_pattern", "conditions")
    ).casefold()
    return [
        capability
        for capability in load_base_capabilities()
        if capability["skill"] == value.get("skill")
        and all(str(term).casefold() in material for term in capability["match_terms"])
    ]


def base_reconciliation_status(
    records: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    records = records or state_index()
    deterministic = unmatched = ambiguous = 0
    for record in records.values():
        if record.get("state") != "candidate":
            continue
        matches = base_capability_matches(record.get("object", {}))
        if len(matches) == 1:
            deterministic += 1
        elif matches:
            ambiguous += 1
        else:
            unmatched += 1
    return {
        "status": "needs-reconciliation" if deterministic else "ready",
        "deterministic": deterministic,
        "ambiguous": ambiguous,
        "unmatched": unmatched,
    }


def find_record(record_id: str) -> dict[str, Any]:
    records = state_index()
    exact = records.get(record_id)
    if exact:
        return exact
    matches = [value for key, value in records.items() if key.startswith(record_id)]
    if len(matches) != 1:
        raise ValueError(f"learning record not found or ambiguous: {record_id}")
    return matches[0]


def approved_objects() -> list[dict[str, Any]]:
    return sorted(
        [
            value["object"]
            for value in state_index().values()
            if value.get("state") in ACTIVE_STATES and value.get("object")
        ],
        key=lambda item: (item["skill"], item["kind"], item["semantic_id"], item["id"]),
    )


def manifest_for_objects(objects: list[dict[str, Any]]) -> dict[str, Any]:
    objects = sorted(
        objects,
        key=lambda item: (item["skill"], item["kind"], item["semantic_id"], item["id"]),
    )
    semantic: dict[tuple[str, str, str], str] = {}
    entries = []
    for value in objects:
        key = (value["skill"], value["kind"], value["semantic_id"])
        if key in semantic:
            raise ValueError(
                "conflicting approved learning objects: "
                f"{semantic[key]} and {value['id']} share {value['semantic_id']}"
            )
        semantic[key] = value["id"]
        sha256 = digest(value)
        entries.append(
            {
                "id": value["id"],
                "semantic_id": value["semantic_id"],
                "kind": value["kind"],
                "skill": value["skill"],
                "object_sha256": sha256,
            }
        )
    core = {"schema_version": SCHEMA_VERSION, "objects": entries}
    return {**core, "revision": digest(core), "generated_at": now()}


def rebuild_manifest() -> dict[str, Any]:
    objects = approved_objects()
    manifest = manifest_for_objects(objects)
    atomic_json(manifest_path(), manifest)
    sync_operator_policy(objects)
    return manifest


def sync_operator_policy(objects: list[dict[str, Any]]) -> None:
    path = operator_policy.policy_path()
    try:
        current = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        current = {}
    retained = [
        item
        for item in current.get("active", [])
        if item.get("source") != "blue-sec-learning"
    ]
    learned = [
        {
            "policy_id": f"operator-{value['semantic_id']}",
            "policy_key": value["semantic_id"],
            "category": "workflow-order",
            "scope": "global-security",
            "summary": value["successful_pattern"],
            "value": "required",
            "state": "active",
            "source": "blue-sec-learning",
            "learning_id": value["id"],
        }
        for value in objects
        if value["kind"] == "operator-policy"
    ]
    active = sorted(
        [*retained, *learned],
        key=lambda item: (str(item.get("category")), str(item.get("policy_key"))),
    )
    value = {
        "schema_version": 1,
        "generated_at": now(),
        "precedence": current.get(
            "precedence",
            [
                "current-explicit-user-instruction",
                "repository-AGENTS-policy",
                "project-operator-policy",
                "global-security-operator-policy",
                "skill-default",
            ],
        ),
        "host_policy_always_wins": True,
        "active": active,
        "review_count": int(current.get("review_count", 0)),
        "superseded_count": int(current.get("superseded_count", 0)),
        "policy_digest": hashlib.sha256(
            stable_json(
                [
                    (item.get("policy_id"), item.get("summary"))
                    for item in active
                ]
            )
        ).hexdigest(),
    }
    operator_policy.atomic_json(path, value)


def load_manifest(rebuild: bool = False) -> dict[str, Any]:
    path = manifest_path()
    if rebuild or not path.exists():
        return rebuild_manifest()
    value = json.loads(path.read_text(encoding="utf-8"))
    core = {"schema_version": value.get("schema_version"), "objects": value.get("objects", [])}
    if value.get("revision") != digest(core):
        raise ValueError("active learning manifest hash mismatch")
    for item in value.get("objects", []):
        load_object(str(item["object_sha256"]))
    return value


def validate_for_approval(value: dict[str, Any], *, allow_medium: bool = False) -> list[str]:
    failures: list[str] = []
    if value.get("confidence") != "high" and not allow_medium:
        failures.append("approval requires high confidence")
    policy_record = {
        "task": value.get("task"),
        "failure": value.get("failure"),
        "correction": value.get("correction"),
        "successful_pattern": value.get("successful_pattern"),
        "conditions": value.get("conditions"),
        "evidence_refs": value.get("evidence_hashes", []),
    }
    failures.extend(promotion_failures(policy_record))
    if value.get("kind") == "functional-change":
        failures.append("functional changes require the code candidate workflow")
    for record in state_index().values():
        active = record.get("object", {})
        if record.get("state") != "approved" or active.get("id") == value.get("id"):
            continue
        if (
            active.get("skill"),
            active.get("kind"),
            active.get("semantic_id"),
        ) == (
            value.get("skill"),
            value.get("kind"),
            value.get("semantic_id"),
        ):
            failures.append(
                f"semantic rule is already approved by {active.get('id')}; use supersede"
            )
    return failures


def audit_store() -> dict[str, Any]:
    failures = ledger_diagnostics(ledger_path())
    migration = {
        "legacy_records": 0,
        "migrated_records": 0,
        "pending_records": 0,
        "receipt_revision": None,
    }
    base_reconciliation = {
        "status": "degraded",
        "deterministic": 0,
        "ambiguous": 0,
        "unmatched": 0,
    }
    try:
        records = state_index()
        manifest = load_manifest(rebuild=True)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        failures.append(str(error))
        records = {}
        manifest = {"objects": [], "revision": None}
    try:
        migration = migration_status()
        if migration["pending_records"]:
            failures.append(
                f"legacy learning migration pending: {migration['pending_records']} record(s)"
            )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        failures.append(str(error))
    try:
        base_reconciliation = base_reconciliation_status(records)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        failures.append(str(error))
    return {
        "status": "ready" if not failures else "degraded",
        "records": len(records),
        "candidate": sum(1 for item in records.values() if item.get("state") == "candidate"),
        "approved": sum(1 for item in records.values() if item.get("state") == "approved"),
        "superseded": sum(1 for item in records.values() if item.get("state") == "superseded"),
        "revoked": sum(1 for item in records.values() if item.get("state") == "revoked"),
        "archived_in_base": sum(
            1 for item in records.values() if item.get("state") == "archived-in-base"
        ),
        "manifest_revision": manifest.get("revision"),
        "migration": migration,
        "base_reconciliation": base_reconciliation,
        "failures": failures,
    }
