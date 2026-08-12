#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import effective_skills
import learning_store
import session_distill


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_PATH = Path("knowledge-packs/approved.jsonl")


def now() -> str:
    return datetime.now(UTC).isoformat()


def legacy_event_id(file_sha256: str, event: str, sequence: int = 0) -> str:
    return f"legacy-{file_sha256[:20]}-{event}-{sequence}"


def git(*args: str, cwd: Path = ROOT, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def record_id(value: dict[str, Any]) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{learning_store.digest(value)[:10]}"


def command_record(args: argparse.Namespace) -> None:
    kind = args.kind or (
        "knowledge-entry" if args.ownership == "upstream" else "instruction-rule"
    )
    seed = {
        "kind": kind,
        "skill": args.skill,
        "ownership": args.ownership,
        "source": args.source or "local",
        "task": args.task,
        "failure": args.failure,
        "correction": args.correction,
        "successful_pattern": args.success,
        "conditions": args.conditions,
        "confidence": args.confidence,
        "sensitivity": args.sensitivity,
        "evidence_refs": args.evidence,
        "semantic_id": args.semantic_id,
        "created_at": now(),
    }
    seed["id"] = record_id(seed)
    value = learning_store.make_object(seed)
    with learning_store.store_lock():
        existing = next(
            (
                item
                for item in learning_store.state_index().values()
                if item.get("object", {}).get("fingerprint") == value["fingerprint"]
            ),
            None,
        )
        if existing:
            event = learning_store.append_event(
                {
                    "event": "observed",
                    "record_id": existing["id"],
                    "object_sha256": existing.get("object_sha256"),
                    "occurrences": 1,
                }
            )
            print(f"[existing] {existing['id']} occurrences={existing.get('occurrences', 1) + 1}")
            print(learning_store.ledger_path())
            return
        sha256, path = learning_store.write_object(value)
        learning_store.append_event(
            {
                "event": "recorded",
                "record_id": value["id"],
                "object_sha256": sha256,
            }
        )
    print(f"[recorded] {value['id']} kind={kind}")
    print(path)


def eval_attestation(path: Path, skill: str) -> dict[str, Any]:
    path = path.expanduser().resolve()
    report = json.loads(path.read_text(encoding="utf-8"))
    core = {
        key: report.get(key)
        for key in (
            "schema_version",
            "host",
            "model",
            "effective_revision",
            "dataset_sha256",
            "cases",
        )
    }
    if report.get("result_sha256") != learning_store.digest(core):
        raise ValueError("Skill Eval result hash is invalid")
    if not report.get("passed"):
        raise ValueError("Skill Eval did not pass")
    matching = [
        item
        for item in report.get("cases", [])
        if item.get("skill") == skill and item.get("type") == "behavior"
    ]
    if not matching or not all(item.get("passed") for item in matching):
        raise ValueError(f"Skill Eval has no passing behavior case for {skill}")
    return {
        "eval_result_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "effective_revision": report.get("effective_revision"),
        "dataset_sha256": report.get("dataset_sha256"),
    }


def promote(
    record: dict[str, Any],
    *,
    allow_medium: bool,
    approval_basis: str = "independent-review",
    independent_scenarios: int = 2,
    eval_result_sha256: str | None = None,
) -> dict[str, Any]:
    if record.get("state") == "approved":
        return effective_skills.compile_snapshot(activate=True)
    value = record["object"]
    failures = learning_store.validate_for_approval(value, allow_medium=allow_medium)
    if failures:
        raise ValueError("learning approval blocked:\n- " + "\n- ".join(failures))
    with learning_store.store_lock():
        prospective = [*learning_store.approved_objects(), value]
        manifest = learning_store.manifest_for_objects(prospective)
        result = effective_skills.compile_snapshot(manifest=manifest)
        learning_store.append_event(
            {
                "event": "approved",
                "record_id": record["id"],
                "object_sha256": record["object_sha256"],
                "approval_basis": approval_basis,
                "independent_scenarios": independent_scenarios,
                "eval_result_sha256": eval_result_sha256,
            }
        )
        committed = learning_store.rebuild_manifest()
        if committed["revision"] != manifest["revision"]:
            raise ValueError("learning state changed during approval")
        effective_skills.activate_revision(str(result["revision"]))
    return result


def command_promote(args: argparse.Namespace) -> None:
    if args.review or args.commit:
        print("[notice] --review/--commit are retired; approval stays in the local content plane")
    record = learning_store.find_record(args.record_id)
    scenarios = args.independent_scenarios
    approval_basis = "independent-review"
    eval_sha256 = None
    if args.session_correction:
        if record["object"].get("kind") == "operator-policy":
            raise ValueError("global operator policy requires two independent scenarios")
        if args.eval_result is None:
            raise ValueError("single-session correction approval requires --eval-result")
        attestation = eval_attestation(args.eval_result, str(record["object"]["skill"]))
        approval_basis = "single-session-user-correction-with-skill-eval"
        scenarios = 1
        eval_sha256 = attestation["eval_result_sha256"]
    if scenarios < 1:
        raise ValueError("independent scenarios must be positive")
    result = promote(
        record,
        allow_medium=args.allow_medium,
        approval_basis=approval_basis,
        independent_scenarios=scenarios,
        eval_result_sha256=eval_sha256,
    )
    print(f"[approved] {args.record_id} effective_revision={result['revision']}")


def command_migrate(args: argparse.Namespace) -> None:
    legacy = learning_store.legacy_records()
    planned = []
    for item in legacy:
        value = item["value"]
        object_value = item["object"]
        object_sha256 = learning_store.digest(object_value)
        destination_state = {
            "candidate": "candidate",
            "promoted": "archived-in-base",
            "dismissed": "revoked",
        }[item["state"]]
        planned.append(
            {
                "legacy_id": str(value["id"]),
                "legacy_filename": item["filename"],
                "legacy_file_sha256": item["file_sha256"],
                "legacy_state": item["state"],
                "new_state": destination_state,
                "object_sha256": object_sha256,
            }
        )
    if args.dry_run:
        print(
            json.dumps(
                {
                    "legacy_records": len(planned),
                    "states": {
                        state: sum(1 for item in planned if item["new_state"] == state)
                        for state in ("candidate", "archived-in-base", "revoked")
                    },
                    "records": planned,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    receipt_records = []
    with learning_store.store_lock():
        for source, receipt in zip(legacy, planned, strict=True):
            value = source["value"]
            object_sha256, _ = learning_store.write_object(source["object"])
            event_ids: list[str] = []
            if source["state"] == "promoted":
                event = learning_store.append_event(
                    {
                        "event_id": legacy_event_id(source["file_sha256"], "imported-base"),
                        "event": "imported-base",
                        "record_id": value["id"],
                        "object_sha256": object_sha256,
                        "occurrences": max(1, int(value.get("occurrences", 1))),
                    }
                )
                event_ids.append(event["event_id"])
            else:
                event = learning_store.append_event(
                    {
                        "event_id": legacy_event_id(source["file_sha256"], "recorded"),
                        "event": "recorded",
                        "record_id": value["id"],
                        "object_sha256": object_sha256,
                    }
                )
                event_ids.append(event["event_id"])
                occurrences = max(1, int(value.get("occurrences", 1)))
                if occurrences > 1:
                    observed = learning_store.append_event(
                        {
                            "event_id": legacy_event_id(source["file_sha256"], "observed"),
                            "event": "observed",
                            "record_id": value["id"],
                            "object_sha256": object_sha256,
                            "occurrences": occurrences - 1,
                        }
                    )
                    event_ids.append(observed["event_id"])
                if source["state"] == "dismissed":
                    revoked = learning_store.append_event(
                        {
                            "event_id": legacy_event_id(source["file_sha256"], "revoked"),
                            "event": "revoked",
                            "record_id": value["id"],
                            "object_sha256": object_sha256,
                            "reason": value.get("dismissed_reason") or "legacy dismissal",
                        }
                    )
                    event_ids.append(revoked["event_id"])
            receipt_records.append({**receipt, "event_ids": event_ids})
        core = {"schema_version": 1, "records": receipt_records}
        receipt = {
            **core,
            "revision": learning_store.digest(core),
            "generated_at": now(),
        }
        learning_store.atomic_json(learning_store.migration_receipt_path(), receipt)
        learning_store.rebuild_manifest()
    print(
        json.dumps(
            {
                "migrated": len(receipt_records),
                "receipt": str(learning_store.migration_receipt_path()),
                "revision": receipt["revision"],
                "status": learning_store.migration_status(),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


def command_revoke(args: argparse.Namespace) -> None:
    record = learning_store.find_record(args.record_id)
    with learning_store.store_lock():
        prospective = [
            value
            for value in learning_store.approved_objects()
            if value["id"] != record["id"]
        ]
        manifest = learning_store.manifest_for_objects(prospective)
        result = effective_skills.compile_snapshot(manifest=manifest)
        learning_store.append_event(
            {
                "event": "revoked",
                "record_id": record["id"],
                "object_sha256": record.get("object_sha256"),
                "reason": args.reason,
            }
        )
        committed = learning_store.rebuild_manifest()
        if committed["revision"] != manifest["revision"]:
            raise ValueError("learning state changed during revocation")
        effective_skills.activate_revision(str(result["revision"]))
    print(f"[revoked] {record['id']} effective_revision={result['revision']}")


def command_supersede(args: argparse.Namespace) -> None:
    old = learning_store.find_record(args.record_id)
    replacement = learning_store.find_record(args.replacement_id)
    old_object = old["object"]
    new_object = replacement["object"]
    if (old_object["skill"], old_object["kind"]) != (new_object["skill"], new_object["kind"]):
        raise ValueError("replacement must target the same skill and learning kind")
    if replacement.get("state") != "approved":
        failures = [
            item
            for item in learning_store.validate_for_approval(
                new_object, allow_medium=args.allow_medium
            )
            if "use supersede" not in item
        ]
        if failures:
            raise ValueError("learning approval blocked:\n- " + "\n- ".join(failures))
    with learning_store.store_lock():
        prospective = [
            value
            for value in learning_store.approved_objects()
            if value["id"] not in {old["id"], replacement["id"]}
        ]
        prospective.append(new_object)
        manifest = learning_store.manifest_for_objects(prospective)
        result = effective_skills.compile_snapshot(manifest=manifest)
        learning_store.append_event(
            {
                "event": "superseded",
                "record_id": old["id"],
                "object_sha256": old.get("object_sha256"),
                "supersedes": replacement["id"],
                "reason": args.reason,
            }
        )
        if replacement.get("state") != "approved":
            learning_store.append_event(
                {
                    "event": "approved",
                    "record_id": replacement["id"],
                    "object_sha256": replacement.get("object_sha256"),
                }
            )
        committed = learning_store.rebuild_manifest()
        if committed["revision"] != manifest["revision"]:
            raise ValueError("learning state changed during supersession")
        effective_skills.activate_revision(str(result["revision"]))
    print(f"[superseded] {old['id']} -> {replacement['id']} effective_revision={result['revision']}")


def archived_hashes(root: Path = ROOT) -> set[str]:
    path = root / ARCHIVE_PATH
    if not path.exists():
        return set()
    values = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("object_sha256"):
            values.add(str(item["object_sha256"]))
    return values


def archive_entries() -> list[dict[str, Any]]:
    entries = []
    for record in learning_store.state_index().values():
        value = record.get("object", {})
        approvals = [
            event for event in record.get("events", []) if event.get("event") == "approved"
        ]
        scenarios = int(approvals[-1].get("independent_scenarios", 2)) if approvals else 0
        if record.get("state") != "approved" or value.get("kind") == "operator-policy":
            continue
        if scenarios < 2:
            continue
        entries.append(
            {
                "schema_version": 1,
                "id": value["id"],
                "semantic_id": value["semantic_id"],
                "kind": value["kind"],
                "skill": value["skill"],
                "conditions": value["conditions"],
                "successful_pattern": value["successful_pattern"],
                "evidence_hashes": value["evidence_hashes"],
                "object_sha256": learning_store.digest(value),
            }
        )
    return entries


def write_archive(root: Path, entries: list[dict[str, Any]]) -> None:
    path = root / ARCHIVE_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n" for value in entries),
        encoding="utf-8",
    )
    manifest = {
        "schema_version": 1,
        "objects": len(entries),
        "content_sha256": learning_store.digest(entries),
    }
    learning_store.atomic_json(path.parent / "manifest.json", manifest)


def command_archive(args: argparse.Namespace) -> None:
    entries = archive_entries()
    missing = [item for item in entries if item["object_sha256"] not in archived_hashes()]
    if args.dry_run:
        print(json.dumps({"eligible": len(missing), "objects": missing}, ensure_ascii=False, indent=2))
        return
    if not missing:
        print("[current] no approved knowledge requires archival")
        return
    if git("status", "--porcelain").stdout.strip():
        raise ValueError("archive requires a clean main worktree")
    if git("branch", "--show-current").stdout.strip() != "main":
        raise ValueError("archive must start from main")
    base = git("rev-parse", "origin/main").stdout.strip()
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    tag = f"blue-sec-candidate/knowledge-{stamp}"
    keep_local_tag = not args.push
    with tempfile.TemporaryDirectory(prefix="blue-sec-archive-") as temporary:
        worktree = Path(temporary) / "worktree"
        git("worktree", "add", "--detach", str(worktree), base)
        try:
            combined = {item["object_sha256"]: item for item in entries}
            write_archive(worktree, sorted(combined.values(), key=lambda item: item["object_sha256"]))
            git("add", str(ARCHIVE_PATH), "knowledge-packs/manifest.json", cwd=worktree)
            git(
                "-c",
                "user.name=Blue Sec Learning",
                "-c",
                "user.email=blue-sec-learning@invalid.local",
                "commit",
                "-m",
                f"Archive approved knowledge: {stamp}",
                cwd=worktree,
            )
            commit = git("rev-parse", "HEAD", cwd=worktree).stdout.strip()
            git("tag", tag, commit)
            if args.push:
                git("push", "origin", f"refs/tags/{tag}")
        finally:
            git("worktree", "remove", "--force", str(worktree), check=False)
            if not keep_local_tag:
                git("tag", "-d", tag, check=False)
    print(
        json.dumps(
            {
                "candidate_tag": tag,
                "commit": commit,
                "pushed": args.push,
                "local_reference_retained": keep_local_tag,
            },
            indent=2,
        )
    )


def command_list(args: argparse.Namespace) -> None:
    records = learning_store.state_index()
    shown = 0
    for record in sorted(records.values(), key=lambda item: item["id"]):
        if args.state != "all" and record.get("state") != args.state:
            continue
        value = record.get("object", {})
        print(
            f"{record['id']}\t{record['state']}\t{value.get('kind')}\t"
            f"{value.get('skill')}\tx{record.get('occurrences', 1)}"
        )
        shown += 1
    print(f"[total] {shown}")


def command_show(args: argparse.Namespace) -> None:
    print(json.dumps(learning_store.find_record(args.record_id), ensure_ascii=False, indent=2))


def command_status(_: argparse.Namespace) -> None:
    result = learning_store.audit_store()
    result["effective"] = effective_skills.status()
    result["archive_eligible"] = sum(
        item["object_sha256"] not in archived_hashes() for item in archive_entries()
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


def command_review(args: argparse.Namespace) -> None:
    """Expose session lesson bundles as review cards; never approve implicitly."""
    session_distill.command_review(args)


def command_reconcile(_: argparse.Namespace) -> None:
    with learning_store.store_lock():
        manifest = learning_store.rebuild_manifest()
        revision = effective_skills.revision_for(manifest)
        destination = effective_skills.effective_root() / revision
        failures = effective_skills.snapshot_failures(revision) if destination.exists() else []
        quarantined = None
        if failures:
            quarantined = destination.with_name(f".{revision}.corrupt-{os.getpid()}")
            destination.replace(quarantined)
        metadata = effective_skills.compile_snapshot(manifest=manifest)
        effective_skills.activate_revision(str(metadata["revision"]))
    print(
        json.dumps(
            {
                "status": "ready",
                "revision": metadata["revision"],
                "quarantined": str(quarantined) if quarantined else None,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


def command_reconcile_base(args: argparse.Namespace) -> None:
    capabilities = {
        item["id"]: item for item in learning_store.load_base_capabilities()
    }
    records = learning_store.state_index()
    selected: list[tuple[dict[str, Any], dict[str, Any], str]] = []
    if bool(args.record) != bool(args.capability):
        raise ValueError("--record and --capability must be supplied together")
    if args.record:
        record = learning_store.find_record(args.record)
        capability = capabilities.get(args.capability)
        if not capability:
            raise ValueError(f"base capability not found: {args.capability}")
        if record.get("state") != "candidate":
            raise ValueError("only candidate records can be reconciled against base")
        if capability["skill"] != record.get("object", {}).get("skill"):
            raise ValueError("base capability targets a different Skill")
        selected.append((record, capability, "explicit-confirmation"))
    else:
        for record in records.values():
            if record.get("state") != "candidate":
                continue
            matches = learning_store.base_capability_matches(record.get("object", {}))
            if len(matches) == 1:
                selected.append((record, matches[0], "deterministic-terms"))

    base_commit = git("rev-parse", "HEAD").stdout.strip()
    mappings = [
        {
            "record_id": record["id"],
            "object_sha256": record.get("object_sha256"),
            "capability_id": capability["id"],
            "coverage_match": match,
            "base_commit": base_commit,
        }
        for record, capability, match in selected
    ]
    if args.dry_run:
        print(
            json.dumps(
                {
                    "status": "dry-run",
                    "base_commit": base_commit,
                    "eligible": len(mappings),
                    "records": mappings,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    with learning_store.store_lock():
        for mapping in mappings:
            event_id = "base-" + learning_store.digest(
                {
                    "record_id": mapping["record_id"],
                    "capability_id": mapping["capability_id"],
                    "base_commit": mapping["base_commit"],
                }
            )[:24]
            learning_store.append_event(
                {
                    "event_id": event_id,
                    "event": "covered-by-base",
                    **mapping,
                }
            )
        receipt_path = learning_store.base_reconciliation_receipt_path()
        previous = {}
        if receipt_path.exists():
            previous = json.loads(receipt_path.read_text(encoding="utf-8"))
        combined = {
            str(item["record_id"]): item
            for item in previous.get("records", [])
            if isinstance(item, dict) and item.get("record_id")
        }
        combined.update({str(item["record_id"]): item for item in mappings})
        receipt = {
            "schema_version": 1,
            "generated_at": now(),
            "base_commit": base_commit,
            "records": [combined[key] for key in sorted(combined)],
        }
        receipt["revision"] = learning_store.digest(receipt["records"])
        learning_store.atomic_json(receipt_path, receipt)
    print(
        json.dumps(
            {
                "status": "applied",
                "base_commit": base_commit,
                "reconciled": len(mappings),
                "receipt": str(learning_store.base_reconciliation_receipt_path()),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


def command_audit(_: argparse.Namespace) -> None:
    result = learning_store.audit_store()
    if result["failures"]:
        raise ValueError("\n".join(result["failures"]))
    print(
        f"[ok] learning ledger records={result['records']} "
        f"candidate={result['candidate']} approved={result['approved']}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage the Blue Sec Hub local knowledge plane")
    commands = parser.add_subparsers(dest="command", required=True)

    record = commands.add_parser("record", help="capture an immutable learning candidate")
    record.add_argument("--skill", required=True)
    record.add_argument("--ownership", choices=("local", "upstream"), default="local")
    record.add_argument("--source")
    record.add_argument("--kind", choices=sorted(learning_store.OBJECT_KINDS))
    record.add_argument("--semantic-id")
    record.add_argument("--task", required=True)
    record.add_argument("--failure", required=True)
    record.add_argument("--correction", required=True)
    record.add_argument("--success", required=True)
    record.add_argument("--conditions", required=True)
    record.add_argument("--evidence", action="append", default=[])
    record.add_argument("--confidence", choices=("low", "medium", "high"), default="medium")
    record.add_argument("--sensitivity", choices=("public", "internal", "restricted"), default="internal")
    record.set_defaults(function=command_record)

    migrate = commands.add_parser("migrate", help="import legacy learning records")
    migrate.add_argument("--dry-run", action="store_true")
    migrate.set_defaults(function=command_migrate)

    promote_parser = commands.add_parser("promote", help="approve content without changing Git")
    promote_parser.add_argument("record_id")
    promote_parser.add_argument("--allow-medium", action="store_true")
    promote_parser.add_argument("--expect-text", action="append", default=[])
    promote_parser.add_argument("--include", action="append", default=[])
    promote_parser.add_argument("--commit", action="store_true")
    promote_parser.add_argument("--review", action="store_true")
    promote_parser.add_argument("--session-correction", action="store_true")
    promote_parser.add_argument("--eval-result", type=Path)
    promote_parser.add_argument("--independent-scenarios", type=int, default=2)
    promote_parser.set_defaults(function=command_promote)

    revoke = commands.add_parser("revoke")
    revoke.add_argument("record_id")
    revoke.add_argument("--reason", required=True)
    revoke.set_defaults(function=command_revoke)

    dismiss = commands.add_parser("dismiss")
    dismiss.add_argument("record_id")
    dismiss.add_argument("--reason", required=True)
    dismiss.set_defaults(function=command_revoke)

    supersede = commands.add_parser("supersede")
    supersede.add_argument("record_id")
    supersede.add_argument("replacement_id")
    supersede.add_argument("--reason", required=True)
    supersede.add_argument("--allow-medium", action="store_true")
    supersede.set_defaults(function=command_supersede)

    archive = commands.add_parser("archive")
    archive.add_argument("--dry-run", action="store_true")
    archive.add_argument("--push", action="store_true")
    archive.set_defaults(function=command_archive)

    listing = commands.add_parser("list")
    listing.add_argument(
        "--state",
        choices=("all", "candidate", "approved", "superseded", "revoked", "archived-in-base"),
        default="all",
    )
    listing.set_defaults(function=command_list)
    show = commands.add_parser("show")
    show.add_argument("record_id")
    show.set_defaults(function=command_show)
    commands.add_parser("status").set_defaults(function=command_status)
    review = commands.add_parser(
        "review", help="show privacy-safe session learning candidates for approval"
    )
    review.add_argument("--run-id")
    review.add_argument("--candidate", action="append", default=[])
    review.add_argument("--include-blocked", action="store_true")
    review.add_argument("--json", action="store_true")
    review.set_defaults(function=command_review)
    commands.add_parser("audit").set_defaults(function=command_audit)
    commands.add_parser("reconcile").set_defaults(function=command_reconcile)
    reconcile_base = commands.add_parser(
        "reconcile-base",
        help="mark local candidates already implemented by versioned base capabilities",
    )
    mode = reconcile_base.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    reconcile_base.add_argument("--record")
    reconcile_base.add_argument("--capability")
    reconcile_base.set_defaults(function=command_reconcile_base)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        args.function(args)
    except (OSError, ValueError, TimeoutError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        detail = error.stderr.strip() if isinstance(error, subprocess.CalledProcessError) and error.stderr else str(error)
        print(f"error: {detail}", file=os.sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
