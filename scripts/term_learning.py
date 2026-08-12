#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from security_terms import (
    GLOSSARY,
    compact,
    load_glossary,
    normalize,
    validate_glossary,
)
from term_sources import discover_security_terms, parse_cwe_catalog


ROOT = Path(__file__).resolve().parents[1]
CACHE_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_CACHE",
        Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
        / "blue-sec-hub",
    )
)
DATA_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_DATA",
        Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        / "blue-sec-hub",
    )
)
UPSTREAMS = CACHE_ROOT / "upstreams"
TERM_ROOT = DATA_ROOT / "term-learning"
OFFICIAL = TERM_ROOT / "official.json"
CANDIDATES = TERM_ROOT / "candidates.jsonl"
CONFLICTS = TERM_ROOT / "conflicts.jsonl"
REJECTED = TERM_ROOT / "rejected.jsonl"
CWE_ARCHIVE = CACHE_ROOT / "feeds" / "mitre-cwe" / "cwec_latest.xml.zip"
SCHEMA_VERSION = 1


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(normalize(value).encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{digest}"


def slug(value: str) -> str:
    result = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    return result[:80] or "unknown"


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600 if TERM_ROOT in path.parents else 0o644)
    temporary.replace(path)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    result = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{number}: {error}") from error
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{number}: record must be an object")
        result.append(value)
    return result


def atomic_jsonl(path: Path, values: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    content = "".join(
        json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n"
        for value in values
    )
    temporary.write_text(content, encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def active_alias_index() -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for term in load_glossary()["terms"]:
        for alias in (
            term["id"],
            *term.get("triggers", []),
            *term.get("aliases", []),
        ):
            result.setdefault(compact(alias), set()).add(str(term["id"]))
    return result


def update_candidates(discovered: list[dict[str, Any]]) -> dict[str, int]:
    previous = {value["id"]: value for value in load_jsonl(CANDIDATES)}
    rejected_aliases = {
        compact(alias)
        for value in load_jsonl(REJECTED)
        for alias in [value.get("term", ""), *value.get("aliases", [])]
        if alias
    }
    active = active_alias_index()
    current_ids: set[str] = set()
    covered = rejected = 0

    for item in discovered:
        aliases = [item["term"], *item["aliases"]]
        normalized_aliases = {compact(alias) for alias in aliases}
        candidate_id = stable_id("term", item["term"])
        if normalized_aliases & rejected_aliases:
            rejected += 1
            continue
        if any(alias in active for alias in normalized_aliases):
            covered += 1
            if candidate_id in previous:
                current_ids.add(candidate_id)
                if previous[candidate_id].get("state") != "promoted":
                    previous[candidate_id]["state"] = "covered"
                previous[candidate_id]["covered_by"] = sorted(
                    {
                        canonical
                        for alias in normalized_aliases
                        for canonical in active.get(alias, set())
                    }
                )
                previous[candidate_id]["last_seen_at"] = now()
            continue
        current_ids.add(candidate_id)
        source_names = {source["name"] for source in item["sources"]}
        state = "ready" if len(source_names) >= 2 else "candidate"
        existing = previous.get(candidate_id, {})
        previous[candidate_id] = {
            "schema_version": SCHEMA_VERSION,
            "id": candidate_id,
            "state": (
                existing.get("state")
                if existing.get("state") == "promoted"
                else state
            ),
            "term": item["term"],
            "canonical_suggestion": slug(item["term"]),
            "aliases": sorted(set(aliases), key=str.casefold),
            "sources": item["sources"],
            "source_count": len(source_names),
            "first_seen_at": existing.get("first_seen_at") or now(),
            "last_seen_at": now(),
        }

    for candidate_id, value in previous.items():
        if candidate_id not in current_ids and value.get("state") in {
            "candidate",
            "ready",
        }:
            value["state"] = "stale"
    values = sorted(previous.values(), key=lambda item: item["id"])
    atomic_jsonl(CANDIDATES, values)
    return {
        "discovered": len(discovered),
        "covered": covered,
        "rejected": rejected,
        "candidates": sum(
            1 for value in values if value["state"] == "candidate"
        ),
        "ready": sum(1 for value in values if value["state"] == "ready"),
        "stale": sum(1 for value in values if value["state"] == "stale"),
        "covered_records": sum(
            1 for value in values if value["state"] == "covered"
        ),
    }


def command_discover(_: argparse.Namespace) -> None:
    try:
        official = parse_cwe_catalog(CWE_ARCHIVE)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        if not OFFICIAL.exists():
            raise
        official = json.loads(OFFICIAL.read_text(encoding="utf-8"))
        print(f"[warning] keeping previous official terms: {error}")
    if official["source"]["available"] or not OFFICIAL.exists():
        atomic_json(OFFICIAL, official)
    else:
        official = json.loads(OFFICIAL.read_text(encoding="utf-8"))
        print(f"[warning] keeping previous official terms; missing {CWE_ARCHIVE}")
    load_glossary.cache_clear()
    stats = update_candidates(discover_security_terms(UPSTREAMS, CACHE_ROOT))
    print(
        f"[official] cwe={len(official['terms'])} "
        f"available={str(official['source']['available']).lower()}"
    )
    print(
        "[community] "
        + " ".join(f"{name}={value}" for name, value in stats.items())
    )
    print(f"[data] {TERM_ROOT}")


def find_candidate(value: str) -> dict[str, Any]:
    candidates = load_jsonl(CANDIDATES)
    exact = [item for item in candidates if item["id"] == value]
    if exact:
        return exact[0]
    matches = [item for item in candidates if item["id"].startswith(value)]
    if len(matches) != 1:
        raise SystemExit(f"candidate not found or ambiguous: {value}")
    return matches[0]


def command_list(args: argparse.Namespace) -> None:
    shown = 0
    for value in load_jsonl(CANDIDATES):
        if args.state != "all" and value.get("state") != args.state:
            continue
        print(
            f"{value['id']}\t{value['state']}\t"
            f"sources={value.get('source_count', 0)}\t{value['term']}"
        )
        shown += 1
    print(f"[total] {shown}")


def command_show(args: argparse.Namespace) -> None:
    print(json.dumps(find_candidate(args.candidate_id), ensure_ascii=False, indent=2))


def append_conflict(
    candidate: dict[str, Any],
    canonical: str,
    collisions: dict[str, list[str]],
) -> None:
    conflicts = load_jsonl(CONFLICTS)
    conflict = {
        "schema_version": SCHEMA_VERSION,
        "id": stable_id("conflict", candidate["id"] + canonical),
        "state": "open",
        "candidate_id": candidate["id"],
        "term": candidate["term"],
        "requested_canonical": canonical,
        "collisions": collisions,
        "created_at": now(),
    }
    conflicts = [value for value in conflicts if value["id"] != conflict["id"]]
    conflicts.append(conflict)
    atomic_jsonl(CONFLICTS, sorted(conflicts, key=lambda item: item["id"]))


def command_promote(args: argparse.Namespace) -> None:
    candidate = find_candidate(args.candidate_id)
    if candidate.get("state") == "promoted":
        print(f"[current] already promoted: {candidate['id']}")
        return
    if candidate.get("state") == "covered":
        raise SystemExit(
            f"candidate is already covered by {candidate.get('covered_by', [])}"
        )
    canonical = args.canonical or candidate["canonical_suggestion"]
    if not re.fullmatch(r"[a-z0-9-]+", canonical):
        raise SystemExit("canonical id must contain lowercase letters, digits and hyphens")

    glossary = json.loads(GLOSSARY.read_text(encoding="utf-8"))
    terms = glossary["terms"]
    existing = next((term for term in terms if term["id"] == canonical), None)
    aliases = list(
        dict.fromkeys(
            [
                candidate["term"],
                *candidate.get("aliases", []),
                *args.alias,
            ]
        )
    )
    triggers = list(dict.fromkeys([candidate["term"], *args.trigger, *args.alias]))
    collisions: dict[str, list[str]] = {}
    for term in terms:
        if term["id"] == canonical:
            continue
        known = {
            compact(value)
            for value in (
                term["id"],
                *term.get("triggers", []),
                *term.get("aliases", []),
            )
        }
        for alias in [*aliases, *triggers]:
            if compact(alias) in known:
                collisions.setdefault(alias, []).append(term["id"])
    if collisions:
        append_conflict(candidate, canonical, collisions)
        raise SystemExit(
            "promotion blocked by alias conflicts; inspect "
            f"{CONFLICTS}"
        )

    if existing:
        existing["aliases"] = sorted(
            set(existing.get("aliases", [])) | set(aliases),
            key=str.casefold,
        )
        existing["triggers"] = sorted(
            set(existing.get("triggers", [])) | set(triggers),
            key=str.casefold,
        )
    else:
        terms.append(
            {
                "id": canonical,
                "category": args.category,
                "triggers": triggers,
                "aliases": aliases,
            }
        )

    original = GLOSSARY.read_text(encoding="utf-8")
    atomic_json(GLOSSARY, glossary)
    load_glossary.cache_clear()
    failures = validate_glossary()
    if failures:
        GLOSSARY.write_text(original, encoding="utf-8")
        GLOSSARY.chmod(0o644)
        load_glossary.cache_clear()
        raise SystemExit("\n".join(failures))

    candidates = load_jsonl(CANDIDATES)
    for value in candidates:
        if value["id"] == candidate["id"]:
            value["state"] = "promoted"
            value["promotion"] = {
                "canonical": canonical,
                "promoted_at": now(),
                "glossary": str(GLOSSARY),
                "evidence_refs": args.evidence,
            }
    atomic_jsonl(CANDIDATES, candidates)
    print(f"[promoted] {candidate['id']} -> {canonical}")
    print(GLOSSARY)


def command_add(args: argparse.Namespace) -> None:
    candidate_id = stable_id(
        "learning-term",
        "\n".join(
            [
                args.canonical,
                args.term,
                *sorted(args.alias, key=str.casefold),
                *sorted(args.trigger, key=str.casefold),
            ]
        ),
    )
    candidates = load_jsonl(CANDIDATES)
    existing = next(
        (value for value in candidates if value["id"] == candidate_id),
        None,
    )
    if not existing:
        candidates.append(
            {
                "schema_version": SCHEMA_VERSION,
                "id": candidate_id,
                "state": "ready",
                "term": args.term,
                "canonical_suggestion": args.canonical,
                "aliases": sorted(
                    set([args.term, *args.alias]),
                    key=str.casefold,
                ),
                "sources": [
                    {
                        "name": "blue-skill-learning",
                        "kind": "validated-local-learning",
                        "evidence_refs": args.evidence,
                    }
                ],
                "source_count": 1,
                "first_seen_at": now(),
                "last_seen_at": now(),
            }
        )
        atomic_jsonl(CANDIDATES, sorted(candidates, key=lambda item: item["id"]))
    promotion_args = argparse.Namespace(
        candidate_id=candidate_id,
        canonical=args.canonical,
        category=args.category,
        alias=args.alias,
        trigger=args.trigger,
        evidence=args.evidence,
    )
    command_promote(promotion_args)


def command_dismiss(args: argparse.Namespace) -> None:
    candidate = find_candidate(args.candidate_id)
    rejected = load_jsonl(REJECTED)
    record = {
        "schema_version": SCHEMA_VERSION,
        "id": stable_id("rejected", candidate["term"]),
        "term": candidate["term"],
        "aliases": candidate.get("aliases", []),
        "reason": args.reason,
        "rejected_at": now(),
    }
    rejected = [value for value in rejected if value["id"] != record["id"]]
    rejected.append(record)
    atomic_jsonl(REJECTED, sorted(rejected, key=lambda item: item["id"]))
    candidates = load_jsonl(CANDIDATES)
    for value in candidates:
        if value["id"] == candidate["id"]:
            value["state"] = "dismissed"
            value["dismissed_at"] = now()
            value["dismissed_reason"] = args.reason
    atomic_jsonl(CANDIDATES, candidates)
    print(f"[dismissed] {candidate['id']}")


def command_prune(args: argparse.Namespace) -> None:
    if args.stale_days < 0:
        raise SystemExit("--stale-days must be zero or greater")
    cutoff = datetime.now(timezone.utc) - timedelta(days=args.stale_days)
    candidates = load_jsonl(CANDIDATES)
    kept = []
    removed = 0
    for value in candidates:
        if value.get("state") != "stale":
            kept.append(value)
            continue
        try:
            last_seen = datetime.fromisoformat(value["last_seen_at"])
        except (KeyError, ValueError):
            kept.append(value)
            continue
        if last_seen <= cutoff:
            removed += 1
        else:
            kept.append(value)
    atomic_jsonl(CANDIDATES, kept)
    print(f"[pruned] stale={removed} retained={len(kept)}")


def command_audit(_: argparse.Namespace) -> None:
    failures = validate_glossary()
    for path in (CANDIDATES, CONFLICTS, REJECTED):
        try:
            values = load_jsonl(path)
        except ValueError as error:
            failures.append(str(error))
            continue
        identifiers: set[str] = set()
        for value in values:
            identifier = value.get("id")
            if not identifier or identifier in identifiers:
                failures.append(f"{path}: duplicate or missing id {identifier}")
            identifiers.add(str(identifier))
            if path == CANDIDATES and value.get("state") not in {
                "candidate",
                "ready",
                "stale",
                "covered",
                "promoted",
                "dismissed",
            }:
                failures.append(f"{path}: invalid state {value.get('state')}")
            if path == CONFLICTS and value.get("state") not in {
                "open",
                "resolved",
            }:
                failures.append(f"{path}: invalid state {value.get('state')}")
    if OFFICIAL.exists():
        try:
            official = json.loads(OFFICIAL.read_text(encoding="utf-8"))
            if official.get("schema_version") != SCHEMA_VERSION:
                failures.append(f"{OFFICIAL}: invalid schema version")
        except json.JSONDecodeError as error:
            failures.append(f"{OFFICIAL}: {error}")
    if failures:
        raise SystemExit("\n".join(failures))
    candidates = load_jsonl(CANDIDATES)
    official_count = 0
    if OFFICIAL.exists():
        official_count = len(
            json.loads(OFFICIAL.read_text(encoding="utf-8")).get("terms", [])
        )
    print(
        f"[ok] terms={len(load_glossary()['terms'])} official={official_count} "
        f"candidates={sum(1 for value in candidates if value.get('state') == 'candidate')} "
        f"ready={sum(1 for value in candidates if value.get('state') == 'ready')} "
        f"stale={sum(1 for value in candidates if value.get('state') == 'stale')} "
        f"covered={sum(1 for value in candidates if value.get('state') == 'covered')} "
        f"conflicts={len(load_jsonl(CONFLICTS))}"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Discover and safely promote Blue Sec Hub security terms"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    discover = commands.add_parser(
        "discover",
        help="refresh official terms and community candidates",
    )
    discover.set_defaults(function=command_discover)

    listing = commands.add_parser("list", help="list term candidates")
    listing.add_argument(
        "--state",
        choices=(
            "all",
            "candidate",
            "ready",
            "stale",
            "covered",
            "promoted",
            "dismissed",
        ),
        default="all",
    )
    listing.set_defaults(function=command_list)

    show = commands.add_parser("show", help="show one candidate")
    show.add_argument("candidate_id")
    show.set_defaults(function=command_show)

    promote = commands.add_parser(
        "promote",
        help="promote a reviewed candidate into the repository glossary",
    )
    promote.add_argument("candidate_id")
    promote.add_argument("--canonical")
    promote.add_argument("--category", default="emerging")
    promote.add_argument("--alias", action="append", default=[])
    promote.add_argument("--trigger", action="append", default=[])
    promote.add_argument("--evidence", action="append", required=True)
    promote.set_defaults(function=command_promote)

    add = commands.add_parser(
        "add",
        help="add a validated local term or alias without an upstream candidate",
    )
    add.add_argument("--canonical", required=True)
    add.add_argument("--term", required=True)
    add.add_argument("--category", default="emerging")
    add.add_argument("--alias", action="append", default=[])
    add.add_argument("--trigger", action="append", default=[])
    add.add_argument("--evidence", action="append", required=True)
    add.set_defaults(function=command_add)

    dismiss = commands.add_parser("dismiss", help="reject a noisy or ambiguous term")
    dismiss.add_argument("candidate_id")
    dismiss.add_argument("--reason", required=True)
    dismiss.set_defaults(function=command_dismiss)

    prune = commands.add_parser("prune", help="remove old stale candidates")
    prune.add_argument("--stale-days", type=int, default=90)
    prune.set_defaults(function=command_prune)

    audit = commands.add_parser("audit", help="validate all terminology layers")
    audit.set_defaults(function=command_audit)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        args.function(args)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
