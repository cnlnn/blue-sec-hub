#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
GLOSSARY = Path(os.environ.get("BLUE_SEC_GLOSSARY", ROOT / "security_terms.json"))
DATA_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_DATA",
        Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        / "blue-sec-hub",
    )
)
TERM_LEARNING = DATA_ROOT / "term-learning"
OFFICIAL_TERMS = TERM_LEARNING / "official.json"
CANDIDATES = TERM_LEARNING / "candidates.jsonl"
EFFECTIVE_ROUTING = DATA_ROOT / "effective" / "current" / "routing-terms.json"


def normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value.casefold()).strip()


def compact(value: str) -> str:
    return re.sub(r"[\s_-]+", "", normalize(value))


def contains_cjk(value: str) -> bool:
    return bool(re.search(r"[\u3400-\u9fff]", value))


@lru_cache(maxsize=1)
def load_glossary() -> dict[str, Any]:
    value = json.loads(GLOSSARY.read_text(encoding="utf-8"))
    if value.get("schema_version") != 1 or not isinstance(value.get("terms"), list):
        raise ValueError(f"Invalid security term glossary: {GLOSSARY}")
    value = {"schema_version": 1, "terms": [dict(term) for term in value["terms"]]}
    base_ids = {term["id"] for term in value["terms"]}
    base_by_id = {term["id"]: term for term in value["terms"]}
    base_alias_owners: dict[str, set[str]] = {}
    for term in value["terms"]:
        for alias in (
            term["id"],
            *term.get("triggers", []),
            *term.get("routing_aliases", term.get("aliases", [])),
        ):
            base_alias_owners.setdefault(compact(alias), set()).add(term["id"])
    if OFFICIAL_TERMS.exists():
        official = json.loads(OFFICIAL_TERMS.read_text(encoding="utf-8"))
        for term in official.get("terms", []):
            aliases = (
                term.get("triggers", [])
                + term.get("aliases", [])
                + [term.get("id", "")]
            )
            owners = {
                owner
                for alias in aliases
                for owner in base_alias_owners.get(compact(alias), set())
                if alias
            }
            if len(owners) == 1:
                target = base_by_id[next(iter(owners))]
                target["aliases"] = list(
                    dict.fromkeys(
                        [*target.get("aliases", []), *term.get("aliases", [])]
                    )
                )
                target["triggers"] = list(
                    dict.fromkeys(
                        [*target.get("triggers", []), *term.get("triggers", [])]
                    )
                )
                target.setdefault("official_refs", []).append(term["id"])
                continue
            if term.get("id") in base_ids or len(owners) > 1:
                continue
            value["terms"].append(term)
    value["layers"] = {
        "base": str(GLOSSARY),
        "official": str(OFFICIAL_TERMS) if OFFICIAL_TERMS.exists() else None,
    }
    return value


def load_candidate_hints() -> list[dict[str, Any]]:
    if not CANDIDATES.exists():
        return []
    result = []
    for line in CANDIDATES.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if value.get("state") in {"candidate", "ready"}:
            result.append(value)
    return result


def load_effective_routing_terms() -> list[dict[str, Any]]:
    try:
        value = json.loads(EFFECTIVE_ROUTING.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [item for item in value.get("terms", []) if isinstance(item, dict)]


def trigger_matches(query: str, trigger: str) -> bool:
    normalized_query = normalize(query)
    normalized_trigger = normalize(trigger)
    if contains_cjk(normalized_trigger):
        return compact(normalized_trigger) in compact(normalized_query)
    return bool(
        re.search(
            rf"(?<![a-z0-9]){re.escape(normalized_trigger)}(?![a-z0-9])",
            normalized_query,
        )
    )


def expand_query(query: str, limit: int = 40) -> dict[str, Any]:
    matches: list[tuple[dict[str, Any], str, int]] = []
    for term in load_glossary()["terms"]:
        for trigger in term.get("triggers", []):
            if trigger_matches(query, trigger):
                matches.append((term, trigger, 2))
        trigger_values = {normalize(value) for value in term.get("triggers", [])}
        for alias in term.get("routing_aliases", term.get("aliases", [])):
            if normalize(alias) in trigger_values:
                continue
            if trigger_matches(query, alias):
                matches.append((term, alias, 1))

    specific_matches = []
    for term, trigger, priority in matches:
        normalized = compact(trigger)
        if any(
            (
                normalized == compact(other_trigger)
                and priority < other_priority
            )
            or (
                normalized != compact(other_trigger)
                and normalized in compact(other_trigger)
                and compact(other_trigger) in compact(query)
            )
            for _, other_trigger, other_priority in matches
        ):
            continue
        specific_matches.append((term, trigger))

    best_by_id: dict[str, tuple[dict[str, Any], str]] = {}
    for term, trigger in specific_matches:
        current = best_by_id.get(term["id"])
        if current is None or len(compact(trigger)) > len(compact(current[1])):
            best_by_id[term["id"]] = (term, trigger)
    best_matches = list(best_by_id.values())

    terms: list[str] = [query]
    normalized_terms = {normalize(query)}
    canonical: list[str] = []
    matched_triggers: list[str] = []
    for term, trigger in best_matches:
        if term["id"] not in canonical:
            canonical.append(term["id"])
        if trigger not in matched_triggers:
            matched_triggers.append(trigger)
        for alias in [
            *term.get("routing_aliases", term.get("aliases", [])),
            *term.get("search_aliases", []),
            *term.get("display_aliases", []),
        ]:
            if normalize(alias) not in normalized_terms:
                terms.append(alias)
                normalized_terms.add(normalize(alias))
            if len(terms) >= limit:
                break
        if len(terms) >= limit:
            break
    candidate_matches: list[str] = []
    for candidate in load_candidate_hints():
        aliases = [
            candidate.get("term", ""),
            *candidate.get("aliases", []),
        ]
        if not any(alias and trigger_matches(query, alias) for alias in aliases):
            continue
        candidate_matches.append(str(candidate["id"]))
        for alias in aliases:
            if (
                alias
                and len(alias) <= 120
                and normalize(alias) not in normalized_terms
            ):
                terms.append(alias)
                normalized_terms.add(normalize(alias))
            if len(terms) >= limit:
                break
        if len(terms) >= limit:
            break
    routing_matches: list[str] = []
    for item in load_effective_routing_terms():
        term = str(item.get("term") or "")
        if not term or not trigger_matches(query, term):
            continue
        routing_matches.append(str(item.get("semantic_id") or item.get("id")))
        if normalize(term) not in normalized_terms and len(terms) < limit:
            terms.append(term)
            normalized_terms.add(normalize(term))
    return {
        "query": query,
        "canonical": canonical,
        "matched_triggers": matched_triggers,
        "candidate_matches": candidate_matches,
        "routing_matches": routing_matches,
        "search_terms": terms,
    }


def canonicalize_term(value: str) -> str:
    normalized = normalize(value)
    for term in load_glossary()["terms"]:
        if term.get("canonicalize") is False:
            continue
        if normalized == normalize(term["id"]):
            return str(term["id"])
    for term in load_glossary()["terms"]:
        if term.get("canonicalize") is False:
            continue
        candidates = term.get("triggers", [])
        if any(normalized == normalize(candidate) for candidate in candidates):
            return str(term["id"])
    for term in load_glossary()["terms"]:
        if term.get("canonicalize") is False:
            continue
        candidates = term.get("routing_aliases", term.get("aliases", []))
        if any(normalized == normalize(candidate) for candidate in candidates):
            return str(term["id"])
    return value.strip()


def validate_glossary() -> list[str]:
    failures: list[str] = []
    identifiers: set[str] = set()
    for index, term in enumerate(load_glossary()["terms"]):
        identifier = term.get("id")
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-z0-9-]+", identifier):
            failures.append(f"term[{index}] has invalid id")
        elif identifier in identifiers:
            failures.append(f"duplicate term id: {identifier}")
        identifiers.add(str(identifier))
        for field in ("triggers", "aliases"):
            values = term.get(field)
            if not isinstance(values, list) or not values or not all(
                isinstance(item, str) and item.strip() for item in values
            ):
                failures.append(f"{identifier}: {field} must be non-empty strings")
        for field in ("routing_aliases", "search_aliases", "display_aliases"):
            if field not in term:
                continue
            values = term[field]
            if not isinstance(values, list) or not all(
                isinstance(item, str) and item.strip() for item in values
            ):
                failures.append(f"{identifier}: {field} must contain strings")
        if "canonicalize" in term and not isinstance(term["canonicalize"], bool):
            failures.append(f"{identifier}: canonicalize must be boolean")
    return failures


def main() -> None:
    parser = argparse.ArgumentParser(description="Expand bilingual security terminology")
    parser.add_argument("query")
    args = parser.parse_args()
    print(json.dumps(expand_query(args.query), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
