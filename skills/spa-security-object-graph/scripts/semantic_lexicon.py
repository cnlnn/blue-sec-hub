#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
from copy import deepcopy
from functools import lru_cache
from pathlib import Path
from typing import Any


SKILL_ROOT = Path(__file__).resolve().parents[1]
BASE_LEXICON = SKILL_ROOT / "references" / "semantic-lexicon.json"
DATA_ROOT = Path(
    os.environ.get(
        "BLUE_SEC_DATA",
        Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        / "blue-sec-hub",
    )
)
LOCAL_LEXICONS = DATA_ROOT / "spa-security-object-graph" / "lexicons"
REQUIRED_CATEGORIES = {
    "write_action",
    "read_action",
    "lifecycle_action",
    "actor",
    "business_object",
    "resource",
    "gate",
    "public_boundary",
    "sensitive_capability",
}
URL_OR_PATH = re.compile(r"(?:https?://|/)", re.IGNORECASE)
IP_ADDRESS = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
DOMAIN_NAME = re.compile(
    r"(?<![A-Za-z0-9-])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![A-Za-z0-9-])"
)
OPAQUE_IDENTIFIER = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{16,}(?![A-Fa-f0-9])")
CJK = re.compile(r"[\u3400-\u9fff]")


def normalized_ascii(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def alias_matches(value: str, alias: str) -> bool:
    if CJK.search(alias):
        return alias.casefold() in value.casefold()
    normalized_value = f" {normalized_ascii(value)} "
    normalized_alias = normalized_ascii(alias)
    return bool(normalized_alias) and f" {normalized_alias} " in normalized_value


def validate_lexicon(value: dict[str, Any], source: str = "lexicon") -> list[str]:
    failures: list[str] = []
    if value.get("schema_version") != 1:
        failures.append(f"{source}: schema_version must be 1")
    if "taxonomy_version" in value and value.get("taxonomy_version") != 1:
        failures.append(f"{source}: taxonomy_version must be 1")
    categories = value.get("categories")
    if not isinstance(categories, dict):
        return [*failures, f"{source}: categories must be an object"]
    for category, concepts in categories.items():
        if not re.fullmatch(r"[a-z][a-z0-9_-]*", str(category)):
            failures.append(f"{source}: invalid category {category!r}")
            continue
        if category not in REQUIRED_CATEGORIES:
            failures.append(f"{source}: unknown taxonomy category {category!r}")
            continue
        if not isinstance(concepts, dict):
            failures.append(f"{source}: category {category} must be an object")
            continue
        alias_owners: dict[str, str] = {}
        for concept, aliases in concepts.items():
            if not re.fullmatch(r"[a-z][a-z0-9-]*", str(concept)):
                failures.append(f"{source}: invalid concept {concept!r}")
            if (
                not isinstance(aliases, list)
                or not aliases
                or not all(isinstance(alias, str) and alias.strip() for alias in aliases)
            ):
                failures.append(f"{source}: {category}.{concept} needs aliases")
                continue
            for alias in aliases:
                if len(alias) > 64:
                    failures.append(f"{source}: alias is too long: {alias!r}")
                if (
                    URL_OR_PATH.search(alias)
                    or IP_ADDRESS.search(alias)
                    or DOMAIN_NAME.search(alias)
                ):
                    failures.append(f"{source}: target-specific alias: {alias!r}")
                if OPAQUE_IDENTIFIER.search(alias):
                    failures.append(f"{source}: opaque identifier alias: {alias!r}")
                key = (
                    re.sub(r"\s+", "", alias.casefold())
                    if CJK.search(alias)
                    else normalized_ascii(alias)
                )
                owner = alias_owners.get(key)
                if owner and owner != concept:
                    failures.append(
                        f"{source}: ambiguous alias {alias!r} in "
                        f"{category}.{owner} and {category}.{concept}"
                    )
                alias_owners[key] = str(concept)
    return failures


def merge_lexicon(base: dict[str, Any], overlay: dict[str, Any]) -> None:
    for category, concepts in overlay.get("categories", {}).items():
        target_category = base["categories"].setdefault(category, {})
        for concept, aliases in concepts.items():
            existing = target_category.setdefault(concept, [])
            existing.extend(alias for alias in aliases if alias not in existing)


@lru_cache(maxsize=1)
def load_lexicon() -> dict[str, Any]:
    value = json.loads(BASE_LEXICON.read_text(encoding="utf-8"))
    failures = validate_lexicon(value, str(BASE_LEXICON))
    missing = REQUIRED_CATEGORIES - set(value.get("categories", {}))
    failures.extend(
        f"{BASE_LEXICON}: missing category {category}" for category in sorted(missing)
    )
    merged = deepcopy(value)
    sources = [str(BASE_LEXICON)]
    if LOCAL_LEXICONS.exists():
        for path in sorted(LOCAL_LEXICONS.glob("*.json")):
            overlay = json.loads(path.read_text(encoding="utf-8"))
            overlay_failures = validate_lexicon(overlay, str(path))
            failures.extend(overlay_failures)
            if not overlay_failures:
                merge_lexicon(merged, overlay)
                sources.append(str(path))
    failures.extend(validate_lexicon(merged, "merged SPA semantic lexicon"))
    if failures:
        raise ValueError("\n".join(failures))
    merged["sources"] = sources
    return merged


def tag_text(value: str, lexicon: dict[str, Any] | None = None) -> dict[str, list[str]]:
    lexicon = lexicon or load_lexicon()
    result: dict[str, list[str]] = {}
    for category, concepts in lexicon["categories"].items():
        matches = [
            concept
            for concept, aliases in concepts.items()
            if any(alias_matches(value, alias) for alias in aliases)
        ]
        if matches:
            result[category] = sorted(matches)
    return result

if __name__ == "__main__":
    lexicon = load_lexicon()
    print(
        json.dumps(
            {
                "schema_version": lexicon["schema_version"],
                "taxonomy_version": lexicon["taxonomy_version"],
                "categories": len(lexicon["categories"]),
                "sources": lexicon["sources"],
            },
            ensure_ascii=False,
            indent=2,
        )
    )
