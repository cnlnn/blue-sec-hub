from __future__ import annotations

import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from security_terms import compact, normalize


SCHEMA_VERSION = 1
VULNERABILITY_WORDS = {
    "abuse",
    "assignment",
    "attack",
    "authorization",
    "authentication",
    "bypass",
    "clickjacking",
    "confusion",
    "deception",
    "deserialization",
    "disclosure",
    "exploitation",
    "exposure",
    "forgery",
    "hijacking",
    "inclusion",
    "injection",
    "overflow",
    "pollution",
    "poisoning",
    "privilege escalation",
    "race condition",
    "rebinding",
    "redirect",
    "request smuggling",
    "scripting",
    "takeover",
    "traversal",
    "type juggling",
    "unauthorized",
    "upload",
    "weak password",
}
GENERIC_TITLES = {
    "hack",
    "security",
    "recon",
    "reconnaissance",
    "methodology",
    "traffic analysis",
    "source code scanning",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def local_name(element: ElementTree.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def extract_parenthetical_aliases(value: str) -> list[str]:
    result = []
    for match in re.finditer(r"\((?:'|\")?([^()'\"]{3,100})(?:'|\")?\)", value):
        alias = match.group(1).strip()
        if alias and not alias.isdigit():
            result.append(alias)
    return result


def parse_cwe_catalog(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {
            "schema_version": SCHEMA_VERSION,
            "generated_at": now(),
            "source": {
                "name": "mitre-cwe",
                "available": False,
                "path": str(path),
            },
            "terms": [],
        }
    try:
        with zipfile.ZipFile(path) as archive:
            xml_entries = [
                entry
                for entry in archive.infolist()
                if entry.filename.casefold().endswith(".xml")
            ]
            if not xml_entries:
                raise ValueError(f"CWE archive has no XML document: {path}")
            if xml_entries[0].file_size > 100 * 1024 * 1024:
                raise ValueError(f"CWE XML exceeds size limit: {path}")
            root = ElementTree.fromstring(archive.read(xml_entries[0]))
    except zipfile.BadZipFile as error:
        raise ValueError(f"Invalid CWE archive {path}: {error}") from error

    terms = []
    for element in root.iter():
        if local_name(element) != "Weakness":
            continue
        identifier = element.attrib.get("ID")
        name = element.attrib.get("Name", "").strip()
        status = element.attrib.get("Status", "")
        if not identifier or not name or status.casefold() == "deprecated":
            continue
        name_without_parenthetical = re.sub(
            r"\s*\([^)]{2,160}\)\s*",
            " ",
            name,
        ).strip()
        aliases = [
            f"CWE-{identifier}",
            name,
            *(
                [name_without_parenthetical]
                if name_without_parenthetical != name
                else []
            ),
            *extract_parenthetical_aliases(name),
        ]
        for child in element.iter():
            if local_name(child) not in {"Alternate_Term", "Term"}:
                continue
            if child.text and child.text.strip():
                aliases.append(child.text.strip())
        aliases = list(dict.fromkeys(alias for alias in aliases if len(alias) <= 160))
        terms.append(
            {
                "id": f"cwe-{identifier}",
                "category": "cwe",
                "triggers": aliases,
                "aliases": aliases,
                "provenance": {
                    "authority": "MITRE CWE",
                    "source": "https://cwe.mitre.org/data/downloads.html",
                    "status": status,
                },
            }
        )

    alias_owners: dict[str, set[str]] = {}
    for term in terms:
        for alias in term["aliases"]:
            alias_owners.setdefault(compact(alias), set()).add(term["id"])
    ambiguous_aliases = {
        alias for alias, owners in alias_owners.items() if len(owners) > 1
    }
    for term in terms:
        cwe_id = term["aliases"][0]
        unique_aliases = [
            alias
            for alias in term["aliases"]
            if alias == cwe_id or compact(alias) not in ambiguous_aliases
        ]
        term["aliases"] = unique_aliases
        term["triggers"] = unique_aliases
    terms.sort(key=lambda item: int(item["id"].split("-", 1)[1]))
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now(),
        "source": {
            "name": "mitre-cwe",
            "available": True,
            "path": str(path),
            "version": root.attrib.get("Version"),
            "date": root.attrib.get("Date"),
            "weaknesses": len(terms),
            "ambiguous_aliases_excluded": len(ambiguous_aliases),
        },
        "terms": terms,
    }


def frontmatter_value(text: str, key: str) -> str | None:
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end < 0:
        return None
    match = re.search(
        rf"(?m)^{re.escape(key)}:\s*[\"']?([^\n\"']+)",
        text[3:end],
    )
    return match.group(1).strip() if match else None


def heading_value(text: str) -> str | None:
    match = re.search(r"(?m)^#\s+(.+?)\s*$", text)
    if not match:
        return None
    value = re.sub(r"^SKILL:\s*", "", match.group(1), flags=re.I)
    value = re.split(r"\s+[—–]\s+", value, maxsplit=1)[0]
    return value.strip(" #`")


def humanize(value: str) -> str:
    return re.sub(r"[-_]+", " ", value).strip()


def expand_aliases(value: str) -> list[str]:
    aliases = [value]
    aliases.extend(extract_parenthetical_aliases(value))
    without_parenthetical = re.sub(r"\s*\([^)]{2,100}\)\s*", " ", value).strip()
    if without_parenthetical and without_parenthetical != value:
        aliases.append(without_parenthetical)
    aliases.extend(
        part.strip()
        for part in re.split(r"\s+(?:/|&|\band\b)\s+", value, flags=re.I)
        if 2 <= len(part.strip()) <= 100
    )
    aliases.extend(re.findall(r"\b[A-Z][A-Z0-9]{1,9}\b", value))
    return list(dict.fromkeys(alias for alias in aliases if 2 <= len(alias) <= 120))


def looks_like_vulnerability(path: Path, aliases: list[str]) -> bool:
    lowered_parts = {part.casefold() for part in path.parts}
    if "vulnerabilities" in lowered_parts:
        return True
    combined = " ".join(aliases).casefold()
    return any(word in combined for word in VULNERABILITY_WORDS)


def discover_security_terms(
    upstreams: Path,
    cache_root: Path,
) -> list[dict[str, Any]]:
    discovered: dict[str, dict[str, Any]] = {}
    alias_keys: dict[str, str] = {}

    paths = set(upstreams.rglob("UPSTREAM_SKILL.md")) if upstreams.exists() else set()
    paths.update((upstreams / "strix" / "vulnerabilities").glob("*.md"))
    for path in sorted(paths):
        relative = path.relative_to(upstreams)
        if not relative.parts:
            continue
        source_name = relative.parts[0]
        text = path.read_text(encoding="utf-8", errors="replace")
        metadata_name = frontmatter_value(text, "name")
        heading = heading_value(text)
        directory_name = (
            path.parent.name if path.name == "UPSTREAM_SKILL.md" else path.stem
        )
        raw_aliases = [
            value
            for value in (
                heading,
                humanize(metadata_name) if metadata_name else None,
                humanize(directory_name),
            )
            if value and 3 <= len(value) <= 120
        ]
        aliases = list(
            dict.fromkeys(
                alias
                for value in raw_aliases
                for alias in expand_aliases(value)
            )
        )
        if not aliases or not looks_like_vulnerability(relative, aliases):
            continue
        preferred = aliases[0]
        if normalize(preferred) in GENERIC_TITLES:
            continue
        key = next(
            (
                alias_keys[compact(alias)]
                for alias in aliases
                if compact(alias) in alias_keys
            ),
            compact(preferred),
        )
        for alias in aliases:
            alias_keys[compact(alias)] = key
        record = discovered.setdefault(
            key,
            {
                "term": preferred,
                "aliases": set(),
                "sources": [],
            },
        )
        record["aliases"].update(aliases)
        source = {
            "name": source_name,
            "kind": "community-upstream",
            "path": str(path),
        }
        if source not in record["sources"]:
            record["sources"].append(source)

    checklist = (
        cache_root
        / "feeds"
        / "owasp-wstg"
        / "checklists"
        / "checklist.json"
    )
    if checklist.exists():
        value = json.loads(checklist.read_text(encoding="utf-8"))
        for category in value.get("categories", {}).values():
            for test in category.get("tests", []):
                name = str(test.get("name") or "").strip()
                preferred = re.sub(
                    r"^(?:test(?:ing)?|assess(?:ing)?)\s+(?:for\s+)?",
                    "",
                    name,
                    flags=re.I,
                ).strip()
                aliases = expand_aliases(preferred)
                if not aliases or not looks_like_vulnerability(checklist, aliases):
                    continue
                key = next(
                    (
                        alias_keys[compact(alias)]
                        for alias in aliases
                        if compact(alias) in alias_keys
                    ),
                    compact(preferred),
                )
                for alias in aliases:
                    alias_keys[compact(alias)] = key
                record = discovered.setdefault(
                    key,
                    {
                        "term": preferred,
                        "aliases": set(),
                        "sources": [],
                    },
                )
                record["aliases"].update(aliases)
                source = {
                    "name": "owasp-wstg",
                    "kind": "official-guidance",
                    "path": str(checklist),
                    "reference": test.get("id"),
                }
                if source not in record["sources"]:
                    record["sources"].append(source)

    return [
        {
            "term": value["term"],
            "aliases": sorted(value["aliases"], key=str.casefold),
            "sources": sorted(
                value["sources"],
                key=lambda item: (item["name"], item["path"]),
            ),
        }
        for value in discovered.values()
    ]
