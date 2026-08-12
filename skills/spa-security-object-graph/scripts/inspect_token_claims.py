#!/usr/bin/env python3
"""Summarize token claim names without persisting credential values."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from collect_spa_assets import parse_header_file


TOKEN_HEADER_RE = re.compile(
    r"(?:authorization|token|session|credential|jwt|cookie)",
    re.IGNORECASE,
)
JWT_RE = re.compile(
    r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$"
)
CLAIM_CATEGORIES = {
    "identifier": re.compile(
        r"(?:^|_)(?:sub|uid|user(?:id|name)?|account|employee|staff|"
        r"member|principal|subject|id)(?:$|_)",
        re.IGNORECASE,
    ),
    "contact": re.compile(
        r"(?:email|phone|mobile|address|contact)",
        re.IGNORECASE,
    ),
    "organization": re.compile(
        r"(?:org|organization|tenant|department|company|group|path)",
        re.IGNORECASE,
    ),
    "privilege": re.compile(
        r"(?:role|permission|privilege|scope|authority|grant|admin)",
        re.IGNORECASE,
    ),
    "session": re.compile(
        r"(?:sid|session|nonce|jti|iat|nbf|exp|auth_time|acr|amr)",
        re.IGNORECASE,
    ),
}
REGISTERED_CLAIMS = {
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
}


def decode_segment(value: str) -> dict[str, Any] | None:
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(value + padding)
        result = json.loads(decoded)
    except (ValueError, json.JSONDecodeError):
        return None
    return result if isinstance(result, dict) else None


def token_candidates(headers: dict[str, str]) -> list[str]:
    tokens: list[str] = []
    for name, value in headers.items():
        if name.casefold() == "cookie":
            tokens.extend(
                part.split("=", 1)[1].strip()
                for part in value.split(";")
                if "=" in part and part.split("=", 1)[1].strip()
            )
            continue
        if not TOKEN_HEADER_RE.search(name):
            continue
        candidate = re.sub(r"^(?:Bearer|Token)\s+", "", value, flags=re.I)
        if candidate:
            tokens.append(candidate.strip())
    return list(dict.fromkeys(tokens))


def claim_categories(names: list[str]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {
        category: [] for category in (*CLAIM_CATEGORIES, "other")
    }
    for name in names:
        matched = False
        for category, pattern in CLAIM_CATEGORIES.items():
            if pattern.search(name):
                result[category].append(name)
                matched = True
        if not matched:
            result["other"].append(name)
    return {
        category: sorted(set(values))
        for category, values in result.items()
        if values
    }


def inspect_header_file(path: Path) -> dict[str, Any]:
    headers = parse_header_file(path)
    records = []
    for index, token in enumerate(token_candidates(headers), 1):
        parts = token.split(".")
        payload = (
            decode_segment(parts[1])
            if len(parts) == 3 and JWT_RE.fullmatch(token)
            else None
        )
        claim_names = sorted(str(name) for name in (payload or {}))
        records.append(
            {
                "index": index,
                "format": "jwt" if payload is not None else "opaque",
                "claimNames": claim_names,
                "claimCategories": claim_categories(claim_names),
                "registeredClaimsPresent": sorted(
                    set(claim_names) & REGISTERED_CLAIMS
                ),
                "rawValuesPersisted": False,
            }
        )
    return {
        "schema_version": 1,
        "sourceSha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "headerNames": sorted(headers),
        "tokenCount": len(records),
        "tokens": records,
        "rawValuesPersisted": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("header_file", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    result = inspect_header_file(args.header_file)
    output = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(output, encoding="utf-8")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
