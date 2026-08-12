#!/usr/bin/env python3
"""Replace captured runtime JSON values with schema-only representations."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from collect_browser_assets import redact_runtime_json


def is_redacted_json_shape(value: object) -> bool:
    if isinstance(value, dict):
        if "$redactedType" in value:
            marker = value["$redactedType"]
            if marker == "array":
                item_shapes = value.get("itemShapes")
                return (
                    set(value) <= {"$redactedType", "count", "itemShapes"}
                    and isinstance(value.get("count"), int)
                    and isinstance(item_shapes, list)
                    and all(is_redacted_json_shape(item) for item in item_shapes)
                )
            if marker == "string":
                return (
                    set(value) <= {"$redactedType", "length"}
                    and isinstance(value.get("length"), int)
                )
            return (
                marker in {"null", "boolean", "integer", "number"}
                and set(value) == {"$redactedType"}
            )
        return all(is_redacted_json_shape(child) for child in value.values())
    return False


def sanitize_manifest(manifest_path: Path) -> dict[str, int]:
    manifest_path = manifest_path.resolve()
    capture_root = manifest_path.parent
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rewritten = 0
    reconciled = 0
    skipped = 0
    for record in manifest.get("responses", []):
        if record.get("resourceType") not in {"xhr", "fetch"}:
            continue
        if record.get("storedRepresentation") == "redacted-json-shape":
            skipped += 1
            continue
        local_path = record.get("localPath")
        if not local_path:
            continue
        path = Path(local_path).resolve()
        if not path.is_relative_to(capture_root) or not path.is_file():
            skipped += 1
            continue
        raw = path.read_bytes()
        source_digest = hashlib.sha256(raw).hexdigest()
        try:
            value = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if is_redacted_json_shape(value):
            record["storedBytes"] = len(raw)
            record["storedSha256"] = source_digest
            record["storedRepresentation"] = "redacted-json-shape"
            reconciled += 1
            continue
        stored = (
            json.dumps(
                redact_runtime_json(value),
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        ).encode()
        path.write_bytes(stored)
        path.chmod(0o600)
        record["storedBytes"] = len(stored)
        record["storedSha256"] = hashlib.sha256(stored).hexdigest()
        record["storedRepresentation"] = "redacted-json-shape"
        record["storedSourceSha256"] = source_digest
        record["storedSourceMatchedResponseHash"] = (
            source_digest == record.get("sha256")
        )
        rewritten += 1
    manifest["runtimeJsonValuePolicy"] = "redacted-by-default"
    manifest["runtimeJsonSanitization"] = {
        "rewritten": rewritten,
        "reconciled": reconciled,
        "alreadyRedactedOrSkipped": skipped,
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    manifest_path.chmod(0o600)
    return {
        "rewritten": rewritten,
        "reconciled": reconciled,
        "skipped": skipped,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    print(json.dumps(sanitize_manifest(args.manifest), sort_keys=True))


if __name__ == "__main__":
    main()
