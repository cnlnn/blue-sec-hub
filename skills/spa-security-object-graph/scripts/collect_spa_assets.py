#!/usr/bin/env python3
"""Collect same-origin SPA HTML, JavaScript, manifests, and source maps."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
from collections import deque
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen

SCRIPT_REF_RE = re.compile(
    r"(?:sourceMappingURL\s*=\s*(?P<sourcemap>[^\s*]+)"
    r"|(?P<quote>[\"'`])(?P<quoted>[^\"'`\s]+?\.(?:js|mjs|cjs|map)"
    r"(?:\?[^\"'`\s]*)?)(?P=quote))",
    re.I,
)
ASSET_REF_RE = re.compile(
    r"\.(?:js|mjs|cjs|map)(?:\?[^#\s]*)?$",
    re.IGNORECASE,
)
INVALID_ASSET_REF_RE = re.compile(r"[\s'\"`{};,]|(?:^|/)(?:undefined|null)(?:/|$)", re.I)
EXPLICIT_ASSET_REF_RE = re.compile(
    r"(?:\bimport\s*\(|\bimportScripts\s*\(|\bnew\s+(?:Worker|SharedWorker)\s*\()"
    r"\s*(?P<quote>[\"'`])(?P<value>[^\"'`]{1,2048})(?P=quote)",
    re.IGNORECASE,
)
STRONG_ASSET_STRING_RE = re.compile(
    r"(?:^|/)(?:assets?|static|dist|build|scripts?|js|chunks?)/"
    r"|(?:^|[/._-])chunk[-._]|\.min\."
    r"|[._-][0-9a-f]{6,}\.(?:js|mjs|cjs)(?:$|\?)"
    r"|\.worker\.(?:js|mjs)(?:$|\?)",
    re.IGNORECASE,
)


class AssetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.refs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "script" and values.get("src"):
            self.refs.append(values["src"])
        if tag == "link" and values.get("href"):
            rel = (values.get("rel") or "").lower()
            href = values["href"]
            if any(word in rel for word in ("modulepreload", "preload", "manifest")) or re.search(r"\.(?:js|mjs|map)(?:\?|$)", href, re.I):
                self.refs.append(href)


def canonical(url: str) -> str:
    parts = urlsplit(url)
    scheme = parts.scheme or "https"
    return urlunsplit((scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, ""))


def same_origin(left: str, right: str) -> bool:
    a, b = urlsplit(left), urlsplit(right)
    return (a.scheme.lower(), a.netloc.lower()) == (b.scheme.lower(), b.netloc.lower())


def local_path(root: Path, url: str, content_type: str) -> Path:
    parts = urlsplit(url)
    path = parts.path
    if not path or path.endswith("/"):
        path += "index.html"
    name = Path(path).name or "asset"
    if "." not in name and "html" in content_type:
        path += ".html"
    if parts.query:
        stem, suffix = Path(path).stem, Path(path).suffix
        digest = hashlib.sha256(parts.query.encode()).hexdigest()[:10]
        path = str(Path(path).with_name(f"{stem}.{digest}{suffix}"))
    safe_parts = [re.sub(r"[^A-Za-z0-9._-]", "_", item) for item in Path(path.lstrip("/")).parts]
    return root.joinpath(parts.netloc, *safe_parts)


def discover_records(text: str, content_type: str) -> list[dict[str, str]]:
    refs: list[dict[str, str]] = []
    if "html" in content_type or "<script" in text[:5000].lower():
        parser = AssetParser()
        parser.feed(text)
        refs.extend(
            {"value": value, "discoveryType": "html-tag"}
            for value in parser.refs
            if valid_asset_ref(value)
        )
    for match in EXPLICIT_ASSET_REF_RE.finditer(text):
        value = match.group("value")
        if valid_asset_ref(value):
            refs.append(
                {
                    "value": value,
                    "discoveryType": "explicit-code-reference",
                }
            )
    for match in SCRIPT_REF_RE.finditer(text):
        value = match.group("quoted") or match.group("sourcemap")
        if match.group("quoted") and (
            "+" in text[max(0, match.start() - 8):match.start()]
            or "+" in text[match.end():min(len(text), match.end() + 8)]
        ):
            continue
        if not value:
            continue
        value = value.strip("'\"`")
        if not valid_asset_ref(value):
            continue
        if match.group("sourcemap"):
            refs.append({"value": value, "discoveryType": "source-map"})
        elif plausible_asset_string(value):
            refs.append({"value": value, "discoveryType": "strong-asset-string"})
    return list(
        {
            (item["value"], item["discoveryType"]): item
            for item in refs
        }.values()
    )


def discover(text: str, content_type: str) -> list[str]:
    return list(
        dict.fromkeys(item["value"] for item in discover_records(text, content_type))
    )


def valid_asset_ref(value: str) -> bool:
    """Reject parser tails and unresolved expressions before URL construction."""
    if not value or len(value) > 2048:
        return False
    if INVALID_ASSET_REF_RE.search(value) or any(
        marker in value for marker in ("${", "+", "\\")
    ):
        return False
    return ASSET_REF_RE.search(urlsplit(value).path + (
        "?" + urlsplit(value).query if urlsplit(value).query else ""
    )) is not None


def plausible_asset_string(value: str) -> bool:
    path = urlsplit(value).path
    return path.startswith("/") or STRONG_ASSET_STRING_RE.search(path) is not None


def invalid_asset_response(url: str, content_type: str, body: bytes) -> str | None:
    path = urlsplit(url).path
    if not re.search(r"\.(?:js|mjs|cjs|map)$", path, re.IGNORECASE):
        return None
    prefix = body[:1000].lstrip().lower()
    if "html" in content_type or prefix.startswith((b"<!doctype html", b"<html")):
        return "fake-200-html-fallback-for-script"
    return None


def collect_site(
    start_url: str,
    out_dir: Path,
    headers: dict[str, str] | None = None,
    max_files: int = 600,
    max_total_bytes: int = 250 * 1024 * 1024,
    timeout: float = 15.0,
) -> dict:
    if "://" not in start_url:
        start_url = "https://" + start_url
    start_url = canonical(start_url)
    if urlsplit(start_url).scheme not in {"http", "https"}:
        raise ValueError("Only HTTP(S) URLs are supported")
    out_dir.mkdir(parents=True, exist_ok=True)
    request_headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/134 Safari/537.36",
        "Accept": "text/html,application/javascript,text/javascript,application/json,*/*;q=0.8",
    }
    request_headers.update(headers or {})
    queue = deque([(start_url, None, 0, "entrypoint")])
    queued = {start_url}
    records = []
    total_bytes = 0

    while queue and len(records) < max_files and total_bytes < max_total_bytes:
        url, referrer, depth, discovery_type = queue.popleft()
        record = {
            "url": url,
            "referrer": referrer,
            "depth": depth,
            "discoveryType": discovery_type,
        }
        try:
            req_headers = dict(request_headers)
            if referrer:
                req_headers["Referer"] = referrer
            request = Request(url, headers=req_headers)
            with urlopen(request, timeout=timeout) as response:
                final_url = canonical(response.geturl())
                if not same_origin(start_url, final_url):
                    record.update({"status": response.status, "skipped": "cross-origin redirect", "finalUrl": final_url})
                    records.append(record)
                    continue
                remaining = max_total_bytes - total_bytes
                body = response.read(min(remaining, 20 * 1024 * 1024) + 1)
                if len(body) > min(remaining, 20 * 1024 * 1024):
                    record.update({"status": response.status, "skipped": "asset exceeds byte limit"})
                    records.append(record)
                    continue
                content_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
                destination = local_path(out_dir, final_url, content_type)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(body)
                total_bytes += len(body)
                record.update({
                    "status": response.status,
                    "finalUrl": final_url,
                    "contentType": content_type,
                    "bytes": len(body),
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "localPath": str(destination),
                })
                invalid_reason = invalid_asset_response(
                    final_url,
                    content_type,
                    body,
                )
                if invalid_reason:
                    record["invalidReason"] = invalid_reason
                else:
                    text = body.decode("utf-8", errors="replace")
                    for discovered in discover_records(text, content_type):
                        value = discovered["value"]
                        candidate = canonical(urljoin(final_url, value))
                        if candidate not in queued and same_origin(start_url, candidate):
                            queued.add(candidate)
                            queue.append(
                                (
                                    candidate,
                                    final_url,
                                    depth + 1,
                                    discovered["discoveryType"],
                                )
                            )
        except HTTPError as error:
            record.update({"status": error.code, "error": str(error)})
        except (URLError, TimeoutError, OSError, ValueError) as error:
            record.update({"error": str(error)})
        records.append(record)
        time.sleep(0.03)

    report = {
        "startUrl": start_url,
        "generatedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "filesAttempted": len(records),
        "downloadedBytes": total_bytes,
        "queueRemaining": len(queue),
        "limits": {"maxFiles": max_files, "maxTotalBytes": max_total_bytes, "timeout": timeout},
        "records": records,
    }
    (out_dir / "collection-manifest.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


def parse_headers(values: list[str]) -> dict[str, str]:
    headers = {}
    for value in values:
        if ":" not in value:
            raise ValueError(f"Invalid header (expected Name: value): {value}")
        name, content = value.split(":", 1)
        headers[name.strip()] = content.strip()
    return headers


def parse_header_file(path: Path) -> dict[str, str]:
    if not path.exists():
        raise ValueError(f"Header file does not exist: {path}")
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise ValueError(f"Header file permissions must be 0600: {path}")
    text = path.read_text(encoding="utf-8")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return parse_headers(
            [
                line.strip()
                for line in text.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
        )
    if not isinstance(value, dict) or not all(
        isinstance(name, str) and isinstance(content, str)
        for name, content in value.items()
    ):
        raise ValueError("Header JSON must be an object containing string values")
    return {name.strip(): content.strip() for name, content in value.items()}


def load_headers(values: list[str], header_file: Path | None) -> dict[str, str]:
    headers = parse_header_file(header_file) if header_file else {}
    headers.update(parse_headers(values))
    return headers


def add_header_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--header-file",
        type=Path,
        default=(
            Path(os.environ["SPA_GRAPH_HEADER_FILE"])
            if os.environ.get("SPA_GRAPH_HEADER_FILE")
            else None
        ),
        help="0600 text/JSON file containing request headers",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="Repeatable non-secret request header: 'Name: value'",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Starting domain or URL")
    parser.add_argument("--out", required=True, type=Path, help="Asset output directory")
    add_header_arguments(parser)
    parser.add_argument("--max-files", type=int, default=600)
    parser.add_argument("--max-mb", type=int, default=250)
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()
    report = collect_site(
        args.url,
        args.out,
        load_headers(args.header, args.header_file),
        args.max_files,
        args.max_mb * 1024 * 1024,
        args.timeout,
    )
    print(args.out / "collection-manifest.json")
    print(json.dumps({key: report[key] for key in ("filesAttempted", "downloadedBytes", "queueRemaining")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
