#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from xml.etree import ElementTree

import web_assessment
import source_mapper


ROOT = Path(__file__).resolve().parents[1]
SPA_COMMAND = ROOT / "scripts" / "spa_graph.py"
REPORT_COMMAND = ROOT / "scripts" / "report_ingestion.py"
SCHEDULING_TERMINAL = {"tested", "blocked", "not-applicable"}
COVERAGE_SATISFIED = {"tested", "not-applicable"}
RESOLVED = SCHEDULING_TERMINAL
AUTH_HEADERS = {"authorization", "cookie", "proxy-authorization", "x-api-key"}
SUBJECT_FIELD_RE = re.compile(
    r"(?:^|[._-])(?:user|account|owner|creator|member|subject|principal|operator)id$",
    re.I,
)
PARENT_FIELD_RE = re.compile(
    r"(?:^|[._-])(?:tenant|org|organization|department|project|workspace|parent|group)id$",
    re.I,
)
SENSITIVE_FIELD_RE = re.compile(
    r"password|secret|token|mobile|phone|email|identity|credential|role|permission|"
    r"tenant|organization|owner|balance|address|medical|patient|salary|account",
    re.I,
)
SUCCESS_CODE_RE = re.compile(r"^(?:0|1|200|ok|success)$", re.I)
HIGH_VALUE_PATH_RE = re.compile(
    r"admin|approve|audit|config|permission|role|tenant|organization|user|account|"
    r"export|download|credential|reset|secret|token",
    re.I,
)
CORS_TEST_ORIGIN = "https://cross-origin.invalid"
CORS_TEST_ORIGIN_SHA256 = hashlib.sha256(CORS_TEST_ORIGIN.encode()).hexdigest()


def now() -> str:
    return datetime.now(UTC).isoformat()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    if os.name != "nt":
        temporary.chmod(0o600)
    temporary.replace(path)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def parse_header_file(path: Path) -> dict[str, str]:
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise ValueError(f"credential file must be mode 0600: {path}")
    text = path.read_text(encoding="utf-8")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = None
    if isinstance(value, dict):
        return {str(key): str(item) for key, item in value.items()}
    headers = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name, separator, content = line.partition(":")
        if not separator:
            raise ValueError(f"invalid header line in {path}")
        headers[name.strip()] = content.strip()
    return headers


@dataclass
class CredentialLease:
    source: str
    headers: dict[str, str]
    path: Path | None = None
    consume: bool = False

    @property
    def fingerprint(self) -> str:
        material = json.dumps(
            sorted((key.casefold(), hashlib.sha256(value.encode()).hexdigest()) for key, value in self.headers.items()),
            separators=(",", ":"),
        )
        return hashlib.sha256(material.encode()).hexdigest()

    def metadata(self, status: str) -> dict[str, Any]:
        return {
            "type": "credential-lease-state",
            "status": status,
            "source": self.source,
            "header_names": sorted(self.headers),
            "fingerprint": self.fingerprint if self.headers else None,
            "token_claims": token_claim_summary(self.headers),
        }

    def cleanup(self) -> None:
        if self.consume and self.path and self.path.exists():
            self.path.unlink()


@dataclass
class RawRequest:
    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None
    source: str


def origin(value: str) -> str:
    parsed = urlsplit(value if "://" in value else "https://" + value)
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def target_url(value: str) -> str:
    return value if "://" in value else "https://" + value


def load_credential_lease(
    target: str,
    header_file: Path | None,
    lease_file: Path | None,
    consume: bool,
) -> CredentialLease:
    if lease_file:
        if os.name != "nt" and lease_file.stat().st_mode & 0o077:
            raise ValueError("credential lease must be mode 0600")
        value = load_json(lease_file, {})
        lease_origin = str(value.get("target_origin") or "")
        if lease_origin and lease_origin != origin(target):
            raise ValueError("credential lease target does not match assessment target")
        expires_at = value.get("expires_at")
        if expires_at:
            expiry = datetime.fromisoformat(str(expires_at))
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=UTC)
            if expiry <= datetime.now(UTC):
                return CredentialLease("credential-lease-expired", {}, lease_file, consume)
        headers = value.get("headers", {})
        if not isinstance(headers, dict):
            raise ValueError("credential lease headers must be an object")
        return CredentialLease(
            str(value.get("source") or "credential-lease"),
            {str(key): str(item) for key, item in headers.items()},
            lease_file,
            consume,
        )
    if header_file:
        return CredentialLease("header-file", parse_header_file(header_file))
    return CredentialLease("anonymous", {})


def har_requests(path: Path | None, target: str) -> list[RawRequest]:
    if path is None:
        return []
    value = load_json(path, {})
    entries = value.get("log", {}).get("entries", [])
    result = []
    target_host = urlsplit(target_url(target)).hostname or ""
    for entry in entries:
        request = entry.get("request", {})
        url = str(request.get("url") or "")
        candidate_host = urlsplit(url).hostname or ""
        if not url or web_assessment.registrable_domain(candidate_host) != web_assessment.registrable_domain(target_host):
            continue
        headers = {
            str(item.get("name")): str(item.get("value"))
            for item in request.get("headers", [])
            if item.get("name")
        }
        post = request.get("postData", {})
        body = post.get("text")
        result.append(
            RawRequest(
                str(request.get("method") or "GET").upper(),
                url,
                headers,
                body.encode() if isinstance(body, str) else None,
                "har",
            )
        )
    return result


def transient_corpus_requests(path: Path, target: str) -> list[RawRequest]:
    value = load_json(path, {})
    target_host = urlsplit(target_url(target)).hostname or ""
    result = []
    for request in value.get("requests", []):
        url = str(request.get("url") or "")
        candidate_host = urlsplit(url).hostname or ""
        if not url or web_assessment.registrable_domain(
            candidate_host
        ) != web_assessment.registrable_domain(target_host):
            continue
        encoded_body = request.get("body_base64")
        try:
            body = base64.b64decode(encoded_body) if encoded_body else None
        except (ValueError, TypeError):
            continue
        headers = request.get("headers", {})
        if not isinstance(headers, dict):
            continue
        result.append(
            RawRequest(
                str(request.get("method") or "GET").upper(),
                url,
                {str(key): str(item) for key, item in headers.items()},
                body,
                "browser-runtime",
            )
        )
    return result


def raw_request_from_private_value(value: dict[str, Any], source: str) -> RawRequest:
    encoded_body = value.get("body_base64")
    try:
        body = base64.b64decode(encoded_body) if encoded_body else None
    except (ValueError, TypeError) as error:
        raise ValueError("invalid private request body encoding") from error
    headers = value.get("headers", {})
    if not isinstance(headers, dict):
        raise ValueError("private request headers must be an object")
    return RawRequest(
        str(value.get("method") or "GET").upper(),
        str(value.get("url") or ""),
        {str(key): str(item) for key, item in headers.items()},
        body,
        source,
    )


def load_transaction_corpus(
    path: Path | None,
    target: str,
) -> dict[str, dict[str, dict[str, RawRequest]]]:
    if path is None:
        return {}
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise ValueError("transaction corpus must be mode 0600")
    try:
        value = load_json(path, {})
    finally:
        if path.exists():
            path.unlink()
    if value.get("target_origin") and value["target_origin"] != origin(target):
        raise ValueError("transaction corpus target does not match assessment target")
    target_host = urlsplit(target_url(target)).hostname or ""
    result: dict[str, dict[str, dict[str, RawRequest]]] = {}
    for transaction in value.get("transactions", []):
        if transaction.get("ownership") != "self-owned":
            raise ValueError("transactions must be bound to a self-owned object")
        if transaction.get("reversible") is not True:
            raise ValueError("transactions must be explicitly reversible")
        case_id = str(transaction.get("test_case_id") or "")
        variant_id = str(transaction.get("variant_id") or "")
        if not case_id or not variant_id:
            raise ValueError("transaction requires test_case_id and variant_id")
        requests = {
            step: raw_request_from_private_value(transaction.get(step, {}), "transaction-corpus")
            for step in ("prestate", "mutation", "rollback", "verify")
        }
        if requests["prestate"].method not in {"GET", "HEAD"} or requests[
            "verify"
        ].method not in {"GET", "HEAD"}:
            raise ValueError("transaction prestate and verify requests must be read-only")
        if requests["mutation"].method not in {"POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("transaction mutation must be a write method")
        if requests["rollback"].method not in {"POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError("transaction rollback must be a write method")
        for request in requests.values():
            request_host = urlsplit(request.url).hostname or ""
            if not request.url or web_assessment.registrable_domain(
                request_host
            ) != web_assessment.registrable_domain(target_host):
                raise ValueError("transaction request is outside the active same-site scope")
        result.setdefault(case_id, {})[variant_id] = requests
    return result


def request_key(method: str, url: str) -> tuple[str, str, str, tuple[str, ...]]:
    parsed = urlsplit(url)
    query_fields = tuple(sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}))
    return (
        method.upper(),
        f"{parsed.scheme.lower()}://{parsed.netloc.lower()}",
        parsed.path or "/",
        query_fields,
    )


def token_claim_summary(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Describe JWT claim names without retaining the token or claim values."""
    summaries = []
    for header_name, header_value in headers.items():
        candidates = []
        if header_name.casefold() == "authorization":
            scheme, _, value = header_value.partition(" ")
            if scheme.casefold() == "bearer" and value:
                candidates.append(value)
        elif header_name.casefold() == "cookie":
            candidates.extend(
                value
                for item in header_value.split(";")
                for _, separator, value in [item.strip().partition("=")]
                if separator
            )
        for token in candidates:
            parts = token.split(".")
            if len(parts) != 3:
                continue
            try:
                padding = "=" * (-len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + padding))
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            claim_names = sorted(str(key) for key in payload)
            summaries.append(
                {
                    "source_header": header_name,
                    "claim_count": len(claim_names),
                    "claim_names": claim_names,
                    "sensitive_claim_names": [
                        name for name in claim_names if SENSITIVE_FIELD_RE.search(name)
                    ],
                    "values_persisted": False,
                }
            )
    return summaries


def json_shape(value: Any, depth: int = 0) -> Any:
    if depth > 8:
        return "depth-limit"
    if isinstance(value, dict):
        return {str(key): json_shape(child, depth + 1) for key, child in sorted(value.items())}
    if isinstance(value, list):
        shapes = [json_shape(child, depth + 1) for child in value[:3]]
        return {"type": "array", "count": len(value), "item_shapes": shapes}
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return "string"


def scalar_fields(value: Any, prefix: str = "") -> list[str]:
    result = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            result.extend(scalar_fields(child, child_prefix))
    elif isinstance(value, list):
        for child in value[:3]:
            result.extend(scalar_fields(child, prefix + "[]"))
    else:
        result.append(prefix)
    return result


def response_summary(status: int, final_url: str, headers: Any, body: bytes, elapsed: float) -> dict[str, Any]:
    content_type = str(headers.get("content-type", "")).split(";", 1)[0].casefold()
    summary: dict[str, Any] = {
        "status": status,
        "final_path": urlsplit(final_url).path,
        "content_type": content_type,
        "length": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "elapsed_ms": round(elapsed * 1000, 2),
        "header_names": sorted(str(key).casefold() for key in headers.keys()),
    }
    allow_origin = str(headers.get("access-control-allow-origin", "")).strip()
    allow_origin_kind = (
        "absent"
        if not allow_origin
        else "wildcard"
        if allow_origin == "*"
        else "null"
        if allow_origin.casefold() == "null"
        else "origin"
    )
    vary_tokens = {
        item.strip().casefold()
        for item in str(headers.get("vary", "")).split(",")
        if item.strip()
    }
    summary["cors"] = {
        "allow_origin_kind": allow_origin_kind,
        "allow_origin_sha256": (
            hashlib.sha256(allow_origin.encode()).hexdigest()
            if allow_origin_kind == "origin"
            else None
        ),
        "allow_credentials": str(
            headers.get("access-control-allow-credentials", "")
        ).strip().casefold()
        == "true",
        "vary_origin": "origin" in vary_tokens,
    }
    summary["edge_control_hint"] = any(
        re.search(r"(?:waf|captcha|challenge|ratelimit|retry-after)", name, re.I)
        for name in summary["header_names"]
    )
    summary["probe_reflected"] = b"blue-sec-probe-" in body
    summary["challenge_hint"] = bool(
        re.search(rb"(?:captcha|challenge|verify\s+you\s+are\s+human)", body[:500_000], re.I)
    )
    if "json" in content_type or body.lstrip().startswith((b"{", b"[")):
        try:
            value = json.loads(body)
            fields = sorted(set(scalar_fields(value)))
            summary["json_shape"] = json_shape(value)
            summary["field_names"] = fields
            summary["sensitive_field_names"] = [field for field in fields if SENSITIVE_FIELD_RE.search(field)]
            if isinstance(value, dict):
                for key in ("code", "status", "success"):
                    if key in value:
                        summary["business_code_hash"] = hashlib.sha256(str(value[key]).encode()).hexdigest()
                        summary["business_success_hint"] = bool(SUCCESS_CODE_RE.match(str(value[key])))
                        break
        except (json.JSONDecodeError, UnicodeDecodeError):
            summary["parse_error"] = "invalid-json"
    return summary


class RateLimiter:
    def __init__(self, requests_per_second: float = 2.0) -> None:
        if requests_per_second <= 0:
            raise ValueError("requests per second must be greater than zero")
        self.configured_rate = requests_per_second
        self.current_rate = requests_per_second
        self.interval = 1.0 / requests_per_second
        self.last = 0.0
        self.requests = 0
        self.transient_failures = 0
        self.circuit_opened = 0
        self.circuit_until = 0.0

    def wait(self) -> None:
        circuit_remaining = self.circuit_until - time.monotonic()
        if circuit_remaining > 0:
            time.sleep(circuit_remaining)
        remaining = self.interval - (time.monotonic() - self.last)
        if remaining > 0:
            time.sleep(remaining)
        self.last = time.monotonic()

    def observe(self, result: dict[str, Any]) -> None:
        self.requests += 1
        transient = bool(result.get("error")) or result.get("status") in {429, 503}
        if transient:
            self.transient_failures += 1
            self.current_rate = max(0.25, self.current_rate / 2)
            self.interval = 1.0 / self.current_rate
            if self.transient_failures >= 5:
                self.circuit_opened += 1
                self.circuit_until = time.monotonic() + min(
                    30.0, 2.0 ** min(self.transient_failures - 4, 4)
                )
            return
        self.transient_failures = 0
        self.current_rate = min(
            self.configured_rate,
            self.current_rate + max(0.25, self.configured_rate / 10),
        )
        self.interval = 1.0 / self.current_rate

    def snapshot(self) -> dict[str, Any]:
        return {
            "configured_requests_per_second": self.configured_rate,
            "current_requests_per_second": round(self.current_rate, 3),
            "requests": self.requests,
            "transient_failures": self.transient_failures,
            "circuit_opened": self.circuit_opened,
        }


class ScopeRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> Request | None:
        old_host = urlsplit(request.full_url).hostname or ""
        new_host = urlsplit(new_url).hostname or ""
        if web_assessment.registrable_domain(old_host) != web_assessment.registrable_domain(
            new_host
        ):
            return None
        return super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )


class ExactOriginRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        file_pointer: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> Request | None:
        if origin(request.full_url) != origin(new_url):
            return None
        return super().redirect_request(
            request, file_pointer, code, message, headers, new_url
        )


def send_request(
    template: RawRequest,
    limiter: RateLimiter,
    timeout: float = 20.0,
    maximum_attempts: int = 3,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for attempt in range(1, maximum_attempts + 1):
        limiter.wait()
        headers = {
            key: value
            for key, value in template.headers.items()
            if key.casefold() not in {"host", "content-length", "transfer-encoding"}
        }
        request = Request(template.url, data=template.body, headers=headers, method=template.method)
        started = time.monotonic()
        try:
            with build_opener(ScopeRedirectHandler()).open(
                request, timeout=timeout
            ) as response:
                body = response.read(2 * 1024 * 1024 + 1)
                result = response_summary(
                    response.status,
                    response.geturl(),
                    response.headers,
                    body[: 2 * 1024 * 1024],
                    time.monotonic() - started,
                )
        except HTTPError as error:
            try:
                body = error.read(2 * 1024 * 1024 + 1)
                result = response_summary(
                    error.code,
                    error.geturl(),
                    error.headers,
                    body[: 2 * 1024 * 1024],
                    time.monotonic() - started,
                )
            finally:
                error.close()
        except (URLError, TimeoutError, OSError) as error:
            result = {
                "error": type(error).__name__,
                "message_hash": hashlib.sha256(str(error).encode()).hexdigest(),
            }
        result["attempts"] = attempt
        limiter.observe(result)
        if result.get("status") not in {429, 503} or attempt == maximum_attempts:
            return result
        time.sleep(min(2 ** (attempt - 1), 8))
    return result


def discovery_get(
    url: str,
    headers: dict[str, str],
    limiter: RateLimiter,
    maximum_bytes: int = 4 * 1024 * 1024,
) -> tuple[dict[str, Any], bytes]:
    limiter.wait()
    request_headers = {
        key: value
        for key, value in headers.items()
        if key.casefold() not in {"host", "content-length", "transfer-encoding"}
    }
    request_headers.setdefault("Accept", "application/json, application/xml, text/plain, */*;q=0.5")
    request_headers.setdefault("User-Agent", "Blue-Sec-Hub/0.5 safe-discovery")
    request = Request(url, headers=request_headers, method="GET")
    started = time.monotonic()
    try:
        with build_opener(ExactOriginRedirectHandler()).open(request, timeout=20) as response:
            body = response.read(maximum_bytes + 1)
            summary = response_summary(
                response.status,
                response.geturl(),
                response.headers,
                body[:maximum_bytes],
                time.monotonic() - started,
            )
    except HTTPError as error:
        try:
            body = error.read(maximum_bytes + 1)
            summary = response_summary(
                error.code,
                error.geturl(),
                error.headers,
                body[:maximum_bytes],
                time.monotonic() - started,
            )
        finally:
            error.close()
    except (URLError, TimeoutError, OSError) as error:
        return ({"error": type(error).__name__, "message_hash": hashlib.sha256(str(error).encode()).hexdigest()}, b"")
    summary["oversized"] = len(body) > maximum_bytes
    return summary, body[:maximum_bytes]


def sanitized_openapi(value: dict[str, Any], target: str) -> dict[str, Any] | None:
    if not isinstance(value.get("paths"), dict) or not (value.get("openapi") or value.get("swagger")):
        return None
    methods = {"get", "head", "options", "post", "put", "patch", "delete", "trace"}

    def schema_shape(raw: Any, depth: int = 0) -> Any:
        if depth > 8 or not isinstance(raw, dict):
            return {}
        allowed = {
            "type", "format", "required", "nullable", "readOnly", "writeOnly",
            "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems",
            "pattern", "enum", "$ref", "additionalProperties",
        }
        result = {key: raw[key] for key in allowed if key in raw}
        if isinstance(raw.get("properties"), dict):
            result["properties"] = {
                str(key): schema_shape(child, depth + 1)
                for key, child in raw["properties"].items()
                if isinstance(child, dict)
            }
        if isinstance(raw.get("items"), dict):
            result["items"] = schema_shape(raw["items"], depth + 1)
        for keyword in ("allOf", "anyOf", "oneOf"):
            if isinstance(raw.get(keyword), list):
                result[keyword] = [schema_shape(child, depth + 1) for child in raw[keyword] if isinstance(child, dict)]
        return result

    def safe_parameter(parameter: dict[str, Any]) -> dict[str, Any]:
        result = {
            key: parameter[key]
            for key in ("name", "in", "required", "style", "explode", "allowEmptyValue")
            if key in parameter
        }
        if isinstance(parameter.get("schema"), dict):
            result["schema"] = schema_shape(parameter["schema"])
        return result
    paths: dict[str, Any] = {}
    for route, path_item in value["paths"].items():
        if not isinstance(route, str) or not isinstance(path_item, dict):
            continue
        sanitized_item: dict[str, Any] = {}
        common = path_item.get("parameters", [])
        if isinstance(common, list):
            sanitized_item["parameters"] = [
                safe_parameter(parameter)
                for parameter in common
                if isinstance(parameter, dict) and parameter.get("name")
            ]
        for method, operation in path_item.items():
            if method.casefold() not in methods or not isinstance(operation, dict):
                continue
            parameters = operation.get("parameters", [])
            sanitized_item[method.casefold()] = {
                "operationId": operation.get("operationId"),
                "tags": [str(tag) for tag in operation.get("tags", []) if isinstance(tag, str)][:20],
                "parameters": [
                    safe_parameter(parameter)
                    for parameter in parameters
                    if isinstance(parameter, dict) and parameter.get("name")
                ],
            }
        if any(key in methods for key in sanitized_item):
            paths[route] = sanitized_item
    if not paths:
        return None
    servers = []
    for server in value.get("servers", []):
        if isinstance(server, dict) and isinstance(server.get("url"), str):
            servers.append({"url": server["url"]})
    if not servers and value.get("swagger"):
        scheme = next(
            (item for item in value.get("schemes", []) if item in {"http", "https"}),
            urlsplit(target_url(target)).scheme,
        )
        host = value.get("host") or urlsplit(target_url(target)).netloc
        base_path = str(value.get("basePath") or "/")
        servers.append({"url": f"{scheme}://{host}{base_path}"})
    result = {
        "openapi": str(value.get("openapi") or value.get("swagger")),
        "info": {"title": "sanitized-current-schema", "version": "current"},
        "servers": servers or [{"url": origin(target)}],
        "paths": paths,
    }
    components = value.get("components", {})
    if isinstance(components, dict) and isinstance(components.get("schemas"), dict):
        result["components"] = {
            "schemas": {
                str(key): schema_shape(child)
                for key, child in components["schemas"].items()
                if isinstance(child, dict)
            }
        }
    return result


def sitemap_routes(body: bytes, source_url: str, target: str) -> list[dict[str, Any]]:
    routes: set[str] = set()
    try:
        root = ElementTree.fromstring(body)
        for element in root.iter():
            if element.tag.rsplit("}", 1)[-1].casefold() != "loc" or not element.text:
                continue
            candidate = urljoin(source_url, element.text.strip())
            if origin(candidate) == origin(target):
                routes.add(urlsplit(candidate).path or "/")
    except ElementTree.ParseError:
        return []
    return [
        {"kind": "route", "method": "GET", "url": route, "validation_state": "documented", "profiles": ["rest"]}
        for route in sorted(routes)
    ]


def robots_routes(body: bytes) -> list[dict[str, Any]]:
    routes = set()
    text = body.decode("utf-8", errors="replace")
    for line in text.splitlines():
        name, separator, value = line.partition(":")
        if separator and name.strip().casefold() in {"allow", "disallow"}:
            path = value.strip().split("#", 1)[0].strip()
            if path.startswith("/") and "*" not in path and "$" not in path:
                routes.add(urlsplit(path).path or "/")
    return [
        {"kind": "route", "method": "GET", "url": route, "validation_state": "documented", "profiles": ["rest"]}
        for route in sorted(routes)
    ]


def collect_protocol_documents(
    workspace: Path,
    target: str,
    headers: dict[str, str],
    requests_per_second: float,
    refresh: bool = False,
) -> list[tuple[str, Path]]:
    root = workspace / "current-protocol-discovery"
    root.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        root.chmod(0o700)
    ledger_path = root / "discovery-ledger.json"
    if ledger_path.is_file() and not refresh:
        cached = [("openapi", path) for path in sorted(root.glob("openapi-*.json"))]
        manual = root / "protocol-and-route-surfaces.json"
        if manual.is_file():
            cached.append(("manual", manual))
        return cached
    limiter = RateLimiter(requests_per_second)
    base = origin(target)
    nonce_url = f"{base}/.blue-sec-not-found-{uuid.uuid4().hex}.json"
    fallback, _ = discovery_get(nonce_url, headers, limiter)
    candidates = (
        ("openapi", "/openapi.json"),
        ("openapi", "/swagger.json"),
        ("openapi", "/v3/api-docs"),
        ("oauth", "/.well-known/openid-configuration"),
        ("robots", "/robots.txt"),
        ("sitemap", "/sitemap.xml"),
    )
    inputs: list[tuple[str, Path]] = []
    manual_surfaces: list[dict[str, Any]] = []
    ledger = []
    for kind, path in candidates:
        url = urljoin(base + "/", path.lstrip("/"))
        summary, body = discovery_get(url, headers, limiter)
        disposition = "rejected"
        reason = "not-a-recognized-document"
        if summary.get("status") in {404, 410}:
            reason = "not-found"
        elif summary.get("final_path") != path:
            reason = "redirected-away"
        elif summary.get("sha256") and summary.get("sha256") == fallback.get("sha256"):
            reason = "fallback-equivalent"
        elif summary.get("oversized"):
            reason = "oversized"
        elif summary.get("status") == 200:
            if kind in {"openapi", "oauth"}:
                try:
                    value = json.loads(body)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    value = None
                if kind == "openapi" and isinstance(value, dict):
                    sanitized = sanitized_openapi(value, target)
                    if sanitized:
                        destination = root / f"openapi-{hashlib.sha256(path.encode()).hexdigest()[:10]}.json"
                        atomic_json(destination, sanitized)
                        inputs.append(("openapi", destination))
                        disposition, reason = "documented", "valid-openapi-structure"
                elif kind == "oauth" and isinstance(value, dict) and value.get("issuer"):
                    for field in ("authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri", "registration_endpoint"):
                        endpoint = value.get(field)
                        if isinstance(endpoint, str) and endpoint.startswith(("http://", "https://")):
                            manual_surfaces.append({
                                "kind": "api",
                                "method": "GET" if field in {"userinfo_endpoint", "jwks_uri"} else "UNKNOWN",
                                "url": endpoint,
                                "validation_state": "documented",
                                "profiles": ["oauth-oidc"],
                                "fields": [],
                            })
                    disposition, reason = "documented", "valid-oidc-metadata"
            elif kind == "robots" and b"user-agent" in body.lower():
                manual_surfaces.extend(robots_routes(body))
                disposition, reason = "documented", "valid-robots-structure"
            elif kind == "sitemap":
                routes = sitemap_routes(body, url, target)
                if routes:
                    manual_surfaces.extend(routes)
                    disposition, reason = "documented", "valid-sitemap-structure"
        ledger.append({"kind": kind, "path": path, "status": disposition, "reason": reason, "response": summary})
    if manual_surfaces:
        manual = root / "protocol-and-route-surfaces.json"
        atomic_json(manual, {"surfaces": manual_surfaces})
        inputs.append(("manual", manual))
        atomic_json(
            root / "route-seeds.json",
            {
                "routes": [
                    item["url"]
                    for item in manual_surfaces
                    if item.get("kind") == "route"
                ]
            },
        )
    atomic_json(ledger_path, {"schema_version": 1, "candidates": ledger})
    return inputs


def decode_body(template: RawRequest) -> tuple[str, Any]:
    if not template.body:
        return "none", None
    content_type = next(
        (value for key, value in template.headers.items() if key.casefold() == "content-type"),
        "",
    ).casefold()
    if "json" in content_type:
        try:
            return "json", json.loads(template.body)
        except json.JSONDecodeError:
            return "raw", template.body
    if "x-www-form-urlencoded" in content_type:
        return "form", parse_qsl(template.body.decode(errors="replace"), keep_blank_values=True)
    return "raw", template.body


def field_matches(name: str, mode: str) -> bool:
    leaf = re.sub(r"\[\]$", "", name).rsplit(".", 1)[-1]
    pattern = PARENT_FIELD_RE if mode == "tenant-parent-binding" else SUBJECT_FIELD_RE
    if pattern.search(leaf):
        return True
    compact = re.sub(r"[^a-z0-9]", "", leaf.casefold())
    suffixes = (
        ("tenantid", "orgid", "organizationid", "departmentid", "projectid", "workspaceid", "parentid", "groupid")
        if mode == "tenant-parent-binding"
        else ("userid", "accountid", "ownerid", "creatorid", "memberid", "subjectid", "principalid", "operatorid")
    )
    return any(compact.endswith(suffix) for suffix in suffixes)


def nonexistent_like(value: Any) -> Any:
    if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
        return 2147483646
    return "blue-sec-nonexistent-" + uuid.uuid4().hex[:12]


def mutate_mapping(value: Any, variant: str, mode: str | None, fields: list[str]) -> Any:
    if not isinstance(value, dict):
        return value
    result = json.loads(json.dumps(value))
    names = [key for key in result if field_matches(key, mode or "")]
    if not names:
        names = [field for field in fields if field_matches(field, mode or "") and "." not in field]
    for name in names:
        if variant.startswith("omitted-"):
            result.pop(name, None)
        elif "nonexistent" in variant or "conflicting" in variant:
            result[name] = nonexistent_like(result.get(name))
        elif "empty" in variant:
            result[name] = ""
    return result


def variant_request(
    template: RawRequest,
    variant: str,
    mode: str | None,
    fields: list[str],
) -> tuple[RawRequest | None, str | None]:
    headers = dict(template.headers)
    url = template.url
    body = template.body
    if variant in {"baseline", "authenticated-baseline", "self-subject", "self-owned-baseline", "current-parent", "current-state-baseline", "low-privilege-forced-access"}:
        return RawRequest(template.method, url, headers, body, template.source), None
    if variant == "anonymous-variant":
        headers = {key: value for key, value in headers.items() if key.casefold() not in AUTH_HEADERS}
        return RawRequest(template.method, url, headers, body, template.source), None
    if variant == "cors-origin-variant":
        if template.method not in {"GET", "HEAD", "OPTIONS"}:
            return None, "CORS origin probe requires an observed safe read request"
        headers["Origin"] = CORS_TEST_ORIGIN
        return RawRequest(template.method, url, headers, body, template.source), None
    if variant in {"cache-header-review", "content-type-variant"}:
        return None, "variant is resolved from baseline response metadata"
    if variant == "oauth-metadata-review":
        return None, "variant is resolved from baseline OAuth metadata"
    if variant == "graphql-typename":
        if template.method != "POST":
            return None, "GraphQL typename probe requires an observed POST request shape"
        headers["Content-Type"] = "application/json"
        body = json.dumps({"query": "query BlueSecTypeName { __typename }"}).encode()
        return RawRequest(template.method, url, headers, body, template.source), None
    if variant == "sse-handshake":
        if template.method not in {"GET", "HEAD"}:
            return None, "SSE handshake requires an observed safe read request"
        headers["Accept"] = "text/event-stream"
        return RawRequest(template.method, url, headers, body, template.source), None
    if variant == "path-normalization-variant":
        parsed = urlsplit(url)
        path = re.sub(r"/{2,}", "/", parsed.path)
        path = "/./".join(path.split("/", 2)) if path.count("/") >= 2 else path
        url = urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, ""))
        return RawRequest(template.method, url, headers, body, template.source), None
    kind, decoded = decode_body(template)
    parsed = urlsplit(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    marker = "blue-sec-probe-" + uuid.uuid4().hex[:8]
    if variant in {"syntax-marker", "parser-marker"}:
        replacement: Any = "'\"<>" + marker
    elif variant == "boolean-true":
        replacement = "1 AND 1=1"
    elif variant == "boolean-false":
        replacement = "1 AND 1=2"
    elif variant == "harmless-marker":
        replacement = f"<span data-blue-sec-probe=\"{marker}\"></span>"
    elif variant == "nonexistent-self-path":
        replacement = marker
    else:
        replacement = None
    if query:
        updated = []
        matched = False
        for key, value in query:
            if mode and field_matches(key, mode):
                matched = True
                if variant.startswith("omitted-"):
                    continue
                if "conflicting" in variant:
                    updated.append((key, value))
                    updated.append((key, str(nonexistent_like(value))))
                    continue
                if "nonexistent" in variant or "conflicting" in variant:
                    value = str(nonexistent_like(value))
            elif replacement is not None and not matched:
                value = str(replacement)
                matched = True
            updated.append((key, value))
        query = updated
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query, doseq=True), ""))
    elif kind == "json" and isinstance(decoded, dict):
        if mode:
            if "conflicting" in variant:
                return None, "duplicate-key mutation is not safe for normalized JSON bodies"
            decoded = mutate_mapping(decoded, variant, mode, fields)
        elif replacement is not None:
            candidate = next((key for key in decoded if not re.search(r"page|size|limit|offset", key, re.I)), None)
            if candidate is None:
                return None, "no safe scalar request field available"
            decoded[candidate] = replacement
        body = json.dumps(decoded, separators=(",", ":")).encode()
    elif mode and fields and template.method in {"GET", "HEAD"}:
        field = next((item for item in fields if field_matches(item, mode)), None)
        if not field or variant.startswith("omitted-"):
            return None, "subject or parent field is absent from the current request shape"
        url = urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                urlencode([(field, nonexistent_like("value"))]),
                "",
            )
        )
    elif replacement is not None and fields and template.method in {"GET", "HEAD"}:
        url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode([(fields[0], replacement)]), ""))
    else:
        return None, "request value required for safe deterministic mutation"
    return RawRequest(template.method, url, headers, body, template.source), None


def differential(baseline: dict[str, Any], variant: dict[str, Any]) -> dict[str, Any]:
    keys = ("status", "content_type", "length", "sha256", "business_code_hash", "json_shape")
    changed = [key for key in keys if baseline.get(key) != variant.get(key)]
    equivalent_structure = (
        baseline.get("status") == variant.get("status")
        and baseline.get("json_shape") is not None
        and baseline.get("json_shape") == variant.get("json_shape")
    )
    return {
        "changed_dimensions": changed,
        "equivalent_structure": equivalent_structure,
        "baseline_success": 200 <= int(baseline.get("status", 0)) < 300,
        "variant_success": 200 <= int(variant.get("status", 0)) < 300,
    }


def cors_validation_dependencies(
    template: RawRequest,
    baseline: dict[str, Any],
    result: dict[str, Any],
    evidence_ref: str,
) -> list[dict[str, Any]]:
    cors = result.get("cors", {})
    reflected = (
        cors.get("allow_origin_kind") == "origin"
        and cors.get("allow_origin_sha256") == CORS_TEST_ORIGIN_SHA256
    )
    credentialed_policy = reflected and cors.get("allow_credentials") is True
    cookie_context = any(
        str(name).casefold() == "cookie" for name in template.headers
    )
    protected_response = bool(
        baseline.get("sensitive_field_names")
        or HIGH_VALUE_PATH_RE.search(urlsplit(template.url).path)
    )
    successful_response = 200 <= int(result.get("status", 0)) < 300
    if not (
        credentialed_policy
        and cookie_context
        and protected_response
        and successful_response
    ):
        return []
    return [
        {
            "id": "concrete-endpoint",
            "kind": "endpoint-reachability",
            "status": "satisfied",
            "evidence_refs": [evidence_ref],
        },
        {
            "id": "cross-origin-readability",
            "kind": "browser-policy",
            "status": "satisfied",
            "evidence_refs": [evidence_ref],
        },
        {
            "id": "ambient-credential-delivery",
            "kind": "browser-auth-context",
            "status": "pending",
            "reason": (
                "prove that the browser sends the current ambient credential from "
                "a controlled cross-origin context; a replayed Cookie header is insufficient"
            ),
            "resolution_action": "controlled-browser-cross-origin-read",
        },
        {
            "id": "protected-response-impact",
            "kind": "confidentiality-impact",
            "status": "satisfied",
            "evidence_refs": [evidence_ref],
        },
    ]


def evidence_for_variant(
    workspace: Path,
    case: dict[str, Any],
    variant: str,
    baseline: dict[str, Any],
    result: dict[str, Any],
    oracle: dict[str, Any],
    request_variant: RawRequest | None = None,
) -> str:
    evidence_id = f"runner-{case['id']}-{hashlib.sha256(variant.encode()).hexdigest()[:10]}"
    path = workspace / "evidence" / "runner" / f"{evidence_id}.json"
    request_material_hash = None
    if request_variant is not None:
        material = b"\0".join(
            (
                request_variant.method.encode(),
                request_variant.url.encode(),
                request_variant.body or b"",
            )
        )
        request_material_hash = hashlib.sha256(material).hexdigest()
    atomic_json(
        path,
        {
            "schema_version": 1,
            "test_case_id": case["id"],
            "variant": variant,
            "captured_at": now(),
            "baseline": baseline,
            "result": result,
            "oracle": oracle,
            "technique_refs": list(case.get("technique_refs", [])),
            "payload_template_ref": case.get("payload_template_ref"),
            "payload_material_sha256": request_material_hash,
            "raw_values_persisted": False,
        },
    )
    relative = str(path.relative_to(workspace))
    web_assessment.append_event(
        workspace,
        {"type": "evidence", "path": relative, "kind": "runner-request-response", "sha256": file_sha256(path)},
    )
    return relative


def authorization_evidence(mode: str | None) -> list[str]:
    return {
        "anonymous-boundary": ["anonymous-authenticated-differential"],
        "low-privilege-function": ["function-impact"],
        "implicit-subject-binding": ["self-subject-baseline"],
        "self-owned-object": ["self-owned-baseline"],
        "cross-principal-ownership": ["cross-principal-baseline"],
        "tenant-parent-binding": ["tenant-parent-baseline"],
        "protected-property": ["protected-property-baseline"],
        "workflow-precondition": ["workflow-state-baseline"],
        "state-transition": ["workflow-state-baseline"],
    }.get(mode or "", [])


def select_template(
    case: dict[str, Any],
    shape: dict[str, Any],
    surface: dict[str, Any],
    raw: dict[tuple[str, str, str, tuple[str, ...]], list[RawRequest]],
    lease: CredentialLease,
) -> RawRequest | None:
    method = str(shape.get("method") or surface.get("method") or "GET").upper()
    url = str(surface.get("url") or "")
    key = request_key(method, url)
    exact = raw.get(key, [])
    path_candidates = [
        request
        for request_key_value, requests in raw.items()
        if request_key_value[:3] == key[:3]
        for request in requests
    ]
    candidate = (
        exact[-1]
        if exact
        else path_candidates[0]
        if len(path_candidates) == 1
        else None
    )
    if candidate is not None:
        headers = dict(candidate.headers)
        headers.update(lease.headers)
        return RawRequest(method, candidate.url, headers, candidate.body, candidate.source)
    if path_candidates:
        return None
    if method not in {"GET", "HEAD", "OPTIONS"}:
        return None
    return RawRequest(method, url, dict(lease.headers), None, "surface")


def record_blocked_case(
    workspace: Path,
    case: dict[str, Any],
    reason: str,
) -> None:
    for variant in case.get("variants", []):
        web_assessment.append_event(
            workspace,
            {
                "type": "variant-result",
                "test_case_id": case["id"],
                "variant_id": variant,
                "status": "blocked",
                "reason": reason,
            },
        )
    web_assessment.append_event(
        workspace,
        {
            "type": "test-result",
            "test_cell_id": case["test_cell_id"],
            "test_case_id": case["id"],
            "status": "blocked",
            "reason": reason,
        },
    )


def run_transaction_case(
    workspace: Path,
    case: dict[str, Any],
    transactions: dict[str, dict[str, RawRequest]],
    limiter: RateLimiter,
) -> None:
    evidence_refs = []
    blocked = []
    cleanup_complete = True
    candidate_reasons = []
    cleanup_failed = False
    for variant in case.get("variants", []):
        if cleanup_failed:
            blocked.append(variant)
            web_assessment.append_event(
                workspace,
                {
                    "type": "variant-result",
                    "test_case_id": case["id"],
                    "variant_id": variant,
                    "status": "blocked",
                    "reason": "a prior rollback failed; later writes were not sent",
                },
            )
            continue
        transaction = transactions.get(variant)
        if transaction is None:
            blocked.append(variant)
            web_assessment.append_event(
                workspace,
                {
                    "type": "variant-result",
                    "test_case_id": case["id"],
                    "variant_id": variant,
                    "status": "blocked",
                    "reason": "private transaction template unavailable for this variant",
                },
            )
            continue
        prestate = send_request(transaction["prestate"], limiter)
        if not 200 <= int(prestate.get("status", 0)) < 300:
            blocked.append(variant)
            web_assessment.append_event(
                workspace,
                {
                    "type": "variant-result",
                    "test_case_id": case["id"],
                    "variant_id": variant,
                    "status": "blocked",
                    "reason": "self-owned prestate could not be read; mutation was not sent",
                },
            )
            continue
        mutation = send_request(
            transaction["mutation"], limiter, maximum_attempts=1
        )
        rollback = send_request(
            transaction["rollback"], limiter, maximum_attempts=1
        )
        verify = send_request(transaction["verify"], limiter)
        rollback_ok = 200 <= int(rollback.get("status", 0)) < 300
        restored = rollback_ok and prestate.get("sha256") == verify.get("sha256")
        oracle = {
            "mutation": differential(prestate, mutation),
            "rollback_status": rollback.get("status"),
            "restored": restored,
        }
        evidence_ref = evidence_for_variant(
            workspace,
            case,
            variant,
            prestate,
            {
                "mutation": mutation,
                "rollback": rollback,
                "verify": verify,
            },
            oracle,
            transaction["mutation"],
        )
        evidence_refs.append(evidence_ref)
        mutation_status = int(mutation.get("status", 0))
        if not restored:
            blocked.append(variant)
            cleanup_complete = False
            cleanup_failed = True
            status = "blocked"
            reason = "rollback or cleanup verification failed"
        elif mutation_status == 0 or mutation_status == 429 or mutation_status >= 500:
            blocked.append(variant)
            status = "blocked"
            reason = "mutation did not produce a stable application response"
        else:
            status = "tested"
            reason = None
            if 200 <= mutation_status < 300:
                candidate_reasons.append(
                    f"{variant} write was accepted and restored; policy impact requires validation"
                )
        event = {
            "type": "variant-result",
            "test_case_id": case["id"],
            "variant_id": variant,
            "status": status,
            "evidence_refs": [evidence_ref],
            "oracle": oracle,
        }
        if reason:
            event["reason"] = reason
        web_assessment.append_event(workspace, event)
    if candidate_reasons:
        web_assessment.append_event(
            workspace,
            {
                "type": "candidate",
                "schema_version": 1,
                "claim_kind": "vulnerability",
                "id": web_assessment.stable_id(
                    "candidate", {"case": case["id"], "executor": "transaction"}
                ),
                "title": "Reversible self-owned write requires policy impact validation",
                "validation_state": "candidate",
                "potential_impact": "unauthorized state change if policy ownership is bypassed",
                "investigation_priority": "high",
                "reasons": candidate_reasons,
                "evidence_refs": sorted(set(evidence_refs)),
                "surface_refs": [case.get("surface_ref")],
            },
        )
    status = "blocked" if blocked else "tested"
    result_event = {
        "type": "test-result",
        "test_cell_id": case["test_cell_id"],
        "test_case_id": case["id"],
        "status": status,
        "evidence_refs": sorted(set(evidence_refs)),
        "cleanup": {
            "status": "completed" if cleanup_complete else "failed",
            "evidence_refs": sorted(set(evidence_refs)),
        },
        "negative_result": not candidate_reasons,
    }
    if blocked:
        result_event["reason"] = "transaction variants unresolved: " + ", ".join(
            blocked
        )
    if case.get("authorization_mode") and status == "tested":
        result_event["authorization_evidence"] = authorization_evidence(
            case.get("authorization_mode")
        )
    web_assessment.append_event(workspace, result_event)


def run_case(
    workspace: Path,
    case: dict[str, Any],
    plan: dict[str, Any],
    inventory: dict[str, Any],
    raw: dict[tuple[str, str, str, tuple[str, ...]], list[RawRequest]],
    lease: CredentialLease,
    limiter: RateLimiter,
    transactions: dict[str, dict[str, dict[str, RawRequest]]] | None = None,
) -> None:
    payload_policy = str(case.get("payload_policy") or "needs-agent")
    if payload_policy != "safe-auto":
        record_blocked_case(
            workspace,
            case,
            (
                "payload technique is prohibited by policy"
                if payload_policy == "blocked"
                else "payload technique requires an agent-bound controlled context"
            ),
        )
        return
    shapes = {item["id"]: item for item in plan.get("request_shapes", [])}
    surfaces = {item["id"]: item for item in inventory.get("surfaces", [])}
    shape = shapes.get(case.get("request_shape_id"), {})
    surface = surfaces.get(case.get("surface_ref"), {})
    template = select_template(case, shape, surface, raw, lease)
    mode = case.get("authorization_mode")
    if template and template.method in {"POST", "PUT", "PATCH", "DELETE"} and shape.get("semantics") == "write":
        transaction = (transactions or {}).get(case["id"], {})
        if transaction:
            run_transaction_case(workspace, case, transaction, limiter)
            return
        reason = "write transaction requires a verified pre-state and executable rollback template"
        record_blocked_case(workspace, case, reason)
        return
    if template is None:
        reason = "raw request template unavailable for non-safe method"
        record_blocked_case(workspace, case, reason)
        return
    baseline = send_request(template, limiter)
    if baseline.get("status") in {429, 503} or baseline.get("challenge_hint"):
        reason = "rate limit, service protection, or interactive challenge prevented a stable baseline"
        web_assessment.append_event(
            workspace,
            {
                "type": "runtime-condition",
                "kind": "edge-protection",
                "status": "blocked",
                "reason": reason,
            },
        )
        record_blocked_case(workspace, case, reason)
        return
    if lease.headers and baseline.get("status") == 401:
        reason = "credential rejected by current endpoint; refresh the credential lease"
        web_assessment.append_event(
            workspace,
            {
                "type": "runtime-condition",
                "kind": "credential",
                "status": "blocked",
                "reason": reason,
            },
        )
        record_blocked_case(workspace, case, reason)
        return
    evidence_refs = []
    candidate = False
    low_privilege_impact = False
    blocked_variants = []
    candidate_reasons = []
    candidate_dependencies: list[dict[str, Any]] = []
    variant_oracles: dict[str, dict[str, Any]] = {}
    baseline_variant = next(
        (item for item in case.get("variants", []) if "baseline" in item),
        None,
    )
    for variant in case.get("variants", []):
        request_variant, resolution = variant_request(
            template,
            variant,
            mode,
            list(shape.get("body_fields", [])),
        )
        if request_variant is None and resolution:
            result = baseline
            oracle = {"resolution": resolution, "changed_dimensions": []}
            status = "tested" if variant == "cache-header-review" else "blocked"
            reason = resolution
        else:
            result = baseline if variant == baseline_variant else send_request(request_variant or template, limiter)
            oracle = differential(baseline, result)
            status = "tested"
            reason = None
        evidence_ref = evidence_for_variant(
            workspace,
            case,
            variant,
            baseline,
            result,
            oracle,
            request_variant or template,
        )
        evidence_refs.append(evidence_ref)
        variant_oracles[variant] = oracle
        if status == "blocked":
            blocked_variants.append(variant)
        event = {
            "type": "variant-result",
            "test_case_id": case["id"],
            "variant_id": variant,
            "status": status,
            "evidence_refs": [evidence_ref],
            "oracle": oracle,
        }
        if reason:
            event["reason"] = reason
        web_assessment.append_event(workspace, event)
        if (
            mode == "anonymous-boundary"
            and variant == "anonymous-variant"
            and oracle.get("equivalent_structure")
            and oracle.get("variant_success")
            and (result.get("sensitive_field_names") or HIGH_VALUE_PATH_RE.search(urlsplit(template.url).path))
        ):
            repeat = send_request(request_variant or template, limiter)
            repeat_oracle = differential(result, repeat)
            if repeat_oracle.get("equivalent_structure") and repeat_oracle.get("variant_success"):
                candidate = True
                finding_id = web_assessment.stable_id("finding", {"case": case["id"], "mode": mode})
                web_assessment.append_event(
                    workspace,
                    {
                        "type": "finding",
                        "schema_version": 1,
                        "claim_kind": "vulnerability",
                        "id": finding_id,
                        "claim_id": finding_id,
                        "title": "Authenticated response remains structurally accessible without credentials",
                        "validation_state": "confirmed",
                        "attacker_prerequisites": ["network access to the affected endpoint"],
                        "validation_dependencies": [
                            {
                                "id": dependency_id,
                                "status": "satisfied",
                                "evidence_refs": [evidence_ref],
                                "reason": None,
                            }
                            for dependency_id in (
                                "attacker-source",
                                "controlled-input",
                                "reachable-path",
                                "consumer",
                                "trigger-result",
                                "observable-impact",
                            )
                        ],
                        "potential_impact": "unauthorized disclosure of protected response data",
                        "confirmed_impact": "anonymous retrieval reproduced the protected response structure",
                        "investigation_priority": "high",
                        "formal_severity": "high",
                        "next_actions": ["continue adjacent authorization and object-boundary coverage"],
                        "alternative_explanations": [],
                        "coverage_effect": "continue",
                        "authorization_mode": mode,
                        "authorization_evidence_quality": "anonymous-authenticated-differential",
                        "evidence_refs": [evidence_ref],
                        "impact_evidence_refs": [evidence_ref],
                        "surface_refs": [case.get("surface_ref")],
                    },
                )
        if (
            mode == "low-privilege-function"
            and oracle.get("variant_success")
            and (
                result.get("sensitive_field_names")
                or HIGH_VALUE_PATH_RE.search(urlsplit(template.url).path)
            )
        ):
            low_privilege_impact = True
            candidate = True
            web_assessment.append_event(
                workspace,
                {
                    "type": "candidate",
                    "schema_version": 1,
                    "claim_kind": "vulnerability",
                    "id": web_assessment.stable_id(
                        "candidate", {"case": case["id"], "mode": mode}
                    ),
                    "title": "Low-privilege request reached a potentially protected function",
                    "validation_state": "candidate",
                    "potential_impact": "function-level authorization bypass",
                    "investigation_priority": "high",
                    "authorization_mode": mode,
                    "authorization_evidence_quality": "function-impact",
                    "evidence_refs": [evidence_ref],
                    "surface_refs": [case.get("surface_ref")],
                },
            )
        if mode in {"implicit-subject-binding", "tenant-parent-binding"} and (
            "nonexistent" in variant or "conflicting" in variant
        ) and oracle.get("variant_success") and oracle.get("changed_dimensions"):
            candidate = True
            candidate_reasons.append("client-controlled subject or parent field changed the response")
        if mode is None and result.get("probe_reflected"):
            candidate = True
            candidate_reasons.append("harmless marker was reflected in the response")
        if mode is None and variant == "path-normalization-variant" and (
            oracle.get("variant_success") and not oracle.get("baseline_success")
        ):
            candidate = True
            candidate_reasons.append("normalized path changed a denied baseline into a successful response")
        if (
            mode is None
            and case.get("family") == "platform-exposure.headers-cache-cors"
            and variant == "cors-origin-variant"
        ):
            candidate_dependencies = cors_validation_dependencies(
                template, baseline, result, evidence_ref
            )
            if candidate_dependencies:
                candidate = True
                candidate_reasons.append(
                    "credentialed cross-origin policy signal requires browser-context prerequisite validation"
                )
        if (
            mode is None
            and case.get("executor_id") == "passive-response-review"
            and case.get("family") != "platform-exposure.headers-cache-cors"
            and result.get("sensitive_field_names")
        ):
            candidate = True
            candidate_reasons.append("response shape contains potentially sensitive fields")
    true_oracle = variant_oracles.get("boolean-true", {})
    false_oracle = variant_oracles.get("boolean-false", {})
    if mode is None and true_oracle and false_oracle and (
        true_oracle.get("equivalent_structure")
        and true_oracle.get("variant_success")
        and false_oracle.get("changed_dimensions")
    ):
        candidate = True
        candidate_reasons.append("boolean true and false variants produced a repeatable structural differential")
    if candidate_reasons:
        candidate_event = {
            "type": "candidate",
            "schema_version": 1,
            "claim_kind": "vulnerability",
            "id": web_assessment.stable_id(
                "candidate",
                {
                    "case": case["id"],
                    "executor": case.get("executor_id"),
                    "mode": mode,
                },
            ),
            "title": (
                "Subject or parent binding differential requires ownership validation"
                if mode in {"implicit-subject-binding", "tenant-parent-binding"}
                else "Deterministic response differential requires impact validation"
            ),
            "validation_state": "candidate",
            "potential_impact": "authorization, injection, or policy impact if the differential reaches a protected consumer",
            "investigation_priority": "high",
            "reasons": sorted(set(candidate_reasons)),
            "evidence_refs": sorted(set(evidence_refs)),
            "surface_refs": [case.get("surface_ref")],
        }
        if candidate_dependencies:
            candidate_event["validation_dependencies"] = candidate_dependencies
            candidate_event["title"] = (
                "Cross-origin policy signal requires browser-context impact validation"
            )
        if mode:
            candidate_event.update(
                {
                    "authorization_mode": mode,
                    "authorization_evidence_quality": "subject-binding-differential",
                }
            )
        web_assessment.append_event(
            workspace,
            candidate_event,
        )
    final_status = "tested"
    final_reason = None
    if blocked_variants:
        final_status = "blocked"
        final_reason = "deterministic mutation unavailable for: " + ", ".join(
            sorted(blocked_variants)
        )
    elif mode == "low-privilege-function" and not low_privilege_impact:
        final_status = "blocked"
        final_reason = "role policy or protected-function impact evidence is unavailable"
    result_event = {
        "type": "test-result",
        "test_cell_id": case["test_cell_id"],
        "test_case_id": case["id"],
        "status": final_status,
        "evidence_refs": sorted(set(evidence_refs)),
        "negative_result": not candidate,
    }
    if final_reason:
        result_event["reason"] = final_reason
    if mode and final_status == "tested":
        result_event["authorization_evidence"] = authorization_evidence(mode)
    web_assessment.append_event(workspace, result_event)


def execute_auto_queue(
    workspace: Path,
    raw_requests: list[RawRequest],
    lease: CredentialLease,
    limiter: RateLimiter,
    transactions: dict[str, dict[str, dict[str, RawRequest]]],
    lane: str | None = None,
    start_iteration: int = 0,
) -> int:
    raw: dict[tuple[str, str, str, tuple[str, ...]], list[RawRequest]] = {}
    for request in raw_requests:
        raw.setdefault(request_key(request.method, request.url), []).append(request)
    iteration = start_iteration
    while True:
        plan = load_json(workspace / "test-plan.json", {})
        inventory = load_json(workspace / "surface-inventory.json", {})
        pending = [
            item
            for item in plan.get("executable_cases", [])
            if item.get("case_kind") == "api-test"
            and item.get("automation_state") == "auto-ready"
            and (lane is None or item.get("execution_lane") == lane)
            and (
                item.get("status") not in RESOLVED
                or any(
                    item.get("variant_results", {}).get(variant, {}).get("status")
                    not in RESOLVED
                    for variant in item.get("variants", [])
                )
            )
        ]
        if not pending:
            return iteration
        case = pending[0]
        iteration += 1
        web_assessment.append_event(
            workspace,
            {
                "type": "runner-checkpoint",
                "status": "running",
                "phase": "fast-find" if lane == "fast-find" else "risk-execution",
                "iteration": iteration,
            },
        )
        run_case(workspace, case, plan, inventory, raw, lease, limiter, transactions)
        web_assessment.compile_workspace(workspace)


def record_event_once(workspace: Path, event: dict[str, Any], key: tuple[str, ...]) -> None:
    existing = web_assessment.read_events(workspace)
    if any(all(item.get(field) == event.get(field) for field in key) for item in existing):
        return
    web_assessment.append_event(workspace, event)


def historical_entrypoint(value: str, target: str) -> tuple[str, str] | None:
    text = value.strip()
    match = re.match(r"^(GET|HEAD|OPTIONS|POST|PUT|PATCH|DELETE)\s+(\S+)$", text, re.I)
    method = match.group(1).upper() if match else "UNKNOWN"
    candidate = match.group(2) if match else text
    if len(candidate) > 2048 or any(character.isspace() for character in candidate):
        return None
    if candidate.startswith(("http://", "https://")):
        if web_assessment.registrable_domain(urlsplit(candidate).hostname or "") != web_assessment.registrable_domain(urlsplit(target_url(target)).hostname or ""):
            return None
        return method, candidate
    if candidate.startswith("/") and not candidate.startswith("//"):
        return method, candidate
    return None


def run_history_lookup(workspace: Path, target: str) -> tuple[Path | None, Path | None]:
    host = urlsplit(target_url(target)).hostname or target
    history_input = None
    route_seeds_path = None
    try:
        result = subprocess.run(
            [sys.executable, str(REPORT_COMMAND), "search", "--system", host, "--json"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
        matches = []
        surfaces = []
        route_seeds = set()
        if result.returncode == 0 and result.stdout.strip():
            value = json.loads(result.stdout)
            if isinstance(value, list):
                for item in value[:100]:
                    if not isinstance(item, dict):
                        continue
                    matches.append({
                        "report_sha256": item.get("sha256"),
                        "finding_ids": [finding.get("id") for finding in item.get("findings", []) if isinstance(finding, dict) and finding.get("id")],
                    })
                    for finding in item.get("findings", []):
                        if not isinstance(finding, dict):
                            continue
                        for raw_entrypoint in finding.get("entrypoints", []) or []:
                            parsed = historical_entrypoint(str(raw_entrypoint), target)
                            if not parsed:
                                continue
                            method, entrypoint = parsed
                            path = urlsplit(urljoin(target_url(target), entrypoint)).path or "/"
                            api_like = method != "UNKNOWN" or bool(re.search(r"/(?:api|rest|graphql|service|svc|v\d+)(?:/|$)", path, re.I))
                            surfaces.append({
                                "kind": "api" if api_like else "route",
                                "method": method,
                                "url": entrypoint,
                                "validation_state": "historical",
                                "profiles": ["historical"],
                            })
                            if not api_like:
                                route_seeds.add(path)
        if surfaces:
            history_input = workspace / "current-history-surfaces.json"
            atomic_json(history_input, {"surfaces": surfaces})
        if route_seeds:
            route_seeds_path = workspace / "current-history-route-seeds.json"
            atomic_json(route_seeds_path, {"routes": sorted(route_seeds)})
        status = "completed-with-matches" if matches else "completed-no-match"
        event = {
            "type": "history-lookup",
            "status": status,
            "target_keys": [host],
            "matches": matches,
            "lookup_fingerprint": hashlib.sha256(json.dumps(matches, sort_keys=True).encode()).hexdigest(),
        }
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        event = {"type": "history-lookup", "status": "blocked", "target_keys": [host], "reason": "local report lookup unavailable"}
    record_event_once(workspace, event, ("type", "status", "lookup_fingerprint"))
    return history_input, route_seeds_path


def merge_route_seeds(workspace: Path, paths: list[Path]) -> Path | None:
    routes = set()
    for path in paths:
        value = load_json(path, {})
        for item in value.get("routes", []) if isinstance(value, dict) else []:
            if isinstance(item, str) and item.startswith("/"):
                routes.add(item)
    if not routes:
        return None
    destination = workspace / ".runtime" / "combined-route-seeds.json"
    atomic_json(destination, {"routes": sorted(routes)})
    return destination


def binding_kind(field: str) -> str:
    leaf = re.sub(r"\[\d+\]", "", field).rsplit(".", 1)[-1].casefold()
    if re.search(r"(?:token|ticket|challenge|session|cookie|nonce)$", leaf):
        return "session"
    if re.search(r"(?:user|owner|creator|subject|actor|member).*id$", leaf):
        return "subject"
    if re.search(r"(?:tenant|org|parent|project|group|department).*id$", leaf):
        return "parent"
    if re.search(r"(?:file|attachment|document|storage).*(?:id|key)$", leaf):
        return "file"
    if re.search(r"(?:id|uuid|key)$", leaf):
        return "object"
    return "value"


def update_object_provenance(workspace: Path, browser_output: Path) -> None:
    manifest = load_json(
        browser_output / "browser-assets" / "browser-manifest.json", {}
    )
    destination = workspace / "object-provenance.json"
    existing = load_json(destination, {"slots": []})
    inventory = load_json(
        browser_output / "analysis" / "surface-inventory.json", {"surfaces": []}
    )

    def surface_refs(endpoint: dict[str, Any]) -> list[str]:
        method = str(endpoint.get("method") or "UNKNOWN").upper()
        path = web_assessment.normalize_path(
            urlsplit(str(endpoint.get("url") or "/")).path
        )
        return sorted(
            item["id"]
            for item in inventory.get("surfaces", [])
            if item.get("id")
            and str(item.get("method") or "UNKNOWN").upper() == method
            and item.get("path_template") == path
        )
    slots = {
        str(item.get("id")): item
        for item in existing.get("slots", [])
        if item.get("id")
    }
    for producer in manifest.get("valueProducers", []):
        slot_id = str(producer.get("bindingSlotId") or "")
        if not slot_id:
            continue
        field = str(producer.get("field") or "")
        producer_refs = surface_refs(producer)
        previous = slots.get(slot_id, {})
        slots[slot_id] = {
            "id": slot_id,
            "kind": binding_kind(field),
            "semantic_alias": field.rsplit(".", 1)[-1],
            "producer": {
                "method": producer.get("method"),
                "field": producer.get("field"),
                "endpoint_slot": (previous.get("producer") or {}).get(
                    "endpoint_slot", f"endpoint-{uuid.uuid4()}"
                ),
            },
            "consumer": previous.get("consumer"),
            "producer_refs": sorted(
                set(previous.get("producer_refs", [])) | set(producer_refs)
            ),
            "consumer_refs": list(previous.get("consumer_refs", [])),
            "route_refs": list(previous.get("route_refs", [])),
            "ownership": "current-runtime-observed",
            "evidence": "identifier-produced-in-current-browser-response",
        }
    for flow in manifest.get("dataFlows", []):
        slot_id = str(flow.get("bindingSlotId") or "")
        if not slot_id:
            continue
        producer = flow.get("from", {})
        consumer = flow.get("to", {})
        field = str(consumer.get("field") or producer.get("field") or "")
        previous = slots.get(slot_id, {})
        slots[slot_id] = {
            "id": slot_id,
            "kind": binding_kind(field),
            "semantic_alias": field.rsplit(".", 1)[-1],
            "producer": {
                "method": producer.get("method"),
                "field": producer.get("field"),
                "endpoint_slot": (previous.get("producer") or {}).get(
                    "endpoint_slot", f"endpoint-{uuid.uuid4()}"
                ),
            },
            "consumer": {
                "method": consumer.get("method"),
                "field": consumer.get("field"),
                "endpoint_slot": (previous.get("consumer") or {}).get(
                    "endpoint_slot", f"endpoint-{uuid.uuid4()}"
                ),
            },
            "producer_refs": sorted(
                set(previous.get("producer_refs", []))
                | set(surface_refs(producer))
            ),
            "consumer_refs": sorted(
                set(previous.get("consumer_refs", []))
                | set(surface_refs(consumer))
            ),
            "route_refs": list(previous.get("route_refs", [])),
            "ownership": "current-runtime-observed",
            "evidence": "producer-value-reused-by-consumer",
        }
    for binding in manifest.get("routeParameterBindings", []):
        for item in binding.get("bindings", []):
            slot_id = str(item.get("bindingSlotId") or "")
            if not slot_id:
                continue
            slots[slot_id] = {
                "id": slot_id,
                "kind": "route-parameter",
                "semantic_alias": item.get("parameter"),
                "producer": {"source": item.get("source")},
                "consumer": {"route_template": binding.get("template")},
                "consumer_refs": [],
                "route_refs": [],
                "route_templates": [binding.get("template")],
                "ownership": "current-runtime-observed",
                "evidence": "dynamic-route-bound-in-current-browser-run",
            }
    atomic_json(
        destination,
        {
            "schema_version": 1,
            "generated_at": now(),
            "slots": sorted(slots.values(), key=lambda item: item["id"]),
            "raw_values_persisted": False,
            "rebind_policy": "replay the current producer recipe after restart",
        },
    )


def request_binding_fields(request: RawRequest) -> list[str]:
    fields = [name for name, _ in parse_qsl(urlsplit(request.url).query, keep_blank_values=True)]
    body_kind, body = decode_body(request)

    def visit(value: Any, prefix: str = "") -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                name = f"{prefix}.{key}" if prefix else str(key)
                if isinstance(item, (dict, list)):
                    visit(item, name)
                elif item not in {None, ""}:
                    fields.append(name)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{prefix}[{index}]")

    if body_kind == "json":
        visit(body)
    elif body_kind == "form":
        fields.extend(str(name) for name, value in body if value not in {None, ""})
    return sorted(
        {
            field
            for field in fields
            if re.search(r"(?:^|[._\[-])(?:id|[a-z0-9_-]*id|key)$", field, re.I)
        }
    )


def update_request_binding_provenance(
    workspace: Path, requests: list[RawRequest]
) -> None:
    destination = workspace / "object-provenance.json"
    value = load_json(destination, {"slots": []})
    inventory = load_json(workspace / "surface-inventory.json", {"surfaces": []})
    slots = {
        str(item.get("id")): item
        for item in value.get("slots", [])
        if item.get("id")
    }
    signatures = {
        (
            str((item.get("producer") or {}).get("method") or ""),
            str((item.get("producer") or {}).get("field") or ""),
            tuple(item.get("consumer_refs", [])),
        )
        for item in slots.values()
        if (item.get("producer") or {}).get("source")
        == "current-request-baseline"
    }
    for request in requests:
        method = request.method.upper()
        path = web_assessment.normalize_path(urlsplit(request.url).path)
        consumer_refs = sorted(
            item["id"]
            for item in inventory.get("surfaces", [])
            if item.get("id")
            and str(item.get("method") or "UNKNOWN").upper() == method
            and item.get("path_template") == path
        )
        if not consumer_refs:
            continue
        fields = request_binding_fields(request)
        if "{id}" in path:
            fields.append("path.id")
        for field in sorted(set(fields)):
            signature = (method, field, tuple(consumer_refs))
            if signature in signatures:
                continue
            signatures.add(signature)
            slot_id = f"binding-{uuid.uuid4()}"
            slots[slot_id] = {
                "id": slot_id,
                "kind": binding_kind(field),
                "semantic_alias": field.rsplit(".", 1)[-1],
                "producer": {
                    "source": "current-request-baseline",
                    "method": method,
                    "field": field,
                },
                "consumer": {"method": method, "field": field},
                "producer_refs": consumer_refs,
                "consumer_refs": consumer_refs,
                "route_refs": [],
                "ownership": "current-identity-accessible",
                "evidence": "identifier-present-in-current-request-baseline",
            }
    atomic_json(
        destination,
        {
            "schema_version": 1,
            "generated_at": now(),
            "slots": sorted(slots.values(), key=lambda item: item["id"]),
            "raw_values_persisted": False,
            "rebind_policy": "replay the current producer recipe after restart",
        },
    )


def browser_collection(
    workspace: Path,
    target: str,
    identity: str,
    headers: dict[str, str],
    storage_state: Path | None,
    refresh: bool,
    raw_request_sink: list[RawRequest] | None = None,
    seed_routes: Path | None = None,
    max_pages: int = 0,
    phase: str = "full",
) -> Path | None:
    output = workspace / f"current-discovery-{phase}-{identity}"
    inventory = output / "analysis" / "surface-inventory.json"
    if inventory.exists() and not refresh and raw_request_sink is None:
        return inventory
    runtime = workspace / ".runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        runtime.chmod(0o700)
    header_path = runtime / f"runner-headers-{identity}.json"
    if headers:
        atomic_json(header_path, headers)
    coverage_context = runtime / f"coverage-context-{identity}.json"
    request_corpus = runtime / f"request-corpus-{identity}.json"
    expected_identities = ["anonymous"] + (
        ["current-authenticated"] if identity == "current-authenticated" else []
    )
    atomic_json(
        coverage_context,
        {
            "expectedRoleIds": expected_identities,
            "observedRoleIds": [identity],
            "expectedStateIds": ["current"],
            "observedStateIds": ["current"],
        },
    )
    command = [
        sys.executable,
        str(SPA_COMMAND),
        target,
        "--out",
        str(output),
        "--browser",
        "--browser-pages",
        str(max_pages),
        "--verify-safe-reads",
        "--probe-limit",
        "1000000",
        "--coverage-context",
        str(coverage_context),
        "--request-corpus-out",
        str(request_corpus),
    ]
    if headers:
        command.extend(["--header-file", str(header_path)])
    if storage_state:
        command.extend(["--browser-storage-state", str(storage_state)])
    if seed_routes and seed_routes.is_file():
        command.extend(["--seed-routes", str(seed_routes)])
    captured_requests: list[RawRequest] = []
    try:
        result = subprocess.run(
            command,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode == 0 and request_corpus.exists():
            captured_requests = transient_corpus_requests(request_corpus, target)
            for request in captured_requests:
                request.source = f"browser-runtime-{identity}"
        if result.returncode == 0:
            update_object_provenance(workspace, output)
    finally:
        for temporary in (header_path, coverage_context, request_corpus):
            if temporary.exists():
                temporary.unlink()
    if result.returncode != 0:
        if (workspace / "coverage.json").exists():
            web_assessment.append_event(
                workspace,
                {
                    "type": "runtime-condition",
                    "kind": "browser",
                    "status": "blocked",
                    "reason": hashlib.sha256(result.stderr.encode()).hexdigest(),
                },
            )
        return None
    if raw_request_sink is not None:
        raw_request_sink.extend(captured_requests)
    return inventory if inventory.exists() else None


def browser_collections(
    workspace: Path,
    target: str,
    lease: CredentialLease,
    storage_state: Path | None,
    refresh: bool,
    raw_request_sink: list[RawRequest] | None = None,
    seed_routes: Path | None = None,
    max_pages: int = 0,
    phase: str = "full",
) -> list[tuple[str, Path]]:
    contexts: list[tuple[str, dict[str, str], Path | None]] = [
        ("anonymous", {}, None)
    ]
    if lease.headers or storage_state:
        contexts.append(("current-authenticated", lease.headers, storage_state))
    inventories = []
    for identity, headers, context_state in contexts:
        inventory = browser_collection(
            workspace,
            target,
            identity,
            headers,
            context_state,
            refresh,
            raw_request_sink,
            seed_routes,
            max_pages,
            phase,
        )
        if inventory:
            inventories.append((identity, inventory))
    return inventories


def record_browser_route_results(
    workspace: Path,
    inventories: list[tuple[str, Path]],
) -> None:
    plan = load_json(workspace / "test-plan.json", {})
    route_cases = [
        item
        for item in plan.get("executable_cases", [])
        if item.get("case_kind") == "route-navigation"
    ]
    for identity, inventory_path in inventories:
        inventory = load_json(inventory_path, {})
        routes = {
            str(item.get("path") or "/"): item
            for item in inventory.get("routes", [])
        }
        for case in route_cases:
            if case.get("identity") != identity:
                continue
            route = routes.get(str(case.get("path_template") or "/"))
            if not route:
                continue
            validation = route.get("validation", {})
            state = validation.get("state")
            reason = str(validation.get("reason") or state or "route not resolved")
            evidence_id = web_assessment.stable_id(
                "route-evidence",
                {
                    "identity": identity,
                    "route_id": case.get("route_id"),
                    "inventory_sha256": file_sha256(inventory_path),
                },
            )
            record_event_once(
                workspace,
                {
                    "type": "evidence",
                    "id": evidence_id,
                    "path": f"{inventory_path.resolve()}#/routes",
                    "kind": "sanitized-browser-route",
                    "sha256": file_sha256(inventory_path),
                },
                ("type", "id"),
            )
            if state == "runtime-visited":
                event = {
                    "type": "route-result",
                    "route_id": case["route_id"],
                    "test_case_id": case["id"],
                    "status": "tested",
                    "stages": {stage: "completed" for stage in web_assessment.ROUTE_STAGE_IDS},
                    "evidence_refs": [evidence_id],
                }
            elif state == "rejected":
                event = {
                    "type": "route-result",
                    "route_id": case["route_id"],
                    "test_case_id": case["id"],
                    "status": "not-applicable",
                    "reason": reason,
                    "stages": {
                        stage: "completed" if stage in {"discovered", "current-validated"} else "not-applicable"
                        for stage in web_assessment.ROUTE_STAGE_IDS
                    },
                    "evidence_refs": [evidence_id],
                }
            else:
                event = {
                    "type": "route-result",
                    "route_id": case["route_id"],
                    "test_case_id": case["id"],
                    "status": "blocked",
                    "reason": reason,
                    "stages": {
                        stage: "completed" if stage == "discovered" else "blocked"
                        for stage in web_assessment.ROUTE_STAGE_IDS
                    },
                    "evidence_refs": [evidence_id],
                }
            record_event_once(
                workspace,
                event,
                ("type", "test_case_id", "status"),
            )


def write_runner_state(workspace: Path, value: dict[str, Any]) -> None:
    state = {
        "schema_version": 1,
        "updated_at": now(),
        "raw_credentials_persisted": False,
        **value,
    }
    atomic_json(workspace / "runner-state.json", state)


def acquire_lock(path: Path) -> None:
    if path.exists():
        try:
            pid = int(path.read_text(encoding="utf-8").strip())
            os.kill(pid, 0)
        except (ValueError, OSError, ProcessLookupError):
            path.unlink()
        else:
            raise ValueError(f"runner already active: pid={pid}")
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, f"{os.getpid()}\n".encode())
    finally:
        os.close(descriptor)


def audit_execution(workspace: Path) -> dict[str, Any]:
    plan = load_json(workspace / "test-plan.json", {})
    route_inventory = load_json(workspace / "route-inventory.json", {})
    coverage = load_json(workspace / "coverage.json", {})
    inventory = load_json(workspace / "surface-inventory.json", {})
    auto_cases = [item for item in plan.get("executable_cases", []) if item.get("automation_state") == "auto-ready"]
    needs_agent = [item for item in plan.get("executable_cases", []) if item.get("automation_state") == "needs-agent" and item.get("status") not in COVERAGE_SATISFIED]
    unresolved_auto = [item for item in auto_cases if item.get("status") not in COVERAGE_SATISFIED]
    unsafe_auto = [
        item["id"]
        for item in auto_cases
        if item.get("case_kind") == "api-test"
        and (
            item.get("payload_policy") != "safe-auto"
            or not item.get("binding_requirements")
            or not item.get("oracle_id")
        )
    ]
    variant_gaps = [
        f"{case['id']}:{variant}"
        for case in auto_cases
        for variant in case.get("variants", [])
        if case.get("variant_results", {}).get(variant, {}).get("status") not in COVERAGE_SATISFIED
    ]
    unresolved_routes = [
        item["id"]
        for item in route_inventory.get("routes", [])
        if item.get("stages", {}).get("tests-resolved", {}).get("state") not in {"completed", "not-applicable"}
    ]
    unresolved_candidates = [
        item.get("id")
        for item in coverage.get("candidates", [])
        if not web_assessment.candidate_resolution_complete(item)
    ]
    candidate_dependency_gaps = [
        f"{candidate.get('id')}:{dependency.get('id')}"
        for candidate in coverage.get("candidates", [])
        for dependency in web_assessment.candidate_dependency_gaps(candidate)
    ]
    prerequisite_graph = load_json(
        workspace / "prerequisite-graph.json", {"prerequisites": []}
    )
    evidence_index = load_json(workspace / "evidence-index.json", {"evidence": []})
    indexed_evidence = {
        str(value)
        for item in evidence_index.get("evidence", [])
        for value in (item.get("id"), item.get("path"))
        if value
    }
    canonical_evidence = {
        name
        for name in (
            "coverage.json",
            "surface-inventory.json",
            "route-inventory.json",
            "test-plan.json",
            "object-provenance.json",
        )
        if (workspace / name).is_file()
    }

    def prerequisite_evidence_available(reference: object) -> bool:
        value = str(reference or "")
        base = value.split("#", 1)[0]
        return bool(
            value in indexed_evidence
            or base in indexed_evidence
            or base in canonical_evidence
        )

    test_prerequisite_gaps = [
        item.get("id")
        for item in prerequisite_graph.get("prerequisites", [])
        if item.get("owner_kind") == "test-case"
        and item.get("status") != "satisfied"
    ]
    prerequisite_evidence_gaps = [
        item.get("id")
        for item in prerequisite_graph.get("prerequisites", [])
        if item.get("owner_kind") == "test-case"
        and item.get("status") == "satisfied"
        and not any(
            prerequisite_evidence_available(reference)
            for reference in item.get("evidence_refs", [])
        )
    ]
    inventory_blockers = [str(item) for item in inventory.get("blockers", [])]
    gaps = [
        *[f"auto-case:{item['id']}" for item in unresolved_auto],
        *[f"unsafe-auto-policy:{item}" for item in unsafe_auto],
        *[f"variant:{item}" for item in variant_gaps],
        *[f"agent-case:{item['id']}" for item in needs_agent],
        *[f"route:{item}" for item in unresolved_routes],
        *[f"candidate:{item}" for item in unresolved_candidates],
        *[f"candidate-dependency:{item}" for item in candidate_dependency_gaps],
        *[f"test-prerequisite:{item}" for item in test_prerequisite_gaps],
        *[f"prerequisite-evidence:{item}" for item in prerequisite_evidence_gaps],
        *[f"inventory:{item}" for item in inventory_blockers],
    ]
    counts = {
        "auto_cases": len(auto_cases),
        "auto_unresolved": len(unresolved_auto),
        "unsafe_auto_policy": len(unsafe_auto),
        "variant_gaps": len(variant_gaps),
        "needs_agent": len(needs_agent),
        "route_gaps": len(unresolved_routes),
        "candidate_gaps": len(unresolved_candidates),
        "candidate_dependency_gaps": len(candidate_dependency_gaps),
        "test_prerequisite_gaps": len(test_prerequisite_gaps),
        "prerequisite_evidence_gaps": len(prerequisite_evidence_gaps),
        "inventory_blockers": len(inventory_blockers),
    }
    return {"status": "passed" if not gaps else "blocked", "counts": counts, "gaps": gaps[:5000]}


def execute(args: argparse.Namespace) -> int:
    workspace = args.workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    lock = workspace / ".runner.lock"
    acquire_lock(lock)
    lease = CredentialLease("anonymous", {})
    try:
        lease = load_credential_lease(
            args.target,
            args.header_file,
            args.credential_lease,
            args.consume_auth,
        )
        transactions = load_transaction_corpus(
            getattr(args, "transaction_corpus", None), args.target
        )
        raw_requests = har_requests(args.har, args.target)
        replay_auth_available = bool(lease.headers) or any(
            any(name.casefold() in AUTH_HEADERS for name in item.headers)
            for item in raw_requests
        )
        if not (workspace / "coverage.json").exists():
            web_assessment.initialize(workspace, args.target)
        else:
            web_assessment.ensure_workspace(workspace, args.target)
        # Binding slots are task-run leases. Resume replays current producers
        # instead of trusting identifiers observed by a previous process.
        atomic_json(
            workspace / "object-provenance.json",
            {
                "schema_version": 1,
                "generated_at": now(),
                "slots": [],
                "raw_values_persisted": False,
                "rebind_policy": "replay the current producer recipe after restart",
            },
        )
        web_assessment.append_event(workspace, {"type": "runner-checkpoint", "status": "running", "phase": "start", "iteration": 0})
        web_assessment.append_event(
            workspace,
            lease.metadata(
                "expired"
                if lease.source == "credential-lease-expired"
                else "available"
                if lease.headers or args.storage_state
                else "anonymous-only"
            ),
        )
        if lease.headers or args.storage_state or replay_auth_available:
            record_event_once(
                workspace,
                {"type": "identity", "id": "current-authenticated", "status": "available", "evidence_refs": []},
                ("type", "id"),
            )
        if replay_auth_available:
            for mode in (
                "anonymous-boundary",
                "low-privilege-function",
                "implicit-subject-binding",
                "workflow-precondition",
            ):
                record_event_once(
                    workspace,
                    {"type": "authorization-capability", "id": mode, "status": "available", "reason": "current authenticated request corpus available"},
                    ("type", "id", "status"),
                )
        elif args.storage_state:
            for mode in (
                "anonymous-boundary",
                "low-privilege-function",
                "implicit-subject-binding",
                "workflow-precondition",
            ):
                record_event_once(
                    workspace,
                    {
                        "type": "authorization-capability",
                        "id": mode,
                        "status": "conditional",
                        "reason": "browser session is available but API replay credentials are not exportable",
                    },
                    ("type", "id", "status"),
                )
        record_event_once(workspace, {"type": "phase", "phase_id": "scope-safety", "status": "completed"}, ("type", "phase_id", "status"))
        history_input, history_route_seeds = run_history_lookup(workspace, args.target)
        protocol_inputs = collect_protocol_documents(
            workspace,
            args.target,
            lease.headers,
            args.requests_per_second,
            args.refresh,
        )
        protocol_route_seeds = workspace / "current-protocol-discovery" / "route-seeds.json"
        seed_routes = merge_route_seeds(
            workspace,
            [
                path
                for path in (protocol_route_seeds, history_route_seeds)
                if path and path.is_file()
            ],
        )
        source_map_input = None
        if getattr(args, "source_root", None):
            source_map_input = workspace / "source-control-map.json"
            atomic_json(
                source_map_input,
                source_mapper.map_source(args.source_root.resolve()),
            )
        limiter = RateLimiter(args.requests_per_second)
        fast_runtime_requests: list[RawRequest] = []
        fast_inventories = browser_collections(
            workspace,
            args.target,
            lease,
            args.storage_state,
            True,
            fast_runtime_requests,
            seed_routes,
            max_pages=12,
            phase="fast",
        )
        raw_requests.extend(fast_runtime_requests)
        fast_replay_auth = any(
            item.source == "browser-runtime-current-authenticated"
            and any(name.casefold() in AUTH_HEADERS for name in item.headers)
            for item in fast_runtime_requests
        )
        if fast_replay_auth and not replay_auth_available:
            replay_auth_available = True
            for mode in (
                "anonymous-boundary",
                "low-privilege-function",
                "implicit-subject-binding",
                "workflow-precondition",
            ):
                record_event_once(
                    workspace,
                    {
                        "type": "authorization-capability",
                        "id": mode,
                        "status": "available",
                        "reason": "current authenticated fast browser request corpus available",
                    },
                    ("type", "id", "status"),
                )
        fast_inputs: list[tuple[str, Path]] = []
        fast_inputs.extend(("spa", path) for _, path in fast_inventories)
        fast_inputs.extend(protocol_inputs)
        if history_input:
            fast_inputs.append(("history", history_input))
        if args.har:
            fast_inputs.append(("har", args.har))
        if source_map_input:
            fast_inputs.append(("manual", source_map_input))
        web_assessment.compile_workspace(
            workspace,
            fast_inputs,
            replace_inputs=bool(fast_inputs),
        )
        update_request_binding_provenance(workspace, raw_requests)
        record_browser_route_results(workspace, fast_inventories)
        web_assessment.compile_workspace(workspace)
        iteration = execute_auto_queue(
            workspace,
            raw_requests,
            lease,
            limiter,
            transactions,
            lane="fast-find",
        )
        browser_runtime_requests: list[RawRequest] = []
        browser_inventories = browser_collections(
            workspace,
            args.target,
            lease,
            args.storage_state,
            args.refresh,
            browser_runtime_requests,
            seed_routes,
            max_pages=0,
            phase="full",
        )
        raw_requests.extend(browser_runtime_requests)
        browser_replay_auth = any(
            item.source == "browser-runtime-current-authenticated"
            and any(name.casefold() in AUTH_HEADERS for name in item.headers)
            for item in browser_runtime_requests
        )
        if browser_replay_auth and not replay_auth_available:
            replay_auth_available = True
            for mode in (
                "anonymous-boundary",
                "low-privilege-function",
                "implicit-subject-binding",
                "workflow-precondition",
            ):
                record_event_once(
                    workspace,
                    {
                        "type": "authorization-capability",
                        "id": mode,
                        "status": "available",
                        "reason": "current authenticated browser request corpus available",
                    },
                    ("type", "id", "status"),
                )
        inputs = []
        inputs.extend(("spa", path) for _, path in browser_inventories)
        inputs.extend(protocol_inputs)
        if history_input:
            inputs.append(("history", history_input))
        if args.har:
            inputs.append(("har", args.har))
        if source_map_input:
            inputs.append(("manual", source_map_input))
        web_assessment.compile_workspace(workspace, inputs, replace_inputs=bool(inputs))
        update_request_binding_provenance(workspace, raw_requests)
        record_browser_route_results(workspace, browser_inventories)
        for phase_id in (
            "related-passive-discovery",
            "surface-normalization",
            "work-unit-clustering",
            "test-plan-compilation",
        ):
            record_event_once(workspace, {"type": "phase", "phase_id": phase_id, "status": "completed"}, ("type", "phase_id", "status"))
        web_assessment.compile_workspace(workspace)
        iteration = execute_auto_queue(
            workspace,
            raw_requests,
            lease,
            limiter,
            transactions,
            start_iteration=iteration,
        )
        web_assessment.compile_workspace(workspace)
        audit = audit_execution(workspace)
        web_assessment.append_event(workspace, {"type": "execution-audit", **audit})
        record_event_once(
            workspace,
            {"type": "phase", "phase_id": "risk-execution", "status": "completed" if audit["counts"]["auto_unresolved"] == 0 else "blocked", "gaps": audit["gaps"]},
            ("type", "phase_id", "status"),
        )
        record_event_once(
            workspace,
            {"type": "phase", "phase_id": "adjacent-replan", "status": "completed" if audit["status"] == "passed" else "blocked", "gaps": audit["gaps"]},
            ("type", "phase_id", "status"),
        )
        preliminary = web_assessment.compile_workspace(workspace)
        coverage = load_json(workspace / "coverage.json", {})
        completion_gate_gaps = [
            gate
            for gate, passed in coverage.get("stop_gates", {}).items()
            if not passed
            and gate != "independent_execution_audit_passed"
        ]
        if audit["status"] == "passed" and completion_gate_gaps:
            audit = {
                **audit,
                "status": "blocked",
                "counts": {
                    **audit["counts"],
                    "completion_gate_gaps": len(completion_gate_gaps),
                },
                "gaps": [
                    *audit["gaps"],
                    *[f"completion-gate:{gate}" for gate in completion_gate_gaps],
                ][:5000],
            }
            web_assessment.append_event(
                workspace,
                {"type": "execution-audit", **audit},
            )
        final_state = (
            "complete"
            if audit["status"] == "passed"
            and preliminary["assessment_state"] == "complete"
            else "needs-agent"
        )
        web_assessment.append_event(
            workspace,
            {
                "type": "runner-checkpoint",
                "status": final_state,
                "phase": "audit",
                "iteration": iteration,
                "reason": (
                    None
                    if final_state == "complete"
                    else "unresolved execution or completion-gate gaps"
                ),
            },
        )
        result = web_assessment.compile_workspace(workspace)
        write_runner_state(
            workspace,
            {
                "target": target_url(args.target),
                "status": final_state,
                "iteration": iteration,
                "credential_source": lease.source,
                "credential_fingerprint": lease.fingerprint if lease.headers else None,
                "audit": audit,
                "assessment_state": result["assessment_state"],
                "transport": limiter.snapshot(),
            },
        )
        print(json.dumps({"runner_state": final_state, "workspace": str(workspace), "audit": audit, **result}, ensure_ascii=False, indent=2))
        return 0 if final_state == "complete" else 2
    finally:
        lease.cleanup()
        if lock.exists():
            lock.unlink()


def status(args: argparse.Namespace) -> int:
    value = load_json(args.workspace / "runner-state.json", {"status": "not-started"})
    print(json.dumps(value, ensure_ascii=False, indent=2))
    return 0 if value.get("status") == "complete" else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run resumable deterministic Blue Sec Hub Web assessments")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--target", required=True)
    run.add_argument("--workspace", required=True, type=Path)
    run.add_argument("--credential-lease", type=Path)
    run.add_argument("--consume-auth", action="store_true")
    run.add_argument("--header-file", type=Path)
    run.add_argument("--storage-state", type=Path)
    run.add_argument("--har", type=Path)
    run.add_argument("--transaction-corpus", type=Path, help=argparse.SUPPRESS)
    run.add_argument("--source-root", type=Path)
    run.add_argument("--refresh", action="store_true")
    run.add_argument("--requests-per-second", type=float, default=2.0)
    run.set_defaults(function=execute)
    show = commands.add_parser("status")
    show.add_argument("--workspace", required=True, type=Path)
    show.set_defaults(function=status)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        raise SystemExit(args.function(args))
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
