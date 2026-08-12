#!/usr/bin/env python3
"""Build and optionally validate a unified SPA feature, route, and API inventory."""

from __future__ import annotations

import argparse
from bisect import bisect_right
import hashlib
import json
import re
import time
import uuid
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from collect_spa_assets import add_header_arguments, load_headers
from route_inventory import build_route_inventory


PERMISSION_VALUE_RE = re.compile(
    r"\bpermission\s*:\s*['\"`](?P<permission>[^'\"`]{2,200})['\"`]"
)
PERMISSION_KEY_RE = re.compile(
    r"(?P<key>[A-Za-z_$][\w$-]{2,160})\s*:\s*\{[^{}]{0,800}$"
)
NEARBY_ROUTE_RE = re.compile(r"['\"`](/[^'\"`]{1,180})['\"`]\s*:\s*\{")
NOT_FOUND_RE = re.compile(
    r"\b404\b|not[\s_-]*found|no static resource|cannot\s+(?:get|post|put|delete)"
    r"|页面不存在|资源不存在|接口不存在|请求地址不存在",
    re.IGNORECASE,
)
LOGIN_RE = re.compile(
    r"\blogin\b|sign[\s_-]*in|unauthorized|未认证|请先登录|登录已过期|未登录"
    r"|token.{0,20}(?:不存在|无效|过期|missing|invalid|expired)",
    re.IGNORECASE,
)
ASSET_RE = re.compile(
    r"\.(?:js|mjs|cjs|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf)(?:$|\?)",
    re.IGNORECASE,
)
UNRESOLVED_RE = re.compile(r"\$\{|[{};]|(?:^|/)(?:undefined|null)(?:/|$)", re.IGNORECASE)
SAFE_READ_METHODS = {"GET", "HEAD"}
DYNAMIC_PATH_RE = re.compile(r"(?:^|/)(?::[A-Za-z_$][\w$]*|\[[^\]]+\]|<[^>]+>)(?:/|$)")
UNSAFE_READ_PATH_RE = re.compile(
    r"(?:delete|remove|logout|reset|send|trigger|execute|run|start|stop|"
    r"create|update|save|submit|approve|reject|revoke|publish|deploy|upload|"
    r"import|export|download|payment|refund|callback|webhook)",
    re.IGNORECASE,
)


def load_json(path: Path | None, default: Any) -> Any:
    if not path or not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_target(value: str) -> str:
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    return urlunsplit(
        (parts.scheme.casefold(), parts.netloc.casefold(), parts.path or "/", "", "")
    )


def normalize_api_path(value: str, target: str) -> tuple[str | None, str | None]:
    candidate = value.strip()
    if not candidate:
        return None, "empty"
    if candidate.startswith(("http://", "https://")):
        parsed = urlsplit(candidate)
        target_parts = urlsplit(target)
        if parsed.netloc.casefold() != target_parts.netloc.casefold():
            return None, "cross-origin"
        candidate = re.sub(
            r";(?:jsessionid|sessionid)=[^/?#;]+",
            "",
            parsed.path or "/",
            flags=re.IGNORECASE,
        )
        if parsed.query:
            candidate += "?" + parsed.query
    if any(character.isspace() for character in candidate):
        return None, "contains-whitespace"
    if UNRESOLVED_RE.search(candidate) or any(
        marker in candidate for marker in ("+", "\\", "\"", "'", "`")
    ):
        return None, "unresolved-expression"
    if not candidate.startswith("/"):
        return None, "relative-path-without-observed-base"
    path = urlsplit(candidate).path
    if not path or path == "/" or ASSET_RE.search(path):
        return None, "not-api-path"
    path = re.sub(r"/{2,}", "/", path)
    return path, None


def candidate_url(target: str, path: str) -> str:
    parts = urlsplit(normalize_target(target))
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def permission_features(asset_roots: list[Path]) -> list[dict]:
    features: dict[tuple[str, str], dict] = {}
    for root in asset_roots:
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix.casefold() not in {
                ".js",
                ".mjs",
                ".cjs",
            }:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            newline_offsets = [
                index for index, character in enumerate(text) if character == "\n"
            ]
            for match in PERMISSION_VALUE_RE.finditer(text):
                key_context = text[max(0, match.start() - 1000):match.start()]
                key_match = PERMISSION_KEY_RE.search(key_context)
                if not key_match:
                    continue
                previous = text[max(0, match.start() - 3000):match.start()]
                route_matches = list(NEARBY_ROUTE_RE.finditer(previous))
                route = route_matches[-1].group(1) if route_matches else None
                key_name = key_match.group("key")
                key = (key_name, match.group("permission"))
                item = features.setdefault(
                    key,
                    {
                        "id": f"permission:{match.group('permission')}",
                        "type": "permission-control",
                        "name": key_name,
                        "permission": match.group("permission"),
                        "routes": set(),
                        "evidence": [],
                        "apiRefs": [],
                    },
                )
                if route:
                    item["routes"].add(route)
                item["evidence"].append(
                    {
                        "source": str(path),
                        "line": bisect_right(newline_offsets, match.start()) + 1,
                        "offset": match.start(),
                    }
                )
    result = []
    for item in features.values():
        item["routes"] = sorted(item["routes"])
        result.append(item)
    return sorted(result, key=lambda item: item["id"])


def graph_api_candidates(graph: dict, target: str) -> tuple[list[dict], list[dict]]:
    accepted: dict[tuple[str, str], dict] = {}
    rejected: list[dict] = []
    for endpoint in graph.get("endpoints", []):
        raw_path = str(endpoint.get("path", ""))
        path, reason = normalize_api_path(raw_path, target)
        method = str(endpoint.get("method") or "UNKNOWN").upper()
        evidence = {
            "source": endpoint.get("source"),
            "line": endpoint.get("line"),
            "offset": endpoint.get("offset"),
            "rawExpression": endpoint.get("rawExpression"),
        }
        if reason:
            rejected.append(
                {
                    "method": method,
                    "candidate": raw_path,
                    "reason": reason,
                    "evidence": evidence,
                }
            )
            continue
        key = (method, path)
        dynamic_path = DYNAMIC_PATH_RE.search(path) is not None
        item = accepted.setdefault(
            key,
            {
                "method": method,
                "path": path,
                "url": None if dynamic_path else candidate_url(target, path),
                "urlResolution": {
                    "state": "unresolved" if dynamic_path else "candidate",
                    "reason": (
                        "dynamic-path-value-required"
                        if dynamic_path
                        else "same-origin-root-path-from-static-expression"
                    ),
                },
                "queryParameters": sorted(
                    {name for name, _ in parse_qsl(urlsplit(raw_path).query)}
                ),
                "fields": set(),
                "evidence": [],
                "featureRefs": [],
                "validation": {
                    "state": "unverified",
                    "reason": "static-candidate",
                },
            },
        )
        item["fields"].update(endpoint.get("directFields") or [])
        if evidence not in item["evidence"]:
            item["evidence"].append(evidence)
    result = []
    for item in accepted.values():
        item["fields"] = sorted(item["fields"])
        result.append(item)
    return sorted(result, key=lambda item: (item["path"], item["method"])), rejected


def runtime_observations(
    browser_manifest: dict,
    target: str,
) -> tuple[dict[tuple[str, str], dict], list[dict]]:
    result: dict[tuple[str, str], dict] = {}
    rejected: list[dict] = []
    target_parts = urlsplit(target)
    document_baseline = None
    for response in browser_manifest.get("responses", []):
        if response.get("resourceType") != "document" or response.get("status") != 200:
            continue
        local_path = response.get("localPath")
        if not local_path:
            continue
        try:
            document_baseline = {
                "status": 200,
                "url": response.get("url"),
                "contentType": response.get("contentType"),
                "body": Path(local_path).read_bytes(),
            }
            break
        except OSError:
            continue
    for response in browser_manifest.get("responses", []):
        if response.get("resourceType") not in {"xhr", "fetch"}:
            continue
        raw_url = str(response.get("url", ""))
        parsed = urlsplit(raw_url)
        if parsed.netloc.casefold() != target_parts.netloc.casefold():
            rejected.append(
                {
                    "method": response.get("method"),
                    "candidate": raw_url,
                    "reason": "cross-origin-runtime-response",
                }
            )
            continue
        path, reason = normalize_api_path(raw_url, target)
        if reason:
            rejected.append(
                {
                    "method": response.get("method"),
                    "candidate": raw_url,
                    "reason": reason,
                }
            )
            continue
        method = str(response.get("method") or "UNKNOWN").upper()
        body = b""
        local_path = response.get("localPath")
        if local_path:
            try:
                body = Path(local_path).read_bytes()
            except OSError:
                pass
        sample = {
            "status": response.get("status"),
            "url": candidate_url(target, path),
            "contentType": response.get("contentType"),
            "body": body,
        }
        validation = classify_response(sample, document_baseline)
        if validation["state"] == "reachable":
            validation["state"] = "runtime-observed"
            validation["reason"] = "normal-browser-request"
        result[(method, path)] = {
            "status": response.get("status"),
            "contentType": response.get("contentType"),
            "source": "browser-runtime",
            "url": candidate_url(target, path),
            "path": path,
            "method": method,
            "requestFields": response.get("requestFields") or [],
            "validation": validation,
        }
    return result, rejected


def add_runtime_apis(
    apis: list[dict],
    runtime: dict[tuple[str, str], dict],
) -> None:
    by_key = {(api["method"], api["path"]): api for api in apis}
    for key, observation in runtime.items():
        if key in by_key:
            api = by_key[key]
            api["validation"] = observation["validation"]
            api["url"] = observation["url"]
            api["urlResolution"] = {
                "state": "observed",
                "reason": "browser-runtime-request",
            }
            api["fields"] = sorted(
                set(api["fields"]) | set(observation["requestFields"])
            )
            continue
        method, path = key
        apis.append(
            {
                "method": method,
                "path": path,
                "url": observation["url"],
                "urlResolution": {
                    "state": "observed",
                    "reason": "browser-runtime-request",
                },
                "queryParameters": sorted(
                    {name for name, _ in parse_qsl(urlsplit(observation["url"]).query)}
                ),
                "fields": sorted(set(observation["requestFields"])),
                "evidence": [
                    {
                        "source": "browser-runtime",
                        "line": None,
                        "offset": None,
                        "rawExpression": observation["url"],
                    }
                ],
                "featureRefs": [],
                "validation": observation["validation"],
            }
        )
    apis.sort(key=lambda item: (item["path"], item["method"]))


def link_features(routes: list[dict], permissions: list[dict], apis: list[dict]) -> list[dict]:
    features = []
    for route in routes:
        route_names = sorted(
            {
                evidence.get("name")
                for evidence in route.get("evidence", [])
                if evidence.get("name")
            }
        )
        route_titles = sorted(
            {
                evidence.get("title")
                for evidence in route.get("evidence", [])
                if evidence.get("title")
            }
        )
        features.append(
            {
                "id": f"route:{route['path']}",
                "type": "route",
                "name": (
                    route_names[0]
                    if route_names
                    else route_titles[0]
                    if route_titles
                    else route["path"]
                ),
                "route": route["path"],
                "navigation": route["navigation"],
                "chunks": sorted(
                    {
                        evidence["chunk"]
                        for evidence in route.get("evidence", [])
                        if evidence.get("chunk")
                    }
                ),
                "evidence": route.get("evidence", []),
                "apiRefs": [],
            }
        )
    features.extend(permissions)
    by_source: dict[str, list[tuple[str, int]]] = {}
    for feature in features:
        for evidence in feature.get("evidence", []):
            source = str(evidence.get("source") or "")
            offset = evidence.get("offset")
            if source and isinstance(offset, int):
                by_source.setdefault(source, []).append((feature["id"], offset))
    by_id = {feature["id"]: feature for feature in features}
    for api in apis:
        references: dict[str, int] = {}
        for evidence in api["evidence"]:
            source = str(evidence.get("source") or "")
            offset = evidence.get("offset")
            if not source or not isinstance(offset, int):
                continue
            for feature_id, feature_offset in by_source.get(source, []):
                distance = abs(offset - feature_offset)
                if distance <= 12_000:
                    references[feature_id] = min(
                        distance,
                        references.get(feature_id, distance),
                    )
        api["featureRefs"] = [
            {"id": feature_id, "evidence": "same-source-proximity", "distance": distance}
            for feature_id, distance in sorted(
                references.items(),
                key=lambda item: (item[1], item[0]),
            )[:5]
        ]
        for reference in api["featureRefs"]:
            by_id[reference["id"]]["apiRefs"].append(
                {
                    "method": api["method"],
                    "path": api["path"],
                    "evidence": reference["evidence"],
                    "distance": reference["distance"],
                }
            )
    return sorted(features, key=lambda item: item["id"])


def runtime_ui_features(browser_manifest: dict) -> list[dict]:
    features = []
    for control in browser_manifest.get("uiControls", []):
        label = next(
            (
                str(control.get(key))
                for key in ("ariaLabel", "text", "title", "name", "id")
                if control.get(key)
            ),
            str(control.get("tag") or "interactive-control"),
        )
        features.append(
            {
                "id": control.get("id"),
                "type": "runtime-ui-control",
                "name": label,
                "page": control.get("page"),
                "control": {
                    key: control.get(key)
                    for key in (
                        "tag",
                        "type",
                        "role",
                        "placeholder",
                        "autocomplete",
                        "href",
                        "action",
                        "method",
                        "required",
                        "maxLength",
                        "disabled",
                        "visible",
                        "exerciseState",
                    )
                },
                "evidence": [
                    {
                        "source": "browser-dom",
                        "page": control.get("page"),
                    }
                ],
                "apiRefs": [],
            }
        )
    return sorted(features, key=lambda item: item["id"] or "")


def normalized_body(body: bytes) -> str:
    text = body[:500_000].decode("utf-8", errors="replace").casefold()
    text = re.sub(r"\b[0-9a-f]{16,}\b", ":token", text)
    text = re.sub(r"\d{10,}", ":number", text)
    return re.sub(r"\s+", " ", text).strip()


def looks_not_found(body: bytes, content_type: str) -> bool:
    text = normalized_body(body)
    if "json" in (content_type or "").casefold() or text.startswith(("{", "[")):
        try:
            value = json.loads(body[:500_000].decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return NOT_FOUND_RE.search(text) is not None
        if not isinstance(value, dict):
            return False
        code = value.get("code", value.get("status", value.get("statusCode")))
        message = " ".join(
            str(value.get(key, "")) for key in ("message", "msg", "error", "detail")
        )
        scalar_not_found = isinstance(code, (str, int, float)) and code in {
            404,
            410,
            "404",
            "410",
        }
        return scalar_not_found or (
            bool(message) and NOT_FOUND_RE.search(message) is not None
        )
    return NOT_FOUND_RE.search(text) is not None


def application_response_classification(
    body: bytes,
    content_type: str,
) -> tuple[str, str] | None:
    text = normalized_body(body)
    if "json" not in (content_type or "").casefold() and not text.startswith("{"):
        return None
    try:
        value = json.loads(body[:500_000].decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict):
        return None
    code = next(
        (
            value.get(key)
            for key in ("returnCode", "rtnCode", "code", "status", "statusCode")
            if value.get(key) is not None
        ),
        None,
    )
    message = " ".join(
        str(value.get(key, ""))
        for key in ("returnMessage", "rtnMsg", "message", "msg", "error", "detail")
    )
    if LOGIN_RE.search(message):
        return "recognized", "application-authentication-boundary"
    try:
        numeric_code = int(str(code))
    except (TypeError, ValueError):
        return None
    if numeric_code in {401, 403}:
        return "recognized", "application-authentication-boundary"
    if numeric_code in {400, 405, 415, 422}:
        return "recognized", "application-request-validation"
    if numeric_code >= 500:
        return "recognized", "application-server-error"
    if numeric_code not in {0, 200}:
        return "recognized", "application-error"
    return None


def response_sample(url: str, timeout: float, headers: dict[str, str]) -> dict:
    request = Request(url, headers=headers, method="GET")
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read(500_001)
            return {
                "status": response.status,
                "requestedUrl": url,
                "url": response.geturl(),
                "contentType": response.headers.get("Content-Type", ""),
                "responseHeaders": {
                    "access-control-allow-origin": response.headers.get_all(
                        "Access-Control-Allow-Origin"
                    )
                    or [],
                    "access-control-allow-credentials": response.headers.get_all(
                        "Access-Control-Allow-Credentials"
                    )
                    or [],
                    "vary": response.headers.get_all("Vary") or [],
                },
                "body": body,
            }
    except HTTPError as error:
        return {
            "status": error.code,
            "requestedUrl": url,
            "url": error.geturl(),
            "contentType": error.headers.get("Content-Type", ""),
            "responseHeaders": {
                "access-control-allow-origin": error.headers.get_all(
                    "Access-Control-Allow-Origin"
                )
                or [],
                "access-control-allow-credentials": error.headers.get_all(
                    "Access-Control-Allow-Credentials"
                )
                or [],
                "vary": error.headers.get_all("Vary") or [],
            },
            "body": error.read(500_001),
        }
    except (URLError, TimeoutError, OSError) as error:
        return {
            "status": None,
            "requestedUrl": url,
            "url": url,
            "contentType": "",
            "responseHeaders": {},
            "body": b"",
            "error": str(error),
        }


def classify_response(sample: dict, baseline: dict | None = None) -> dict:
    status = sample.get("status")
    body = normalized_body(sample.get("body") or b"")
    digest = hashlib.sha256(body.encode()).hexdigest()
    evidence = {
        "status": status,
        "contentType": sample.get("contentType"),
        "requestedPath": urlsplit(str(sample.get("requestedUrl", ""))).path,
        "effectivePath": urlsplit(str(sample.get("url", ""))).path,
        "bodyDigest": digest,
        "cors": sample.get("responseHeaders") or {},
    }
    if status is None:
        return {"state": "blocked", "reason": "network-error", "evidence": evidence}
    if status in {404, 410}:
        return {"state": "rejected", "reason": f"http-{status}", "evidence": evidence}
    if status == 200 and looks_not_found(
        sample.get("body") or b"",
        str(sample.get("contentType") or ""),
    ):
        return {
            "state": "rejected",
            "reason": "fake-200-not-found-body",
            "evidence": evidence,
        }
    if baseline and status == 200 and baseline.get("status") == 200:
        baseline_body = normalized_body(baseline.get("body") or b"")
        similarity = SequenceMatcher(None, body, baseline_body).ratio()
        evidence["notFoundBaselineSimilarity"] = round(similarity, 4)
        if similarity >= 0.97:
            return {
                "state": "rejected",
                "reason": "fake-200-fallback-match",
                "evidence": evidence,
            }
    application_classification = application_response_classification(
        sample.get("body") or b"",
        str(sample.get("contentType") or ""),
    )
    if application_classification:
        state, reason = application_classification
        return {"state": state, "reason": reason, "evidence": evidence}
    if status in {401, 403} or (status in {200, 302} and LOGIN_RE.search(body)):
        return {
            "state": "recognized",
            "reason": "authentication-boundary",
            "evidence": evidence,
        }
    if status in {400, 405, 415, 422}:
        return {
            "state": "recognized",
            "reason": "request-validation",
            "evidence": evidence,
        }
    if 300 <= status < 400:
        return {
            "state": "recognized",
            "reason": "http-redirect",
            "evidence": evidence,
        }
    requested = urlsplit(str(sample.get("requestedUrl", "")))
    effective = urlsplit(str(sample.get("url", "")))
    if (
        requested.netloc
        and effective.netloc
        and (
            requested.netloc.casefold() != effective.netloc.casefold()
            or requested.path != effective.path
        )
    ):
        return {
            "state": "recognized",
            "reason": "redirected-boundary",
            "evidence": evidence,
        }
    if 200 <= status < 300:
        return {"state": "reachable", "reason": "non-fallback-response", "evidence": evidence}
    return {"state": "unverified", "reason": f"http-{status}", "evidence": evidence}


def classify_cors(sample: dict, probe_origin: str) -> dict | None:
    headers = sample.get("responseHeaders") or {}
    allowed = [
        str(value).strip()
        for value in headers.get("access-control-allow-origin", [])
    ]
    if probe_origin not in allowed:
        return None
    credentials = any(
        str(value).strip().casefold() == "true"
        for value in headers.get("access-control-allow-credentials", [])
    )
    if len(allowed) != 1:
        reason = "multiple-allow-origin-values-browser-rejects"
    elif credentials:
        reason = "credentialed-arbitrary-origin-reflection"
    else:
        reason = "arbitrary-origin-reflection"
    return {
        "state": "candidate",
        "reason": reason,
        "probeOrigin": probe_origin,
        "allowOrigins": allowed,
        "allowCredentials": credentials,
        "status": sample.get("status"),
        "effectivePath": urlsplit(str(sample.get("url", ""))).path,
    }


def validate_safe_reads(
    apis: list[dict],
    target: str,
    headers: dict[str, str],
    timeout: float,
    limit: int,
    delay: float,
) -> dict:
    probe_origin = "https://blue-sec.invalid"
    probe_headers = dict(headers)
    probe_headers.setdefault("Origin", probe_origin)
    sentinel_path = f"/__blue_sec_not_found_{uuid.uuid4().hex}"
    baseline = response_sample(
        candidate_url(target, sentinel_path),
        timeout,
        probe_headers,
    )
    probed = 0
    cors_candidates = []
    for api in apis:
        if probed >= limit:
            break
        if api["validation"]["state"] != "unverified":
            continue
        if not api.get("url"):
            api["validation"] = {
                "state": "unverified",
                "reason": "dynamic-path-value-required",
            }
            continue
        if api["method"] not in SAFE_READ_METHODS:
            api["validation"] = {
                "state": "unverified",
                "reason": "unsafe-or-unknown-method-not-probed",
            }
            continue
        if UNSAFE_READ_PATH_RE.search(api["path"]):
            api["validation"] = {
                "state": "unverified",
                "reason": "get-path-has-potential-side-effect",
            }
            continue
        sample = response_sample(api["url"], timeout, probe_headers)
        api["validation"] = classify_response(sample, baseline)
        cors = classify_cors(sample, probe_origin)
        if cors and api["validation"]["state"] != "rejected":
            cors_candidates.append(
                {
                    "method": api["method"],
                    "path": api["path"],
                    **cors,
                }
            )
        probed += 1
        time.sleep(delay)
    return {
        "sentinelPath": sentinel_path,
        "baseline": classify_response(baseline),
        "probed": probed,
        "corsProbeOrigin": probe_origin,
        "corsCandidates": cors_candidates,
    }


def unresolved_assets(collection_manifest: dict) -> list[dict]:
    result = []
    for record in collection_manifest.get("records", []):
        if record.get("status") == 200 and not record.get("invalidReason"):
            continue
        url = str(record.get("url", ""))
        if re.search(r"\.(?:js|mjs|cjs|map)(?:$|\?)", url, re.IGNORECASE):
            result.append(
                {
                    "url": url,
                    "status": record.get("status"),
                    "error": record.get("error"),
                    "reason": record.get("invalidReason"),
                }
            )
    return result


def navigation_route_key(value: str) -> str:
    parsed = urlsplit(value)
    return parsed.fragment or parsed.path or "/"


def annotate_route_validation(routes: list[dict], browser_manifest: dict) -> list[str]:
    outcomes = {
        navigation_route_key(str(item.get("requestedUrl", ""))): item
        for item in browser_manifest.get("navigationAttempts", [])
    }
    legacy_visited = {
        navigation_route_key(str(value))
        for value in browser_manifest.get("pagesVisited", [])
    }
    for route in routes:
        outcome = outcomes.get(route["path"])
        if outcome:
            status = outcome.get("status")
            render = outcome.get("render", {})
            if outcome.get("state") != "visited":
                validation = {
                    "state": "blocked",
                    "reason": "navigation-failed",
                    "evidence": outcome,
                }
            elif status in {404, 410}:
                validation = {
                    "state": "rejected",
                    "reason": f"http-{status}",
                    "evidence": outcome,
                }
            elif render.get("state") == "rendered":
                validation = {
                    "state": "runtime-visited",
                    "reason": "browser-navigation-and-render-confirmed",
                    "evidence": outcome,
                }
            elif render.get("state") == "rejected":
                validation = {
                    "state": "rejected",
                    "reason": render.get("reason", "render-rejected"),
                    "evidence": outcome,
                }
            else:
                validation = {
                    "state": "blocked",
                    "reason": render.get("reason", "render-not-confirmed"),
                    "evidence": outcome,
                }
        elif route["path"] in legacy_visited:
            validation = {
                "state": "runtime-visited",
                "reason": "legacy-browser-manifest",
            }
        else:
            validation = {
                "state": "unverified",
                "reason": (
                    "dynamic-parameters-unresolved"
                    if route["navigation"] == "blocked-parameters"
                    else "not-runtime-visited"
                ),
            }
        route["validation"] = validation
    for template in routes:
        parameter_names = template.get("parameterNames", [])
        if not parameter_names or template["validation"]["state"] in {
            "runtime-visited",
            "recognized",
        }:
            continue
        pattern = re.escape(template.get("pathTemplate", template["path"]))
        for parameter in parameter_names:
            pattern = pattern.replace(re.escape(f":{parameter}"), "[^/]+")
        matcher = re.compile(f"^{pattern}$")
        observed = [
            route
            for route in routes
            if route is not template
            and not route.get("parameterNames")
            and route.get("validation", {}).get("state") == "runtime-visited"
            and matcher.match(route["path"])
        ]
        if not observed:
            continue
        source = observed[0]
        template["validation"] = {
            **source["validation"],
            "reason": "observed-dynamic-route-matched-template",
            "observedRouteRef": source["path"],
        }
        template["parameterState"] = "observed"
        template["parameterSources"] = [
            {
                "parameter": parameter,
                "source": "browser-navigation",
                "valuePersisted": False,
            }
            for parameter in parameter_names
        ]
        source["aliasOf"] = template["path"]
    return [
        route["path"]
        for route in routes
        if not route.get("aliasOf")
        and route["validation"]["state"] not in {"runtime-visited", "recognized"}
    ]


def build_surface_inventory(
    target: str,
    asset_roots: list[Path],
    graph: dict,
    browser_manifest: dict | None = None,
    collection_manifest: dict | None = None,
    probe_safe_reads: bool = False,
    headers: dict[str, str] | None = None,
    timeout: float = 12.0,
    probe_limit: int = 200,
    delay: float = 0.03,
    coverage_context: dict | None = None,
) -> dict:
    target = normalize_target(target)
    browser_manifest = browser_manifest or {}
    collection_manifest = collection_manifest or {}
    coverage_context = coverage_context or {}
    combined_routes: dict[str, dict] = {}
    for root in asset_roots:
        for route in build_route_inventory(root)["routes"]:
            item = combined_routes.setdefault(
                route["path"],
                {
                    "path": route["path"],
                    "id": route.get("id"),
                    "pathTemplate": route.get("pathTemplate", route["path"]),
                    "parameterNames": route.get("parameterNames", []),
                    "parameterState": route.get("parameterState", "not-required"),
                    "navigation": route["navigation"],
                    "sources": set(),
                    "evidence": [],
                },
            )
            item["sources"].update(route["sources"])
            for evidence in route.get("evidence", []):
                if evidence not in item["evidence"]:
                    item["evidence"].append(evidence)
    for outcome in browser_manifest.get("navigationAttempts", []):
        requested = str(outcome.get("requestedUrl") or "")
        if not requested:
            continue
        route_path = navigation_route_key(requested)
        item = combined_routes.setdefault(
            route_path,
            {
                "path": route_path,
                "id": None,
                "pathTemplate": route_path,
                "parameterNames": [],
                "parameterState": "not-required",
                "navigation": "eligible",
                "sources": set(),
                "evidence": [],
            },
        )
        item["sources"].add("browser-navigation")
        evidence = {
            "source": "browser-navigation",
            "offset": 0,
            "requestedUrl": requested,
        }
        if evidence not in item["evidence"]:
            item["evidence"].append(evidence)
    routes = []
    for item in combined_routes.values():
        item["sources"] = sorted(item["sources"])
        item["evidence"] = sorted(
            item["evidence"],
            key=lambda evidence: (
                evidence["source"],
                evidence["offset"],
            ),
        )
        routes.append(item)
    routes.sort(key=lambda item: item["path"])

    apis, rejected_static = graph_api_candidates(graph, target)
    runtime, rejected_runtime = runtime_observations(browser_manifest, target)
    add_runtime_apis(apis, runtime)
    probe = None
    if probe_safe_reads:
        probe = validate_safe_reads(
            apis,
            target,
            headers or {},
            timeout,
            probe_limit,
            delay,
        )
    unresolved = unresolved_assets(collection_manifest)
    unvisited_routes = annotate_route_validation(routes, browser_manifest)
    routes = [route for route in routes if not route.get("aliasOf")]
    permissions = permission_features(asset_roots)
    features = link_features(routes, permissions, apis)
    features.extend(runtime_ui_features(browser_manifest))
    features.sort(key=lambda item: item["id"] or "")
    validation_counts: dict[str, int] = {}
    for api in apis:
        state = api["validation"]["state"]
        validation_counts[state] = validation_counts.get(state, 0) + 1
    blockers = []
    if not collection_manifest:
        blockers.append("static asset collection evidence missing")
    if collection_manifest.get("queueRemaining"):
        blockers.append(
            f"{collection_manifest['queueRemaining']} static assets remained queued"
        )
    if unresolved:
        blockers.append(f"{len(unresolved)} JavaScript/source-map assets unresolved")
    if not browser_manifest:
        blockers.append("browser runtime collection evidence missing")
    if browser_manifest.get("navigationQueueRemaining"):
        blockers.append(
            f"{browser_manifest['navigationQueueRemaining']} browser pages remained queued"
        )
    navigation_failures = browser_manifest.get("navigationFailures", [])
    if navigation_failures:
        blockers.append(f"{len(navigation_failures)} browser navigations failed")
    if unvisited_routes:
        blockers.append(f"{len(unvisited_routes)} routes not runtime visited")
    unverified_count = sum(
        count
        for state, count in validation_counts.items()
        if state in {"unverified", "blocked"}
    )
    if unverified_count:
        blockers.append(f"{unverified_count} API candidates not validated")
    if any(
        LOGIN_RE.search(json.dumps(response, ensure_ascii=False))
        for response in browser_manifest.get("responses", [])
    ):
        blockers.append("authenticated or role-gated surfaces may remain")
    unresolved_controls = [
        control
        for control in browser_manifest.get("uiControls", [])
        if control.get("visible")
        and not control.get("disabled")
        and control.get("exerciseState")
        not in {"exercised", "route-queued", "related-passive"}
    ]
    if unresolved_controls:
        blockers.append(
            f"{len(unresolved_controls)} visible UI controls not exercised or resolved"
        )
    blocked_requests = browser_manifest.get("blockedRequests", [])
    if blocked_requests:
        blockers.append(
            f"{len(blocked_requests)} page-initiated side-effect requests require classification"
        )
    expected_roles = set(coverage_context.get("expectedRoleIds") or [])
    observed_roles = set(coverage_context.get("observedRoleIds") or [])
    if not expected_roles:
        blockers.append("expected identity and role inventory not supplied")
    elif expected_roles - observed_roles:
        blockers.append(
            f"{len(expected_roles - observed_roles)} expected roles not observed"
        )
    expected_states = set(coverage_context.get("expectedStateIds") or [])
    observed_states = set(coverage_context.get("observedStateIds") or [])
    if expected_states - observed_states:
        blockers.append(
            f"{len(expected_states - observed_states)} expected business states not observed"
        )
    state = "complete" if not blockers else "interim"
    return {
        "schemaVersion": 1,
        "target": target,
        "assessmentState": state,
        "countingRule": (
            "Only runtime-observed, reachable, or recognized APIs are valid. "
            "Static unverified and rejected candidates are counted separately."
        ),
        "totals": {
            "features": len(features),
            "routes": len(routes),
            "apiCandidates": len(apis),
            "validApis": sum(
                count
                for validation_state, count in validation_counts.items()
                if validation_state in {"runtime-observed", "reachable", "recognized"}
            ),
            "unverifiedApis": unverified_count,
        "rejectedStaticCandidates": len(rejected_static),
            "rejectedRuntimeCandidates": len(rejected_runtime),
            "unresolvedAssets": len(unresolved),
            "unvisitedRoutes": len(unvisited_routes),
            "observedOnlyUiControls": len(unresolved_controls),
            "navigationFailures": len(navigation_failures),
            "blockedRequests": len(blocked_requests),
            "currentValidatedRoutes": sum(
                route.get("validation", {}).get("state")
                in {"runtime-visited", "recognized"}
                for route in routes
            ),
            "renderedRoutes": sum(
                route.get("validation", {}).get("state") == "runtime-visited"
                for route in routes
            ),
            "corsCandidates": len((probe or {}).get("corsCandidates", [])),
        },
        "validationCounts": validation_counts,
        "features": features,
        "routes": routes,
        "apis": apis,
        "rejectedStaticCandidates": rejected_static,
        "rejectedRuntimeCandidates": rejected_runtime,
        "unresolvedAssets": unresolved,
        "unvisitedRoutes": unvisited_routes,
        "coverageContext": {
            "expectedRoleIds": sorted(expected_roles),
            "observedRoleIds": sorted(observed_roles),
            "missingRoleIds": sorted(expected_roles - observed_roles),
            "expectedStateIds": sorted(expected_states),
            "observedStateIds": sorted(observed_states),
            "missingStateIds": sorted(expected_states - observed_states),
        },
        "probe": probe,
        "completionBlockers": blockers,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--asset-root", action="append", required=True, type=Path)
    parser.add_argument("--graph", required=True, type=Path)
    parser.add_argument("--browser-manifest", type=Path)
    parser.add_argument("--collection-manifest", type=Path)
    add_header_arguments(parser)
    parser.add_argument(
        "--coverage-context",
        type=Path,
        help="JSON with expected/observed role and business-state IDs",
    )
    parser.add_argument("--probe-safe-reads", action="store_true")
    parser.add_argument("--probe-limit", type=int, default=200)
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    inventory = build_surface_inventory(
        args.target,
        args.asset_root,
        load_json(args.graph, {}),
        load_json(args.browser_manifest, {}),
        load_json(args.collection_manifest, {}),
        args.probe_safe_reads,
        headers=load_headers(args.header, args.header_file),
        timeout=args.timeout,
        probe_limit=args.probe_limit,
        coverage_context=load_json(args.coverage_context, {}),
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(inventory, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    args.out.chmod(0o600)
    print(
        f"[ok] state={inventory['assessmentState']} "
        f"features={inventory['totals']['features']} "
        f"routes={inventory['totals']['routes']} "
        f"validApis={inventory['totals']['validApis']} "
        f"unverifiedApis={inventory['totals']['unverifiedApis']} "
        f"out={args.out}"
    )


if __name__ == "__main__":
    main()
