#!/usr/bin/env python3
"""Capture runtime SPA assets and lazy chunks with system Python Playwright."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import uuid
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, parse_qsl, quote, urljoin, urlsplit, urlunsplit

from collect_spa_assets import add_header_arguments, invalid_asset_response, load_headers
from route_inventory import route_candidates, route_is_safe_to_visit

if TYPE_CHECKING:
    from playwright.sync_api import Request, Response

TRACKED_FIELD_RE = re.compile(r"(?:id|ids|version|size|quota|balance|duration|token|key|uuid|package|pool)$", re.I)
READ_POST_RE = re.compile(
    r"(?:^|[/_.-])(?:list|page|query|search|find|detail|get|count|tree|menu|"
    r"stat|statistics|overview|preview|without[-_]?auth|without[-_]?page)(?:$|[/_.-])",
    re.I,
)
SIDE_EFFECT_REQUEST_RE = re.compile(
    r"(?:^|[/_.-])(?:create|add|save|update|delete|remove|upload|download|export|"
    r"reset|send|pay|approve|publish|import|execute|start|stop|activate)(?:$|[/_.-])",
    re.I,
)
DANGEROUS_CONTROL_RE = re.compile(
    r"delete|remove|create|save|update|upload|download|export|reset|logout|"
    r"send|pay|approve|publish|import|execute|start|stop|submit|confirm|"
    r"删除|移除|新建|创建|保存|更新|上传|下载|导出|重置|退出|发送|支付|"
    r"审批|发布|导入|执行|启动|停止|提交|确认",
    re.I,
)
SAFE_CONTROL_RE = re.compile(
    r"tab|next|previous|search|query|filter|preview|detail|open|expand|collapse|"
    r"close|page|more|查看|详情|搜索|查询|筛选|预览|展开|收起|关闭|下一页|"
    r"上一页|更多",
    re.I,
)
VOLATILE_URL_SEGMENT_RE = re.compile(
    r"(?:\d{2,}|[0-9a-f]{16,}|[0-9a-f]{8}-[0-9a-f-]{27,}|[A-Za-z0-9_-]{24,})",
    re.I,
)
ROUTE_PARAM_RE = re.compile(r":([A-Za-z_$][\w$]*)")
ROUTE_PARAM_FIELD_RE = re.compile(r"(?:^|[._\[\]-])([A-Za-z_$][\w$]*)$", re.I)


def normalize_url(value: str) -> str:
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, ""))


def safe_file_name(url_value: str, content_type: str) -> Path:
    parsed = urlsplit(url_value)
    parts = [re.sub(r"[^A-Za-z0-9._-]", "_", item) for item in Path(parsed.path.lstrip("/")).parts]
    if not parts or parsed.path.endswith("/"):
        parts.append("index.html")
    result = Path(re.sub(r"[^A-Za-z0-9._-]", "_", parsed.netloc), *parts)
    if not result.suffix:
        if "javascript" in content_type:
            result = result.with_suffix(".js")
        elif "json" in content_type:
            result = result.with_suffix(".json")
        elif "html" in content_type:
            result = result.with_suffix(".html")
        else:
            result = result.with_suffix(".txt")
    if parsed.query:
        digest = hashlib.sha256(parsed.query.encode()).hexdigest()[:10]
        result = result.with_name(f"{result.stem}.{digest}{result.suffix}")
    return result


def redact_url(value: str) -> str:
    parsed = urlsplit(value)
    path = re.sub(
        r";(?:jsessionid|sessionid)=[^/?#;]+",
        "",
        parsed.path,
        flags=re.IGNORECASE,
    )
    path = "/".join(
        "{id}" if VOLATILE_URL_SEGMENT_RE.fullmatch(segment) else segment
        for segment in path.split("/")
    )
    fragment = parsed.fragment
    if "?" in fragment:
        fragment_path, fragment_query = fragment.split("?", 1)
        fragment_keys = [
            key for key, _ in parse_qsl(fragment_query, keep_blank_values=True)
        ]
        fragment = fragment_path
        if fragment_keys:
            fragment += "?" + "&".join(
                f"{key}=:value" for key in fragment_keys
            )
    fragment_path, separator, fragment_query = fragment.partition("?")
    fragment_path = "/".join(
        "{id}" if VOLATILE_URL_SEGMENT_RE.fullmatch(segment) else segment
        for segment in fragment_path.split("/")
    )
    fragment = fragment_path + (separator + fragment_query if separator else "")
    if not parsed.query:
        return urlunsplit((parsed.scheme, parsed.netloc, path, "", fragment))
    keys = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    query = "&".join(f"{key}=:value" for key in keys)
    return urlunsplit((parsed.scheme, parsed.netloc, path, query, fragment))


def redact_route_value(value: str, base: str) -> str:
    parsed = urlsplit(redact_url(urljoin(base, value)))
    return urlunsplit(("", "", parsed.path, parsed.query, parsed.fragment))


def chrome_executable() -> str | None:
    for name in ("google-chrome-stable", "google-chrome", "chromium", "chromium-browser"):
        if executable := shutil.which(name):
            return executable
    candidates = [
        Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
    ]
    for variable in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
        if root := os.environ.get(variable):
            candidates.extend(
                (
                    Path(root) / "Google/Chrome/Application/chrome.exe",
                    Path(root) / "Chromium/Application/chrome.exe",
                    Path(root) / "Microsoft/Edge/Application/msedge.exe",
                )
            )
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def browser_storage_state_metadata(path: Path | None) -> dict:
    if path is None:
        return {"applied": False}
    if not path.is_file():
        raise ValueError(f"browser storage state does not exist: {path}")
    if os.name == "posix" and path.stat().st_mode & 0o077:
        raise ValueError("browser storage state must not be group/world accessible")
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid browser storage state: {path}") from error
    if not isinstance(state, dict):
        raise ValueError("browser storage state must be a JSON object")
    origins = state.get("origins", [])
    cookies = state.get("cookies", [])
    if not isinstance(origins, list) or not isinstance(cookies, list):
        raise ValueError("browser storage state cookies/origins must be arrays")
    return {
        "applied": True,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "originCount": len(origins),
        "cookieCount": len(cookies),
    }


def redact_runtime_json(value: object) -> object:
    if isinstance(value, dict):
        return {
            str(key): redact_runtime_json(child)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return {
            "$redactedType": "array",
            "count": len(value),
            "itemShapes": [
                redact_runtime_json(child) for child in value[:3]
            ],
        }
    if value is None:
        return {"$redactedType": "null"}
    if isinstance(value, bool):
        return {"$redactedType": "boolean"}
    if isinstance(value, int):
        return {"$redactedType": "integer"}
    if isinstance(value, float):
        return {"$redactedType": "number"}
    return {"$redactedType": "string", "length": len(str(value))}


def flatten_scalars(value: object, prefix: str = "") -> list[tuple[str, object]]:
    result: list[tuple[str, object]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            result.extend(flatten_scalars(child, child_prefix))
    elif isinstance(value, list):
        for index, child in enumerate(value[:100]):
            result.extend(flatten_scalars(child, f"{prefix}[{index}]"))
    elif value is not None:
        result.append((prefix, value))
    return result


def runtime_route_candidates(value: object, key: str = "") -> set[str]:
    result: set[str] = set()
    if isinstance(value, dict):
        for child_key, child in value.items():
            result.update(runtime_route_candidates(child, str(child_key)))
    elif isinstance(value, list):
        for child in value[:10_000]:
            result.update(runtime_route_candidates(child, key))
    elif (
        isinstance(value, str)
        and re.search(r"route|path|menu.*url", key, re.I)
        and value.startswith("/")
        and not value.startswith("//")
        and not re.search(r"\.[A-Za-z0-9]{2,5}(?:\?|$)", value)
        and len(value) <= 300
    ):
        result.add(value)
    return result


def request_values(request: Request) -> list[tuple[str, object]]:
    values: list[tuple[str, object]] = []
    query = parse_qs(urlsplit(request.url).query, keep_blank_values=True)
    for key, items in query.items():
        values.extend((f"query.{key}", item) for item in items)
    post_data = request.post_data
    if not post_data:
        return values
    try:
        values.extend(flatten_scalars(json.loads(post_data), "body"))
    except (json.JSONDecodeError, TypeError):
        for key, items in parse_qs(post_data, keep_blank_values=True).items():
            values.extend((f"body.{key}", item) for item in items)
    return values


def tracked(field: str, value: object) -> bool:
    leaf = re.sub(r"\[\d+\]", "", field).rsplit(".", 1)[-1]
    if not TRACKED_FIELD_RE.search(leaf):
        return False
    if isinstance(value, bool) or value in (None, ""):
        return False
    if re.search(r"(?:id|ids|uuid)$", leaf, re.I) and (
        isinstance(value, int) or (isinstance(value, str) and value.isdigit())
    ):
        return True
    return len(str(value)) >= 4


def value_fingerprint(value: object) -> str:
    encoded = json.dumps([type(value).__name__, value], ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(encoded.encode()).hexdigest()


def remember_route_parameter(
    values: dict[str, list[object]], field: str, value: object
) -> None:
    leaf = re.sub(r"\[\d+\]", "", field).rsplit(".", 1)[-1]
    if not re.search(r"(?:id|uuid|key|code|name)$", leaf, re.I):
        return
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return
    rendered = str(value)
    if not rendered or len(rendered) > 128 or re.search(r"[\s/?#&]", rendered):
        return
    bucket = values.setdefault(leaf.casefold(), [])
    if value not in bucket and len(bucket) < 20:
        bucket.append(value)


def resolve_dynamic_routes(
    routes: set[str],
    values: dict[str, list[object]],
    binding_slots: dict[tuple[str, str], str] | None = None,
) -> tuple[set[str], list[dict]]:
    binding_slots = binding_slots if binding_slots is not None else {}
    resolved: set[str] = set()
    bindings: list[dict] = []
    for template in routes:
        names = ROUTE_PARAM_RE.findall(template)
        if not names:
            continue
        candidates: list[object] = []
        for name in names:
            exact = values.get(name.casefold(), [])
            generic = values.get("id", []) if name.casefold().endswith("id") else []
            selected = exact or generic
            if not selected:
                candidates = []
                break
            candidates.append(selected[0])
        if not candidates:
            continue
        route = template
        route_bindings = []
        for name, value in zip(names, candidates):
            route = route.replace(f":{name}", quote(str(value), safe=""), 1)
            route_bindings.append({
                "parameter": name,
                "bindingSlotId": binding_slots.setdefault(
                    (template, name), f"binding-{uuid.uuid4()}"
                ),
                "source": "current-runtime-observed-value",
            })
        resolved.add(route)
        bindings.append(
            {
                "template": template,
                "bindings": route_bindings,
            }
        )
    return resolved, bindings


def registrable_domain(host: str) -> str:
    host = host.lower().rstrip(".")
    if not host or re.fullmatch(r"\d+(?:\.\d+){3}", host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    compound_suffixes = {
        "ac.uk",
        "co.jp",
        "co.kr",
        "co.uk",
        "com.au",
        "com.cn",
        "gov.cn",
        "net.au",
        "net.cn",
        "org.cn",
        "org.uk",
    }
    tail = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if tail in compound_suffixes else tail


def control_disposition(control: dict) -> str:
    text = " ".join(
        str(control.get(key) or "")
        for key in ("text", "ariaLabel", "title", "name", "id", "href", "action")
    )
    if DANGEROUS_CONTROL_RE.search(text):
        return "planned-unsafe"
    if control.get("tag") == "a" and control.get("href"):
        return "route-queued"
    if control.get("role") == "tab" or SAFE_CONTROL_RE.search(text):
        return "eligible"
    return "observed-only"


def network_request_decision(
    method: str,
    path: str,
    resource_type: str,
    active_scope: bool = True,
) -> tuple[str, str]:
    method = method.upper()
    if not active_scope:
        if method in {"GET", "HEAD", "OPTIONS"}:
            return "allowed", "normal-browser-cross-origin-resource"
        return "blocked", "out-of-scope-side-effect-request"
    if method in {"GET", "HEAD"} and resource_type in {"xhr", "fetch"} and SIDE_EFFECT_REQUEST_RE.search(path):
        return "blocked", "side-effect-like-safe-method-request"
    if method in {"GET", "HEAD"} and resource_type in {
        "document",
        "script",
        "stylesheet",
        "image",
        "font",
        "media",
        "manifest",
    }:
        return "allowed", "browser-resource"
    if method in {"GET", "HEAD", "OPTIONS"}:
        return "allowed", "safe-method"
    if (
        method == "POST"
        and READ_POST_RE.search(path)
        and not SIDE_EFFECT_REQUEST_RE.search(path)
    ):
        return "allowed", "recognized-read-post"
    return "blocked", "unclassified-side-effect-request"


def collect_ui_controls(page, page_url: str, frame_url: str | None = None) -> list[dict]:
    """Inventory interactive DOM surfaces without clicking or reading input values."""
    controls = page.locator(
        "a[href],button,input,select,textarea,"
        "[role=button],[role=link],[onclick],form"
    ).evaluate_all(
        """nodes => nodes.map((node, domIndex) => {
          const style = window.getComputedStyle(node);
          const rect = node.getBoundingClientRect();
          const clean = value => (value || "").replace(/\\s+/g, " ").trim().slice(0, 180);
          return {
            tag: node.tagName.toLowerCase(),
            type: clean(node.getAttribute("type")),
            text: clean(node.innerText || node.textContent),
            ariaLabel: clean(node.getAttribute("aria-label")),
            title: clean(node.getAttribute("title")),
            name: clean(node.getAttribute("name")),
            id: clean(node.id),
            role: clean(node.getAttribute("role")),
            placeholder: clean(node.getAttribute("placeholder")),
            autocomplete: clean(node.getAttribute("autocomplete")),
            href: clean(node.getAttribute("href")),
            action: clean(node.getAttribute("action")),
            method: clean(node.getAttribute("method")).toUpperCase(),
            ariaExpanded: clean(node.getAttribute("aria-expanded")),
            required: Boolean(node.required),
            maxLength: Number.isFinite(node.maxLength) ? node.maxLength : null,
            disabled: Boolean(node.disabled || node.getAttribute("aria-disabled") === "true"),
            visible: style.display !== "none" && style.visibility !== "hidden"
              && rect.width > 0 && rect.height > 0,
            domIndex
          };
        })"""
    )
    result = []
    for control in controls:
        for attribute in ("href", "action"):
            if control.get(attribute):
                control[attribute] = redact_url(
                    urljoin(frame_url or page_url, str(control[attribute]))
                )
        identity = {
            "page": redact_url(page_url),
            "frame": redact_url(frame_url or page_url),
            **control,
        }
        stable_identity = {
            key: value for key, value in identity.items() if key != "domIndex"
        }
        identity["id"] = "ui:" + hashlib.sha256(
            json.dumps(stable_identity, ensure_ascii=False, sort_keys=True).encode()
        ).hexdigest()[:20]
        identity["exerciseState"] = control_disposition(identity)
        if identity["exerciseState"] == "route-queued":
            page_parts = urlsplit(identity["page"])
            href_parts = urlsplit(identity["href"])
            if (
                href_parts.scheme in {"http", "https"}
                and (href_parts.scheme, href_parts.netloc)
                != (page_parts.scheme, page_parts.netloc)
            ):
                identity["exerciseState"] = "related-passive"
        result.append(identity)
    return result


def render_snapshot(page, api_count: int) -> dict:
    try:
        body_text = page.locator("body").inner_text(timeout=2_000)
    except Exception:
        body_text = ""
    normalized = re.sub(r"\s+", " ", body_text).strip()
    controls = collect_ui_controls(page, page.url)
    material = json.dumps(
        {
            "title": page.title()[:240],
            "text": normalized[:20_000],
            "controls": [
                {
                    key: item.get(key)
                    for key in ("tag", "type", "text", "role", "href", "action")
                }
                for item in controls
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return {
        "domFingerprint": hashlib.sha256(material.encode()).hexdigest(),
        "bodyTextLength": len(normalized),
        "controlCount": len(controls),
        "sameOriginApiCount": api_count,
        "frameCount": len(page.frames),
        "blank": len(normalized) < 20 and not controls and api_count == 0,
    }


def collect_browser_assets(
    start_url: str,
    out_dir: Path,
    headers: dict[str, str] | None = None,
    max_pages: int = 0,
    storage_state_path: Path | None = None,
    request_corpus_path: Path | None = None,
    seed_routes_path: Path | None = None,
) -> dict:
    try:
        from playwright.sync_api import sync_playwright
    except ModuleNotFoundError as error:
        raise RuntimeError(
            "browser collection requires the spa-browser optional dependency"
        ) from error

    start_url = normalize_url(start_url)
    start = urlsplit(start_url)
    origin = f"{start.scheme}://{start.netloc}"
    out_dir.mkdir(parents=True, exist_ok=True)
    request_headers = dict(headers or {})
    cookie_name = next((name for name in request_headers if name.lower() == "cookie"), None)
    cookie_header = request_headers.pop(cookie_name, "") if cookie_name else ""
    storage_state = browser_storage_state_metadata(storage_state_path)

    records: list[dict] = []
    data_flows: list[dict] = []
    observed_values: dict[str, list[dict]] = {}
    binding_slot_ids: dict[str, str] = {}
    route_parameter_values: dict[str, list[object]] = {}
    route_parameter_bindings: list[dict] = []
    route_binding_slots: dict[tuple[str, str], str] = {}
    request_events: list[dict] = []
    response_events: list[dict] = []
    network_decisions: list[dict] = []
    blocked_requests: list[dict] = []
    request_corpus: list[dict] = []
    control_attempts: list[dict] = []
    saved: set[str] = set()
    discovered_routes: set[str] = set()
    if seed_routes_path and seed_routes_path.is_file():
        try:
            seed_value = json.loads(seed_routes_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            seed_value = []
        if isinstance(seed_value, dict):
            seed_value = seed_value.get("routes", seed_value.get("surfaces", []))
        for item in seed_value if isinstance(seed_value, list) else []:
            value = item.get("url") or item.get("path") if isinstance(item, dict) else item
            if not isinstance(value, str):
                continue
            parsed_seed = urlsplit(urljoin(origin + "/", value))
            if f"{parsed_seed.scheme}://{parsed_seed.netloc}" == origin:
                discovered_routes.add(parsed_seed.path or "/")
    attempted: set[str] = set()
    visited: set[str] = set()
    navigation_attempts: list[dict] = []
    ui_controls: dict[str, dict] = {}
    exercised_controls: set[str] = set()
    same_origin_frames: set[str] = set()
    service_workers: set[tuple[str, str]] = set()
    active_runtime_origins: set[str] = {origin}
    navigation_queue = deque([start_url])
    queued = {start_url}
    saturation_rounds = 0
    last_global_signature = None
    confirmation_pending = False
    state = {"history_mode": False, "sequence": 0}

    with sync_playwright() as playwright:
        executable = chrome_executable()
        launch_options = {"headless": True}
        if executable:
            launch_options["executable_path"] = executable
        browser = playwright.chromium.launch(**launch_options)
        context = browser.new_context(
            extra_http_headers=request_headers,
            ignore_https_errors=True,
            storage_state=str(storage_state_path) if storage_state_path else None,
        )

        def in_active_scope(parsed) -> bool:
            candidate_origin = f"{parsed.scheme}://{parsed.netloc}"
            active = candidate_origin == origin or (
                registrable_domain(parsed.hostname or "")
                == registrable_domain(start.hostname or "")
            )
            if active:
                active_runtime_origins.add(candidate_origin)
            return active

        def guard_request(network_route) -> None:
            request = network_route.request
            parsed = urlsplit(request.url)
            request_origin = f"{parsed.scheme}://{parsed.netloc}"
            method = request.method.upper()
            resource_type = request.resource_type
            active_scope = in_active_scope(parsed)
            decision_state, decision_reason = network_request_decision(
                method,
                parsed.path,
                resource_type,
                active_scope,
            )
            allow_reason = decision_reason if decision_state == "allowed" else None
            fields = sorted({field for field, _ in request_values(request)})
            decision = {
                "method": method,
                "url": redact_url(request.url),
                "resourceType": resource_type,
                "requestFields": fields,
                "activeScope": active_scope,
                "decision": "allowed" if allow_reason else "blocked",
                "reason": decision_reason,
            }
            network_decisions.append(decision)
            if allow_reason:
                if active_scope and resource_type in {"xhr", "fetch"}:
                    try:
                        body = request.post_data_buffer
                        request_corpus.append(
                            {
                                "method": method,
                                "url": request.url,
                                "headers": request.all_headers(),
                                "body_base64": (
                                    base64.b64encode(body).decode() if body else None
                                ),
                                "resource_type": resource_type,
                            }
                        )
                    except Exception:
                        pass
                network_route.continue_()
            else:
                blocked_requests.append(decision)
                network_route.abort("blockedbyclient")

        context.route("**/*", guard_request)
        if cookie_header:
            cookies = []
            for item in cookie_header.split(";"):
                name, separator, value = item.strip().partition("=")
                if separator and name:
                    cookies.append({
                        "name": name,
                        "value": value,
                        "domain": start.hostname,
                        "path": "/",
                        "secure": start.scheme == "https",
                    })
            if cookies:
                context.add_cookies(cookies)
        page = context.new_page()

        def next_sequence() -> int:
            state["sequence"] += 1
            return state["sequence"]

        def observe_request(request: Request) -> None:
            sequence = next_sequence()
            parsed = urlsplit(request.url)
            if not in_active_scope(parsed):
                return
            values = request_values(request)
            request_events.append({
                "sequence": sequence,
                "method": request.method,
                "url": redact_url(request.url),
                "resourceType": request.resource_type,
                "values": values,
            })
            for field, value in values:
                remember_route_parameter(route_parameter_values, field, value)
                if not tracked(field, value):
                    continue
                for source in observed_values.get(value_fingerprint(value), []):
                    if source["url"] == redact_url(request.url):
                        continue
                    flow = {
                        "evidence": "observed-value-reuse",
                        "bindingSlotId": source["bindingSlotId"],
                        "from": {
                            key: item
                            for key, item in source.items()
                            if key != "bindingSlotId"
                        },
                        "to": {"method": request.method, "url": redact_url(request.url), "field": field},
                    }
                    if flow not in data_flows:
                        data_flows.append(flow)

        def capture(response: Response) -> None:
            sequence = next_sequence()
            url = response.url
            parsed = urlsplit(url)
            if not in_active_scope(parsed):
                return
            request = response.request
            content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
            record = {
                "url": redact_url(url),
                "method": request.method,
                "status": response.status,
                "resourceType": request.resource_type,
                "contentType": content_type,
                "requestFields": sorted({field for field, _ in request_values(request)}),
            }
            should_save = request.resource_type in {"document", "script", "xhr", "fetch"} or re.search(
                r"javascript|json|html", content_type
            )
            if should_save and url not in saved:
                saved.add(url)
                try:
                    body = response.body()
                    if len(body) <= 20 * 1024 * 1024:
                        destination = out_dir / safe_file_name(url, content_type)
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        stored_body = body
                        stored_representation = "original"
                        parsed_json = None
                        if (
                            request.resource_type in {"xhr", "fetch"}
                            and (
                                "json" in content_type
                                or body.lstrip().startswith((b"{", b"["))
                            )
                        ):
                            try:
                                parsed_json = json.loads(body)
                                stored_body = (
                                    json.dumps(
                                        redact_runtime_json(parsed_json),
                                        ensure_ascii=False,
                                        indent=2,
                                    )
                                    + "\n"
                                ).encode()
                                stored_representation = "redacted-json-shape"
                            except (json.JSONDecodeError, UnicodeDecodeError):
                                pass
                        if parsed_json is not None:
                            discovered_routes.update(
                                runtime_route_candidates(parsed_json)
                            )
                        destination.write_bytes(stored_body)
                        record.update({
                            "localPath": str(destination),
                            "bytes": len(body),
                            "sha256": hashlib.sha256(body).hexdigest(),
                            "storedBytes": len(stored_body),
                            "storedSha256": hashlib.sha256(stored_body).hexdigest(),
                            "storedRepresentation": stored_representation,
                        })
                        invalid_reason = invalid_asset_response(
                            url,
                            content_type,
                            body,
                        )
                        if invalid_reason:
                            record["invalidReason"] = invalid_reason
                        if request.resource_type == "script" or "javascript" in content_type:
                            if not invalid_reason:
                                text = body.decode("utf-8", errors="replace")
                                discovered_routes.update(route_candidates(text))
                                if re.search(r"createWebHistory|mode\s*:\s*['\"]history['\"]", text):
                                    state["history_mode"] = True
                        if "json" in content_type or body.lstrip().startswith((b"{", b"[")):
                            try:
                                response_values = flatten_scalars(
                                    parsed_json
                                    if parsed_json is not None
                                    else json.loads(body),
                                    "response",
                                )
                                record["responseFields"] = sorted({field for field, _ in response_values})
                                response_events.append({
                                    "sequence": sequence, "method": request.method, "url": redact_url(url), "values": response_values,
                                })
                                for field, value in response_values:
                                    remember_route_parameter(route_parameter_values, field, value)
                                    if tracked(field, value):
                                        fingerprint = value_fingerprint(value)
                                        binding_slot_ids.setdefault(
                                            fingerprint, f"binding-{uuid.uuid4()}"
                                        )
                                        observed_values.setdefault(value_fingerprint(value), []).append({
                                            "method": request.method,
                                            "url": redact_url(url),
                                            "field": field,
                                            "bindingSlotId": binding_slot_ids[fingerprint],
                                        })
                            except (json.JSONDecodeError, UnicodeDecodeError):
                                pass
                except Exception as error:  # Playwright can evict redirect bodies.
                    record["bodyError"] = str(error)
            records.append(record)

        page.on("request", observe_request)
        page.on("response", capture)

        def queue_runtime_url(value: str, base: str) -> None:
            candidate = urljoin(base, value)
            parsed = urlsplit(candidate)
            if f"{parsed.scheme}://{parsed.netloc}" != origin:
                return
            if candidate not in attempted and candidate not in queued:
                queued.add(candidate)
                navigation_queue.append(candidate)

        while (
            navigation_queue
            or (max_pages <= 0 and saturation_rounds < 2)
        ) and (max_pages <= 0 or len(attempted) < max_pages):
            if not navigation_queue:
                global_signature = (
                    len(attempted),
                    len(discovered_routes),
                    len(ui_controls),
                    len(saved),
                    len(active_runtime_origins),
                    len(visited),
                    len(same_origin_frames),
                    len(service_workers),
                    len({
                        (
                            event.get("method"),
                            event.get("url"),
                            event.get("resourceType"),
                        )
                        for event in request_events
                    }),
                )
                if global_signature == last_global_signature:
                    saturation_rounds += 1
                else:
                    saturation_rounds = 0
                    last_global_signature = global_signature
                if saturation_rounds >= 2:
                    break
                navigation_queue.append(start_url)
                confirmation_pending = True
            target = navigation_queue.popleft()
            confirmation = confirmation_pending and target == start_url
            if confirmation:
                confirmation_pending = False
            elif target in attempted:
                continue
            else:
                attempted.add(target)
            navigation = {
                "requestedUrl": redact_url(target),
                "state": "failed",
            }
            request_start = len(request_events)
            record_start = len(records)
            try:
                response = page.goto(
                    target,
                    wait_until="domcontentloaded",
                    timeout=30_000,
                )
                page.wait_for_timeout(1_200)
                effective_url = page.url
                api_count = sum(
                    item.get("resourceType") in {"xhr", "fetch"}
                    for item in request_events[request_start:]
                )
                render = render_snapshot(page, api_count)
                try:
                    registrations = page.evaluate(
                        """async () => {
                          if (!('serviceWorker' in navigator)) return [];
                          const items = await navigator.serviceWorker.getRegistrations();
                          return items.map(item => ({
                            scope: item.scope,
                            scriptURL: (item.active || item.waiting || item.installing || {}).scriptURL || ''
                          }));
                        }"""
                    )
                    for registration in registrations or []:
                        scope = str(registration.get("scope") or "")
                        script_url = str(registration.get("scriptURL") or "")
                        if scope and in_active_scope(urlsplit(scope)):
                            service_workers.add((redact_url(scope), redact_url(script_url) if script_url else ""))
                except Exception:
                    pass
                login_redirect = bool(
                    re.search(r"(?:^|[/#?])(?:login|signin|auth)(?:$|[/#?])", effective_url, re.I)
                    and not re.search(r"(?:^|[/#?])(?:login|signin|auth)(?:$|[/#?])", target, re.I)
                )
                if response and response.status in {404, 410}:
                    render.update({"state": "rejected", "reason": f"http-{response.status}"})
                elif login_redirect:
                    render.update({"state": "blocked", "reason": "login-redirect"})
                elif render["blank"]:
                    render.update({"state": "blocked", "reason": "blank-page"})
                else:
                    render.update({"state": "rendered", "reason": "route-specific-signal"})
                    visited.add(target)
                navigation.update(
                    {
                        "state": "visited",
                        "effectiveUrl": redact_url(effective_url),
                        "status": response.status if response else None,
                        "title": page.title()[:240],
                        "render": render,
                    }
                )
                route_control_refs: set[str] = set()
                route_api_refs: set[str] = set()
                route_lazy_refs: set[str] = set()
                frame_controls = []
                stable_rounds = 0
                last_signature = None
                while stable_rounds < 2:
                    frame_controls = []
                    hrefs = []
                    for frame in page.frames:
                        frame_parts = urlsplit(frame.url)
                        if frame.url and f"{frame_parts.scheme}://{frame_parts.netloc}" != origin:
                            continue
                        if frame.url:
                            same_origin_frames.add(redact_url(frame.url))
                            queue_runtime_url(frame.url, page.url)
                        try:
                            controls = collect_ui_controls(frame, page.url, frame.url)
                            frame_controls.extend((frame, item) for item in controls)
                            hrefs.extend(
                                frame.locator("a[href]").evaluate_all(
                                    "nodes => nodes.map(node => node.href)"
                                )
                            )
                        except Exception:
                            continue
                    for _, control in frame_controls:
                        ui_controls.setdefault(control["id"], control)
                        route_control_refs.add(control["id"])
                    for href in hrefs:
                        queue_runtime_url(href, page.url)
                    if page.url != target:
                        queue_runtime_url(page.url, target)
                    route_api_refs.update(
                        item["url"]
                        for item in request_events[request_start:]
                        if item.get("resourceType") in {"xhr", "fetch"}
                    )
                    route_lazy_refs.update(
                        item["url"]
                        for item in records[record_start:]
                        if item.get("resourceType") == "script"
                    )
                    signature = (
                        tuple(sorted(route_control_refs)),
                        tuple(sorted(route_api_refs)),
                        tuple(sorted(route_lazy_refs)),
                        tuple(sorted(discovered_routes)),
                        redact_url(page.url),
                    )
                    eligible = next(
                        (
                            (frame, control)
                            for frame, control in frame_controls
                            if control["exerciseState"] == "eligible"
                            and control["visible"]
                            and not control["disabled"]
                            and control["id"] not in exercised_controls
                        ),
                        None,
                    )
                    if eligible:
                        stable_rounds = 0
                        last_signature = signature
                        frame, control = eligible
                        exercised_controls.add(control["id"])
                        attempt = {
                            "controlId": control["id"],
                            "page": redact_url(page.url),
                            "state": "failed",
                        }
                        try:
                            locator = frame.locator(
                                "a[href],button,input,select,textarea,"
                                "[role=button],[role=link],[onclick],form"
                            ).nth(int(control.get("domIndex", 0)))
                            locator.click(timeout=2_000)
                            page.wait_for_timeout(350)
                            attempt["state"] = "exercised"
                            attempt["effectiveUrl"] = redact_url(page.url)
                            ui_controls[control["id"]]["exerciseState"] = "exercised"
                        except Exception as error:
                            attempt["error"] = str(error)[:300]
                        control_attempts.append(attempt)
                    else:
                        if signature == last_signature:
                            stable_rounds += 1
                        else:
                            stable_rounds = 0
                            last_signature = signature
                        page.wait_for_timeout(350)
                navigation["controlRefs"] = sorted(route_control_refs)
                navigation["runtimeApiRefs"] = sorted(route_api_refs)
                navigation["lazyChunkRefs"] = sorted(route_lazy_refs)
                navigation["saturationRounds"] = stable_rounds
            except Exception as error:
                navigation["error"] = str(error)[:500]
            navigation_attempts.append(navigation)
            resolved_routes, bindings = resolve_dynamic_routes(
                discovered_routes,
                route_parameter_values,
                route_binding_slots,
            )
            discovered_routes.update(resolved_routes)
            for binding in bindings:
                if binding not in route_parameter_bindings:
                    route_parameter_bindings.append(binding)
            for route in sorted(discovered_routes):
                if not route_is_safe_to_visit(route):
                    continue
                base_path = start.path.rsplit("/", 1)[0] + "/"
                candidates = {
                    urljoin(origin + "/", route),
                    f"{origin}{base_path}#{route}",
                }
                for candidate in sorted(candidates):
                    if candidate not in attempted and candidate not in queued:
                        queued.add(candidate)
                        navigation_queue.append(candidate)

        nonce = uuid.uuid4().hex[:12]
        base_path = start.path.rsplit("/", 1)[0] + "/"
        probe_urls = {
            "history": f"{origin}/__blue_sec_route_not_found_{nonce}",
            "hash": f"{origin}{base_path}#/__blue_sec_route_not_found_{nonce}",
        }
        fallback_probes = []
        for mode, probe_url in probe_urls.items():
            fallback_probe = {
                "mode": mode,
                "state": "failed",
                "requestedUrl": redact_url(probe_url),
            }
            probe_page = None
            try:
                probe_page = context.new_page()
                probe_response = probe_page.goto(
                    probe_url,
                    wait_until="domcontentloaded",
                    timeout=30_000,
                )
                probe_page.wait_for_timeout(1_200)
                fallback_probe.update(
                    {
                        "state": "captured",
                        "effectiveUrl": redact_url(probe_page.url),
                        "status": probe_response.status if probe_response else None,
                        "render": render_snapshot(probe_page, 0),
                    }
                )
            except Exception as error:
                fallback_probe["error"] = str(error)[:500]
            finally:
                if probe_page is not None:
                    probe_page.close()
            fallback_probes.append(fallback_probe)
        fallback_fingerprints = {
            item["mode"]: item.get("render", {}).get("domFingerprint")
            for item in fallback_probes
            if item.get("render", {}).get("domFingerprint")
        }
        if fallback_fingerprints:
            for navigation in navigation_attempts:
                render = navigation.get("render", {})
                requested_url = str(navigation.get("requestedUrl") or "")
                navigation_mode = (
                    "hash" if urlsplit(requested_url).fragment else "history"
                )
                if (
                    requested_url != redact_url(start_url)
                    and render.get("state") == "rendered"
                    and render.get("domFingerprint")
                    == fallback_fingerprints.get(navigation_mode)
                ):
                    render.update(
                        {"state": "rejected", "reason": "spa-fallback-fingerprint"}
                    )
                    requested = navigation.get("requestedUrl")
                    if requested:
                        visited.discard(requested)

        # Response-body callbacks can overlap with the page's next request. Reconcile in memory
        # after navigation so exact values are compared without persisting those values.
        for request_event in request_events:
            for request_field, request_value in request_event["values"]:
                if not tracked(request_field, request_value):
                    continue
                fingerprint = value_fingerprint(request_value)
                for response_event in response_events:
                    if response_event["sequence"] >= request_event["sequence"]:
                        continue
                    for response_field, response_value in response_event["values"]:
                        if not tracked(response_field, response_value) or value_fingerprint(response_value) != fingerprint:
                            continue
                        flow = {
                            "evidence": "observed-value-reuse",
                            "bindingSlotId": binding_slot_ids.setdefault(
                                fingerprint, f"binding-{uuid.uuid4()}"
                            ),
                            "from": {"method": response_event["method"], "url": response_event["url"], "field": response_field},
                            "to": {"method": request_event["method"], "url": request_event["url"], "field": request_field},
                        }
                        if flow not in data_flows:
                            data_flows.append(flow)

        manifest = {
            "startUrl": redact_url(start_url),
            "generatedAt": datetime.now(UTC).isoformat(),
            "pythonPlaywright": True,
            "chromeExecutable": executable,
            "browserStorageState": storage_state,
            "runtimeJsonValuePolicy": "redacted-by-default",
            "historyMode": state["history_mode"],
            "pagesAttempted": sorted(redact_url(value) for value in attempted),
            "pagesVisited": sorted(
                item["requestedUrl"]
                for item in navigation_attempts
                if item.get("render", {}).get("state") == "rendered"
            ),
            "navigationAttempts": navigation_attempts,
            "navigationFailures": [
                item
                for item in navigation_attempts
                if item["state"] != "visited"
                or item.get("render", {}).get("state") != "rendered"
            ],
            "navigationQueueRemaining": len(navigation_queue),
            "navigationLimit": max_pages if max_pages > 0 else None,
            "navigationExhaustive": not navigation_queue,
            "saturationRounds": saturation_rounds,
            "routesDiscovered": sorted(
                {redact_route_value(route, origin + "/") for route in discovered_routes}
            ),
            "routesEligibleForVisit": sorted(
                {
                    redact_route_value(route, origin + "/")
                    for route in discovered_routes
                    if route_is_safe_to_visit(route)
                }
            ),
            "routesSkippedForSafety": sorted(
                {
                    redact_route_value(route, origin + "/")
                    for route in discovered_routes
                    if not route_is_safe_to_visit(route)
                }
            ),
            "routesBlockedParameters": sorted(
                {
                    redact_route_value(route, origin + "/")
                    for route in discovered_routes
                    if not route_is_safe_to_visit(route)
                }
            ),
            "routeParameterBindings": sorted(
                route_parameter_bindings,
                key=lambda item: item["template"],
            ),
            "fallbackProbe": fallback_probes[0],
            "fallbackProbes": fallback_probes,
            "sameOriginFrames": sorted(same_origin_frames),
            "serviceWorkers": [
                {"scope": scope, "scriptUrl": script_url}
                for scope, script_url in sorted(service_workers)
            ],
            "activeRuntimeOrigins": sorted(active_runtime_origins),
            "responses": records,
            "uiControls": sorted(ui_controls.values(), key=lambda item: item["id"]),
            "controlAttempts": control_attempts,
            "networkDecisions": network_decisions,
            "blockedRequests": blocked_requests,
            "valueProducers": [
                {
                    "bindingSlotId": slot_id,
                    "method": method,
                    "url": url,
                    "field": field,
                }
                for slot_id, method, url, field in sorted(
                    {
                        (
                            source["bindingSlotId"],
                            source["method"],
                            source["url"],
                            source["field"],
                        )
                        for sources in observed_values.values()
                        for source in sources
                        if re.search(
                            r"(?:^|[._\[])(?:id|[A-Za-z0-9_-]*Id|uuid|[A-Za-z0-9_-]*Key)$",
                            source["field"],
                            re.I,
                        )
                        and not re.search(
                            r"(?:token|secret|credential|password)",
                            source["field"],
                            re.I,
                        )
                    },
                    key=lambda item: (item[1], item[2], item[3], item[0]),
                )
            ],
            "dataFlows": data_flows,
        }
        (out_dir / "browser-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        if request_corpus_path:
            request_corpus_path.parent.mkdir(parents=True, exist_ok=True)
            request_corpus_path.write_text(
                json.dumps({"requests": request_corpus}, ensure_ascii=False),
                encoding="utf-8",
            )
            request_corpus_path.chmod(0o600)
        browser.close()
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Starting domain or URL")
    parser.add_argument("--out", required=True, type=Path)
    add_header_arguments(parser)
    parser.add_argument(
        "--max-pages",
        type=int,
        default=0,
        help="Maximum route navigations; 0 exhausts the discovered queue",
    )
    parser.add_argument(
        "--storage-state",
        type=Path,
        help="Playwright storage-state JSON; must be mode 0600 on POSIX",
    )
    parser.add_argument(
        "--request-corpus-out",
        type=Path,
        help="Private transient raw request corpus for the assessment runner",
    )
    args = parser.parse_args()
    collect_browser_assets(
        args.url,
        args.out,
        load_headers(args.header, args.header_file),
        args.max_pages,
        args.storage_state,
        args.request_corpus_out,
    )
    print(args.out / "browser-manifest.json")


if __name__ == "__main__":
    main()
