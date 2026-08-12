#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import knowledge_runtime
import security_conclusion


ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = ROOT / "skills" / "blue-web-patrol"
TEMPLATE = SKILL_ROOT / "templates" / "coverage-matrix.json"
STANDARDS = SKILL_ROOT / "references" / "standards-baseline.json"
PAYLOAD_TECHNIQUES = SKILL_ROOT / "references" / "payload-technique-registry.json"
PREREQUISITE_REGISTRY = SKILL_ROOT / "references" / "prerequisite-registry.json"
_PAYLOAD_REGISTRY: dict[str, Any] | None = None
_PREREQUISITE_REGISTRY: dict[str, Any] | None = None

# Scheduling may stop on a blocker, but blocked work never satisfies coverage.
SCHEDULING_TERMINAL = {"tested", "blocked", "not-applicable"}
COVERAGE_SATISFIED = {"tested", "not-applicable"}
RESOLVED = SCHEDULING_TERMINAL
ACTIONABLE_SAFETY = {"passive", "read-only", "reversible"}
SAFETY_CLASSES = ACTIONABLE_SAFETY | {"blocked"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
MUTATING_LIFECYCLES = {
    "write",
    "create",
    "update",
    "delete",
    "approve",
    "publish",
    "upload",
    "import",
    "reset",
}
TEST_RESULT_STATES = RESOLVED | {
    "queued",
    "running",
    "mapped",
    "waiting-prerequisite",
}
MISSED_CAUSES = {
    "discovery",
    "mapping",
    "applicability",
    "priority",
    "execution",
    "validation",
    "evidence",
}
EVENT_TYPES = {
    "test-result",
    "identity",
    "business-state",
    "authorization-capability",
    "request-shape",
    "history-lookup",
    "phase",
    "candidate",
    "finding",
    "candidate-disposition",
    "candidate-dependency",
    "prerequisite-result",
    "missed-finding",
    "evidence",
    "credential-state",
    "runtime-condition",
    "surface-discovered",
    "route-result",
    "control-result",
    "surface-link",
    "variant-result",
    "runner-checkpoint",
    "credential-lease-state",
    "execution-audit",
    "priority-signal",
    "priority-change",
    "queue-preemption",
    "starvation-promotion",
}
PRIORITY_SIGNAL_POINTS = {
    "attacker-reachable-producer": 3,
    "controlled-input": 3,
    "dangerous-sink": 2,
    "privilege-bridge": 3,
    "sensitive-consumer": 2,
    "runtime-differential": 2,
    "adjacent-confirmed-finding": 2,
    "prerequisite-near-closure": 3,
    "evidence-backed-exhaustion": -3,
    "duplicate-confirmed": -4,
    "not-applicable-confirmed": -4,
}
NEGATIVE_PRIORITY_SIGNALS = {
    key for key, value in PRIORITY_SIGNAL_POINTS.items() if value < 0
}
STARVATION_INTERVAL = 4
CANDIDATE_DEPENDENCY_STATES = {
    "pending",
    "satisfied",
    "exhausted-with-evidence",
    "blocked",
    "blocked-external",
}
CANDIDATE_DEPENDENCY_TERMINAL = {"satisfied", "exhausted-with-evidence"}
CANDIDATE_RESOLVED_DISPOSITIONS = {"rejected", "duplicate"}
PREREQUISITE_STATES = {
    "pending",
    "searching",
    "satisfied",
    "exhausted-with-evidence",
    "blocked-external",
}
PREREQUISITE_FINAL = {
    "satisfied",
    "exhausted-with-evidence",
    "blocked-external",
}
ROUTE_STAGE_IDS = (
    "discovered",
    "current-validated",
    "navigated",
    "rendered",
    "controls-extracted",
    "runtime-api-linked",
    "tests-resolved",
)
AUTHORIZATION_MODES_BY_FAMILY = {
    "authorization.function-level": (
        "anonymous-boundary",
        "low-privilege-function",
    ),
    "authorization.object-level": (
        "self-owned-object",
        "cross-principal-ownership",
    ),
    "authorization.property-level": ("protected-property",),
    "authorization.tenant-parent-state": (
        "implicit-subject-binding",
        "tenant-parent-binding",
    ),
    "authorization.workflow-state": (
        "workflow-precondition",
        "state-transition",
    ),
    "authorization.file-export": (
        "anonymous-boundary",
        "self-owned-object",
        "cross-principal-ownership",
    ),
}
AUTHORIZATION_MODES = {
    mode
    for modes in AUTHORIZATION_MODES_BY_FAMILY.values()
    for mode in modes
}
AUTHORIZATION_CAPABILITY_STATES = {
    "available",
    "conditional",
    "unavailable",
}
REQUEST_SHAPE_SOURCES = {
    "runtime",
    "har",
    "openapi",
    "documented",
    "historical",
    "manual",
    "surface-validation",
}
AUTHORIZATION_EVIDENCE_BY_MODE = {
    "anonymous-boundary": {"anonymous-authenticated-differential"},
    "low-privilege-function": {"explicit-policy", "function-impact"},
    "implicit-subject-binding": {"self-subject-baseline"},
    "self-owned-object": {"self-owned-baseline"},
    "cross-principal-ownership": {"cross-principal-baseline"},
    "tenant-parent-binding": {"tenant-parent-baseline"},
    "protected-property": {"protected-property-baseline"},
    "workflow-precondition": {"workflow-state-baseline"},
    "state-transition": {"workflow-state-baseline", "self-owned-baseline"},
}
VOLATILE_SEGMENT = re.compile(
    r"^(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27,}|[0-9a-f]{16,}|"
    r"[A-Za-z0-9_-]{24,}={0,2})$",
    re.IGNORECASE,
)
VERSION_SEGMENT = re.compile(r"^v\d+(?:\.\d+)*$", re.IGNORECASE)
LIFECYCLE_WORDS = {
    "list": "read-list",
    "page": "read-list",
    "query": "read-list",
    "search": "read-list",
    "find": "read-detail",
    "get": "read-detail",
    "detail": "read-detail",
    "create": "create",
    "add": "create",
    "save": "create",
    "update": "update",
    "edit": "update",
    "modify": "update",
    "delete": "delete",
    "remove": "delete",
    "approve": "approve",
    "audit": "approve",
    "publish": "publish",
    "export": "export",
    "download": "download",
    "upload": "upload",
    "import": "import",
    "reset": "reset",
    "login": "authenticate",
    "logout": "authenticate",
}
SIDE_EFFECT_WORDS = re.compile(
    r"(?:delete|remove|reset|send|notify|publish|approve|audit|execute|"
    r"trigger|start|stop|pay|refund|transfer|invite)",
    re.IGNORECASE,
)
SENSITIVE_WORDS = re.compile(
    r"(?:password|passwd|secret|token|credential|admin|tenant|customer|"
    r"payment|finance|export|download|upload|file|approve|publish|reset|"
    r"mobile|phone|email|identity|permission|role)",
    re.IGNORECASE,
)
FILE_WORDS = re.compile(
    r"(?:file|upload|download|attachment|archive|zip|image|document|"
    r"import|export|csv|excel|office)",
    re.IGNORECASE,
)
SERVER_FETCH_WORDS = re.compile(
    r"(?:url|uri|callback|webhook|proxy|fetch|remote|convert|render|"
    r"xml|soap|template|job|task)",
    re.IGNORECASE,
)
AUTH_WORDS = re.compile(
    r"(?:login|logout|register|signup|password|reset|mfa|otp|oauth|"
    r"oidc|sso|token|session|captcha)",
    re.IGNORECASE,
)
ABUSE_WORDS = re.compile(
    r"(?:sms|otp|captcha|verify|verification|login|register|signup|"
    r"invite|send|resend|recover|reset|rate|quota|limit)",
    re.IGNORECASE,
)
IDENTIFIER_WORDS = re.compile(
    r"(?:^|[._/-])(?:id|key|code|uuid|guid|token|reference|ref)(?:$|[._/-])|"
    r"(?:object|resource|file|attachment|owner|task|job|order|record)(?:id|key|code)",
    re.IGNORECASE,
)
TENANT_WORDS = re.compile(
    r"(?:tenant|organization|orgid|org_id|company|workspace|project|"
    r"team|department|accountid|account_id|parentid|parent_id)",
    re.IGNORECASE,
)
CLIENT_CONFIG_WORDS = re.compile(
    r"(?:^|[/_.-])(?:config|configuration|bootstrap|runtime-config|"
    r"env|settings)(?:\.js|[/_.-]|$)",
    re.IGNORECASE,
)
TOKEN_CLAIM_WORDS = re.compile(
    r"(?:jwt|token|session|oauth|oidc|sso|userinfo)",
    re.IGNORECASE,
)
QUOTA_WORDS = re.compile(
    r"(?:quota|limit|balance|credit|sms|otp|captcha|rate|count|"
    r"price|amount|duration|capacity|resource)",
    re.IGNORECASE,
)
CHAIN_SIGNIFICANT_WORDS = {
    "artifact",
    "asset",
    "attachment",
    "code",
    "content",
    "document",
    "file",
    "image",
    "key",
    "package",
    "path",
    "plugin",
    "template",
    "url",
}
CHAIN_STOP_WORDS = {
    "api",
    "data",
    "detail",
    "get",
    "id",
    "info",
    "item",
    "list",
    "name",
    "page",
    "query",
    "request",
    "response",
    "status",
    "type",
    "value",
}
CHAIN_GENERIC_FIELDS = {
    "content",
    "data",
    "file",
    "id",
    "image",
    "key",
    "model",
    "name",
    "path",
    "resource",
    "status",
    "type",
    "url",
    "value",
    "version",
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return copy.deepcopy(default)
    return json.loads(path.read_text(encoding="utf-8"))


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        delete=False,
    ) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    temporary.replace(path)


def atomic_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        delete=False,
    ) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    temporary.replace(path)


def stable_id(prefix: str, value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:16]}"


def normalized_target(value: str) -> str:
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    if not parsed.hostname:
        raise ValueError(f"target has no hostname: {value}")
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower().rstrip(".")
    port = parsed.port
    default_port = (scheme == "https" and port == 443) or (
        scheme == "http" and port == 80
    )
    netloc = host if port is None or default_port else f"{host}:{port}"
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, "", ""))


def origin(value: str) -> str:
    parsed = urlsplit(normalized_target(value))
    return f"{parsed.scheme}://{parsed.netloc}"


def normalize_path(path: str) -> str:
    if not path:
        return "/"
    path = "/" + path.lstrip("/")
    segments = []
    for segment in path.split("/"):
        if not segment:
            continue
        bare = segment.split(";", 1)[0]
        if VOLATILE_SEGMENT.fullmatch(bare):
            segments.append("{id}")
        else:
            segments.append(bare)
    return "/" + "/".join(segments)


def normalize_surface_url(value: str, target: str) -> tuple[str, str]:
    absolute = urljoin(origin(target) + "/", value)
    parsed = urlsplit(absolute)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port
    default_port = (scheme == "https" and port == 443) or (
        scheme == "http" and port == 80
    )
    netloc = host if port is None or default_port else f"{host}:{port}"
    path = normalize_path(parsed.path)
    return urlunsplit((scheme, netloc, path, "", "")), path


def registrable_domain(host: str) -> str:
    host = host.lower().rstrip(".")
    if not host or re.fullmatch(r"\d+(?:\.\d+){3}", host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    compound = {
        "co.uk",
        "org.uk",
        "ac.uk",
        "com.cn",
        "net.cn",
        "org.cn",
        "gov.cn",
        "com.au",
        "net.au",
        "co.jp",
        "co.kr",
    }
    tail = ".".join(labels[-2:])
    if tail in compound and len(labels) >= 3:
        return ".".join(labels[-3:])
    return tail


def scope_disposition(target: str, url: str, runtime: bool) -> str:
    target_url = urlsplit(normalized_target(target))
    candidate = urlsplit(url)
    candidate_origin = f"{candidate.scheme}://{candidate.netloc}"
    if candidate_origin == origin(target):
        return "target-origin-active"
    if registrable_domain(candidate.hostname or "") == registrable_domain(
        target_url.hostname or ""
    ):
        return (
            "same-site-runtime-safe-read"
            if runtime
            else "same-site-related-passive"
        )
    return "cross-site-related-passive"


def surface_fingerprint(surface: dict[str, Any]) -> str:
    return stable_id(
        "fp",
        {
            "kind": surface["kind"],
            "method": surface.get("method", "UNKNOWN"),
            "url": surface.get("url"),
            "path_template": surface.get("path_template"),
            "protocol": surface.get("protocol", "http"),
            "fields": sorted(surface.get("fields", [])),
            "validation_state": surface.get("validation_state"),
        },
    )


def finalize_surface(surface: dict[str, Any], target: str) -> dict[str, Any]:
    value = dict(surface)
    value.setdefault("kind", "api")
    value["method"] = str(value.get("method") or "UNKNOWN").upper()
    raw_url = str(value.get("url") or value.get("path") or "/")
    value["url"], value["path_template"] = normalize_surface_url(raw_url, target)
    value.setdefault("protocol", urlsplit(value["url"]).scheme or "http")
    value.setdefault("validation_state", "unverified")
    value.setdefault("runtime_observed", False)
    value.setdefault("fields", [])
    query_fields = [
        name
        for name, _ in parse_qsl(urlsplit(urljoin(origin(target) + "/", raw_url)).query)
    ]
    value["fields"] = sorted(
        {
            *[str(item) for item in value["fields"] if item],
            *query_fields,
        }
    )
    value.setdefault("profiles", [])
    value["profiles"] = sorted({str(item) for item in value["profiles"] if item})
    value.setdefault("source_refs", [])
    value.setdefault("evidence_refs", [])
    if value.get("safety") and value["safety"] not in SAFETY_CLASSES:
        raise ValueError(f"invalid surface safety: {value['safety']}")
    value.setdefault(
        "scope_disposition",
        scope_disposition(target, value["url"], bool(value["runtime_observed"])),
    )
    identity = {
        "kind": value["kind"],
        "method": value["method"],
        "url": value["url"],
        "protocol": value["protocol"],
        "semantic_key": value.get("semantic_key"),
    }
    value["id"] = stable_id("surface", identity)
    value["fingerprint"] = surface_fingerprint(value)
    return value


def source_ref(path: Path, pointer: str) -> str:
    return f"{path.resolve()}#{pointer}"


def load_spa(path: Path, target: str) -> tuple[list[dict[str, Any]], list[str]]:
    data = read_json(path, {})
    surfaces: list[dict[str, Any]] = []
    for index, item in enumerate(data.get("apis", [])):
        state = item.get("validation", {}).get("state", "unverified")
        surfaces.append(
            finalize_surface(
                {
                    "kind": "api",
                    "method": item.get("method", "UNKNOWN"),
                    "url": item.get("url") or item.get("path"),
                    "fields": item.get("fields", []),
                    "validation_state": state,
                    "runtime_observed": state == "runtime-observed",
                    "profiles": ["spa", "rest"],
                    "source_refs": [source_ref(path, f"/apis/{index}")],
                    "evidence_refs": [
                        str(evidence.get("source"))
                        for evidence in item.get("evidence", [])
                        if evidence.get("source")
                    ],
                },
                target,
            )
        )
    for index, item in enumerate(data.get("routes", [])):
        state = item.get("validation", {}).get("state", "unverified")
        evidence = item.get("validation", {}).get("evidence", {})
        surfaces.append(
            finalize_surface(
                {
                    "kind": "route",
                    "method": "NAVIGATE",
                    "url": item.get("path", "/"),
                    "validation_state": state,
                    "runtime_observed": state == "runtime-visited",
                    "profiles": ["spa"],
                    "route_validation": item.get("validation", {}),
                    "route_navigation": item.get("navigation", "eligible"),
                    "route_parameter_names": item.get("parameterNames", []),
                    "route_parameter_state": item.get(
                        "parameterState", "not-required"
                    ),
                    "route_control_refs": evidence.get("controlRefs", []),
                    "route_runtime_api_refs": evidence.get(
                        "runtimeApiRefs", []
                    ),
                    "route_lazy_chunk_refs": evidence.get("lazyChunkRefs", []),
                    "source_refs": [source_ref(path, f"/routes/{index}")],
                },
                target,
            )
        )
    for index, item in enumerate(data.get("features", [])):
        routes = item.get("routes", [])
        feature_url = item.get("page") or (routes[0] if routes else "/")
        fields = [
            item.get("permission"),
            item.get("name"),
            item.get("type"),
        ]
        surfaces.append(
            finalize_surface(
                {
                    "kind": "feature",
                    "method": "OBSERVE",
                    "url": feature_url,
                    "semantic_key": item.get("id")
                    or item.get("name")
                    or f"feature-{index}",
                    "fields": [field for field in fields if field],
                    "validation_state": "recognized",
                    "runtime_observed": item.get("type") == "ui-control",
                    "profiles": ["spa"],
                    "feature_type": item.get("type"),
                    "control": item.get("control", {}),
                    "control_exercise_state": item.get("control", {}).get(
                        "exerciseState"
                    ),
                    "route_refs": routes or ([item["page"]] if item.get("page") else []),
                    "source_refs": [source_ref(path, f"/features/{index}")],
                    "evidence_refs": [
                        str(evidence.get("source"))
                        for evidence in item.get("evidence", [])
                        if evidence.get("source")
                    ],
                },
                target,
            )
        )
    blockers = [str(item) for item in data.get("completionBlockers", [])]
    return surfaces, blockers


def load_har(path: Path, target: str) -> tuple[list[dict[str, Any]], list[str]]:
    data = read_json(path, {})
    entries = data.get("log", {}).get("entries", [])
    surfaces = []
    for index, entry in enumerate(entries):
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = request.get("url")
        if not url:
            continue
        fields = [
            parameter.get("name")
            for parameter in request.get("queryString", [])
            if parameter.get("name")
        ]
        post_data = request.get("postData", {})
        fields.extend(
            parameter.get("name")
            for parameter in post_data.get("params", [])
            if parameter.get("name")
        )
        parsed = urlsplit(url)
        mime_type = str(response.get("content", {}).get("mimeType") or "")
        profiles = ["rest"]
        if parsed.scheme in {"ws", "wss"} or mime_type == "text/event-stream":
            profiles.append("websocket-sse")
        if "xml" in mime_type or "soap" in url.casefold():
            profiles.append("soap-xml")
        surfaces.append(
            finalize_surface(
                {
                    "kind": "api",
                    "method": request.get("method", "UNKNOWN"),
                    "url": url,
                    "fields": fields,
                    "validation_state": "runtime-observed",
                    "runtime_observed": True,
                    "profiles": profiles,
                    "source_refs": [source_ref(path, f"/log/entries/{index}")],
                    "http_status": response.get("status"),
                    "content_type": mime_type or None,
                },
                target,
            )
        )
    return surfaces, []


def openapi_servers(data: dict[str, Any], target: str) -> list[str]:
    values = [
        server.get("url")
        for server in data.get("servers", [])
        if isinstance(server, dict) and server.get("url")
    ]
    return values or [origin(target)]


def load_openapi(path: Path, target: str) -> tuple[list[dict[str, Any]], list[str]]:
    data = read_json(path, {})
    surfaces = []
    methods = {
        "get",
        "head",
        "options",
        "post",
        "put",
        "patch",
        "delete",
        "trace",
    }
    for server in openapi_servers(data, target):
        for route, path_item in data.get("paths", {}).items():
            if not isinstance(path_item, dict):
                continue
            common_parameters = path_item.get("parameters", [])
            for method, operation in path_item.items():
                if method.lower() not in methods or not isinstance(operation, dict):
                    continue
                parameters = [*common_parameters, *operation.get("parameters", [])]
                fields = [
                    parameter.get("name")
                    for parameter in parameters
                    if isinstance(parameter, dict) and parameter.get("name")
                ]
                profiles = ["openapi", "rest"]
                if "graphql" in route.casefold():
                    profiles.append("graphql")
                surfaces.append(
                    finalize_surface(
                        {
                            "kind": "api",
                            "method": method,
                            "url": urljoin(server.rstrip("/") + "/", route.lstrip("/")),
                            "fields": fields,
                            "validation_state": "documented",
                            "runtime_observed": False,
                            "profiles": profiles,
                            "operation_id": operation.get("operationId"),
                            "tags": operation.get("tags", []),
                            "source_refs": [
                                source_ref(
                                    path,
                                    f"/paths/{route}/{method.lower()}",
                                )
                            ],
                        },
                        target,
                    )
                )
    return surfaces, []


def graphql_schema(data: dict[str, Any]) -> dict[str, Any] | None:
    if "__schema" in data:
        return data["__schema"]
    if isinstance(data.get("data"), dict):
        return data["data"].get("__schema")
    return None


def load_graphql(path: Path, target: str) -> tuple[list[dict[str, Any]], list[str]]:
    text = path.read_text(encoding="utf-8")
    surfaces = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None
    if isinstance(data, dict) and graphql_schema(data):
        schema = graphql_schema(data) or {}
        types = {
            item.get("name"): item
            for item in schema.get("types", [])
            if isinstance(item, dict) and item.get("name")
        }
        roots = (
            ("queryType", "query"),
            ("mutationType", "mutation"),
            ("subscriptionType", "subscription"),
        )
        for root_key, operation_kind in roots:
            root_name = (schema.get(root_key) or {}).get("name")
            root = types.get(root_name, {})
            for index, field in enumerate(root.get("fields", []) or []):
                field_name = field.get("name")
                if not field_name:
                    continue
                surfaces.append(
                    finalize_surface(
                        {
                            "kind": "graphql-operation",
                            "method": "POST",
                            "url": f"{origin(target)}/graphql",
                            "fields": [
                                arg.get("name")
                                for arg in field.get("args", [])
                                if arg.get("name")
                            ],
                            "validation_state": "documented",
                            "profiles": ["graphql"],
                            "operation_kind": operation_kind,
                            "operation_name": field_name,
                            "source_refs": [
                                source_ref(
                                    path,
                                    f"/__schema/{operation_kind}/{index}",
                                )
                            ],
                        },
                        target,
                    )
                )
    else:
        for operation_kind, body in re.findall(
            r"\b(type\s+(?:Query|Mutation|Subscription))\s*\{([^}]*)\}",
            text,
            re.IGNORECASE | re.DOTALL,
        ):
            kind = operation_kind.split()[-1].casefold()
            for field_name in re.findall(r"^\s*([A-Za-z_]\w*)\s*(?:\(|:)", body, re.M):
                surfaces.append(
                    finalize_surface(
                        {
                            "kind": "graphql-operation",
                            "method": "POST",
                            "url": f"{origin(target)}/graphql",
                            "validation_state": "documented",
                            "profiles": ["graphql"],
                            "operation_kind": kind,
                            "operation_name": field_name,
                            "source_refs": [str(path.resolve())],
                        },
                        target,
                    )
                )
    blockers = [] if surfaces else ["GraphQL schema contained no root operations"]
    return surfaces, blockers


def generic_entries(data: Any) -> Iterable[dict[str, Any]]:
    if isinstance(data, list):
        yield from (item for item in data if isinstance(item, dict))
        return
    if not isinstance(data, dict):
        return
    for key in ("surfaces", "entries", "findings", "matches", "items"):
        if isinstance(data.get(key), list):
            yield from (
                item for item in data[key] if isinstance(item, dict)
            )
            return
    yield data


def load_generic(
    path: Path,
    target: str,
    kind: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    data = read_json(path, [])
    surfaces = []
    for index, item in enumerate(generic_entries(data)):
        raw_url = item.get("url") or item.get("path") or item.get("endpoint")
        if not raw_url:
            continue
        profiles = item.get("profiles", [])
        if kind == "history":
            profiles = [*profiles, "historical"]
        surfaces.append(
            finalize_surface(
                {
                    **item,
                    "url": raw_url,
                    "kind": item.get("kind", "api"),
                    "method": item.get("method", "UNKNOWN"),
                    "validation_state": (
                        "historical"
                        if kind == "history"
                        else item.get("validation_state", "unverified")
                    ),
                    "runtime_observed": bool(item.get("runtime_observed", False)),
                    "profiles": profiles,
                    "source_refs": [source_ref(path, f"/{index}")],
                },
                target,
            )
        )
    return surfaces, []


LOADERS = {
    "spa": load_spa,
    "har": load_har,
    "openapi": load_openapi,
    "graphql": load_graphql,
    "history": lambda path, target: load_generic(path, target, "history"),
    "manual": lambda path, target: load_generic(path, target, "manual"),
}


def merge_surface(existing: dict[str, Any], incoming: dict[str, Any]) -> None:
    state_rank = {
        "rejected": 0,
        "blocked": 1,
        "unverified": 1,
        "historical": 2,
        "documented": 3,
        "recognized": 4,
        "reachable": 5,
        "runtime-observed": 6,
        "runtime-visited": 7,
    }
    incoming_stronger = state_rank.get(
        incoming["validation_state"], 1
    ) > state_rank.get(existing["validation_state"], 1)
    if incoming_stronger:
        existing["validation_state"] = incoming["validation_state"]
        if incoming.get("route_validation"):
            existing["route_validation"] = incoming["route_validation"]
    existing["runtime_observed"] = bool(
        existing.get("runtime_observed") or incoming.get("runtime_observed")
    )
    for key in ("fields", "profiles", "source_refs", "evidence_refs"):
        existing[key] = sorted(
            {
                *[str(item) for item in existing.get(key, [])],
                *[str(item) for item in incoming.get(key, [])],
            }
        )
    for key in (
        "route_control_refs",
        "route_runtime_api_refs",
        "route_lazy_chunk_refs",
    ):
        if key in existing or key in incoming:
            existing[key] = sorted(
                {
                    *[str(item) for item in existing.get(key, [])],
                    *[str(item) for item in incoming.get(key, [])],
                }
            )
    for key, value in incoming.items():
        if key not in existing or existing[key] in (None, "", [], {}):
            existing[key] = value
    existing["fingerprint"] = surface_fingerprint(existing)


def lifecycle_for(surface: dict[str, Any]) -> str:
    method = surface.get("method", "UNKNOWN")
    if method == "NAVIGATE":
        return "navigate"
    text = " ".join(
        [
            surface.get("path_template", ""),
            str(surface.get("operation_id", "")),
            str(surface.get("operation_name", "")),
        ]
    )
    tokens = re.findall(r"[A-Za-z]+", text)
    for token in reversed(tokens):
        lower = token.casefold()
        for word, lifecycle in LIFECYCLE_WORDS.items():
            if word in lower:
                return lifecycle
    if method in {"GET", "HEAD", "OPTIONS"}:
        return "read"
    if method == "DELETE":
        return "delete"
    if method in {"PUT", "PATCH"}:
        return "update"
    if method == "POST":
        return "write"
    return "unknown"


def controller_for(surface: dict[str, Any]) -> str:
    if surface["kind"] == "graphql-operation":
        return "graphql"
    segments = [
        segment
        for segment in surface["path_template"].strip("/").split("/")
        if segment
        and segment not in {"api", "rest"}
        and not VERSION_SEGMENT.fullmatch(segment)
        and segment != "{id}"
    ]
    if surface["kind"] == "route":
        generic = {"app", "apps", "app_pages", "page", "pages", "ui", "views"}
        route_segments = [segment for segment in segments if segment not in generic]
        if route_segments:
            return "/".join(route_segments[:2])
        return segments[0] if segments else "root"
    controller_segments = segments[:3]
    if len(controller_segments) == 3 and re.match(
        r"^(?:get|list|page|query|search|find|read|detail|download|export|"
        r"create|add|save|update|edit|delete|remove|enable|disable|approve|"
        r"publish|upload|import|execute|start|stop|renew|continue|open)",
        controller_segments[-1],
        re.IGNORECASE,
    ):
        controller_segments = controller_segments[:2]
    return "/".join(controller_segments) if controller_segments else "root"


def infer_profiles(surfaces: list[dict[str, Any]]) -> set[str]:
    profiles = {"rest"}
    for surface in surfaces:
        profiles.update(surface.get("profiles", []))
        text = f"{surface.get('url', '')} {' '.join(surface.get('fields', []))}"
        if surface.get("protocol") in {"ws", "wss"}:
            profiles.add("websocket-sse")
        if "graphql" in text.casefold():
            profiles.add("graphql")
        if re.search(r"\b(?:oauth|oidc|sso)\b", text, re.I):
            profiles.add("oauth-oidc")
        if FILE_WORDS.search(text):
            profiles.add("file-processing")
        if SERVER_FETCH_WORDS.search(text):
            profiles.add("external-api-integration")
    return profiles


def risk_factors(surfaces: list[dict[str, Any]]) -> dict[str, int]:
    text = " ".join(
        [
            surface.get("url", "")
            + " "
            + " ".join(surface.get("fields", []))
            for surface in surfaces
        ]
    )
    methods = {surface.get("method") for surface in surfaces}
    semantic_write = any(
        lifecycle_for(surface) in MUTATING_LIFECYCLES
        for surface in surfaces
    )
    states = {surface.get("validation_state") for surface in surfaces}
    business_impact = max(
        [int(surface.get("risk_factors", {}).get("business_impact", 2)) for surface in surfaces]
        or [2]
    )
    reachability = (
        3
        if states & {"runtime-observed", "reachable"}
        else 2
        if states & {"recognized", "documented"}
        else 1
    )
    privilege_data_transition = (
        4
        if SENSITIVE_WORDS.search(text)
        else 3
        if semantic_write
        else 2
    )
    history_runtime_signal = (
        3
        if "historical" in states
        or any(surface.get("runtime_observed") for surface in surfaces)
        else 1
    )
    chainability = (
        3
        if AUTH_WORDS.search(text)
        or FILE_WORDS.search(text)
        or SERVER_FETCH_WORDS.search(text)
        else 2
        if semantic_write
        else 1
    )
    unknown_coverage_debt = (
        3
        if "blocked" in states
        else 2
        if states & {"unverified"} or "UNKNOWN" in methods
        else 1
    )
    return {
        "business_impact": min(4, max(0, business_impact)),
        "reachability": reachability,
        "privilege_data_transition": privilege_data_transition,
        "history_runtime_signal": history_runtime_signal,
        "chainability": chainability,
        "unknown_coverage_debt": unknown_coverage_debt,
    }


def priority(score: int) -> str:
    if score >= 16:
        return "P0"
    if score >= 11:
        return "P1"
    if score >= 6:
        return "P2"
    return "P3"


def score_for_priority(value: str | None) -> int:
    return {"P0": 18, "P1": 13, "P2": 8, "P3": 3}.get(str(value), 8)


def priority_signals(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    signals: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        if event.get("type") != "priority-signal":
            continue
        signals.setdefault(str(event["target_id"]), []).append(event)
    return signals


def apply_dynamic_priorities(
    plan: dict[str, Any], coverage: dict[str, Any], events: list[dict[str, Any]]
) -> None:
    """Derive scheduling priority from validated evidence without changing severity."""
    signals = priority_signals(events)
    candidates = {str(item.get("id")): item for item in coverage.get("candidates", [])}
    candidate_surfaces: dict[str, int] = {}
    for candidate in candidates.values():
        base = {"critical": 18, "high": 14, "medium": 9, "low": 4}.get(
            str(candidate.get("investigation_priority") or "medium"), 9
        )
        factors = []
        for signal in signals.get(str(candidate.get("id")), []):
            factors.append(
                {
                    "factor": signal["factor"],
                    "points": PRIORITY_SIGNAL_POINTS[str(signal["factor"])],
                    "reason": signal["reason"],
                    "evidence_refs": list(signal["evidence_refs"]),
                    "recorded_at": signal.get("recorded_at"),
                }
            )
        dynamic = min(20, max(0, base + sum(int(item["points"]) for item in factors)))
        candidate.update(
            {
                "base_score": base,
                "base_priority": priority(base),
                "dynamic_score": dynamic,
                "current_priority": priority(dynamic),
                "priority_factors": factors,
                "priority_revision": stable_id("priority", {"id": candidate.get("id"), "base": base, "factors": factors}),
            }
        )
        pending = candidate_dependency_gaps(candidate)
        boost = 3 if pending and len(pending) == 1 else 0
        if candidate.get("investigation_priority") in {"critical", "high"}:
            boost += 2
        for surface in candidate.get("surface_refs", []):
            candidate_surfaces[str(surface)] = max(candidate_surfaces.get(str(surface), 0), boost)

    cells = {str(item["id"]): item for item in plan.get("test_cells", [])}
    for cell in cells.values():
        base = int(
            cell.get(
                "base_score",
                cell.get("risk_score", score_for_priority(cell.get("priority"))),
            )
        )
        factors = []
        for signal in signals.get(str(cell["id"]), []):
            points = PRIORITY_SIGNAL_POINTS[str(signal["factor"])]
            factors.append(
                {
                    "factor": signal["factor"],
                    "points": points,
                    "reason": signal["reason"],
                    "evidence_refs": list(signal["evidence_refs"]),
                    "recorded_at": signal.get("recorded_at"),
                }
            )
        dynamic = min(20, max(0, base + sum(int(item["points"]) for item in factors)))
        cell.update(
            {
                "base_score": base,
                "base_priority": priority(base),
                "dynamic_score": dynamic,
                "current_priority": priority(dynamic),
                "priority": priority(dynamic),
                "priority_factors": factors,
                "priority_revision": stable_id("priority", {"id": cell["id"], "base": base, "factors": factors}),
                "last_prioritized_at": max((str(item.get("recorded_at") or "") for item in factors), default=plan.get("generated_at")),
            }
        )

    preemptions: dict[str, int] = {}
    for event in events:
        if event.get("type") == "queue-preemption" and event.get("deferred_id"):
            key = str(event["deferred_id"])
            preemptions[key] = preemptions.get(key, 0) + 1
    for case in plan.get("executable_cases", []):
        cell = cells.get(str(case.get("test_cell_id")), {})
        base = int(
            case.get(
                "base_score",
                cell.get(
                    "base_score",
                    case.get("risk_score", score_for_priority(case.get("priority"))),
                ),
            )
        )
        factors = [*cell.get("priority_factors", [])]
        for signal in signals.get(str(case["id"]), []):
            factors.append(
                {
                    "factor": signal["factor"],
                    "points": PRIORITY_SIGNAL_POINTS[str(signal["factor"])],
                    "reason": signal["reason"],
                    "evidence_refs": list(signal["evidence_refs"]),
                    "recorded_at": signal.get("recorded_at"),
                }
            )
        surface_boost = candidate_surfaces.get(str(case.get("surface_ref")), 0)
        if surface_boost:
            factors.append({"factor": "candidate-chain-closure", "points": surface_boost, "reason": "an unresolved high-priority candidate on this surface is near closure", "evidence_refs": []})
        dynamic = min(20, max(0, base + sum(int(item["points"]) for item in factors)))
        case.update(
            {
                "base_score": base,
                "base_priority": priority(base),
                "dynamic_score": dynamic,
                "current_priority": priority(dynamic),
                "priority": priority(dynamic),
                "priority_factors": factors,
                "priority_revision": stable_id("priority", {"id": case["id"], "base": base, "factors": factors}),
                "defer_count": preemptions.get(str(case["id"]), 0),
                "queue_age": preemptions.get(str(case["id"]), 0),
                "next_validation_step": case.get("action") or case.get("description"),
            }
        )
        if surface_boost or any(item["factor"] == "prerequisite-near-closure" for item in factors):
            case["execution_lane"] = "chain-closure"


def scheduled_execution_queue(cases: list[dict[str, Any]]) -> list[str]:
    pending = [
        item for item in cases
        if item.get("status") in {"queued", "running", "mapped"}
        and item.get("safety") in ACTIONABLE_SAFETY
    ]
    chain = [item for item in pending if item.get("execution_lane") == "chain-closure"]
    fast = [item for item in pending if item.get("execution_lane") == "fast-find"]
    coverage = [item for item in pending if item.get("execution_lane") == "coverage-close"]
    key = lambda item: (-int(item.get("dynamic_score", 0)), -int(item.get("defer_count", 0)), str(item["id"]))
    chain.sort(key=key)
    fast.sort(key=key)
    coverage.sort(key=key)
    ordered = [*chain]
    high = [*fast]
    while high:
        ordered.extend(high[:STARVATION_INTERVAL])
        high = high[STARVATION_INTERVAL:]
        if coverage:
            ordered.append(coverage.pop(0))
    ordered.extend(coverage)
    return [str(item["id"]) for item in ordered]


def prioritize_prerequisites(
    graph: dict[str, Any], coverage: dict[str, Any], events: list[dict[str, Any]]
) -> None:
    signals = priority_signals(events)
    candidate_scores = {
        str(item.get("id")): int(item.get("dynamic_score", 9))
        for item in coverage.get("candidates", [])
    }
    for item in graph.get("prerequisites", []):
        base = candidate_scores.get(str(item.get("owner_id")), 9)
        factors = []
        for signal in signals.get(str(item.get("id")), []):
            factors.append(
                {
                    "factor": signal["factor"],
                    "points": PRIORITY_SIGNAL_POINTS[str(signal["factor"])],
                    "reason": signal["reason"],
                    "evidence_refs": list(signal["evidence_refs"]),
                    "recorded_at": signal.get("recorded_at"),
                }
            )
        dynamic = min(20, max(0, base + sum(int(value["points"]) for value in factors)))
        item.update(
            {
                "base_score": base,
                "base_priority": priority(base),
                "dynamic_score": dynamic,
                "current_priority": priority(dynamic),
                "priority_factors": factors,
                "priority_revision": stable_id("priority", {"id": item.get("id"), "base": base, "factors": factors}),
            }
        )


FAST_FIND_FAMILIES = {
    "identity-session.authentication",
    "identity-session.session-token",
    "identity-session.response-differential",
    "identity-session.message-delivery-abuse",
    "identity-session.token-claim-minimization",
    "identity-session.oauth-sso",
    "authorization.object-level",
    "authorization.identifier-provenance",
    "authorization.cross-protocol-parity",
    "authorization.function-level",
    "authorization.property-level",
    "authorization.tenant-parent-state",
    "authorization.workflow-state",
    "authorization.file-export",
    "injection.sql-nosql-orm",
    "injection.xml-ldap-xpath",
    "files-data-export.path-read-download",
    "files-data-export.upload-validation",
    "api-protocol.edge-backend-normalization",
    "api-protocol.graphql",
    "business-logic.lifecycle-integrity",
    "business-logic.cross-function-chain",
    "platform-exposure.debug-admin-docs",
    "platform-exposure.client-bootstrap-config",
    "platform-exposure.backup-default-cloud",
    "platform-exposure.error-exception-logging",
}


def execution_lane(case: dict[str, Any]) -> str:
    """Choose speed without allowing the fast lane to replace coverage closure."""
    if case.get("priority") in {"P0", "P1"}:
        return "fast-find"
    if case.get("authorization_mode") not in {None, "cross-principal-ownership"}:
        return "fast-find"
    if case.get("family") in FAST_FIND_FAMILIES:
        return "fast-find"
    return "coverage-close"


def decorate_case(case: dict[str, Any]) -> dict[str, Any]:
    case.setdefault("execution_lane", execution_lane(case))
    case.setdefault("knowledge_seed_refs", [])
    case.setdefault("tool_run_refs", [])
    return case


def apply_knowledge_seeds(
    coverage: dict[str, Any],
    cases: list[dict[str, Any]],
) -> dict[str, Any]:
    """Route local knowledge into testing without treating it as evidence."""
    catalog = knowledge_runtime.load_catalog()
    by_family: dict[str, list[str]] = {}
    for item in catalog.get("local_hypotheses", []):
        family = str(item.get("family") or "")
        if family:
            by_family.setdefault(family, []).append(str(item.get("id")))
    for case in cases:
        refs = sorted(by_family.get(str(case.get("family") or ""), []))[:25]
        case["knowledge_seed_refs"] = refs
        if refs and case.get("execution_lane") == "coverage-close":
            case["execution_lane"] = "fast-find"
    target_matches = coverage.get("history", {}).get("matches", [])
    coverage["knowledge_seeds"] = {
        "formal_patterns": len(catalog.get("formal_patterns", [])),
        "local_hypotheses": len(catalog.get("local_hypotheses", [])),
        "actionable_local_hypotheses": sum(
            bool(item.get("family"))
            for item in catalog.get("local_hypotheses", [])
        ),
        "target_history": len(target_matches),
        "last_refresh_state": "catalog-loaded",
        "source_ledger_sha256": catalog.get("source", {}).get("ledger_sha256"),
        "finding_policy": catalog.get("finding_policy"),
    }
    return catalog


def safety_for(surfaces: list[dict[str, Any]]) -> tuple[str, str]:
    explicit = {
        surface.get("safety")
        for surface in surfaces
        if surface.get("safety")
    }
    if explicit:
        safety_rank = {
            "passive": 0,
            "read-only": 1,
            "reversible": 2,
            "blocked": 3,
        }
        chosen = max(explicit, key=lambda item: safety_rank[str(item)])
        return str(chosen), "explicit-surface-classification"
    methods = {surface.get("method", "UNKNOWN") for surface in surfaces}
    text = " ".join(surface.get("url", "") for surface in surfaces)
    dispositions = {surface.get("scope_disposition") for surface in surfaces}
    if dispositions & {
        "cross-site-related-passive",
        "same-site-related-passive",
    }:
        return "passive", "related-surface-not-active-by-default"
    if methods <= {"NAVIGATE", "OBSERVE"}:
        return "passive", "route-or-feature-inventory"
    if methods <= SAFE_METHODS and not SIDE_EFFECT_WORDS.search(text):
        return "read-only", "safe-method-without-side-effect-signal"
    if (
        methods <= (SAFE_METHODS | {"POST"})
        and "POST" in methods
        and not SIDE_EFFECT_WORDS.search(text)
        and all(
            surface.get("method") != "POST"
            or (
                lifecycle_for(surface) in {"read", "read-list", "read-detail"}
                and (
                    surface.get("runtime_observed")
                    or surface.get("validation_state")
                    in {"runtime-observed", "reachable", "documented"}
                )
            )
            for surface in surfaces
        )
    ):
        return "read-only", "evidence-backed-semantic-read-post"
    return "blocked", "write-or-side-effect-requires-owned-reversible-context"


def all_family_specs(coverage: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        family
        for domain in coverage["coverage"]
        for family in domain.get("families", [])
    ]


def applicable_families(
    surfaces: list[dict[str, Any]],
    coverage: dict[str, Any],
    baseline: bool = False,
) -> list[str]:
    families = {family["id"] for family in all_family_specs(coverage)}
    if baseline:
        return sorted(families)
    selected: set[str] = set()
    text = " ".join(
        surface.get("url", "") + " " + " ".join(surface.get("fields", []))
        for surface in surfaces
    )
    profiles = infer_profiles(surfaces)
    methods = {surface.get("method") for surface in surfaces}
    kinds = {surface.get("kind") for surface in surfaces}
    lifecycles = {lifecycle_for(surface) for surface in surfaces}
    semantic_write = bool(lifecycles & MUTATING_LIFECYCLES)
    fields = {
        str(field)
        for surface in surfaces
        for field in surface.get("fields", [])
        if field
    }
    route_parameters = {
        str(parameter)
        for surface in surfaces
        for parameter in (
            surface.get("route_parameter_names", [])
            or re.findall(
                r":([A-Za-z_$][\w$]*)", surface.get("path_template", "")
            )
        )
        if parameter
    }
    api_like = bool(kinds & {"api", "graphql-operation"})
    if api_like:
        selected.update(
            {
                "authorization.function-level",
                "api-protocol.method-content-type",
                "platform-exposure.headers-cache-cors",
                "platform-exposure.error-exception-logging",
            }
        )
        if fields or lifecycles & {
            "read-detail",
            "update",
            "delete",
            "approve",
            "publish",
            "download",
            "export",
        }:
            selected.add("authorization.object-level")
        if route_parameters or IDENTIFIER_WORDS.search(text):
            selected.add("authorization.identifier-provenance")
        if fields or semantic_write:
            selected.update(
                {
                    "authorization.property-level",
                    "injection.sql-nosql-orm",
                    "api-protocol.parameter-encoding",
                }
            )
        if TENANT_WORDS.search(text):
            selected.add("authorization.tenant-parent-state")
        if re.search(r"(?:/v\d+|batch|bulk|legacy|internal|shadow)", text, re.I):
            selected.add("api-protocol.version-batch-shadow")
        if semantic_write and re.search(
            r"(?:[-.;%]|%2f|%5c|%2e)", " ".join(
                surface.get("path_template", "") for surface in surfaces
            ), re.I
        ):
            selected.add("api-protocol.edge-backend-normalization")
    if kinds & {"route", "feature"}:
        selected.update(
            {
                "authorization.function-level",
                "authorization.workflow-state",
                "browser-content.xss-dom-richtext",
                "browser-content.redirect-scheme",
                "browser-content.postmessage-framing",
                "browser-content.storage-cache",
            }
        )
        if route_parameters:
            selected.update(
                {
                    "authorization.object-level",
                    "authorization.tenant-parent-state",
                    "api-protocol.parameter-encoding",
                }
            )
    elif re.search(
        r"(?:html|markdown|richtext|description|message|template|title|content)",
        text,
        re.I,
    ):
        selected.update(
            {
                "browser-content.xss-dom-richtext",
                "browser-content.redirect-scheme",
            }
        )
    if semantic_write:
        selected.update(
            {
                "authorization.workflow-state",
                "injection.prototype-mass-assignment",
                "business-logic.lifecycle-integrity",
                "business-logic.replay-idempotency",
                "business-logic.race-concurrency",
            }
        )
    if AUTH_WORDS.search(text) or "oauth-oidc" in profiles:
        selected.update(
            {
                "identity-session.authentication",
                "identity-session.recovery-mfa",
                "identity-session.session-token",
                "identity-session.oauth-sso",
                "identity-session.cross-origin-csrf",
            }
        )
    if ABUSE_WORDS.search(text):
        selected.add("identity-session.response-differential")
        if re.search(r"(?:sms|otp|captcha|verify|send|resend|recover|reset)", text, re.I):
            selected.add("identity-session.message-delivery-abuse")
    if TOKEN_CLAIM_WORDS.search(text):
        selected.add("identity-session.token-claim-minimization")
    if CLIENT_CONFIG_WORDS.search(text):
        selected.add("platform-exposure.client-bootstrap-config")
    if QUOTA_WORDS.search(text):
        selected.add("business-logic.quota-resource-abuse")
    if re.search(r"(?:approve|audit|invite|share|publish)", text, re.I):
        selected.add("business-logic.approval-invite-share")
    if FILE_WORDS.search(text) or "file-processing" in profiles:
        selected.add("files-data-export.storage-exposure")
        if lifecycles & {"read", "read-list", "read-detail", "download", "export"}:
            selected.update(
                {
                    "authorization.file-export",
                    "files-data-export.path-read-download",
                }
            )
        if lifecycles & {"upload", "import", "create", "write"} and re.search(
            r"(?:upload|import|multipart|attachment|archive|zip|tar|package)",
            text,
            re.I,
        ):
            selected.add("files-data-export.upload-validation")
        if re.search(r"(?:archive|extract|unpack|zip|tar|7z|rar)", text, re.I):
            selected.add("files-data-export.archive-extraction")
        if re.search(
            r"(?:csv|excel|spreadsheet|formula|export|import)",
            text,
            re.I,
        ):
            selected.update(
                {
                    "authorization.file-export",
                    "files-data-export.import-export-formula",
                }
            )
    if SERVER_FETCH_WORDS.search(text) or "external-api-integration" in profiles:
        selected.update(
            family
            for family in families
            if family.startswith("server-side-processing.")
        )
    if "graphql" in profiles:
        selected.add("api-protocol.graphql")
    if "websocket-sse" in profiles:
        selected.update(
            {
                "api-protocol.websocket-sse-soap",
                "authorization.cross-protocol-parity",
            }
        )
    if re.search(r"(?:xml|soap)", text, re.I):
        selected.update(
            {
                "injection.xml-ldap-xpath",
                "server-side-processing.xxe-parser",
                "api-protocol.websocket-sse-soap",
            }
        )
    return sorted(selected & families)


def semantic_tokens(value: str) -> set[str]:
    expanded = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    return {
        token.casefold()
        for token in re.findall(r"[A-Za-z][A-Za-z0-9]{2,}", expanded)
        if token.casefold() not in CHAIN_STOP_WORDS
    }


def chain_role(lifecycle: str) -> str | None:
    if lifecycle in {"upload", "import", "create"}:
        return "producer"
    if lifecycle in {"update", "approve", "publish"}:
        return "activator"
    if lifecycle in {"read", "read-list", "read-detail", "download", "export"}:
        return "consumer"
    if lifecycle == "delete":
        return "cleanup"
    return None


def annotate_chain_links(
    units: list[dict[str, Any]],
    surfaces: list[dict[str, Any]],
) -> None:
    surface_by_id = {surface["id"]: surface for surface in surfaces}
    descriptors: dict[str, dict[str, Any]] = {}
    for unit in units:
        role = chain_role(unit["lifecycle"])
        values = [
            surface_by_id[ref]
            for ref in unit["surface_refs"]
            if ref in surface_by_id
        ]
        path_tokens = {
            token
            for surface in values
            for token in semantic_tokens(str(surface.get("path_template", "")))
        }
        field_names = {
            re.sub(r"[^a-z0-9]", "", str(field).casefold())
            for surface in values
            for field in surface.get("fields", [])
            if field
        }
        field_names -= CHAIN_GENERIC_FIELDS
        field_tokens = {
            token
            for surface in values
            for field in surface.get("fields", [])
            for token in semantic_tokens(str(field))
        }
        unit["chain_roles"] = [role] if role else []
        unit["chain_links"] = []
        descriptors[unit["id"]] = {
            "role": role,
            "path_tokens": path_tokens,
            "field_names": field_names,
            "field_tokens": field_tokens,
        }
    for index, left in enumerate(units):
        left_descriptor = descriptors[left["id"]]
        if not left_descriptor["role"]:
            continue
        for right in units[index + 1 :]:
            right_descriptor = descriptors[right["id"]]
            if (
                not right_descriptor["role"]
                or left_descriptor["role"] == right_descriptor["role"]
                or left["origin"] != right["origin"]
            ):
                continue
            shared_fields = (
                left_descriptor["field_names"]
                & right_descriptor["field_names"]
            )
            same_controller = left["controller"] == right["controller"]
            shared_path_tokens = (
                left_descriptor["path_tokens"]
                & right_descriptor["path_tokens"]
            )
            if same_controller:
                shared_path_tokens -= semantic_tokens(left["controller"])
            shared_tokens = (
                left_descriptor["field_tokens"]
                & right_descriptor["field_tokens"]
                if shared_fields
                else shared_path_tokens
            )
            significant = shared_tokens & CHAIN_SIGNIFICANT_WORDS
            if same_controller and not shared_fields and not shared_path_tokens:
                continue
            if not same_controller and (
                not shared_fields or not significant
            ):
                continue
            reason = (
                "shared-transfer-field"
                if shared_fields
                else "same-controller-lifecycle"
            )
            for source, target in ((left, right), (right, left)):
                source["chain_links"].append(
                    {
                        "work_unit_id": target["id"],
                        "source_role": descriptors[source["id"]]["role"],
                        "target_role": descriptors[target["id"]]["role"],
                        "shared_semantics": sorted(
                            significant or shared_tokens
                        ),
                        "shared_fields": sorted(shared_fields),
                        "reason": reason,
                    }
                )
                source["applicable_families"] = sorted(
                    {
                        *source["applicable_families"],
                        "business-logic.cross-function-chain",
                    }
                )
    for unit in units:
        unit["chain_links"] = sorted(
            unit["chain_links"],
            key=lambda item: (
                item["work_unit_id"],
                item["source_role"],
                item["target_role"],
            ),
        )


def build_work_units(
    surfaces: list[dict[str, Any]],
    coverage: dict[str, Any],
) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for surface in surfaces:
        if surface.get("validation_state") == "rejected":
            continue
        parsed = urlsplit(surface["url"])
        key = (
            surface["kind"],
            parsed.netloc,
            controller_for(surface),
            lifecycle_for(surface),
        )
        groups.setdefault(key, []).append(surface)
    units = []
    for key, items in groups.items():
        factors = risk_factors(items)
        score = sum(factors.values())
        safety, safety_reason = safety_for(items)
        unit_id = stable_id("unit", key)
        units.append(
            {
                "id": unit_id,
                "kind": key[0],
                "origin": f"{urlsplit(items[0]['url']).scheme}://{key[1]}",
                "controller": key[2],
                "lifecycle": key[3],
                "surface_refs": sorted(item["id"] for item in items),
                "surface_count": len(items),
                "fingerprint": stable_id(
                    "unit-fp",
                    sorted(item["fingerprint"] for item in items),
                ),
                "profiles": sorted(infer_profiles(items)),
                "applicable_families": applicable_families(items, coverage),
                "risk": {
                    "score": score,
                    "priority": priority(score),
                    "factors": factors,
                },
                "safety": {
                    "class": safety,
                    "reason": safety_reason,
                    "auto_actionable": safety in ACTIONABLE_SAFETY,
                },
                "trust_boundaries": sorted(
                    {
                        item["scope_disposition"]
                        for item in items
                        if item.get("scope_disposition")
                    }
                ),
            }
        )
    annotate_chain_links(units, surfaces)
    baseline_key = ("application-baseline", normalized_target(coverage["target"]))
    baseline_id = stable_id("unit", baseline_key)
    units.append(
        {
            "id": baseline_id,
            "kind": "application-baseline",
            "origin": origin(coverage["target"]),
            "controller": "application",
            "lifecycle": "baseline",
            "surface_refs": [],
            "surface_count": 0,
            "fingerprint": stable_id(
                "unit-fp",
                sorted(item["fingerprint"] for item in surfaces),
            ),
            "profiles": sorted(infer_profiles(surfaces)),
            "applicable_families": applicable_families(
                surfaces,
                coverage,
                baseline=True,
            ),
            "risk": {
                "score": 10,
                "priority": "P2",
                "factors": {
                    "business_impact": 2,
                    "reachability": 2,
                    "privilege_data_transition": 2,
                    "history_runtime_signal": 1,
                    "chainability": 1,
                    "unknown_coverage_debt": 2,
                },
            },
            "safety": {
                "class": "read-only",
                "reason": "application-wide-control-baseline",
                "auto_actionable": True,
            },
            "trust_boundaries": ["application-wide"],
            "chain_roles": [],
            "chain_links": [],
        }
    )
    return sorted(
        units,
        key=lambda unit: (
            int(unit["risk"]["priority"][1]),
            -unit["risk"]["score"],
            unit["id"],
        ),
    )


def observed_identity_ids(coverage: dict[str, Any]) -> list[str]:
    identities = coverage.get("dimensions", {}).get("identities", [])
    return [
        item["id"]
        for item in identities
        if item.get("status") in {"available", "observed"}
    ]


def effective_authorization_capabilities(
    coverage: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    dimensions = coverage.setdefault("dimensions", {})
    configured = {
        item["id"]: item
        for item in dimensions.get("authorization_capabilities", [])
        if item.get("id") in AUTHORIZATION_MODES
        and item.get("source") != "derived"
    }
    identities = observed_identity_ids(coverage)
    authenticated = [identity for identity in identities if identity != "anonymous"]
    defaults = {
        "anonymous-boundary": (
            "available" if authenticated and "anonymous" in identities else "conditional"
        ),
        "low-privilege-function": (
            "available" if authenticated else "conditional"
        ),
        "implicit-subject-binding": (
            "available" if authenticated else "conditional"
        ),
        "self-owned-object": "conditional",
        "cross-principal-ownership": "unavailable",
        "tenant-parent-binding": "conditional",
        "protected-property": "conditional",
        "workflow-precondition": (
            "available" if authenticated else "conditional"
        ),
        "state-transition": "conditional",
    }
    result: dict[str, dict[str, Any]] = {}
    for mode in sorted(AUTHORIZATION_MODES):
        default_status = defaults[mode]
        result[mode] = {
            "id": mode,
            "status": default_status,
            "reason": (
                "derived-from-available-identities"
                if default_status == "available"
                else "requires-current-task-context"
                if default_status == "conditional"
                else "second-principal-not-available"
            ),
            "evidence_refs": [],
            "source": "derived",
        }
        if mode in configured:
            result[mode] = configured[mode]
    dimensions["authorization_capabilities"] = sorted(
        result.values(), key=lambda item: item["id"]
    )
    return result


def authorization_dimensions(
    family: str,
    coverage: dict[str, Any],
) -> list[dict[str, str]]:
    identities = observed_identity_ids(coverage)
    authenticated = [
        identity for identity in identities if identity != "anonymous"
    ] or ["authenticated"]
    known_states = coverage.get("dimensions", {}).get("business_states", [])
    states = [
        item["id"]
        for item in known_states
        if item.get("status") in {"available", "observed"}
    ] or ["any"]
    result = []
    for mode in AUTHORIZATION_MODES_BY_FAMILY.get(family, ()):
        if mode == "anonymous-boundary":
            mode_identities = ["anonymous-vs-authenticated"]
        elif mode == "cross-principal-ownership":
            mode_identities = ["cross-principal"]
        else:
            mode_identities = authenticated
        for identity in mode_identities:
            for state in states:
                result.append(
                    {
                        "identity": identity,
                        "business_state": state,
                        "authorization_mode": mode,
                    }
                )
    return result


def cell_dimensions(
    family: str,
    coverage: dict[str, Any],
) -> list[dict[str, str]]:
    if family in AUTHORIZATION_MODES_BY_FAMILY:
        return authorization_dimensions(family, coverage)
    observed = observed_identity_ids(coverage)
    if not observed:
        observed = ["anonymous"]
    states = ["any"]
    if family.startswith(("authorization.", "business-logic.")):
        known_states = coverage.get("dimensions", {}).get("business_states", [])
        observed_states = [
            item["id"]
            for item in known_states
            if item.get("status") in {"available", "observed"}
        ]
        if observed_states:
            states = observed_states
    return [
        {"identity": identity, "business_state": state}
        for identity in observed
        for state in states
    ]


def execution_requirements(
    family: str,
    dimensions: dict[str, str],
) -> dict[str, Any]:
    mode = dimensions.get("authorization_mode")
    if not mode:
        return {
            "request_shape": False,
            "object_context": "none",
            "cleanup_required": False,
        }
    object_context = {
        "self-owned-object": "self-owned",
        "protected-property": "self-owned",
        "state-transition": "self-owned",
        "cross-principal-ownership": "cross-principal",
        "tenant-parent-binding": "current-or-nonexistent-parent",
        "implicit-subject-binding": "current-or-nonexistent-subject",
        "workflow-precondition": "current-business-state",
    }.get(mode, "none")
    return {
        "authorization_capability": mode,
        "identities": (
            ["anonymous", "authenticated"]
            if mode == "anonymous-boundary"
            else ["cross-principal-a", "cross-principal-b"]
            if mode == "cross-principal-ownership"
            else [dimensions.get("identity", "authenticated")]
        ),
        "object_context": object_context,
        "request_shape": True,
        "cleanup_required": mode
        in {
            "self-owned-object",
            "protected-property",
            "workflow-precondition",
            "state-transition",
        },
    }


def build_cells(
    units: list[dict[str, Any]],
    coverage: dict[str, Any],
    old_plan: dict[str, Any],
) -> list[dict[str, Any]]:
    old_cells = {cell["id"]: cell for cell in old_plan.get("test_cells", [])}
    cells = []
    for unit in units:
        for family in unit["applicable_families"]:
            for dimensions in cell_dimensions(family, coverage):
                cell_id = stable_id(
                    "cell",
                    {
                        "unit": unit["id"],
                        "family": family,
                        "dimensions": dimensions,
                    },
                )
                previous = old_cells.get(cell_id, {})
                state = previous.get("status", "queued")
                if state not in TEST_RESULT_STATES:
                    state = "queued"
                reason = previous.get("reason")
                current_fingerprint = unit["fingerprint"]
                prior_fingerprint = previous.get("surface_fingerprint")
                if (
                    state == "tested"
                    and previous.get("negative_result")
                    and prior_fingerprint
                    and prior_fingerprint != current_fingerprint
                ):
                    state = "queued"
                    reason = "negative-result-invalidated-by-surface-change"
                    previous = {}
                authorization_family = family in AUTHORIZATION_MODES_BY_FAMILY
                if (
                    not authorization_family
                    and unit["safety"]["class"] not in ACTIONABLE_SAFETY
                ):
                    state = "blocked"
                    reason = f"safety: {unit['safety']['reason']}"
                elif (
                    state == "blocked"
                    and str(reason or "").startswith("safety:")
                ):
                    state = "queued"
                    reason = None
                cells.append(
                    {
                        "id": cell_id,
                        "work_unit_id": unit["id"],
                        "family": family,
                        "dimensions": dimensions,
                        "execution_requirements": execution_requirements(
                            family, dimensions
                        ),
                        "priority": unit["risk"]["priority"],
                        "risk_score": unit["risk"]["score"],
                        "safety": (
                            "blocked"
                            if authorization_family
                            else unit["safety"]["class"]
                        ),
                        "surface_fingerprint": current_fingerprint,
                        "status": state,
                        "reason": reason,
                        "evidence_refs": previous.get("evidence_refs", []),
                        "cleanup": previous.get("cleanup"),
                        "negative_result": previous.get("negative_result"),
                        "updated_at": previous.get("updated_at"),
                    }
                )
    return sorted(
        cells,
        key=lambda cell: (
            int(cell["priority"][1]),
            -cell["risk_score"],
            cell["id"],
        ),
    )


def request_shape_id(value: dict[str, Any]) -> str:
    return stable_id(
        "request-shape",
        {
            "surface_ref": value.get("surface_ref"),
            "method": str(value.get("method") or "").upper(),
            "path": value.get("path"),
            "source": value.get("source"),
            "semantics": value.get("semantics"),
            "body_fields": sorted(value.get("body_fields", [])),
        },
    )


def request_shapes_for(
    workspace: Path,
    surfaces: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    surface_map = {surface["id"]: surface for surface in surfaces}
    shapes: dict[str, dict[str, Any]] = {}
    orphaned = []
    for surface in surfaces:
        method = str(surface.get("method") or "UNKNOWN").upper()
        lifecycle = lifecycle_for(surface)
        validated = (
            surface.get("runtime_observed")
            or surface.get("validation_state")
            in {"runtime-observed", "reachable", "documented"}
        )
        semantic_read = lifecycle in {"read", "read-list", "read-detail"}
        if not validated or not (
            (method in SAFE_METHODS and semantic_read)
            or (method == "POST" and semantic_read)
        ):
            continue
        shape = {
            "surface_ref": surface["id"],
            "method": method,
            "path": urlsplit(surface["url"]).path or "/",
            "source": "surface-validation",
            "semantics": "read",
            "body_fields": sorted(surface.get("fields", [])),
            "safety": "read-only",
            "cleanup_evidence_refs": [],
            "evidence_refs": list(surface.get("evidence_refs", [])),
        }
        shape["id"] = request_shape_id(shape)
        shapes[shape["id"]] = shape
    for event in read_events(workspace):
        if event.get("type") != "request-shape":
            continue
        shape = {
            "surface_ref": event.get("surface_ref"),
            "method": str(event.get("method") or "UNKNOWN").upper(),
            "path": event.get("path"),
            "source": event.get("source", "manual"),
            "semantics": event.get("semantics", "unknown"),
            "body_fields": sorted(
                str(item) for item in event.get("body_fields", [])
            ),
            "safety": event.get("safety", "blocked"),
            "cleanup_evidence_refs": [
                str(item)
                for item in event.get("cleanup_evidence_refs", [])
            ],
            "evidence_refs": [
                str(item) for item in event.get("evidence_refs", [])
            ],
        }
        shape["id"] = str(event.get("id") or request_shape_id(shape))
        if shape["surface_ref"] not in surface_map:
            orphaned.append(
                {
                    "type": "request-shape",
                    "reference": shape["id"],
                    "reason": "unknown-surface",
                    "recorded_at": event.get("recorded_at") or now(),
                }
            )
            continue
        shapes[shape["id"]] = shape
    return (
        sorted(shapes.values(), key=lambda item: item["id"]),
        orphaned,
    )


def executable_case_variants(mode: str) -> list[str]:
    return {
        "anonymous-boundary": ["authenticated-baseline", "anonymous-variant"],
        "low-privilege-function": ["low-privilege-forced-access"],
        "implicit-subject-binding": [
            "self-subject",
            "omitted-subject",
            "nonexistent-subject",
            "duplicate-conflicting-subject",
        ],
        "self-owned-object": ["self-owned-baseline", "self-owned-variant"],
        "cross-principal-ownership": ["cross-principal-variant"],
        "tenant-parent-binding": [
            "current-parent",
            "omitted-parent",
            "nonexistent-parent",
            "duplicate-conflicting-parent",
        ],
        "protected-property": [
            "self-owned-baseline",
            "protected-field-empty",
            "protected-field-nonexistent",
        ],
        "workflow-precondition": [
            "current-state-baseline",
            "direct-action-variant",
        ],
        "state-transition": [
            "current-state-baseline",
            "adjacent-state-variant",
        ],
    }[mode]


def payload_case_metadata(
    family: str | None,
    automation_state: str,
) -> dict[str, Any]:
    global _PAYLOAD_REGISTRY
    if _PAYLOAD_REGISTRY is None:
        _PAYLOAD_REGISTRY = read_json(PAYLOAD_TECHNIQUES, {})
    registry = _PAYLOAD_REGISTRY
    policy = registry.get("families", {}).get(family or "", {})
    configured = str(policy.get("payload_policy") or "needs-agent")
    effective = configured
    if automation_state != "auto-ready" and configured == "safe-auto":
        effective = "needs-agent"
    return {
        "technique_refs": list(policy.get("technique_refs", [])),
        "payload_template_ref": policy.get("payload_template_ref"),
        "payload_policy": effective,
        "binding_requirements": list(policy.get("binding_requirements", [])),
        "oracle_id": str(policy.get("oracle_id") or "manual-security-boundary"),
    }


def prerequisite_registry() -> dict[str, Any]:
    global _PREREQUISITE_REGISTRY
    if _PREREQUISITE_REGISTRY is None:
        value = read_json(PREREQUISITE_REGISTRY, {})
        declared = set(value.get("families", {}))
        expected = {
            family["id"]
            for domain in read_json(TEMPLATE, {}).get("coverage", [])
            for family in domain.get("families", [])
        }
        if declared != expected:
            missing = sorted(expected - declared)
            extra = sorted(declared - expected)
            raise ValueError(
                "prerequisite registry must explicitly cover every test family; "
                f"missing={missing}, extra={extra}"
            )
        _PREREQUISITE_REGISTRY = value
    return _PREREQUISITE_REGISTRY


def prerequisite_case_fields(family: str | None) -> dict[str, Any]:
    registry = prerequisite_registry()
    strategies = [
        {
            "id": str(item["id"]),
            "safety": str(item.get("safety") or "read-only"),
        }
        for item in registry.get("search_strategies", [])
    ]
    return {
        "prerequisite_refs": [],
        "binding_slots": [],
        "search_strategies": strategies,
        "exhaustion_criteria": copy.deepcopy(
            registry.get("exhaustion_criteria", {})
        ),
        "blocker_class": None,
        "required_prerequisite_kinds": list(
            registry.get("families", {}).get(family or "", [])
        ),
    }


def prerequisite_search_action(kind: str) -> str:
    return {
        "route-parameter": "find a current authorized route-parameter producer",
        "request-shape": "capture the current runtime or documented request shape",
        "owned-object-binding": "find or create a cleanup-safe self-owned object",
        "identifier-producer": "find the current producer of the required identifier",
        "identifier-consumer": "find a current consumer using that identifier",
        "cleanup-chain": "find read, rollback or delete, and cleanup verification actions",
        "owned-oast": "obtain an organization-controlled callback observer",
    }.get(kind, f"discover current evidence for {kind}")


def prerequisite_initial_state(
    kind: str,
    case: dict[str, Any],
    shape: dict[str, Any],
    coverage: dict[str, Any],
    binding_slots: list[dict[str, Any]],
) -> tuple[str, list[str], str | None]:
    evidence = [str(item) for item in case.get("evidence_refs", [])]
    has_shape = bool(case.get("request_shape_id"))
    has_surface = bool(case.get("surface_ref"))
    has_input = bool(shape.get("body_fields")) or bool(
        case.get("parameter_names")
    )
    identities = observed_identity_ids(coverage)
    protocol_surface = bool(
        has_shape
        or case.get("executor_id")
        in {"graphql-safe-probe", "protocol-handshake", "oauth-metadata"}
    )
    slot_kinds = {str(item.get("kind") or "") for item in binding_slots}
    if kind in {"request-shape", "specific-endpoint"}:
        satisfied = has_shape if kind == "request-shape" else has_surface
    elif kind in {"input-position", "protected-property"}:
        satisfied = has_input
    elif kind in {
        "identity-state",
        "session-context",
        "browser-cookie-context",
    }:
        satisfied = bool(identities) or case.get("identity") == "anonymous"
    elif kind in {
        "protocol-operation",
        "protocol-document",
        "graphql-operation-shape",
        "protocol-message-shape",
        "oauth-client-callback-context",
    }:
        satisfied = protocol_surface
    elif kind in {
        "owned-object-binding",
        "file-binding",
        "ownership-context",
    }:
        satisfied = bool(slot_kinds & {"object", "file", "route-parameter"})
    elif kind in {"identifier-producer", "identifier-consumer"}:
        satisfied = any(
            item.get("producer") if kind.endswith("producer") else item.get("consumer")
            for item in binding_slots
        )
    elif kind == "subject-parent-binding":
        satisfied = bool(slot_kinds & {"subject", "parent"})
    elif kind == "route-parameter":
        satisfied = bool(slot_kinds & {"route-parameter"}) or not case.get(
            "parameter_names"
        )
    elif kind == "cleanup-chain":
        satisfied = bool(
            (case.get("cleanup") or {}).get("status")
            in {"completed", "documented"}
            or shape.get("cleanup_evidence_refs")
        )
    elif kind == "authorization-policy-context":
        mode = case.get("authorization_mode")
        satisfied = bool(
            mode == "anonymous-boundary"
            or case.get("policy_evidence_refs")
            or any(
                item.get("id") == mode and item.get("status") == "available"
                for item in coverage.get("dimensions", {}).get(
                    "authorization_capabilities", []
                )
            )
        )
    elif kind in {"protected-response", "cross-origin-credential-context"}:
        # A current request shape is enough to execute the safe baseline. The
        # executor then determines whether the response is protected and
        # credentialed; absence becomes evidence, not an early stop.
        satisfied = has_shape
    elif kind == "business-state":
        satisfied = case.get("business_state") not in {None, "any", "current"} or bool(
            coverage.get("dimensions", {}).get("business_states")
        )
    elif kind == "current-runtime-validation":
        satisfied = bool(evidence)
    elif kind in {"owned-oast"}:
        available = bool(coverage.get("runtime", {}).get("owned_oast_available"))
        return (
            "satisfied" if available else "blocked-external",
            evidence or ["coverage.json#runtime.owned_oast_available"],
            None if available else "organization-controlled OAST is unavailable",
        )
    elif kind == "second-principal":
        available = any(
            item.get("id") == "cross-principal-ownership"
            and item.get("status") == "available"
            for item in coverage.get("dimensions", {}).get(
                "authorization_capabilities", []
            )
        )
        return (
            "satisfied" if available else "blocked-external",
            evidence
            or [
                "coverage.json#dimensions.authorization_capabilities.cross-principal-ownership"
            ],
            None if available else "second authorized principal is unavailable",
        )
    else:
        # These contexts require concrete runtime evidence. A surface name or
        # generic inventory entry is intentionally not enough.
        satisfied = False
    if satisfied and not evidence:
        if kind in {
            "owned-object-binding",
            "file-binding",
            "ownership-context",
            "identifier-producer",
            "identifier-consumer",
            "subject-parent-binding",
            "route-parameter",
        }:
            evidence = ["object-provenance.json#binding-slots"]
        elif kind in {"request-shape", "input-position"}:
            evidence = ["test-plan.json#request-shapes"]
        elif kind in {"specific-endpoint", "current-runtime-validation"}:
            evidence = ["surface-inventory.json#current-surfaces"]
        else:
            evidence = ["coverage.json#current-prerequisite-context"]
    return (
        "satisfied" if satisfied else "pending",
        evidence if satisfied else [],
        None if satisfied else prerequisite_search_action(kind),
    )


def binding_slots_for_case(
    case: dict[str, Any], provenance: dict[str, Any]
) -> list[dict[str, Any]]:
    surface_ref = case.get("surface_ref")
    route_id = case.get("route_id")
    path_template = case.get("path_template")
    values = []
    for item in provenance.get("slots", []):
        consumers = set(item.get("consumer_refs", []))
        producers = set(item.get("producer_refs", []))
        route_refs = set(item.get("route_refs", []))
        route_templates = set(item.get("route_templates", []))
        if (
            (surface_ref and surface_ref in consumers | producers)
            or (route_id and route_id in route_refs)
            or (path_template and path_template in route_templates)
        ):
            values.append(item)
    return values


def build_prerequisite_graph(
    workspace: Path,
    coverage: dict[str, Any],
    plan: dict[str, Any],
    cases: list[dict[str, Any]],
) -> dict[str, Any]:
    old = read_json(workspace / "prerequisite-graph.json", {})
    old_nodes = {item.get("id"): item for item in old.get("prerequisites", [])}
    shapes = {item["id"]: item for item in plan.get("request_shapes", [])}
    provenance = read_json(workspace / "object-provenance.json", {"slots": []})
    nodes: list[dict[str, Any]] = []
    for case in cases:
        fields = prerequisite_case_fields(case.get("family"))
        for key, value in fields.items():
            case.setdefault(key, value)
        required_kinds = list(case.pop("required_prerequisite_kinds", []))
        mode = case.get("authorization_mode")
        if mode == "cross-principal-ownership":
            required_kinds.extend(["second-principal", "owned-object-binding"])
        if mode in {
            "implicit-subject-binding",
            "tenant-parent-binding",
        }:
            required_kinds.append("subject-parent-binding")
        if mode in {
            "self-owned-object",
            "protected-property",
            "workflow-precondition",
            "state-transition",
        }:
            required_kinds.append("owned-object-binding")
        if case.get("case_kind") == "route-navigation" and case.get(
            "parameter_names"
        ):
            required_kinds.append("route-parameter")
        if case.get("case_kind") == "ui-interaction" and case.get(
            "safety"
        ) == "blocked":
            required_kinds.append("control-classification")
        required_kinds = sorted(set(required_kinds))
        slots = binding_slots_for_case(case, provenance)
        case["binding_slots"] = sorted(
            {str(item.get("id")) for item in slots if item.get("id")}
        )
        for kind in required_kinds:
            prerequisite_id = stable_id(
                "prerequisite", {"owner": case["id"], "kind": kind}
            )
            previous = old_nodes.get(prerequisite_id, {})
            state, evidence_refs, reason = prerequisite_initial_state(
                kind,
                case,
                shapes.get(case.get("request_shape_id"), {}),
                coverage,
                slots,
            )
            strategies = []
            previous_strategies = {
                str(item.get("id")): item
                for item in previous.get("search_strategies", [])
            }
            for strategy in case["search_strategies"]:
                item = {
                    **strategy,
                    "status": "not-started" if state not in PREREQUISITE_FINAL else "not-required",
                    "evidence_refs": [],
                }
                item.update(previous_strategies.get(strategy["id"], {}))
                strategies.append(item)
            node = {
                "id": prerequisite_id,
                "owner_kind": "test-case",
                "owner_id": case["id"],
                "kind": kind,
                "status": state,
                "reason": reason,
                "evidence_refs": evidence_refs,
                "binding_slot_refs": case["binding_slots"],
                "search_strategies": strategies,
                "exhaustion_criteria": case["exhaustion_criteria"],
                "stable_rounds": int(previous.get("stable_rounds", 0)),
                "updated_at": previous.get("updated_at"),
            }
            nodes.append(node)
            case["prerequisite_refs"].append(prerequisite_id)

    for candidate in coverage.get("candidates", []):
        for dependency in candidate.get("validation_dependencies", []):
            prerequisite_id = stable_id(
                "prerequisite",
                {"owner": candidate.get("id"), "kind": dependency.get("id")},
            )
            status = {
                "blocked": "blocked-external",
            }.get(dependency.get("status"), dependency.get("status", "pending"))
            nodes.append(
                {
                    "id": prerequisite_id,
                    "owner_kind": "candidate",
                    "owner_id": candidate.get("id"),
                    "legacy_dependency_id": dependency.get("id"),
                    "kind": dependency.get("kind") or dependency.get("id"),
                    "status": status,
                    "reason": dependency.get("reason"),
                    "evidence_refs": dependency.get("evidence_refs", []),
                    "binding_slot_refs": [],
                    "search_strategies": copy.deepcopy(
                        prerequisite_case_fields(None)["search_strategies"]
                    ),
                    "exhaustion_criteria": copy.deepcopy(
                        prerequisite_case_fields(None)["exhaustion_criteria"]
                    ),
                    "stable_rounds": 0,
                    "updated_at": candidate.get("updated_at"),
                }
            )

    by_id = {item["id"]: item for item in nodes}
    for event in read_events(workspace):
        if event.get("type") not in {"prerequisite-result", "candidate-dependency"}:
            continue
        if event.get("type") == "candidate-dependency":
            candidate_id = event.get("id")
            dependency_id = event.get("dependency_id")
            prerequisite_id = stable_id(
                "prerequisite", {"owner": candidate_id, "kind": dependency_id}
            )
            status = {"blocked": "blocked-external"}.get(
                event.get("status"), event.get("status")
            )
        else:
            prerequisite_id = str(event.get("prerequisite_id"))
            status = event.get("status")
        node = by_id.get(prerequisite_id)
        if node is None:
            continue
        values = {
            "reason": event.get("reason"),
            "evidence_refs": [
                str(item) for item in event.get("evidence_refs", [])
            ],
            "stable_rounds": int(
                event.get("stable_rounds", node.get("stable_rounds", 0))
            ),
            "updated_at": event.get("recorded_at") or now(),
        }
        # Newly observed producer/consumer evidence wins over an older search
        # progress event. Terminal adjudications still require a fresh event.
        if not (status == "searching" and node.get("status") == "satisfied"):
            values["status"] = status
        node.update(values)
        strategy_id = event.get("strategy_id")
        if strategy_id:
            for strategy in node["search_strategies"]:
                if strategy["id"] == strategy_id:
                    strategy.update(
                        {
                            "status": event.get("strategy_status", "completed"),
                            "evidence_refs": [
                                str(item) for item in event.get("evidence_refs", [])
                            ],
                        }
                    )

    for node in nodes:
        if node["status"] == "exhausted-with-evidence":
            applicable = [
                item
                for item in node["search_strategies"]
                if item.get("status") != "not-applicable"
            ]
            valid = (
                node.get("stable_rounds", 0)
                >= int(node["exhaustion_criteria"].get("required_stable_rounds", 2))
                and applicable
                and all(
                    item.get("status") in {"completed", "not-required"}
                    and item.get("evidence_refs")
                    for item in applicable
                    if item.get("status") != "not-required"
                )
            )
            if not valid:
                node["status"] = "searching"
                node["reason"] = "exhaustion criteria are not yet evidenced"

    nodes_by_owner: dict[str, list[dict[str, Any]]] = {}
    for node in nodes:
        nodes_by_owner.setdefault(str(node.get("owner_id")), []).append(node)
    for case in cases:
        related = nodes_by_owner.get(case["id"], [])
        if case.get("status") == "not-applicable":
            continue
        unresolved = [item for item in related if item["status"] != "satisfied"]
        if unresolved:
            discoverable = [
                item
                for item in unresolved
                if item["status"] in {"pending", "searching"}
            ]
            external = [
                item for item in unresolved if item["status"] == "blocked-external"
            ]
            exhausted = [
                item
                for item in unresolved
                if item["status"] == "exhausted-with-evidence"
            ]
            if discoverable:
                case["status"] = "waiting-prerequisite"
                case["automation_state"] = "needs-agent"
                case["blocker_class"] = "discoverable-prerequisite"
                case["reason"] = "missing discoverable prerequisites: " + ", ".join(
                    sorted(item["kind"] for item in discoverable)
                )
            elif external or exhausted:
                case["status"] = "blocked"
                case["blocker_class"] = (
                    "external-capability" if external else "evidence-exhausted"
                )
                case["reason"] = "; ".join(
                    str(item.get("reason") or item["kind"])
                    for item in (external or exhausted)
                )
        elif case.get("status") == "waiting-prerequisite":
            case["status"] = "queued"
            case["reason"] = None
            case["blocker_class"] = None

    return {
        "schema_version": 1,
        "assessment_id": coverage.get("assessment_id"),
        "generated_at": now(),
        "states": sorted(PREREQUISITE_STATES),
        "prerequisites": sorted(nodes, key=lambda item: item["id"]),
        "summary": {
            state: sum(item["status"] == state for item in nodes)
            for state in sorted(PREREQUISITE_STATES)
        },
        "binding_slot_count": len(provenance.get("slots", [])),
        "raw_value_policy": "raw values exist only in consumed mode-0600 runtime leases",
    }


def build_executable_cases(
    cells: list[dict[str, Any]],
    units: list[dict[str, Any]],
    request_shapes: list[dict[str, Any]],
    coverage: dict[str, Any],
    old_plan: dict[str, Any],
) -> list[dict[str, Any]]:
    capabilities = effective_authorization_capabilities(coverage)
    unit_map = {unit["id"]: unit for unit in units}
    shapes_by_surface: dict[str, list[dict[str, Any]]] = {}
    for shape in request_shapes:
        shapes_by_surface.setdefault(shape["surface_ref"], []).append(shape)
    old_cases = {
        case["id"]: case
        for case in old_plan.get("executable_cases", [])
        if case.get("id")
    }
    cases = []
    for cell in cells:
        mode = cell.get("dimensions", {}).get("authorization_mode")
        if not mode:
            continue
        capability = capabilities[mode]
        if capability["status"] == "unavailable":
            cell.update(
                {
                    "status": "waiting-prerequisite",
                    "reason": (
                        "authorization capability unavailable: "
                        f"{capability.get('reason') or mode}"
                    ),
                    "safety": "blocked",
                }
            )
        elif capability["status"] == "conditional":
            cell.update(
                {
                    "status": "waiting-prerequisite",
                    "reason": (
                        "authorization capability conditional: "
                        f"{capability.get('reason') or mode}"
                    ),
                    "safety": "blocked",
                }
            )
        unit = unit_map[cell["work_unit_id"]]
        shapes = [
            shape
            for surface_ref in unit.get("surface_refs", [])
            for shape in shapes_by_surface.get(surface_ref, [])
        ]
        compatible = []
        for shape in shapes:
            if shape["safety"] not in ACTIONABLE_SAFETY:
                continue
            if (
                shape["semantics"] == "write"
                and not shape.get("cleanup_evidence_refs")
            ):
                continue
            if (
                cell["execution_requirements"]["cleanup_required"]
                and shape["semantics"] == "write"
                and shape["safety"] != "reversible"
            ):
                continue
            if (
                mode in {"protected-property", "workflow-precondition", "state-transition"}
                and shape["semantics"] != "write"
            ):
                continue
            compatible.append(shape)
        if not compatible:
            cell.update(
                {
                    "status": "waiting-prerequisite",
                    "reason": "request-shape-or-safe-object-context-missing",
                    "safety": "blocked",
                }
            )
            # Preserve a concrete test case so the Agent can discover its
            # producer, request shape, object binding, or cleanup chain.
            compatible = [None]
        cell["status"] = (
            "queued" if cell["status"] not in RESOLVED else cell["status"]
        )
        if cell["status"] == "queued":
            cell["reason"] = None
        if any(shape is not None for shape in compatible):
            cell["safety"] = min(
                (shape["safety"] for shape in compatible if shape is not None),
                key=lambda value: {
                    "passive": 0,
                    "read-only": 1,
                    "reversible": 2,
                }[value],
            )
        for shape in compatible:
            shape_id = shape["id"] if shape else None
            case_id = stable_id(
                "test-case",
                {
                    "test_cell_id": cell["id"],
                    "request_shape_id": shape_id,
                    "authorization_mode": mode,
                    "priority": cell["priority"],
                },
            )
            previous = old_cases.get(case_id, {})
            status = previous.get("status", "queued")
            if status not in TEST_RESULT_STATES:
                status = "queued"
            payload_metadata = payload_case_metadata(
                cell["family"], "auto-ready" if shape else "needs-agent"
            )
            automation_state = (
                "auto-ready"
                if shape and payload_metadata["payload_policy"] == "safe-auto"
                else "needs-agent"
            )
            cases.append(
                {
                    "id": case_id,
                    "case_kind": "api-test",
                    "test_cell_id": cell["id"],
                    "work_unit_id": cell["work_unit_id"],
                    "surface_ref": shape["surface_ref"] if shape else None,
                    "request_shape_id": shape_id,
                    "authorization_mode": mode,
                    "variants": executable_case_variants(mode),
                    "variant_results": previous.get("variant_results", {}),
                    "executor_id": previous.get("executor_id", "authorization-replay"),
                    "automation_state": automation_state,
                    "request_template_ref": previous.get("request_template_ref"),
                    "oracle": previous.get("oracle", {"type": "response-differential"}),
                    "retry_policy": previous.get(
                        "retry_policy",
                        {"maximum_attempts": 3, "backoff": "exponential"},
                    ),
                    "safety_decision": previous.get(
                        "safety_decision",
                        {
                            "state": "allowed" if automation_state == "auto-ready" else "agent-required",
                            "reason": (
                                "planner-safe-request-shape"
                                if automation_state == "auto-ready"
                                else "payload-policy-requires-agent"
                            ),
                        },
                    ),
                    "agent_action": (
                        None
                        if automation_state == "auto-ready"
                        else {
                            "action": "bind-and-validate-controlled-technique",
                            "family": cell["family"],
                            "required_inputs": payload_metadata["binding_requirements"],
                        }
                    ),
                    "execution_requirements": cell["execution_requirements"],
                    "safety": shape["safety"] if shape else "blocked",
                    "status": status,
                    "reason": previous.get("reason"),
                    "evidence_refs": previous.get("evidence_refs", []),
                    "cleanup": previous.get("cleanup"),
                    "updated_at": previous.get("updated_at"),
                    **payload_metadata,
                }
            )
    return sorted(
        cases,
        key=lambda case: (
            next(
                int(cell["priority"][1])
                for cell in cells
                if cell["id"] == case["test_cell_id"]
            ),
            case["id"],
        ),
    )


EXECUTOR_REGISTRY: dict[str, tuple[str, list[str]]] = {
    "identity-session.authentication": (
        "session-differential",
        ["authenticated-baseline", "anonymous-variant"],
    ),
    "identity-session.session-token": (
        "session-differential",
        ["authenticated-baseline", "anonymous-variant", "cache-header-review"],
    ),
    "injection.sql-nosql-orm": (
        "input-differential",
        ["baseline", "syntax-marker", "boolean-true", "boolean-false"],
    ),
    "injection.xml-ldap-xpath": (
        "parser-differential",
        ["baseline", "parser-marker"],
    ),
    "browser-content.xss-dom-richtext": (
        "browser-input-marker",
        ["baseline", "harmless-marker"],
    ),
    "files-data-export.path-read-download": (
        "file-safe-read",
        ["baseline", "nonexistent-self-path"],
    ),
    "api-protocol.parameter-encoding": (
        "protocol-differential",
        ["baseline", "content-type-variant"],
    ),
    "api-protocol.edge-backend-normalization": (
        "protocol-differential",
        ["baseline", "path-normalization-variant"],
    ),
    "api-protocol.graphql": (
        "graphql-safe-probe",
        ["baseline", "graphql-typename"],
    ),
    "api-protocol.websocket-sse-soap": (
        "protocol-handshake",
        ["baseline", "sse-handshake"],
    ),
    "identity-session.oauth-sso": (
        "oauth-metadata",
        ["baseline", "oauth-metadata-review"],
    ),
    "platform-exposure.headers-cache-cors": (
        "passive-response-review",
        ["baseline", "cors-origin-variant"],
    ),
    "platform-exposure.debug-admin-docs": (
        "passive-response-review",
        ["baseline"],
    ),
    "platform-exposure.client-bootstrap-config": (
        "passive-response-review",
        ["baseline"],
    ),
    "platform-exposure.error-exception-logging": (
        "passive-response-review",
        ["baseline"],
    ),
}


def family_executor(family: str) -> tuple[str | None, list[str]]:
    executor = EXECUTOR_REGISTRY.get(family)
    return executor if executor else (None, [])


def build_family_executable_cases(
    cells: list[dict[str, Any]],
    units: list[dict[str, Any]],
    request_shapes: list[dict[str, Any]],
    old_plan: dict[str, Any],
) -> list[dict[str, Any]]:
    unit_map = {unit["id"]: unit for unit in units}
    shapes_by_surface: dict[str, list[dict[str, Any]]] = {}
    for shape in request_shapes:
        shapes_by_surface.setdefault(shape["surface_ref"], []).append(shape)
    old_cases = {
        item["id"]: item
        for item in old_plan.get("executable_cases", [])
        if item.get("id") and item.get("case_kind") == "api-test"
    }
    cases = []
    for cell in cells:
        if cell.get("dimensions", {}).get("authorization_mode"):
            continue
        unit = unit_map[cell["work_unit_id"]]
        executor_id, variants = family_executor(cell["family"])
        compatible = [
            shape
            for surface_ref in unit.get("surface_refs", [])
            for shape in shapes_by_surface.get(surface_ref, [])
            if shape.get("safety") in ACTIONABLE_SAFETY
            and shape.get("semantics") == "read"
        ]
        if not executor_id or not compatible:
            case_id = stable_id(
                "agent-case",
                {"test_cell_id": cell["id"], "family": cell["family"]},
            )
            previous = old_cases.get(case_id, {})
            cases.append(
                {
                    "id": case_id,
                    "case_kind": "api-test",
                    "test_cell_id": cell["id"],
                    "work_unit_id": cell["work_unit_id"],
                    "surface_ref": None,
                    "request_shape_id": None,
                    "family": cell["family"],
                    "authorization_mode": None,
                    "variants": ["agent-review"],
                    "variant_results": previous.get("variant_results", {}),
                    "executor_id": "agent-review",
                    "automation_state": "needs-agent",
                    "agent_role": "tester",
                    "agent_safety": "agent-safe",
                    "expected_event_types": [
                        "test-result",
                        "variant-result",
                        "evidence",
                        "candidate",
                        "finding",
                    ],
                    "agent_action": {
                        "action": "perform-specialized-validation",
                        "family": cell["family"],
                        "work_unit_id": cell["work_unit_id"],
                        "required_inputs": cell["execution_requirements"],
                        "required_evidence": [
                            "normal-baseline",
                            "single-variable-variant",
                            "repeatable-impact-or-negative-control",
                        ],
                        "safety_constraints": [
                            "no-unrelated-object-access",
                            "no-real-message-or-payment",
                            "no-global-state-change",
                            "cleanup-self-owned-writes",
                        ],
                    },
                    "execution_requirements": cell["execution_requirements"],
                    "safety": "blocked",
                    "status": previous.get("status", "queued"),
                    "reason": previous.get(
                        "reason", "deterministic executor or request template unavailable"
                    ),
                    "evidence_refs": previous.get("evidence_refs", []),
                    "cleanup": previous.get("cleanup"),
                    "updated_at": previous.get("updated_at"),
                    **payload_case_metadata(cell["family"], "needs-agent"),
                }
            )
            continue
        for shape in compatible:
            case_id = stable_id(
                "test-case",
                {
                    "test_cell_id": cell["id"],
                    "request_shape_id": shape["id"],
                    "executor_id": executor_id,
                },
            )
            previous = old_cases.get(case_id, {})
            cases.append(
                {
                    "id": case_id,
                    "case_kind": "api-test",
                    "test_cell_id": cell["id"],
                    "work_unit_id": cell["work_unit_id"],
                    "surface_ref": shape["surface_ref"],
                    "request_shape_id": shape["id"],
                    "family": cell["family"],
                    "authorization_mode": None,
                    "variants": variants,
                    "variant_results": previous.get("variant_results", {}),
                    "executor_id": executor_id,
                    "automation_state": "auto-ready",
                    "request_template_ref": previous.get("request_template_ref"),
                    "oracle": previous.get("oracle", {"type": "response-differential"}),
                    "retry_policy": previous.get(
                        "retry_policy",
                        {"maximum_attempts": 3, "backoff": "exponential"},
                    ),
                    "safety_decision": {
                        "state": "allowed",
                        "reason": "read-only-runtime-or-documented-shape",
                    },
                    "execution_requirements": cell["execution_requirements"],
                    "safety": shape["safety"],
                    "status": previous.get("status", "queued"),
                    "reason": previous.get("reason"),
                    "evidence_refs": previous.get("evidence_refs", []),
                    "cleanup": previous.get("cleanup"),
                    "updated_at": previous.get("updated_at"),
                    **payload_case_metadata(cell["family"], "auto-ready"),
                }
            )
    return cases


def route_stage(state: str, reason: str | None = None) -> dict[str, Any]:
    return {"state": state, "reason": reason, "evidence_refs": []}


def build_route_inventory(
    target: str,
    surfaces: list[dict[str, Any]],
) -> dict[str, Any]:
    routes = []
    for surface in surfaces:
        if surface.get("kind") != "route":
            continue
        path_template = surface.get("path_template") or urlsplit(
            surface.get("url", "/")
        ).path
        route_id = stable_id(
            "route",
            {"origin": origin(target), "path_template": path_template},
        )
        validation_state = surface.get("validation_state", "unverified")
        validation = surface.get("route_validation", {})
        render = validation.get("evidence", {}).get("render", {})
        current = validation_state not in {"historical", "unverified"}
        navigated = validation_state == "runtime-visited"
        rendered = navigated and (
            render.get("state") == "rendered"
            or validation.get("reason")
            == "browser-navigation-and-render-confirmed"
        )
        rejected = validation_state == "rejected"
        parameter_names = sorted(
            set(
                surface.get("route_parameter_names", [])
                or re.findall(r":([A-Za-z_$][\w$]*)", path_template)
            )
        )
        parameter_state = surface.get("route_parameter_state") or (
            "unresolved" if parameter_names else "not-required"
        )
        stages = {
            "discovered": route_stage("completed", "surface-inventory"),
            "current-validated": route_stage(
                "completed" if current else "pending",
                validation_state,
            ),
            "navigated": route_stage(
                "completed" if navigated else "not-applicable" if rejected else "pending",
                validation.get("reason") or validation_state,
            ),
            "rendered": route_stage(
                "completed" if rendered else "not-applicable" if rejected else "pending",
                render.get("reason") or validation.get("reason"),
            ),
            "controls-extracted": route_stage(
                "completed"
                if rendered and "route_control_refs" in surface
                else "not-applicable"
                if rejected
                else "pending",
                "browser-dom-inventory" if rendered else None,
            ),
            "runtime-api-linked": route_stage(
                "completed"
                if rendered and "route_runtime_api_refs" in surface
                else "not-applicable"
                if rejected
                else "pending",
                "browser-runtime-correlation" if rendered else None,
            ),
            "tests-resolved": route_stage(
                "not-applicable" if rejected else "pending",
                "rejected-route" if rejected else None,
            ),
        }
        evidence_refs = sorted(
            {
                *surface.get("source_refs", []),
                *surface.get("evidence_refs", []),
            }
        )
        for stage in stages.values():
            stage["evidence_refs"] = evidence_refs if stage["state"] in {
                "completed",
                "not-applicable",
            } else []
        routes.append(
            {
                "id": route_id,
                "surface_ref": surface["id"],
                "origin": origin(target),
                "path_template": path_template,
                "validation_state": validation_state,
                "source_state": (
                    "historical" if validation_state == "historical" else "current"
                ),
                "parameter_names": parameter_names,
                "parameter_state": parameter_state,
                "parameter_sources": surface.get("route_parameter_sources", []),
                "lazy_chunk_refs": surface.get("route_lazy_chunk_refs", []),
                "control_refs": surface.get("route_control_refs", []),
                "runtime_api_refs": surface.get("route_runtime_api_refs", []),
                "stages": stages,
                "evidence_refs": evidence_refs,
            }
        )
    concrete_aliases: set[str] = set()
    for template_route in routes:
        if not template_route["parameter_names"]:
            continue
        pattern = re.escape(template_route["path_template"])
        for parameter in template_route["parameter_names"]:
            pattern = pattern.replace(re.escape(f":{parameter}"), "[^/]+")
        matcher = re.compile(f"^{pattern}$")
        observed = [
            item
            for item in routes
            if item is not template_route
            and not item["parameter_names"]
            and matcher.match(item["path_template"])
            and item["source_state"] == "current"
        ]
        if not observed:
            continue
        best = max(
            observed,
            key=lambda item: sum(
                stage["state"] == "completed" for stage in item["stages"].values()
            ),
        )
        template_route["parameter_state"] = "observed"
        template_route["parameter_sources"] = [
            {
                "parameter": parameter,
                "source": "runtime-route",
                "source_route_ref": best["id"],
                "value_persisted": False,
            }
            for parameter in template_route["parameter_names"]
        ]
        template_route["source_state"] = "current"
        template_route["validation_state"] = best["validation_state"]
        template_route["stages"] = copy.deepcopy(best["stages"])
        template_route["lazy_chunk_refs"] = sorted(
            {*template_route["lazy_chunk_refs"], *best["lazy_chunk_refs"]}
        )
        template_route["control_refs"] = sorted(
            {*template_route["control_refs"], *best["control_refs"]}
        )
        template_route["runtime_api_refs"] = sorted(
            {*template_route["runtime_api_refs"], *best["runtime_api_refs"]}
        )
        template_route["evidence_refs"] = sorted(
            {*template_route["evidence_refs"], *best["evidence_refs"]}
        )
        template_route["observed_route_refs"] = [item["id"] for item in observed]
        concrete_aliases.update(item["id"] for item in observed)
    routes = [item for item in routes if item["id"] not in concrete_aliases]
    routes.sort(key=lambda item: item["id"])
    api_by_path: dict[str, list[str]] = {}
    control_by_key: dict[str, str] = {}
    for surface in surfaces:
        if surface.get("kind") == "api":
            api_by_path.setdefault(surface.get("path_template", ""), []).append(
                surface["id"]
            )
        if surface.get("feature_type") == "runtime-ui-control" and surface.get(
            "semantic_key"
        ):
            control_by_key[str(surface["semantic_key"])] = surface["id"]
    links = []
    for route in routes:
        for api_ref in route["runtime_api_refs"]:
            path = urlsplit(str(api_ref)).path
            for surface_ref in api_by_path.get(path, []):
                links.append(
                    {
                        "from": route["id"],
                        "to": surface_ref,
                        "relation": "runtime-api",
                        "evidence_refs": route["evidence_refs"],
                    }
                )
        for control_ref in route["control_refs"]:
            if surface_ref := control_by_key.get(str(control_ref)):
                links.append(
                    {
                        "from": route["id"],
                        "to": surface_ref,
                        "relation": "visible-control",
                        "evidence_refs": route["evidence_refs"],
                    }
                )
    unique_links = {
        (item["from"], item["to"], item["relation"]): item for item in links
    }
    return {
        "schema_version": 1,
        "target": normalized_target(target),
        "generated_at": now(),
        "stage_order": list(ROUTE_STAGE_IDS),
        "routes": routes,
        "surface_links": sorted(
            unique_links.values(),
            key=lambda item: (item["from"], item["relation"], item["to"]),
        ),
        "summary": {},
    }


def build_route_cases(
    route_inventory: dict[str, Any],
    work_units: list[dict[str, Any]],
    coverage: dict[str, Any],
    old_plan: dict[str, Any],
) -> list[dict[str, Any]]:
    old_cases = {
        item["id"]: item
        for item in old_plan.get("executable_cases", [])
        if item.get("case_kind") == "route-navigation" and item.get("id")
    }
    surface_to_unit = {
        surface_ref: unit
        for unit in work_units
        for surface_ref in unit.get("surface_refs", [])
    }
    identities = observed_identity_ids(coverage) or ["anonymous"]
    if "anonymous" not in identities:
        identities = ["anonymous", *identities]
    authenticated = [identity for identity in identities if identity != "anonymous"]
    captured_identity = authenticated[0] if authenticated else "anonymous"
    observed_states = [
        item["id"]
        for item in coverage.get("dimensions", {}).get("business_states", [])
        if item.get("status") in {"available", "observed"}
    ]
    business_states = observed_states or ["current"]
    captured_state = business_states[0]
    cases = []
    for route in route_inventory["routes"]:
        unit = surface_to_unit.get(route["surface_ref"])
        for identity in identities:
            for business_state in business_states:
                case_id = stable_id(
                    "route-case",
                    {
                        "route_id": route["id"],
                        "identity": identity,
                        "business_state": business_state,
                    },
                )
                previous = old_cases.get(case_id, {})
                rejected = route["validation_state"] == "rejected"
                rendered = (
                    route["stages"]["rendered"]["state"] == "completed"
                    and identity == captured_identity
                    and business_state == captured_state
                )
                if rejected:
                    status = "not-applicable"
                    reason = "current route rejected by response or fallback controls"
                elif rendered:
                    status = "tested"
                    reason = None
                elif route["parameter_state"] == "unresolved":
                    status = "waiting-prerequisite"
                    reason = "dynamic route parameters lack a current authorized source"
                else:
                    status = previous.get("status", "queued")
                    reason = previous.get("reason")
                    if (
                        status in RESOLVED
                        and previous.get("surface_fingerprint")
                        != route["validation_state"]
                    ):
                        status = "queued"
                        reason = "route validation state changed"
                cases.append(
                    {
                        "id": case_id,
                        "case_kind": "route-navigation",
                        "executor_id": "browser-navigation",
                        "automation_state": (
                            "auto-ready"
                            if status not in RESOLVED
                            else "resolved"
                        ),
                        "variant_results": previous.get("variant_results", {}),
                        "route_id": route["id"],
                        "surface_ref": route["surface_ref"],
                        "work_unit_id": unit.get("id") if unit else None,
                        "path_template": route["path_template"],
                        "parameter_names": route["parameter_names"],
                        "parameter_sources": route["parameter_sources"],
                        "identity": identity,
                        "business_state": business_state,
                        "safety": "read-only",
                        "priority": unit.get("risk", {}).get("priority", "P2")
                        if unit
                        else "P2",
                        "status": status,
                        "reason": reason,
                        "evidence_refs": previous.get(
                            "evidence_refs",
                            route.get("evidence_refs", [])
                            if rendered or rejected
                            else [],
                        ),
                        "retry": {
                            "attempts": previous.get("retry", {}).get("attempts", 0)
                        },
                        "surface_fingerprint": route["validation_state"],
                    }
                )
    return sorted(cases, key=lambda item: (int(item["priority"][1]), item["id"]))


def build_control_cases(
    surfaces: list[dict[str, Any]],
    old_plan: dict[str, Any],
) -> list[dict[str, Any]]:
    old_cases = {
        item["id"]: item
        for item in old_plan.get("executable_cases", [])
        if item.get("case_kind") == "ui-interaction" and item.get("id")
    }
    cases = []
    for surface in surfaces:
        if surface.get("feature_type") != "runtime-ui-control":
            continue
        control = surface.get("control", {})
        if not control.get("visible") or control.get("disabled"):
            continue
        case_id = stable_id("control-case", {"surface_ref": surface["id"]})
        previous = old_cases.get(case_id, {})
        disposition = surface.get("control_exercise_state") or "observed-only"
        if disposition in {"exercised", "route-queued"}:
            status = "tested"
            reason = None
            safety = "read-only"
        elif disposition == "related-passive":
            status = "not-applicable"
            reason = "cross-origin link is recorded for passive related-surface review"
            safety = "passive"
        elif disposition == "planned-unsafe":
            status = "waiting-prerequisite"
            reason = "control may cause a side effect and lacks a cleanup-safe case"
            safety = "blocked"
        else:
            status = previous.get("status", "queued")
            reason = previous.get("reason")
            safety = "read-only" if disposition == "eligible" else "blocked"
            if disposition == "observed-only":
                status = "waiting-prerequisite"
                reason = "visible control has not been classified as safe or linked"
        cases.append(
            {
                "id": case_id,
                "case_kind": "ui-interaction",
                "executor_id": "browser-control",
                "automation_state": (
                    "auto-ready"
                    if status not in RESOLVED and safety in ACTIONABLE_SAFETY
                    else "needs-agent"
                    if status not in RESOLVED
                    else "resolved"
                ),
                "variant_results": previous.get("variant_results", {}),
                "control_id": surface.get("semantic_key") or surface["id"],
                "surface_ref": surface["id"],
                "route_refs": surface.get("route_refs", []),
                "identity": "current",
                "business_state": "current",
                "safety": safety,
                "priority": "P2",
                "status": status,
                "reason": reason,
                "evidence_refs": previous.get(
                    "evidence_refs",
                    surface.get("evidence_refs", [])
                    if status in {"tested", "not-applicable"}
                    else [],
                ),
                "retry": {"attempts": previous.get("retry", {}).get("attempts", 0)},
            }
        )
    return sorted(cases, key=lambda item: item["id"])


def apply_route_events(
    workspace: Path,
    route_inventory: dict[str, Any],
    route_cases: list[dict[str, Any]],
    control_cases: list[dict[str, Any]],
) -> None:
    routes = {item["id"]: item for item in route_inventory["routes"]}
    cases = {item["id"]: item for item in [*route_cases, *control_cases]}
    for event in read_events(workspace):
        event_type = event.get("type")
        if event_type == "route-result":
            route = routes.get(str(event.get("route_id")))
            case = cases.get(str(event.get("test_case_id")))
            if route is None or case is None:
                route_inventory.setdefault("orphaned_events", []).append(event)
                continue
            case.update(
                {
                    "status": event["status"],
                    "reason": event.get("reason"),
                    "evidence_refs": event.get("evidence_refs", []),
                    "updated_at": event.get("recorded_at") or now(),
                }
            )
            for stage_id, state in event.get("stages", {}).items():
                if stage_id in route["stages"]:
                    route["stages"][stage_id] = {
                        "state": state,
                        "reason": event.get("reason"),
                        "evidence_refs": event.get("evidence_refs", []),
                    }
        elif event_type == "control-result":
            case = cases.get(str(event.get("test_case_id")))
            if case is None:
                route_inventory.setdefault("orphaned_events", []).append(event)
                continue
            case.update(
                {
                    "status": event["status"],
                    "reason": event.get("reason"),
                    "evidence_refs": event.get("evidence_refs", []),
                    "updated_at": event.get("recorded_at") or now(),
                }
            )
        elif event_type == "surface-link":
            route_inventory["surface_links"].append(
                {
                    "from": event.get("from"),
                    "to": event.get("to"),
                    "relation": event.get("relation"),
                    "evidence_refs": event.get("evidence_refs", []),
                }
            )


def finalize_route_inventory(
    route_inventory: dict[str, Any],
    route_cases: list[dict[str, Any]],
    control_cases: list[dict[str, Any]],
    plan: dict[str, Any],
) -> None:
    cases_by_route: dict[str, list[dict[str, Any]]] = {}
    for item in route_cases:
        cases_by_route.setdefault(item["route_id"], []).append(item)
    cells_by_unit: dict[str, list[dict[str, Any]]] = {}
    for cell in plan.get("test_cells", []):
        cells_by_unit.setdefault(cell["work_unit_id"], []).append(cell)
    for route in route_inventory["routes"]:
        route_case_group = cases_by_route[route["id"]]
        case = route_case_group[0]
        unit_cells = cells_by_unit.get(case.get("work_unit_id"), [])
        if all(item["status"] == "not-applicable" for item in route_case_group):
            state = "not-applicable"
        elif (
            all(
                item["status"] in {"tested", "not-applicable"}
                for item in route_case_group
            )
            and unit_cells
            and all(cell["status"] in COVERAGE_SATISFIED for cell in unit_cells)
        ):
            state = "completed"
        else:
            state = "pending"
        route["stages"]["tests-resolved"] = route_stage(
            state,
            "all-applicable-route-test-cells-resolved"
            if state == "completed"
            else "route-test-cells-unresolved",
        )
    routes = route_inventory["routes"]
    route_inventory["summary"] = {
        "discovered": len(routes),
        "current_validated": sum(
            item["stages"]["current-validated"]["state"] == "completed"
            for item in routes
        ),
        "navigated": sum(
            item["stages"]["navigated"]["state"] == "completed"
            for item in routes
        ),
        "rendered": sum(
            item["stages"]["rendered"]["state"] == "completed"
            for item in routes
        ),
        "not_applicable": sum(
            item["stages"]["rendered"]["state"] == "not-applicable"
            for item in routes
        ),
        "controls_extracted": sum(
            item["stages"]["controls-extracted"]["state"] == "completed"
            for item in routes
        ),
        "runtime_api_linked": sum(
            item["stages"]["runtime-api-linked"]["state"] == "completed"
            for item in routes
        ),
        "controls_accounted": sum(
            item["stages"]["controls-extracted"]["state"]
            in {"completed", "not-applicable"}
            for item in routes
        ),
        "runtime_api_links_accounted": sum(
            item["stages"]["runtime-api-linked"]["state"]
            in {"completed", "not-applicable"}
            for item in routes
        ),
        "tests_resolved": sum(
            item["stages"]["tests-resolved"]["state"]
            in {"completed", "not-applicable"}
            for item in routes
        ),
        "blocked": sum(
            any(item["status"] == "blocked" for item in cases_by_route[route["id"]])
            for route in routes
        ),
        "route_cases_tested": sum(
            all(
                item["status"] in {"tested", "not-applicable"}
                for item in cases_by_route[route["id"]]
            )
            for route in routes
        ),
        "control_cases": len(control_cases),
        "control_cases_tested": sum(
            item["status"] == "tested" for item in control_cases
        ),
        "control_cases_blocked": sum(
            item["status"] == "blocked" for item in control_cases
        ),
    }


def event_path(workspace: Path) -> Path:
    return workspace / "assessment-events.jsonl"


def read_events(workspace: Path) -> list[dict[str, Any]]:
    path = event_path(workspace)
    if not path.exists():
        return []
    events = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{number}: {error}") from error
        if not isinstance(event, dict):
            raise ValueError(f"{path}:{number}: event must be an object")
        validate_event_shape(event)
        events.append(event)
    return events


def validate_candidate_dependencies(dependencies: Any) -> None:
    if dependencies is None:
        return
    if not isinstance(dependencies, list):
        raise ValueError("validation_dependencies must be a list")
    seen: set[str] = set()
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise ValueError("validation dependency must be an object")
        dependency_id = str(dependency.get("id") or "").strip()
        if not dependency_id:
            raise ValueError("validation dependency requires id")
        if dependency_id in seen:
            raise ValueError(f"duplicate validation dependency: {dependency_id}")
        seen.add(dependency_id)
        status = dependency.get("status", "pending")
        if status not in CANDIDATE_DEPENDENCY_STATES:
            raise ValueError(f"invalid validation dependency status: {status}")
        evidence_refs = dependency.get("evidence_refs", [])
        if status in CANDIDATE_DEPENDENCY_TERMINAL and not evidence_refs:
            raise ValueError(f"{status} validation dependency requires evidence_refs")
        if status in {"pending", "blocked", "blocked-external", "exhausted-with-evidence"} and not str(
            dependency.get("reason") or ""
        ).strip():
            raise ValueError(f"{status} validation dependency requires reason")


def candidate_dependency_gaps(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        dependency
        for dependency in candidate.get("validation_dependencies", [])
        if dependency.get("status", "pending")
        not in CANDIDATE_DEPENDENCY_TERMINAL
    ]


def candidate_resolution_complete(candidate: dict[str, Any]) -> bool:
    disposition = candidate.get("disposition")
    if disposition not in CANDIDATE_RESOLVED_DISPOSITIONS:
        return False
    if candidate_dependency_gaps(candidate):
        return False
    return True


def finding_dependencies_satisfied(finding: dict[str, Any]) -> bool:
    return all(
        dependency.get("status") == "satisfied"
        for dependency in finding.get("validation_dependencies", [])
    )


def normalize_conclusion_event(
    event: dict[str, Any], event_type: str, item_id: str
) -> dict[str, Any]:
    raw = {**event, "claim_id": item_id}
    normalized = security_conclusion.normalize(raw, source_type=event_type)
    normalized["id"] = item_id
    normalized["type"] = event_type
    return normalized


def validate_event_shape(event: dict[str, Any]) -> None:
    event_type = event.get("type")
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unsupported event type: {event_type}")
    if event_type == "test-result":
        if not event.get("test_cell_id"):
            raise ValueError("test-result requires test_cell_id")
        status = event.get("status")
        if status not in RESOLVED:
            raise ValueError(f"invalid test-result status: {status}")
        refs = event.get("evidence_refs", [])
        reason = str(event.get("reason") or "").strip()
        if status in {"tested", "not-applicable"} and not refs:
            raise ValueError(f"{status} requires evidence_refs")
        if status in {"blocked", "not-applicable"} and not reason:
            raise ValueError(f"{status} requires reason")
    elif event_type in {"identity", "business-state"} and not event.get("id"):
        raise ValueError(f"{event_type} requires id")
    elif event_type == "authorization-capability":
        mode = event.get("id")
        status = event.get("status")
        if mode not in AUTHORIZATION_MODES:
            raise ValueError(f"invalid authorization capability: {mode}")
        if status not in AUTHORIZATION_CAPABILITY_STATES:
            raise ValueError(f"invalid authorization capability status: {status}")
        if status != "available" and not str(event.get("reason") or "").strip():
            raise ValueError(f"{status} authorization capability requires reason")
    elif event_type == "request-shape":
        if not event.get("surface_ref"):
            raise ValueError("request-shape requires surface_ref")
        if not event.get("method") or not event.get("path"):
            raise ValueError("request-shape requires method and path")
        if event.get("source") not in REQUEST_SHAPE_SOURCES:
            raise ValueError(f"invalid request-shape source: {event.get('source')}")
        if event.get("semantics") not in {"read", "write"}:
            raise ValueError(
                f"invalid request-shape semantics: {event.get('semantics')}"
            )
        if event.get("safety") not in SAFETY_CLASSES:
            raise ValueError(f"invalid request-shape safety: {event.get('safety')}")
        forbidden = {
            key
            for key in (
                "body",
                "body_value",
                "headers",
                "cookies",
                "cookie",
                "token",
                "authorization",
            )
            if key in event
        }
        if forbidden:
            raise ValueError(
                "request-shape cannot persist credential or raw request values: "
                + ", ".join(sorted(forbidden))
            )
        if event.get("credential_values_persisted"):
            raise ValueError("request-shape cannot persist credential values")
    elif event_type == "phase":
        if not event.get("phase_id"):
            raise ValueError("phase requires phase_id")
        if event.get("status") not in {
            "not-started",
            "in-progress",
            "completed",
            "blocked",
            "not-applicable",
        }:
            raise ValueError(f"invalid phase status: {event.get('status')}")
    elif event_type == "history-lookup" and event.get("status") not in {
        "completed-no-match",
        "completed-with-matches",
        "blocked",
    }:
        raise ValueError(f"invalid history status: {event.get('status')}")
    elif event_type == "surface-discovered":
        surface = event.get("surface")
        if not isinstance(surface, dict):
            raise ValueError("surface-discovered requires surface object")
        if surface.get("safety") and surface["safety"] not in SAFETY_CLASSES:
            raise ValueError(f"invalid surface safety: {surface['safety']}")
    elif event_type == "variant-result":
        if not event.get("test_case_id") or not event.get("variant_id"):
            raise ValueError("variant-result requires test_case_id and variant_id")
        if event.get("status") not in RESOLVED:
            raise ValueError("variant-result requires a resolved status")
        if event.get("status") in {"tested", "not-applicable"} and not event.get(
            "evidence_refs"
        ):
            raise ValueError("variant-result tested/not-applicable requires evidence_refs")
        if event.get("status") in {"blocked", "not-applicable"} and not str(
            event.get("reason") or ""
        ).strip():
            raise ValueError("variant-result blocked/not-applicable requires reason")
    elif event_type in {"runner-checkpoint", "credential-lease-state"}:
        if not event.get("status"):
            raise ValueError(f"{event_type} requires status")
        if event_type == "credential-lease-state":
            allowed_claim_keys = {
                "source_header",
                "claim_count",
                "claim_names",
                "sensitive_claim_names",
                "values_persisted",
            }
            for summary in event.get("token_claims", []):
                if not isinstance(summary, dict) or set(summary) - allowed_claim_keys:
                    raise ValueError("credential token claim summary has invalid fields")
                if summary.get("values_persisted") is not False:
                    raise ValueError("credential token claim values cannot be persisted")
    elif event_type == "execution-audit":
        if event.get("status") not in {"passed", "blocked"}:
            raise ValueError("execution-audit status must be passed or blocked")
    elif event_type == "priority-signal":
        if event.get("target_kind") not in {"test-cell", "test-case", "candidate", "prerequisite"}:
            raise ValueError("priority-signal has invalid target_kind")
        if not event.get("target_id"):
            raise ValueError("priority-signal requires target_id")
        factor = str(event.get("factor") or "")
        if factor not in PRIORITY_SIGNAL_POINTS:
            raise ValueError(f"invalid priority signal factor: {factor}")
        if not str(event.get("reason") or "").strip() or not event.get("evidence_refs"):
            raise ValueError("priority-signal requires reason and evidence_refs")
        if "score" in event or "priority" in event:
            raise ValueError("priority-signal cannot set the final score or priority")
        if factor in NEGATIVE_PRIORITY_SIGNALS and event.get("evidence_state") not in {
            "confirmed", "exhausted-with-evidence"
        }:
            raise ValueError("negative priority signal requires confirmed evidence")
    elif event_type in {"priority-change", "queue-preemption", "starvation-promotion"}:
        if not event.get("target_id") and not event.get("deferred_id"):
            raise ValueError(f"{event_type} requires a target reference")
    elif event_type in {"route-result", "control-result"}:
        if not event.get("test_case_id"):
            raise ValueError(f"{event_type} requires test_case_id")
        if event_type == "route-result" and not event.get("route_id"):
            raise ValueError("route-result requires route_id")
        if event.get("status") not in RESOLVED:
            raise ValueError(f"invalid {event_type} status: {event.get('status')}")
        if event.get("status") in {"tested", "not-applicable"} and not event.get(
            "evidence_refs"
        ):
            raise ValueError(f"{event_type} tested/not-applicable requires evidence_refs")
        if event.get("status") in {"blocked", "not-applicable"} and not str(
            event.get("reason") or ""
        ).strip():
            raise ValueError(f"{event_type} blocked/not-applicable requires reason")
        invalid_stages = set(event.get("stages", {})) - set(ROUTE_STAGE_IDS)
        if invalid_stages:
            raise ValueError(
                "route-result contains invalid stages: "
                + ", ".join(sorted(invalid_stages))
            )
        invalid_states = {
            state
            for state in event.get("stages", {}).values()
            if state not in {"pending", "completed", "blocked", "not-applicable"}
        }
        if invalid_states:
            raise ValueError(
                "route-result contains invalid stage states: "
                + ", ".join(sorted(invalid_states))
            )
        if event_type == "route-result" and event.get("status") == "tested":
            required = {
                "current-validated",
                "navigated",
                "rendered",
                "controls-extracted",
                "runtime-api-linked",
            }
            completed = {
                stage
                for stage, state in event.get("stages", {}).items()
                if state == "completed"
            }
            if not required <= completed:
                raise ValueError(
                    "tested route-result requires all runtime route stages completed"
                )
    elif event_type == "surface-link" and not (
        event.get("from") and event.get("to") and event.get("relation")
    ):
        raise ValueError("surface-link requires from, to and relation")
    elif event_type == "missed-finding" and event.get("cause") not in MISSED_CAUSES:
        raise ValueError(f"invalid missed-finding cause: {event.get('cause')}")
    elif event_type == "evidence" and not (
        event.get("id") or event.get("path")
    ):
        raise ValueError("evidence requires id or path")
    elif event_type == "candidate-disposition" and not event.get("id"):
        raise ValueError("candidate-disposition requires id")
    elif event_type == "candidate-dependency":
        if not event.get("id") or not event.get("dependency_id"):
            raise ValueError("candidate-dependency requires id and dependency_id")
        status = event.get("status")
        if status not in CANDIDATE_DEPENDENCY_STATES:
            raise ValueError(f"invalid candidate dependency status: {status}")
        if status in CANDIDATE_DEPENDENCY_TERMINAL and not event.get(
            "evidence_refs"
        ):
            raise ValueError(f"{status} candidate dependency requires evidence_refs")
        if status in {"pending", "blocked", "exhausted-with-evidence"} and not str(
            event.get("reason") or ""
        ).strip():
            raise ValueError(f"{status} candidate dependency requires reason")
    elif event_type == "prerequisite-result":
        if not event.get("prerequisite_id"):
            raise ValueError("prerequisite-result requires prerequisite_id")
        status = event.get("status")
        if status not in PREREQUISITE_STATES:
            raise ValueError(f"invalid prerequisite status: {status}")
        if status in PREREQUISITE_FINAL and not event.get("evidence_refs"):
            raise ValueError(f"{status} prerequisite requires evidence_refs")
        if status != "satisfied" and not str(event.get("reason") or "").strip():
            raise ValueError(f"{status} prerequisite requires reason")
        if status == "exhausted-with-evidence" and int(
            event.get("stable_rounds", 0)
        ) < 2:
            raise ValueError(
                "exhausted-with-evidence prerequisite requires two stable rounds"
            )
    if event_type in {"candidate", "finding"}:
        validate_candidate_dependencies(event.get("validation_dependencies"))


def validate_test_result_for_plan(
    event: dict[str, Any],
    plan: dict[str, Any],
) -> None:
    if event.get("type") != "test-result":
        return
    cells = {
        cell["id"]: cell for cell in plan.get("test_cells", [])
        if cell.get("id")
    }
    cell = cells.get(event.get("test_cell_id"))
    if not cell:
        return
    cases = {
        case["id"]: case
        for case in plan.get("executable_cases", [])
        if case.get("id")
    }
    related = [
        case
        for case in cases.values()
        if case.get("test_cell_id") == cell["id"]
    ]
    case_id = event.get("test_case_id")
    case = cases.get(str(case_id)) if case_id else None
    if case_id and (
        not case or case.get("test_cell_id") != cell["id"]
    ):
        raise ValueError(
            "test-result test_case_id does not belong to test_cell_id"
        )
    mode = cell.get("dimensions", {}).get("authorization_mode")
    if mode and event.get("status") == "tested":
        evidence_types = {
            str(item) for item in event.get("authorization_evidence", [])
        }
        required = AUTHORIZATION_EVIDENCE_BY_MODE[mode]
        if not evidence_types & required:
            raise ValueError(
                "authorization tested result requires one of: "
                + ", ".join(sorted(required))
            )
        if related and case is None:
            raise ValueError(
                "authorization tested result requires test_case_id "
                "when executable cases exist"
            )
    if (
        case
        and case["safety"] == "reversible"
        and event.get("status") == "tested"
        and (event.get("cleanup") or {}).get("status")
        not in {"completed", "documented"}
    ):
        raise ValueError("tested reversible case requires completed cleanup")


def apply_precompile_events(
    workspace: Path,
    coverage: dict[str, Any],
) -> None:
    for event in read_events(workspace):
        event_type = event.get("type")
        if event_type in {"identity", "business-state"}:
            key = "identities" if event_type == "identity" else "business_states"
            item_id = str(event.get("id") or "").strip()
            if not item_id:
                raise ValueError(f"{event_type} requires id")
            values = {
                item["id"]: item
                for item in coverage.setdefault("dimensions", {}).setdefault(
                    key, []
                )
            }
            values[item_id] = {
                "id": item_id,
                "status": event.get("status", "observed"),
                "evidence_refs": event.get("evidence_refs", []),
            }
            coverage["dimensions"][key] = sorted(
                values.values(), key=lambda item: item["id"]
            )
        elif event_type == "authorization-capability":
            values = {
                item["id"]: item
                for item in coverage.setdefault("dimensions", {}).setdefault(
                    "authorization_capabilities", []
                )
                if item.get("id")
            }
            item_id = str(event["id"])
            values[item_id] = {
                "id": item_id,
                "status": event["status"],
                "reason": event.get("reason"),
                "evidence_refs": [
                    str(item) for item in event.get("evidence_refs", [])
                ],
                "cleanup_evidence_refs": [
                    str(item)
                    for item in event.get("cleanup_evidence_refs", [])
                ],
                "source": "event",
            }
            coverage["dimensions"]["authorization_capabilities"] = sorted(
                values.values(), key=lambda item: item["id"]
            )
        elif event_type == "history-lookup":
            coverage["history"].update(
                {
                    "lookup_state": event.get("status", "completed-no-match"),
                    "target_keys": event.get("target_keys", []),
                    "matches": event.get("matches", []),
                    "evidence_refs": event.get("evidence_refs", []),
                }
            )
        elif event_type == "phase":
            phase_id = event.get("phase_id")
            for phase in coverage["phases"]:
                if phase["id"] == phase_id:
                    phase.update(
                        {
                            "status": event.get("status", phase["status"]),
                            "evidence_refs": event.get("evidence_refs", []),
                            "gaps": event.get("gaps", []),
                        }
                    )
                    break
        elif event_type == "credential-state":
            coverage["runtime"]["credential_state"] = event.get(
                "status", "unavailable"
            )
            coverage["runtime"]["credential_reason"] = event.get("reason")


def apply_events(
    workspace: Path,
    coverage: dict[str, Any],
    plan: dict[str, Any],
    inventory: dict[str, Any],
    evidence_index: dict[str, Any],
) -> None:
    cells = {cell["id"]: cell for cell in plan["test_cells"]}
    cases = {
        case["id"]: case for case in plan.get("executable_cases", [])
    }
    cases_by_cell: dict[str, list[dict[str, Any]]] = {}
    for case in cases.values():
        cases_by_cell.setdefault(case["test_cell_id"], []).append(case)
    candidates = {item["id"]: item for item in coverage.get("candidates", [])}
    findings = {item["id"]: item for item in coverage.get("findings", [])}
    missed = {item["id"]: item for item in coverage.get("missed_findings", [])}
    evidence = {
        item["id"]: item for item in evidence_index.get("evidence", [])
    }
    for event in read_events(workspace):
        event_type = event.get("type")
        event_time = event.get("recorded_at") or now()
        if event_type == "variant-result":
            case_id = str(event.get("test_case_id") or "")
            case = cases.get(case_id)
            if case is None:
                plan.setdefault("orphaned_events", []).append(
                    {
                        "type": event_type,
                        "reference": case_id,
                        "reason": "unknown-test-case",
                        "recorded_at": event_time,
                    }
                )
                continue
            variant_id = str(event["variant_id"])
            if variant_id not in case.get("variants", []):
                plan.setdefault("orphaned_events", []).append(
                    {
                        "type": event_type,
                        "reference": f"{case_id}:{variant_id}",
                        "reason": "unknown-case-variant",
                        "recorded_at": event_time,
                    }
                )
                continue
            case.setdefault("variant_results", {})[variant_id] = {
                "status": event["status"],
                "reason": event.get("reason"),
                "evidence_refs": [str(item) for item in event.get("evidence_refs", [])],
                "oracle": event.get("oracle", {}),
                "updated_at": event_time,
            }
        elif event_type == "test-result":
            cell_id = event.get("test_cell_id")
            if cell_id not in cells:
                plan.setdefault("orphaned_events", []).append(
                    {
                        "type": event_type,
                        "reference": cell_id,
                        "reason": "unknown-test-cell",
                        "recorded_at": event_time,
                    }
                )
                continue
            if (
                event.get("negative_result")
                and event.get("surface_fingerprint")
                and event["surface_fingerprint"]
                != cells[cell_id].get("surface_fingerprint")
            ):
                cells[cell_id].update(
                    {
                        "status": "queued",
                        "reason": "negative-result-invalidated-by-surface-change",
                        "evidence_refs": [],
                        "negative_result": None,
                        "updated_at": event_time,
                    }
                )
                continue
            status = event.get("status")
            if status not in RESOLVED:
                raise ValueError(f"invalid test-result status: {status}")
            refs = [str(item) for item in event.get("evidence_refs", [])]
            reason = str(event.get("reason") or "").strip()
            if status in {"tested", "not-applicable"} and not refs:
                raise ValueError(f"{status} requires evidence_refs")
            if status in {"blocked", "not-applicable"} and not reason:
                raise ValueError(f"{status} requires reason")
            cell = cells[cell_id]
            validate_test_result_for_plan(event, plan)
            case_id = event.get("test_case_id")
            if case_id:
                case = cases.get(str(case_id))
            else:
                case = None
            result_values = {
                "status": status,
                "reason": reason or None,
                "evidence_refs": refs,
                "cleanup": event.get("cleanup"),
                "negative_result": event.get("negative_result"),
                "updated_at": event_time,
            }
            if case is not None:
                case.update(result_values)
                related = cases_by_cell[cell_id]
                unresolved = [
                    item for item in related if item["status"] not in RESOLVED
                ]
                cell["evidence_refs"] = sorted(
                    {
                        ref
                        for item in related
                        for ref in item.get("evidence_refs", [])
                    }
                )
                cell["updated_at"] = event_time
                if unresolved:
                    cell["status"] = "queued"
                    cell["reason"] = (
                        f"{len(unresolved)} executable cases unresolved"
                    )
                elif all(item["status"] == "not-applicable" for item in related):
                    cell["status"] = "not-applicable"
                    cell["reason"] = "all executable cases not applicable"
                elif any(item["status"] == "blocked" for item in related):
                    cell["status"] = "blocked"
                    cell["reason"] = "one or more executable cases blocked"
                else:
                    cell["status"] = "tested"
                    cell["reason"] = None
                if all(
                    item["safety"] != "reversible"
                    or (item.get("cleanup") or {}).get("status")
                    in {"completed", "documented"}
                    for item in related
                ):
                    cell["cleanup"] = {"status": "completed"}
            else:
                cell.update(result_values)
            if event.get("negative_result"):
                cell["surface_fingerprint"] = cell.get(
                    "surface_fingerprint"
                )
        elif event_type in {"identity", "business-state"}:
            key = "identities" if event_type == "identity" else "business_states"
            item_id = str(event.get("id") or "").strip()
            if not item_id:
                raise ValueError(f"{event_type} requires id")
            values = {
                item["id"]: item
                for item in coverage.setdefault("dimensions", {}).setdefault(
                    key, []
                )
            }
            values[item_id] = {
                "id": item_id,
                "status": event.get("status", "observed"),
                "evidence_refs": event.get("evidence_refs", []),
            }
            coverage["dimensions"][key] = sorted(
                values.values(), key=lambda item: item["id"]
            )
        elif event_type == "authorization-capability":
            # Precompile handling generated the effective matrix. Replaying here
            # keeps the event authoritative after any derived defaults.
            values = {
                item["id"]: item
                for item in coverage.setdefault("dimensions", {}).setdefault(
                    "authorization_capabilities", []
                )
                if item.get("id")
            }
            item_id = str(event["id"])
            values[item_id] = {
                "id": item_id,
                "status": event["status"],
                "reason": event.get("reason"),
                "evidence_refs": [
                    str(item) for item in event.get("evidence_refs", [])
                ],
                "cleanup_evidence_refs": [
                    str(item)
                    for item in event.get("cleanup_evidence_refs", [])
                ],
                "source": "event",
            }
            coverage["dimensions"]["authorization_capabilities"] = sorted(
                values.values(), key=lambda item: item["id"]
            )
        elif event_type == "history-lookup":
            coverage["history"].update(
                {
                    "lookup_state": event.get("status", "completed-no-match"),
                    "target_keys": event.get("target_keys", []),
                    "matches": event.get("matches", []),
                    "evidence_refs": event.get("evidence_refs", []),
                }
            )
        elif event_type == "phase":
            phase_id = event.get("phase_id")
            matched = False
            for phase in coverage["phases"]:
                if phase["id"] == phase_id:
                    matched = True
                    phase.update(
                        {
                            "status": event.get("status", phase["status"]),
                            "evidence_refs": event.get("evidence_refs", []),
                            "gaps": event.get("gaps", []),
                        }
                    )
                    break
            if not matched:
                plan.setdefault("orphaned_events", []).append(
                    {
                        "type": event_type,
                        "reference": phase_id,
                        "reason": "unknown-phase",
                        "recorded_at": event_time,
                    }
                )
        elif event_type in {"candidate", "finding"}:
            item_id = str(
                event.get("id")
                or stable_id(
                    "finding",
                    {
                        "title": event.get("title"),
                        "surface_refs": event.get("surface_refs", []),
                    },
                )
            )
            item = normalize_conclusion_event(event, event_type, item_id)
            item["recorded_at"] = event_time
            weak_authorization_evidence = event.get(
                "authorization_evidence_quality"
            ) in {
                "ui-hidden-only",
                "request-handler-only",
                "nonexistent-object-only",
                "validation-error-only",
            }
            policy_or_impact = bool(
                event.get("policy_evidence_refs")
                or event.get("impact_evidence_refs")
            )
            authorization_confirmable = not weak_authorization_evidence
            if event.get("authorization_mode") == "low-privilege-function":
                authorization_confirmable = (
                    authorization_confirmable and policy_or_impact
                )
            if (
                event_type == "finding"
                and item.get("validation_state") == "confirmed"
                and item.get("evidence_refs")
                and authorization_confirmable
                and finding_dependencies_satisfied(item)
                and not security_conclusion.validate(item)
            ):
                findings[item_id] = item
                candidates.pop(item_id, None)
            else:
                item["type"] = "candidate"
                item["validation_state"] = item.get("validation_state", "candidate")
                if event_type == "finding" and not finding_dependencies_satisfied(item):
                    item["confirmation_blocker"] = (
                        "one or more validation prerequisites remain unresolved"
                    )
                candidates[item_id] = item
        elif event_type == "candidate-dependency":
            item_id = str(event.get("id") or "")
            candidate = candidates.get(item_id)
            if candidate is None:
                plan.setdefault("orphaned_events", []).append(
                    {
                        "type": event_type,
                        "reference": item_id,
                        "reason": "unknown-candidate",
                        "recorded_at": event_time,
                    }
                )
                continue
            dependency_id = str(event.get("dependency_id") or "")
            dependencies = {
                str(item.get("id")): item
                for item in candidate.get("validation_dependencies", [])
                if item.get("id")
            }
            dependency = dependencies.get(dependency_id)
            if dependency is None:
                plan.setdefault("orphaned_events", []).append(
                    {
                        "type": event_type,
                        "reference": f"{item_id}:{dependency_id}",
                        "reason": "unknown-candidate-dependency",
                        "recorded_at": event_time,
                    }
                )
                continue
            dependency.update(
                {
                    "status": event["status"],
                    "reason": event.get("reason"),
                    "evidence_refs": [
                        str(item) for item in event.get("evidence_refs", [])
                    ],
                    "updated_at": event_time,
                }
            )
            candidate["validation_dependencies"] = sorted(
                dependencies.values(), key=lambda item: str(item["id"])
            )
            candidate["updated_at"] = event_time
        elif event_type == "prerequisite-result":
            if event.get("owner_kind") != "candidate":
                continue
            item_id = str(event.get("owner_id") or "")
            candidate = candidates.get(item_id)
            dependency_id = str(event.get("legacy_dependency_id") or "")
            if candidate is None or not dependency_id:
                continue
            dependencies = {
                str(item.get("id")): item
                for item in candidate.get("validation_dependencies", [])
                if item.get("id")
            }
            dependency = dependencies.get(dependency_id)
            if dependency is None:
                continue
            dependency.update(
                {
                    "status": {
                        "blocked-external": "blocked",
                    }.get(event["status"], event["status"]),
                    "reason": event.get("reason"),
                    "evidence_refs": [
                        str(item) for item in event.get("evidence_refs", [])
                    ],
                    "updated_at": event_time,
                }
            )
            candidate["validation_dependencies"] = sorted(
                dependencies.values(), key=lambda item: str(item["id"])
            )
            candidate["updated_at"] = event_time
        elif event_type == "candidate-disposition":
            item_id = str(event.get("id") or "")
            if item_id in candidates:
                candidates[item_id]["disposition"] = event.get("disposition")
                candidates[item_id]["reason"] = event.get("reason")
                candidates[item_id]["updated_at"] = event_time
            else:
                plan.setdefault("orphaned_events", []).append(
                    {
                        "type": event_type,
                        "reference": item_id,
                        "reason": "unknown-candidate",
                        "recorded_at": event_time,
                    }
                )
        elif event_type == "missed-finding":
            cause = event.get("cause")
            if cause not in MISSED_CAUSES:
                raise ValueError(f"invalid missed-finding cause: {cause}")
            item_id = str(
                event.get("id")
                or stable_id(
                    "missed",
                    {
                        "title": event.get("title"),
                        "cause": cause,
                        "surface_refs": event.get("surface_refs", []),
                    },
                )
            )
            missed[item_id] = {
                **event,
                "id": item_id,
                "recorded_at": event_time,
                "learning_state": event.get("learning_state", "candidate"),
            }
        elif event_type == "evidence":
            item_id = str(
                event.get("id")
                or stable_id(
                    "evidence",
                    {
                        "path": event.get("path"),
                        "sha256": event.get("sha256"),
                        "kind": event.get("kind"),
                    },
                )
            )
            evidence[item_id] = {
                **event,
                "id": item_id,
                "recorded_at": event_time,
            }
        elif event_type == "credential-state":
            coverage["runtime"]["credential_state"] = event.get(
                "status", "unavailable"
            )
            coverage["runtime"]["credential_reason"] = event.get("reason")
        elif event_type == "credential-lease-state":
            coverage["runtime"]["credential_lease"] = {
                "status": event.get("status"),
                "source": event.get("source"),
                "header_names": sorted(str(item) for item in event.get("header_names", [])),
                "fingerprint": event.get("fingerprint"),
                "token_claims": copy.deepcopy(event.get("token_claims", [])),
                "reason": event.get("reason"),
                "recorded_at": event_time,
            }
        elif event_type == "runner-checkpoint":
            coverage["runtime"]["runner_required"] = True
            coverage["runtime"]["runner_state"] = event.get("status")
            coverage["runtime"]["runner_checkpoint"] = {
                "phase": event.get("phase"),
                "iteration": event.get("iteration", 0),
                "reason": event.get("reason"),
                "recorded_at": event_time,
            }
        elif event_type == "execution-audit":
            coverage["runtime"]["runner_required"] = True
            coverage["runtime"]["execution_audit"] = {
                "status": event.get("status"),
                "counts": event.get("counts", {}),
                "gaps": event.get("gaps", []),
                "evidence_refs": event.get("evidence_refs", []),
                "recorded_at": event_time,
            }
        elif event_type == "runtime-condition":
            coverage["runtime"].setdefault("conditions", []).append(
                {
                    "kind": event.get("kind"),
                    "status": event.get("status"),
                    "reason": event.get("reason"),
                    "retry_after": event.get("retry_after"),
                    "recorded_at": event_time,
                }
            )
    plan["test_cells"] = sorted(
        cells.values(),
        key=lambda cell: (
            int(cell["priority"][1]),
            -cell["risk_score"],
            cell["id"],
        ),
    )
    plan["executable_cases"] = sorted(
        cases.values(),
        key=lambda case: (
            int(cells[case["test_cell_id"]]["priority"][1]),
            -cells[case["test_cell_id"]]["risk_score"],
            case["id"],
        ),
    )
    coverage["candidates"] = sorted(candidates.values(), key=lambda item: item["id"])
    coverage["findings"] = sorted(findings.values(), key=lambda item: item["id"])
    coverage["missed_findings"] = sorted(
        missed.values(), key=lambda item: item["id"]
    )
    evidence_index["evidence"] = sorted(
        evidence.values(), key=lambda item: item["id"]
    )


def derive_family_status(cells: list[dict[str, Any]]) -> tuple[str, list[str]]:
    if not cells:
        return "mapped", ["no applicable test cell generated"]
    states = {cell["status"] for cell in cells}
    if states <= {"tested"}:
        return "tested", []
    if states <= {"not-applicable"}:
        return "not-applicable", []
    if states <= SCHEDULING_TERMINAL and "blocked" in states:
        return "blocked", [
            cell.get("reason") or "blocked without reason"
            for cell in cells
            if cell["status"] == "blocked"
        ]
    return "mapped", [
        f"{sum(cell['status'] not in COVERAGE_SATISFIED for cell in cells)} test cells unresolved"
    ]


def derive_coverage(
    coverage: dict[str, Any],
    plan: dict[str, Any],
    inventory: dict[str, Any],
    evidence_index: dict[str, Any],
    route_inventory: dict[str, Any],
) -> None:
    cells_by_family: dict[str, list[dict[str, Any]]] = {}
    for cell in plan["test_cells"]:
        cells_by_family.setdefault(cell["family"], []).append(cell)
    for domain in coverage["coverage"]:
        domain_gaps = []
        domain_states = []
        for family in domain["families"]:
            status, gaps = derive_family_status(cells_by_family.get(family["id"], []))
            family["status"] = status
            family["gaps"] = gaps
            family["test_cell_refs"] = sorted(
                cell["id"] for cell in cells_by_family.get(family["id"], [])
            )
            domain_states.append(status)
            domain_gaps.extend(gaps)
        if domain_states and set(domain_states) <= {"tested", "not-applicable"}:
            domain["status"] = "tested"
        elif domain_states and set(domain_states) <= SCHEDULING_TERMINAL:
            domain["status"] = "blocked"
        else:
            domain["status"] = "mapped"
        domain["gaps"] = sorted(set(domain_gaps))
    unresolved_cells = [
        cell
        for cell in plan["test_cells"]
        if cell["status"] not in COVERAGE_SATISFIED
    ]
    unresolved_candidates = [
        item
        for item in coverage.get("candidates", [])
        if not candidate_resolution_complete(item)
    ]
    candidate_prerequisite_gaps = [
        f"{candidate.get('id')}:{dependency.get('id')}"
        for candidate in coverage.get("candidates", [])
        for dependency in candidate_dependency_gaps(candidate)
    ]
    cleanup_gaps = [
        cell["id"]
        for cell in plan["test_cells"]
        if cell["safety"] == "reversible"
        and cell["status"] != "not-applicable"
        and (cell.get("cleanup") or {}).get("status")
        not in {"completed", "documented"}
    ]
    unresolved_cases = [
        case
        for case in plan.get("executable_cases", [])
        if case["status"] not in COVERAGE_SATISFIED
    ]
    phases_resolved = all(
        phase["status"] in {"completed", "not-applicable"}
        for phase in coverage["phases"]
    )
    history_checked = coverage["history"]["lookup_state"] in {
        "completed-no-match",
        "completed-with-matches",
        "blocked",
    }
    inventory_accounted = not inventory.get("blockers")
    domains_resolved = all(
        domain["status"] == "tested"
        for domain in coverage["coverage"]
    )
    evidence_refs = {
        ref
        for cell in plan["test_cells"]
        for ref in cell.get("evidence_refs", [])
    }
    evidence_refs.update(
        ref
        for case in plan.get("executable_cases", [])
        for ref in case.get("evidence_refs", [])
    )
    indexed_paths = {
        item.get("path") or item.get("id")
        for item in evidence_index.get("evidence", [])
    }
    evidence_indexed = not evidence_refs or evidence_refs <= indexed_paths
    route_cases = [
        case
        for case in plan.get("executable_cases", [])
        if case.get("case_kind") == "route-navigation"
    ]
    control_cases = [
        case
        for case in plan.get("executable_cases", [])
        if case.get("case_kind") == "ui-interaction"
    ]
    api_cases = [
        case
        for case in plan.get("executable_cases", [])
        if case.get("case_kind") == "api-test"
    ]
    route_summary = route_inventory.get("summary", {})
    route_count = route_summary.get("discovered", 0)
    route_current_complete = not route_count or route_summary.get(
        "current_validated", 0
    ) == route_count
    route_render_complete = not route_count or (
        route_summary.get("rendered", 0)
        + route_summary.get("not_applicable", 0)
        == route_count
    )
    route_api_links_complete = not route_count or route_summary.get(
        "runtime_api_links_accounted", 0
    ) == route_count
    route_tests_complete = not route_count or route_summary.get(
        "tests_resolved", 0
    ) == route_count
    route_cases_complete = all(
        case["status"] in {"tested", "not-applicable"} for case in route_cases
    )
    controls_complete = all(
        case["status"] in {"tested", "not-applicable"}
        for case in control_cases
    )
    discovery_queue_exhausted = not any(
        re.search(r"queue|navigation.*(?:failed|remain)|routes? not runtime", blocker, re.I)
        for blocker in inventory.get("blockers", [])
    )
    runner_required = bool(coverage.get("runtime", {}).get("runner_required"))
    auto_cases = [
        case
        for case in plan.get("executable_cases", [])
        if case.get("automation_state") == "auto-ready"
    ]
    needs_agent_cases = [
        case
        for case in plan.get("executable_cases", [])
        if case.get("automation_state") == "needs-agent"
        and case.get("status") not in COVERAGE_SATISFIED
    ]
    variant_total = sum(len(case.get("variants", [])) for case in auto_cases)
    variant_resolved = sum(
        result.get("status") in COVERAGE_SATISFIED
        for case in auto_cases
        for result in case.get("variant_results", {}).values()
    )
    auto_resolved = sum(
        case.get("status") in COVERAGE_SATISFIED for case in auto_cases
    )
    audit = coverage.get("runtime", {}).get("execution_audit", {})
    credential_lease = coverage.get("runtime", {}).get("credential_lease", {})
    auto_queue_complete = auto_resolved == len(auto_cases)
    variants_complete = variant_resolved == variant_total
    agent_queue_complete = not needs_agent_cases
    credential_accounted = credential_lease.get("status") in {
        "available",
        "anonymous-only",
        "expired",
        "unavailable",
        "consumed",
    }
    audit_passed = audit.get("status") == "passed"
    discovery_saturated = (
        discovery_queue_exhausted
        and route_current_complete
        and route_render_complete
        and route_api_links_complete
    )
    gates = {
        "surface_inventory_accounted": inventory_accounted,
        "historical_baseline_checked": history_checked,
        "discovery_phases_resolved": phases_resolved,
        "work_units_compiled": bool(plan["work_units"]),
        "applicable_families_resolved": domains_resolved,
        "test_queue_resolved": not unresolved_cells,
        "high_risk_candidates_resolved": not unresolved_candidates,
        "candidate_prerequisites_resolved": not candidate_prerequisite_gaps,
        "test_prerequisites_resolved": not plan.get(
            "unresolved_prerequisite_refs", []
        ),
        "adjacent_surfaces_checked": coverage["phases"][-1]["status"]
        in {"completed", "not-applicable"},
        "evidence_indexed": evidence_indexed,
        "cleanup_complete_or_documented": not cleanup_gaps,
        "standards_snapshot_recorded": all(
            standard.get("version")
            and standard.get("source_ref")
            and standard.get("source_commit")
            for standard in coverage["standards"]
        ),
        "event_log_resolved": not plan.get("orphaned_events"),
        "route_inventory_current_validated": route_current_complete,
        "route_navigation_and_render_complete": (
            route_cases_complete and route_render_complete
        ),
        "visible_controls_resolved": controls_complete,
        "runtime_api_links_accounted": route_api_links_complete,
        "route_tests_resolved": route_tests_complete,
        "discovery_queue_exhausted": discovery_queue_exhausted,
        "auto_safe_queue_exhausted": (
            auto_queue_complete if runner_required else True
        ),
        "variant_matrix_resolved": (
            variants_complete if runner_required else True
        ),
        "agent_review_queue_resolved": (
            agent_queue_complete if runner_required else True
        ),
        "agent_roles_resolved": (
            agent_queue_complete if runner_required else True
        ),
        "discovery_saturation_confirmed": discovery_saturated,
        "credential_requirements_accounted": (
            credential_accounted if runner_required else True
        ),
        "independent_execution_audit_passed": (
            audit_passed if runner_required else True
        ),
    }
    coverage["stop_gates"] = gates
    coverage["assessment_state"] = (
        "complete" if gates and all(gates.values()) else "interim"
    )
    coverage["inventory_summary"] = inventory["totals"]
    tested_api_refs = {
        case.get("surface_ref")
        for case in api_cases
        if case.get("status") == "tested"
    }
    blocked_api_refs = {
        case.get("surface_ref")
        for case in api_cases
        if case.get("status") == "blocked"
    }
    waiting_api_refs = {
        case.get("surface_ref")
        for case in api_cases
        if case.get("status") == "waiting-prerequisite"
    }
    api_surfaces = [
        surface for surface in inventory.get("surfaces", []) if surface["kind"] == "api"
    ]
    coverage["route_coverage"] = {
        **route_summary,
        "unresolved": sum(
            case["status"] not in {"tested", "not-applicable"}
            for case in route_cases
        ),
    }
    coverage["surface_execution_summary"] = {
        "routes": {
            "discovered": route_count,
            "current_validated": route_summary.get("current_validated", 0),
            "tested": route_summary.get("route_cases_tested", 0),
            "blocked": route_summary.get("blocked", 0),
            "waiting_prerequisite": sum(
                case.get("status") == "waiting-prerequisite"
                for case in route_cases
            ),
        },
        "apis": {
            "discovered": len(api_surfaces),
            "current_validated": sum(
                surface.get("validation_state")
                in {"runtime-observed", "reachable", "recognized", "documented"}
                for surface in api_surfaces
            ),
            "tested": len(tested_api_refs - {None}),
            "blocked": len(blocked_api_refs - {None}),
            "waiting_prerequisite": len(waiting_api_refs - {None}),
        },
        "controls": {
            "discovered": len(control_cases),
            "current_validated": len(control_cases),
            "tested": sum(case["status"] == "tested" for case in control_cases),
            "blocked": sum(case["status"] == "blocked" for case in control_cases),
            "waiting_prerequisite": sum(
                case["status"] == "waiting-prerequisite"
                for case in control_cases
            ),
        },
    }
    coverage["execution_coverage"] = {
        "auto_cases": len(auto_cases),
        "auto_resolved": auto_resolved,
        "variants": variant_total,
        "variants_resolved": variant_resolved,
        "needs_agent": len(needs_agent_cases),
        "audit_passed": audit_passed,
        "candidate_prerequisite_gaps": len(candidate_prerequisite_gaps),
        "test_prerequisite_gaps": len(
            plan.get("unresolved_prerequisite_refs", [])
        ),
    }
    coverage["candidate_prerequisite_gaps"] = candidate_prerequisite_gaps
    coverage["execution_lanes"] = {
        lane: {
            "total": int(values.get("total", 0)),
            "resolved": int(values.get("resolved", 0)),
            "remaining": len(values.get("queue", [])),
            "queue_refs": list(values.get("queue", [])),
            **(
                {
                    "first_finding_at": min(
                        (
                            str(item.get("recorded_at") or item.get("updated_at"))
                            for item in coverage.get("findings", [])
                            if item.get("recorded_at") or item.get("updated_at")
                        ),
                        default=None,
                    )
                }
                if lane == "fast-find"
                else {}
            ),
        }
        for lane, values in plan.get("execution_lanes", {}).items()
    }
    coverage["protocol_profiles"] = [
        {
            "id": profile,
            "status": "accounted",
            "surface_refs": sorted(
                surface["id"]
                for surface in inventory.get("surfaces", [])
                if profile in set(infer_profiles([surface]))
            ),
        }
        for profile in inventory.get("profiles", [])
    ]
    coverage["discovery_rounds"] = [
        {
            "id": "current-inventory",
            "status": "saturated" if discovery_saturated else "in-progress",
            "surface_fingerprint": hashlib.sha256(
                json.dumps(
                    sorted(surface["id"] for surface in inventory.get("surfaces", []))
                ).encode()
            ).hexdigest(),
            "queue_empty": discovery_queue_exhausted,
            "required_stable_rounds": 2,
            "observed_stable_rounds": 2 if discovery_saturated else 0,
        }
    ]
    coverage["queue_summary"] = {
        "total": len(plan["test_cells"]),
        "unresolved": len(unresolved_cells),
        "blocked": sum(
            cell["status"] == "blocked" for cell in plan["test_cells"]
        ),
        "waiting_prerequisite": sum(
            cell["status"] == "waiting-prerequisite"
            for cell in plan["test_cells"]
        ),
        "by_priority": {
            bucket: sum(
                cell["priority"] == bucket
                and cell["status"] not in COVERAGE_SATISFIED
                for cell in plan["test_cells"]
            )
            for bucket in ("P0", "P1", "P2", "P3")
        },
        "executable_cases": {
            "total": len(plan.get("executable_cases", [])),
            "unresolved": len(unresolved_cases),
            "actionable": sum(
                case["status"] not in COVERAGE_SATISFIED
                and case["safety"] in ACTIONABLE_SAFETY
                for case in plan.get("executable_cases", [])
            ),
        },
        "authorization_modes": {
            mode: {
                "capability": next(
                    (
                        item.get("status")
                        for item in coverage.get("dimensions", {}).get(
                            "authorization_capabilities", []
                        )
                        if item.get("id") == mode
                    ),
                    "unavailable",
                ),
                "cells": sum(
                    cell.get("dimensions", {}).get("authorization_mode") == mode
                    for cell in plan["test_cells"]
                ),
                "unresolved": sum(
                    cell.get("dimensions", {}).get("authorization_mode") == mode
                    and cell["status"] not in COVERAGE_SATISFIED
                    for cell in plan["test_cells"]
                ),
                "blocked": sum(
                    cell.get("dimensions", {}).get("authorization_mode") == mode
                    and cell["status"] == "blocked"
                    for cell in plan["test_cells"]
                ),
            }
            for mode in sorted(AUTHORIZATION_MODES)
        },
    }
    coverage["updated_at"] = now()


def render_results(
    coverage: dict[str, Any],
    inventory: dict[str, Any],
    plan: dict[str, Any],
) -> str:
    queue = coverage["queue_summary"]
    lines = [
        "# Web Assessment Results",
        "",
        f"- Assessment state: `{coverage['assessment_state']}`",
        f"- Final: `{'true' if coverage['assessment_state'] == 'complete' else 'false'}`",
        f"- Target: `{coverage['target']}`",
        f"- Assessment ID: `{coverage['assessment_id']}`",
        f"- Normalized surfaces: {inventory['totals']['surfaces']}",
        f"- Source surface records: {inventory['totals'].get('source_records', 0)}",
        f"- Work units: {len(plan['work_units'])}",
        f"- Test cells: {queue['total']}",
        f"- Unresolved test cells: {queue['unresolved']}",
        (
            "- Executable cases: "
            f"{queue.get('executable_cases', {}).get('total', 0)}"
        ),
        (
            "- Unresolved executable cases: "
            f"{queue.get('executable_cases', {}).get('unresolved', 0)}"
        ),
        (
            "- Fast-find remaining: "
            f"{coverage.get('execution_lanes', {}).get('fast-find', {}).get('remaining', 0)}"
        ),
        (
            "- Coverage-close remaining: "
            f"{coverage.get('execution_lanes', {}).get('coverage-close', {}).get('remaining', 0)}"
        ),
        "",
        "## Surface Execution",
        "",
        "| Surface | Discovered | Current Validated | Tested | Waiting Prerequisite | Blocked |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
        *[
            "| "
            + kind.capitalize()
            + " | "
            + " | ".join(
                str(values.get(key, 0))
                for key in (
                    "discovered",
                    "current_validated",
                    "tested",
                    "waiting_prerequisite",
                    "blocked",
                )
            )
            + " |"
            for kind, values in coverage.get("surface_execution_summary", {}).items()
        ],
        "",
        "## Priority Queue",
        "",
    ]
    for bucket in ("P0", "P1", "P2", "P3"):
        lines.append(f"- `{bucket}` unresolved: {queue['by_priority'][bucket]}")
    lines.extend(["", "## Completion Gates", ""])
    for gate, passed in coverage["stop_gates"].items():
        lines.append(f"- `{gate}`: {'passed' if passed else 'blocked'}")
    lines.extend(["", "## Confirmed Vulnerabilities", ""])
    if coverage.get("findings"):
        for finding in coverage["findings"]:
            lines.append(
                f"- `{finding['id']}`: {finding.get('title', 'confirmed finding')}"
            )
    else:
        lines.append("- No confirmed vulnerabilities recorded.")
    risk_candidates = [
        item
        for item in coverage.get("candidates", [])
        if item.get("validation_state") not in {"historical", "blocked-external"}
    ]
    lines.extend(["", "## Risk Candidates", ""])
    if risk_candidates:
        for candidate in risk_candidates:
            impact = candidate.get("potential_impact") or "impact not yet established"
            lines.append(
                f"- `{candidate['id']}`: {candidate.get('title', 'risk signal')} "
                f"(priority: `{candidate.get('investigation_priority', 'medium')}`; "
                f"potential impact: {impact})"
            )
    else:
        lines.append("- No unresolved risk candidates recorded.")
    historical = [
        item for item in coverage.get("candidates", [])
        if item.get("claim_kind") == "historical-claim"
        or item.get("validation_state") == "historical"
    ]
    lines.extend(["", "## Historical Claims", ""])
    if historical:
        for item in historical:
            lines.append(
                f"- `{item['id']}`: {item.get('title', 'historical claim')} "
                f"(reported severity: `{item.get('reported_severity') or 'not-recorded'}`)"
            )
    else:
        lines.append("- No historical claims recorded.")
    external = [
        item for item in coverage.get("candidates", [])
        if item.get("validation_state") == "blocked-external"
    ]
    lines.extend(["", "## External Blockers", ""])
    if external:
        for item in external:
            actions = "; ".join(item.get("next_actions", [])) or "resume condition not recorded"
            lines.append(f"- `{item['id']}`: {item.get('title', 'blocked candidate')}; resume: {actions}")
    else:
        lines.append("- No externally blocked conclusions recorded.")
    lines.extend(["", "## Remaining Gaps", ""])
    gaps = list(inventory.get("blockers", []))
    gaps.extend(
        f"candidate prerequisite unresolved: {item}"
        for item in coverage.get("candidate_prerequisite_gaps", [])
    )
    gaps.extend(
        f"test prerequisite unresolved: {item}"
        for item in plan.get("unresolved_prerequisite_refs", [])
    )
    for domain in coverage["coverage"]:
        if domain["status"] not in {"tested"}:
            gaps.append(f"{domain['id']}: {domain['status']}")
    if gaps:
        lines.extend(f"- {gap}" for gap in gaps)
    else:
        lines.append("- None.")
    return "\n".join(lines) + "\n"


def build_attack_chain_analysis(
    coverage: dict[str, Any],
    plan: dict[str, Any],
) -> dict[str, Any]:
    """Build reference-only capability chains; never promote hypotheses."""
    cells = {item["id"]: item for item in plan.get("test_cells", [])}
    cases = {item["id"]: item for item in plan.get("executable_cases", [])}
    nodes = []
    for kind, records in (
        ("finding", coverage.get("findings", [])),
        ("candidate", coverage.get("candidates", [])),
    ):
        for item in records:
            nodes.append(
                {
                    "id": item.get("id"),
                    "kind": kind,
                    "state": item.get("validation_state", kind),
                    "surface_refs": sorted(filter(None, item.get("surface_refs", []))),
                }
            )
    for case in cases.values():
        cell = cells.get(case.get("test_cell_id"), {})
        if cell.get("status") not in {"tested", "blocked"}:
            continue
        nodes.append(
            {
                "id": case["id"],
                "kind": "tested-capability" if case.get("status") == "tested" else "blocked-capability",
                "family": case.get("family") or cell.get("family"),
                "work_unit_ref": case.get("work_unit_id"),
                "surface_refs": [case["surface_ref"]] if case.get("surface_ref") else [],
            }
        )
    edges = []
    by_unit: dict[str, list[dict[str, Any]]] = {}
    for node in nodes:
        unit = str(node.get("work_unit_ref") or "")
        if unit:
            by_unit.setdefault(unit, []).append(node)
    chain_families = ("authorization.", "files-data-export.", "business-logic.", "server-side-processing.")
    for unit, grouped in by_unit.items():
        eligible = [item for item in grouped if str(item.get("family") or "").startswith(chain_families)]
        for left_index, left in enumerate(eligible):
            for right in eligible[left_index + 1 :]:
                if left.get("family") == right.get("family"):
                    continue
                edges.append(
                    {
                        "id": stable_id("chain-edge", [left["id"], right["id"]]),
                        "from": left["id"],
                        "to": right["id"],
                        "relation": "shared-control-boundary",
                        "work_unit_ref": unit,
                        "confidence": "hypothesis",
                        "reason": "compatible capabilities share a work unit; end-to-end impact is not yet proven",
                    }
                )
    return {
        "schema_version": 1,
        "generated_at": now(),
        "nodes": sorted(nodes, key=lambda item: str(item.get("id"))),
        "edges": sorted(edges, key=lambda item: item["id"]),
        "confirmation_policy": "an edge remains a hypothesis without direct current chain evidence",
    }


def migrate_coverage(value: dict[str, Any], target: str | None = None) -> dict[str, Any]:
    version = int(value.get("schema_version", 1))
    if version >= 8:
        return value
    template = read_json(TEMPLATE, {})
    if version == 7:
        migrated = copy.deepcopy(value)
        migrated["schema_version"] = 8
        for gate, default in template.get("stop_gates", {}).items():
            migrated.setdefault("stop_gates", {}).setdefault(gate, default)
        migrated["assessment_state"] = "interim"
        migrated.setdefault("migration_history", []).append(
            {
                "from_schema_version": 7,
                "to_schema_version": 8,
                "migrated_at": now(),
                "reason": "generic-prerequisite-graph-and-coverage-satisfaction-split",
            }
        )
        migrated["updated_at"] = now()
        return migrated
    if version == 6:
        migrated = copy.deepcopy(value)
        migrated["schema_version"] = 8
        migrated["mode"] = "comprehensive-fast-first"
        migrated.setdefault("knowledge_seeds", copy.deepcopy(template["knowledge_seeds"]))
        migrated.setdefault("execution_lanes", copy.deepcopy(template["execution_lanes"]))
        migrated.setdefault("migration_history", []).append(
            {
                "from_schema_version": 6,
                "to_schema_version": 8,
                "migrated_at": now(),
                "reason": "fast-find-and-coverage-close-execution-lanes",
            }
        )
        migrated["updated_at"] = now()
        return migrated
    if version == 5:
        migrated = copy.deepcopy(value)
        migrated["schema_version"] = 8
        migrated["mode"] = "comprehensive-fast-first"
        migrated.setdefault("knowledge_seeds", copy.deepcopy(template["knowledge_seeds"]))
        migrated.setdefault("execution_lanes", copy.deepcopy(template["execution_lanes"]))
        migrated["assessment_state"] = "interim"
        migrated.setdefault("discovery_rounds", [])
        migrated.setdefault("protocol_profiles", [])
        runtime = migrated.setdefault("runtime", {})
        runtime.setdefault("agent_state", "not-started")
        runtime.setdefault(
            "agent_roles",
            {"recon": "not-started", "tester": "not-started", "auditor": "not-started"},
        )
        for gate, default in template.get("stop_gates", {}).items():
            migrated.setdefault("stop_gates", {}).setdefault(gate, default)
        migrated.setdefault("migration_history", []).append(
            {
                "from_schema_version": 5,
                "to_schema_version": 8,
                "migrated_at": now(),
                "reason": "cross-platform-agent-and-discovery-saturation-contract",
            }
        )
        migrated["updated_at"] = now()
        return migrated
    if version == 4:
        migrated = copy.deepcopy(value)
        migrated["schema_version"] = 8
        migrated["mode"] = "comprehensive-fast-first"
        migrated.setdefault("knowledge_seeds", copy.deepcopy(template["knowledge_seeds"]))
        migrated.setdefault("execution_lanes", copy.deepcopy(template["execution_lanes"]))
        migrated["assessment_state"] = "interim"
        migrated.setdefault(
            "execution_coverage", copy.deepcopy(template["execution_coverage"])
        )
        runtime = migrated.setdefault("runtime", {})
        for key, default in template.get("runtime", {}).items():
            runtime.setdefault(key, copy.deepcopy(default))
        for gate, default in template.get("stop_gates", {}).items():
            migrated.setdefault("stop_gates", {}).setdefault(gate, default)
        migrated.setdefault("migration_history", []).append(
            {
                "from_schema_version": 4,
                "to_schema_version": 8,
                "migrated_at": now(),
                "reason": "deterministic-execution-runner-contract",
            }
        )
        migrated["updated_at"] = now()
        return migrated
    if version == 3:
        migrated = copy.deepcopy(value)
        migrated["schema_version"] = 8
        migrated["mode"] = "comprehensive-fast-first"
        migrated.setdefault("knowledge_seeds", copy.deepcopy(template["knowledge_seeds"]))
        migrated.setdefault("execution_lanes", copy.deepcopy(template["execution_lanes"]))
        migrated["assessment_state"] = "interim"
        migrated.setdefault("route_coverage", copy.deepcopy(template["route_coverage"]))
        migrated.setdefault("surface_execution_summary", {})
        migrated.setdefault(
            "execution_coverage", copy.deepcopy(template["execution_coverage"])
        )
        runtime = migrated.setdefault("runtime", {})
        for key, default in template.get("runtime", {}).items():
            runtime.setdefault(key, copy.deepcopy(default))
        for gate, default in template.get("stop_gates", {}).items():
            migrated.setdefault("stop_gates", {}).setdefault(gate, default)
        migrated.setdefault("migration_history", []).append(
            {
                "from_schema_version": 3,
                "to_schema_version": 8,
                "migrated_at": now(),
                "reason": "route-execution-closure-contract",
            }
        )
        migrated["updated_at"] = now()
        return migrated
    migrated = copy.deepcopy(template)
    migrated["assessment_id"] = value.get(
        "assessment_id", f"assessment-{uuid.uuid4()}"
    )
    migrated["target"] = target or value.get("target", "")
    migrated["created_at"] = value.get("created_at", now())
    migrated["updated_at"] = now()
    migrated["assessment_state"] = "interim"
    migrated["history"].update(value.get("history", {}))
    migrated["candidates"] = value.get("candidates", [])
    migrated["findings"] = value.get("findings", [])
    migrated["input_sources"] = value.get("input_sources", [])
    migrated["migration"] = {
        "from_schema_version": version,
        "migrated_at": now(),
        "legacy_source": value,
    }
    old_phases = {
        item["id"]: item for item in value.get("phases", value.get("passes", []))
    }
    phase_aliases = {
        "historical-differential": "history-cold-start",
        "runtime-baseline": "runtime-collection",
        "active-hypotheses": "risk-execution",
        "adjacent-expansion": "adjacent-replan",
    }
    for old_id, item in old_phases.items():
        new_id = phase_aliases.get(old_id, old_id)
        for phase in migrated["phases"]:
            if phase["id"] == new_id:
                phase["status"] = item.get("status", "not-started")
                phase["evidence_refs"] = item.get(
                    "evidence_refs", item.get("evidence", [])
                )
                phase["gaps"] = item.get("gaps", [])
    old_domains = {item["id"]: item for item in value.get("coverage", [])}
    for domain in migrated["coverage"]:
        if domain["id"] in old_domains:
            old = old_domains[domain["id"]]
            domain["legacy_status"] = old.get("status", "not-started")
            domain["legacy_evidence_refs"] = old.get(
                "evidence_refs", old.get("evidence", [])
            )
            domain["legacy_gaps"] = old.get("gaps", [])
    for key in ("identities", "roles", "business_objects"):
        values = value.get("inventory", {}).get(key, [])
        if key == "identities":
            migrated["dimensions"]["identities"] = values
    return migrated


def migrate_plan(value: dict[str, Any]) -> dict[str, Any]:
    version = int(value.get("schema_version", 1))
    if version >= 8:
        return value
    migrated = copy.deepcopy(value)
    cells = {
        item.get("id"): item
        for item in migrated.get("test_cells", [])
        if item.get("id")
    }
    for case in migrated.get("executable_cases", []):
        family = case.get("family") or cells.get(case.get("test_cell_id"), {}).get(
            "family"
        )
        if family:
            case.setdefault("family", family)
        metadata = payload_case_metadata(family, case.get("automation_state", "needs-agent"))
        for key, default in metadata.items():
            case.setdefault(key, default)
        if case.get("automation_state") == "needs-agent":
            case.setdefault("agent_role", "tester")
            case.setdefault("agent_safety", "agent-safe")
            case.setdefault("expected_event_types", ["test-result", "variant-result", "evidence"])
        prerequisite_fields = prerequisite_case_fields(family)
        prerequisite_fields.pop("required_prerequisite_kinds", None)
        for key, default in prerequisite_fields.items():
            case.setdefault(key, copy.deepcopy(default))
    migrated["schema_version"] = 8
    for case in migrated.get("executable_cases", []):
        case.setdefault("execution_lane", execution_lane(case))
        case.setdefault("knowledge_seed_refs", [])
        case.setdefault("tool_run_refs", [])
    migrated.setdefault("migration_history", []).append(
        {
            "from_schema_version": version,
            "to_schema_version": 8,
            "migrated_at": now(),
            "reason": "generic-prerequisite-graph-and-binding-contract",
        }
    )
    return migrated


def reconcile_template_schema(coverage: dict[str, Any]) -> bool:
    template = read_json(TEMPLATE, {})
    template_hash = hashlib.sha256(TEMPLATE.read_bytes()).hexdigest()
    changed = False
    added_families: list[str] = []
    for key, value in template.items():
        if key in {"coverage", "phases", "stop_gates"}:
            continue
        if key not in coverage:
            coverage[key] = copy.deepcopy(value)
            changed = True
    dimensions = coverage.setdefault("dimensions", {})
    for key, value in template.get("dimensions", {}).items():
        if key not in dimensions:
            dimensions[key] = copy.deepcopy(value)
            changed = True
    phases = {
        phase["id"]: phase
        for phase in coverage.setdefault("phases", [])
        if phase.get("id")
    }
    for phase in template.get("phases", []):
        if phase["id"] not in phases:
            coverage["phases"].append(copy.deepcopy(phase))
            changed = True
    coverage["phases"] = sorted(
        coverage["phases"],
        key=lambda item: [
            phase["id"] for phase in template.get("phases", [])
        ].index(item["id"])
        if item["id"] in {
            phase["id"] for phase in template.get("phases", [])
        }
        else len(template.get("phases", [])),
    )
    domains = {
        domain["id"]: domain
        for domain in coverage.setdefault("coverage", [])
        if domain.get("id")
    }
    for template_domain in template.get("coverage", []):
        domain = domains.get(template_domain["id"])
        if domain is None:
            domain = copy.deepcopy(template_domain)
            coverage["coverage"].append(domain)
            domains[domain["id"]] = domain
            added_families.extend(
                family["id"] for family in domain.get("families", [])
            )
            changed = True
            continue
        families = {
            family["id"]: family
            for family in domain.setdefault("families", [])
            if family.get("id")
        }
        for family in template_domain.get("families", []):
            if family["id"] not in families:
                domain["families"].append(copy.deepcopy(family))
                added_families.append(family["id"])
                changed = True
    gates = coverage.setdefault("stop_gates", {})
    for gate, default in template.get("stop_gates", {}).items():
        if gate not in gates:
            gates[gate] = default
            changed = True
    if coverage.get("planner_template_sha256") != template_hash:
        coverage["planner_template_sha256"] = template_hash
        changed = True
    if added_families:
        coverage.setdefault("schema_revisions", []).append(
            {
                "at": now(),
                "kind": "additive-template-reconciliation",
                "added_families": sorted(added_families),
                "template_sha256": template_hash,
            }
        )
    return changed


def ensure_workspace(workspace: Path, target: str | None = None) -> dict[str, Any]:
    coverage_path = workspace / "coverage.json"
    if not coverage_path.exists():
        if not target:
            raise FileNotFoundError(
                f"{coverage_path} does not exist; run init with --target"
            )
        initialize(workspace, target)
    coverage = read_json(coverage_path, {})
    if int(coverage.get("schema_version", 1)) < 8:
        coverage = migrate_coverage(coverage, target)
        atomic_json(coverage_path, coverage)
    if reconcile_template_schema(coverage):
        atomic_json(coverage_path, coverage)
    plan_path = workspace / "test-plan.json"
    if plan_path.exists():
        plan = read_json(plan_path, {})
        if int(plan.get("schema_version", 1)) < 8:
            atomic_json(plan_path, migrate_plan(plan))
    return coverage


def initialize(workspace: Path, target: str) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    coverage_path = workspace / "coverage.json"
    if coverage_path.exists():
        ensure_workspace(workspace, target)
        print(f"[resume] {workspace}")
        return
    template = read_json(TEMPLATE, {})
    coverage = copy.deepcopy(template)
    coverage["assessment_id"] = f"assessment-{uuid.uuid4()}"
    coverage["target"] = normalized_target(target)
    coverage["created_at"] = now()
    coverage["updated_at"] = coverage["created_at"]
    coverage["standards"] = read_json(STANDARDS, {}).get("standards", [])
    coverage["scope"]["target_origin"] = origin(target)
    coverage["scope"]["active_origins"] = [origin(target)]
    atomic_json(coverage_path, coverage)
    atomic_json(
        workspace / "surface-inventory.json",
        {
            "schema_version": 1,
            "assessment_id": coverage["assessment_id"],
            "target": coverage["target"],
            "surfaces": [],
            "excluded_surfaces": [],
            "blockers": ["surface inputs not compiled"],
            "totals": {"surfaces": 0, "excluded": 0, "by_kind": {}},
        },
    )
    atomic_json(
        workspace / "route-inventory.json",
        {
            "schema_version": 1,
            "assessment_id": coverage["assessment_id"],
            "target": coverage["target"],
            "stage_order": list(ROUTE_STAGE_IDS),
            "routes": [],
            "surface_links": [],
            "summary": {},
        },
    )
    atomic_json(
        workspace / "test-plan.json",
        {
            "schema_version": 8,
            "assessment_id": coverage["assessment_id"],
            "generated_at": coverage["created_at"],
            "authorization_model_version": 2,
            "work_units": [],
            "test_cells": [],
            "request_shapes": [],
            "executable_cases": [],
            "queue": [],
            "execution_queue": [],
            "execution_lanes": {
                "chain-closure": {"queue": [], "resolved": 0},
                "fast-find": {"queue": [], "resolved": 0},
                "coverage-close": {"queue": [], "resolved": 0},
            },
            "replan_history": [],
        },
    )
    atomic_json(
        workspace / "evidence-index.json",
        {
            "schema_version": 1,
            "assessment_id": coverage["assessment_id"],
            "evidence": [],
        },
    )
    atomic_json(
        workspace / "prerequisite-graph.json",
        {
            "schema_version": 1,
            "assessment_id": coverage["assessment_id"],
            "generated_at": coverage["created_at"],
            "states": sorted(PREREQUISITE_STATES),
            "prerequisites": [],
            "summary": {state: 0 for state in sorted(PREREQUISITE_STATES)},
            "binding_slot_count": 0,
            "raw_value_policy": "raw values exist only in consumed mode-0600 runtime leases",
        },
    )
    atomic_json(
        workspace / "object-provenance.json",
        {
            "schema_version": 1,
            "generated_at": coverage["created_at"],
            "slots": [],
            "raw_values_persisted": False,
            "rebind_policy": "replay the current producer recipe after restart",
        },
    )
    atomic_text(
        workspace / "results.md",
        "# Web Assessment Results\n\n- Assessment state: `interim`\n",
    )
    print(f"[initialized] {workspace}")


def source_descriptors(
    coverage: dict[str, Any],
    additions: list[tuple[str, Path]],
    replace: bool = False,
) -> list[dict[str, str]]:
    descriptors = (
        {}
        if replace
        else {
            (item["kind"], item["path"]): item
            for item in coverage.get("input_sources", [])
        }
    )
    for kind, path in additions:
        if kind not in LOADERS:
            raise ValueError(f"unsupported input kind: {kind}")
        resolved = str(path.expanduser().resolve())
        descriptors[(kind, resolved)] = {"kind": kind, "path": resolved}
    return sorted(descriptors.values(), key=lambda item: (item["kind"], item["path"]))


def compile_workspace(
    workspace: Path,
    additions: list[tuple[str, Path]] | None = None,
    replace_inputs: bool = False,
) -> dict[str, Any]:
    coverage = ensure_workspace(workspace)
    apply_precompile_events(workspace, coverage)
    effective_authorization_capabilities(coverage)
    additions = additions or []
    descriptors = source_descriptors(
        coverage,
        additions,
        replace=replace_inputs,
    )
    coverage["input_sources"] = descriptors
    existing_inventory = (
        {}
        if replace_inputs
        else read_json(workspace / "surface-inventory.json", {})
    )
    merged = {
        item["id"]: item
        for item in existing_inventory.get("surfaces", [])
        if item.get("id")
    }
    blockers = []
    for descriptor in descriptors:
        path = Path(descriptor["path"])
        if not path.exists():
            blockers.append(f"input missing: {path}")
            continue
        surfaces, input_blockers = LOADERS[descriptor["kind"]](
            path, coverage["target"]
        )
        blockers.extend(f"{descriptor['kind']}: {item}" for item in input_blockers)
        for surface in surfaces:
            if surface["id"] in merged:
                merge_surface(merged[surface["id"]], surface)
            else:
                merged[surface["id"]] = surface
    for event in read_events(workspace):
        if event.get("type") != "surface-discovered":
            continue
        raw = event.get("surface")
        if not isinstance(raw, dict):
            raise ValueError("surface-discovered requires surface object")
        surface = finalize_surface(raw, coverage["target"])
        if surface["id"] in merged:
            merge_surface(merged[surface["id"]], surface)
        else:
            merged[surface["id"]] = surface
    surfaces = sorted(merged.values(), key=lambda item: item["id"])
    excluded = [
        surface for surface in surfaces if surface["validation_state"] == "rejected"
    ]
    active = [
        surface for surface in surfaces if surface["validation_state"] != "rejected"
    ]
    if not descriptors and not active:
        blockers.append("surface inputs not compiled")
    by_kind: dict[str, int] = {}
    by_kind_source_records: dict[str, int] = {}
    for surface in active:
        by_kind[surface["kind"]] = by_kind.get(surface["kind"], 0) + 1
        by_kind_source_records[surface["kind"]] = (
            by_kind_source_records.get(surface["kind"], 0)
            + len(surface.get("source_refs", []))
        )
    inventory = {
        "schema_version": 1,
        "assessment_id": coverage["assessment_id"],
        "target": coverage["target"],
        "generated_at": now(),
        "profiles": sorted(infer_profiles(active)),
        "surfaces": active,
        "excluded_surfaces": excluded,
        "blockers": sorted(set(blockers)),
        "totals": {
            "surfaces": len(active),
            "source_records": sum(
                len(surface.get("source_refs", [])) for surface in active
            ),
            "excluded": len(excluded),
            "by_kind": by_kind,
            "by_kind_source_records": by_kind_source_records,
        },
    }
    old_plan = read_json(workspace / "test-plan.json", {})
    route_inventory = build_route_inventory(coverage["target"], surfaces)
    work_units = build_work_units(active, coverage)
    cells = build_cells(work_units, coverage, old_plan)
    request_shapes, shape_orphans = request_shapes_for(workspace, active)
    api_cases = build_executable_cases(
        cells,
        work_units,
        request_shapes,
        coverage,
        old_plan,
    )
    api_cases.extend(
        build_family_executable_cases(
            cells,
            work_units,
            request_shapes,
            old_plan,
        )
    )
    route_cases = build_route_cases(route_inventory, work_units, coverage, old_plan)
    control_cases = build_control_cases(active, old_plan)
    plan = {
        "schema_version": 8,
        "assessment_id": coverage["assessment_id"],
        "generated_at": now(),
        "authorization_model_version": 2,
        "source_inventory_ref": str(
            (workspace / "surface-inventory.json").resolve()
        ),
        "risk_model": {
            "range": [0, 20],
            "unknown_business_impact": 2,
            "buckets": {"P0": [16, 20], "P1": [11, 15], "P2": [6, 10], "P3": [0, 5]},
            "safety_is_separate": True,
        },
        "work_units": work_units,
        "test_cells": cells,
        "request_shapes": request_shapes,
        "executable_cases": api_cases,
        "queue": [],
        "execution_queue": [],
        "execution_lanes": {
            "chain-closure": {"queue": [], "resolved": 0},
            "fast-find": {"queue": [], "resolved": 0},
            "coverage-close": {"queue": [], "resolved": 0},
        },
        "replan_history": old_plan.get("replan_history", []),
        "orphaned_events": shape_orphans,
    }
    evidence_index = read_json(
        workspace / "evidence-index.json",
        {
            "schema_version": 1,
            "assessment_id": coverage["assessment_id"],
            "evidence": [],
        },
    )
    apply_events(workspace, coverage, plan, inventory, evidence_index)
    api_cases = plan["executable_cases"]
    apply_route_events(workspace, route_inventory, route_cases, control_cases)
    cell_by_id = {cell["id"]: cell for cell in plan["test_cells"]}
    combined_cases = [*route_cases, *control_cases, *api_cases]
    for case in combined_cases:
        cell = cell_by_id.get(case.get("test_cell_id"), {})
        case.setdefault("priority", cell.get("priority", "P2"))
        case.setdefault("family", cell.get("family"))
        decorate_case(case)
        case["execution_lane"] = execution_lane(case)
    plan["executable_cases"] = combined_cases
    prerequisite_graph = build_prerequisite_graph(
        workspace, coverage, plan, combined_cases
    )
    plan["prerequisite_graph_ref"] = str(
        (workspace / "prerequisite-graph.json").resolve()
    )
    plan["prerequisite_summary"] = prerequisite_graph["summary"]
    plan["unresolved_prerequisite_refs"] = [
        item["id"]
        for item in prerequisite_graph["prerequisites"]
        if item["owner_kind"] == "test-case" and item["status"] != "satisfied"
    ]
    cases_by_cell: dict[str, list[dict[str, Any]]] = {}
    for case in combined_cases:
        if case.get("test_cell_id"):
            cases_by_cell.setdefault(case["test_cell_id"], []).append(case)
    for cell in plan["test_cells"]:
        related = cases_by_cell.get(cell["id"], [])
        if not related:
            continue
        if any(item["status"] == "waiting-prerequisite" for item in related):
            cell["status"] = "waiting-prerequisite"
            cell["reason"] = "one or more cases are waiting for discoverable prerequisites"
        elif any(item["status"] == "blocked" for item in related):
            cell["status"] = "blocked"
            cell["reason"] = "one or more cases remain blocked after prerequisite search"
        elif all(item["status"] == "not-applicable" for item in related):
            cell["status"] = "not-applicable"
            cell["reason"] = "all executable cases are not applicable"
        elif all(item["status"] in COVERAGE_SATISFIED for item in related):
            cell["status"] = "tested"
            cell["reason"] = None
    knowledge_catalog = apply_knowledge_seeds(coverage, combined_cases)
    plan["knowledge_seed_catalog"] = {
        "schema_version": knowledge_catalog.get("schema_version", 1),
        "source_ledger_sha256": knowledge_catalog.get("source", {}).get("ledger_sha256"),
        "formal_patterns": len(knowledge_catalog.get("formal_patterns", [])),
        "local_hypotheses": len(knowledge_catalog.get("local_hypotheses", [])),
        "actionable_local_hypotheses": sum(
            bool(item.get("family"))
            for item in knowledge_catalog.get("local_hypotheses", [])
        ),
        "confirmation_policy": knowledge_catalog.get("finding_policy"),
    }
    apply_dynamic_priorities(plan, coverage, read_events(workspace))
    prioritize_prerequisites(prerequisite_graph, coverage, read_events(workspace))
    atomic_json(workspace / "prerequisite-graph.json", prerequisite_graph)
    plan["executable_cases"] = sorted(
        combined_cases,
        key=lambda case: (
            {"chain-closure": 0, "fast-find": 1, "coverage-close": 2}.get(case.get("execution_lane"), 3),
            int(case.get("current_priority", "P2")[1]),
            -int(case.get("defer_count", 0)),
            {"route-navigation": 0, "ui-interaction": 1, "api-test": 2}.get(
                case.get("case_kind"), 3
            ),
            case["id"],
        ),
    )
    plan["orphaned_events"].extend(route_inventory.get("orphaned_events", []))
    finalize_route_inventory(route_inventory, route_cases, control_cases, plan)
    route_inventory["assessment_id"] = coverage["assessment_id"]
    route_inventory["route_case_refs"] = [item["id"] for item in route_cases]
    route_inventory["control_case_refs"] = [item["id"] for item in control_cases]
    plan["queue"] = [
        cell["id"]
        for cell in plan["test_cells"]
        if cell["status"] not in RESOLVED
    ]
    plan["execution_queue"] = scheduled_execution_queue(plan["executable_cases"])
    for lane in ("chain-closure", "fast-find", "coverage-close"):
        lane_cases = [
            case
            for case in plan["executable_cases"]
            if case.get("execution_lane") == lane
        ]
        plan["execution_lanes"][lane] = {
            "queue": [
                case["id"]
                for case in lane_cases
                if case["status"] in {"queued", "running", "mapped"}
                and case["safety"] in ACTIONABLE_SAFETY
            ],
            "resolved": sum(
                case["status"] in COVERAGE_SATISFIED for case in lane_cases
            ),
            "total": len(lane_cases),
        }
    previous_queue = old_plan.get("queue", [])
    previous_execution_queue = old_plan.get("execution_queue", [])
    if (
        previous_queue != plan["queue"]
        or previous_execution_queue != plan["execution_queue"]
    ):
        history = plan["replan_history"]
        history.append(
            {
                "at": now(),
                "reason": (
                    "initial-compile" if not previous_queue else "surface-or-state-change"
                ),
                "previous_unresolved": len(previous_queue),
                "current_unresolved": len(plan["queue"]),
                "previous_executable": len(previous_execution_queue),
                "current_executable": len(plan["execution_queue"]),
            }
        )
        plan["replan_history"] = history[-200:]
    plan["priority_engine"] = {
        "schema_version": 1,
        "revision": stable_id(
            "priority-engine",
            {
                "cases": [
                    [item["id"], item.get("priority_revision")]
                    for item in plan["executable_cases"]
                ],
                "queue": plan["execution_queue"],
            },
        ),
        "starvation_interval": STARVATION_INTERVAL,
        "unverified_signals": 0,
        "stale_nodes": 0,
    }
    old_cases = {
        str(item.get("id")): item for item in old_plan.get("executable_cases", [])
    }
    for item in plan["executable_cases"]:
        previous = old_cases.get(str(item.get("id")), {})
        old_score = previous.get("dynamic_score", previous.get("risk_score"))
        if old_score is not None and old_score != item.get("dynamic_score"):
            append_event(
                workspace,
                {
                    "type": "priority-change",
                    "target_id": item["id"],
                    "from_score": old_score,
                    "to_score": item.get("dynamic_score"),
                    "from_priority": previous.get("current_priority", previous.get("priority")),
                    "to_priority": item.get("current_priority"),
                    "priority_revision": item.get("priority_revision"),
                    "reason": "deterministic evidence-driven reprioritization",
                },
            )
    derive_coverage(coverage, plan, inventory, evidence_index, route_inventory)
    agent_state = read_json(workspace / "agent-state.json", {})
    if agent_state:
        coverage["runtime"]["agent_state"] = agent_state.get("status", "unknown")
        coverage["runtime"]["agent_roles"] = {
            role: values.get("status", "unknown")
            for role, values in agent_state.get("roles", {}).items()
        }
        coverage["execution_coverage"]["agent_actions"] = len(
            agent_state.get("actions", [])
        )
        unresolved_agent_actions = sum(
            item.get("status") not in {"resolved", "blocked"}
            for item in agent_state.get("actions", [])
        )
        coverage["execution_coverage"]["agent_actions_unresolved"] = unresolved_agent_actions
        coverage["stop_gates"]["agent_roles_resolved"] = unresolved_agent_actions == 0
        if unresolved_agent_actions:
            coverage["assessment_state"] = "interim"
    atomic_json(workspace / "surface-inventory.json", inventory)
    atomic_json(workspace / "route-inventory.json", route_inventory)
    atomic_json(workspace / "prerequisite-graph.json", prerequisite_graph)
    atomic_json(workspace / "test-plan.json", plan)
    atomic_json(workspace / "coverage.json", coverage)
    atomic_json(workspace / "evidence-index.json", evidence_index)
    atomic_json(
        workspace / "candidate-findings.json",
        {
            "schema_version": 1,
            "assessment_id": coverage["assessment_id"],
            "findings": coverage.get("candidates", []),
            "confirmation_policy": "candidate evidence cannot satisfy a confirmed finding",
        },
    )
    atomic_json(
        workspace / "confirmed-findings.json",
        {
            "schema_version": 1,
            "assessment_id": coverage["assessment_id"],
            "findings": coverage.get("findings", []),
        },
    )
    conclusions = [
        *coverage.get("findings", []),
        *coverage.get("candidates", []),
    ]
    atomic_text(
        workspace / "security-conclusions.jsonl",
        "".join(
            json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n"
            for item in sorted(conclusions, key=lambda item: str(item.get("id", "")))
        ),
    )
    atomic_json(
        workspace / "attack-chain-analysis.json",
        build_attack_chain_analysis(coverage, plan),
    )
    atomic_text(
        workspace / "results.md",
        render_results(coverage, inventory, plan),
    )
    return {
        "assessment_state": coverage["assessment_state"],
        "surfaces": inventory["totals"]["surfaces"],
        "work_units": len(plan["work_units"]),
        "test_cells": len(plan["test_cells"]),
        "executable_cases": len(plan["executable_cases"]),
        "route_cases": len(route_cases),
        "control_cases": len(control_cases),
        "unresolved": coverage["queue_summary"]["unresolved"],
        "by_priority": coverage["queue_summary"]["by_priority"],
        "blockers": [
            gate for gate, passed in coverage["stop_gates"].items() if not passed
        ],
    }


def append_event(workspace: Path, value: dict[str, Any]) -> None:
    ensure_workspace(workspace)
    value = dict(value)
    if value.get("type") == "test-result" and value.get("negative_result"):
        plan = read_json(workspace / "test-plan.json", {})
        cell = next(
            (
                item
                for item in plan.get("test_cells", [])
                if item.get("id") == value.get("test_cell_id")
            ),
            None,
        )
        if cell:
            value.setdefault(
                "surface_fingerprint",
                cell.get("surface_fingerprint"),
            )
    validate_event_shape(value)
    if value.get("type") == "test-result":
        validate_test_result_for_plan(
            value,
            read_json(workspace / "test-plan.json", {}),
        )
    value.setdefault("recorded_at", now())
    path = event_path(workspace)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False) + "\n")


def next_cell(workspace: Path) -> dict[str, Any] | None:
    compile_workspace(workspace)
    plan = read_json(workspace / "test-plan.json", {})
    units = {unit["id"]: unit for unit in plan.get("work_units", [])}
    cells = {cell["id"]: cell for cell in plan.get("test_cells", [])}
    shapes = {
        shape["id"]: shape for shape in plan.get("request_shapes", [])
    }
    cases = {
        case["id"]: case for case in plan.get("executable_cases", [])
    }
    routes = {
        route["id"]: route
        for route in read_json(workspace / "route-inventory.json", {}).get(
            "routes", []
        )
    }
    for case_id in plan.get("execution_queue", []):
        case = cases.get(case_id)
        if not case or case["status"] in RESOLVED:
            continue
        if case.get("case_kind") == "route-navigation":
            return {
                **case,
                "route": routes.get(case.get("route_id"), {}),
                "work_unit": units.get(case.get("work_unit_id"), {}),
                "actionable": True,
            }
        if case.get("case_kind") == "ui-interaction":
            return {**case, "actionable": case["safety"] in ACTIONABLE_SAFETY}
        cell = cells.get(case.get("test_cell_id"), {})
        return {
            **case,
            "test_cell": cell,
            "work_unit": units.get(case["work_unit_id"], {}),
            "request_shape": shapes.get(case["request_shape_id"], {}),
            "actionable": case["safety"] in ACTIONABLE_SAFETY,
        }
    for cell in plan.get("test_cells", []):
        if cell["status"] in RESOLVED:
            continue
        if cell.get("dimensions", {}).get("authorization_mode"):
            continue
        unit = units.get(cell["work_unit_id"], {})
        return {
            **cell,
            "work_unit": unit,
            "actionable": cell["safety"] in ACTIONABLE_SAFETY,
        }
    return None


def reprioritize_workspace(workspace: Path, *, apply: bool) -> dict[str, Any]:
    ensure_workspace(workspace)
    before = read_json(workspace / "test-plan.json", {})
    if apply:
        compile_workspace(workspace)
        after = read_json(workspace / "test-plan.json", {})
    else:
        after = copy.deepcopy(before)
        coverage = read_json(workspace / "coverage.json", {})
        apply_dynamic_priorities(after, coverage, read_events(workspace))
        after["execution_queue"] = scheduled_execution_queue(after.get("executable_cases", []))
    previous = {str(item.get("id")): item for item in before.get("executable_cases", [])}
    changes = []
    for item in after.get("executable_cases", []):
        old = previous.get(str(item.get("id")), {})
        if old.get("dynamic_score", old.get("risk_score")) == item.get("dynamic_score"):
            continue
        changes.append(
            {
                "target_id": item.get("id"),
                "from_score": old.get("dynamic_score", old.get("risk_score")),
                "to_score": item.get("dynamic_score"),
                "from_priority": old.get("current_priority", old.get("priority")),
                "to_priority": item.get("current_priority"),
                "priority_revision": item.get("priority_revision"),
            }
        )
    return {
        "status": "applied" if apply else "dry-run",
        "priority_revision": after.get("priority_engine", {}).get("revision"),
        "changes": changes,
        "execution_queue": after.get("execution_queue", []),
    }


def explain_queue(workspace: Path) -> dict[str, Any]:
    compile_workspace(workspace)
    plan = read_json(workspace / "test-plan.json", {})
    cases = {str(item["id"]): item for item in plan.get("executable_cases", [])}
    return {
        "priority_engine": plan.get("priority_engine", {}),
        "queue": [
            {
                "position": position,
                "id": item_id,
                "lane": cases[item_id].get("execution_lane"),
                "base_score": cases[item_id].get("base_score"),
                "dynamic_score": cases[item_id].get("dynamic_score"),
                "current_priority": cases[item_id].get("current_priority"),
                "defer_count": cases[item_id].get("defer_count", 0),
                "priority_factors": cases[item_id].get("priority_factors", []),
                "next_validation_step": cases[item_id].get("next_validation_step"),
            }
            for position, item_id in enumerate(plan.get("execution_queue", []), 1)
            if item_id in cases
        ],
    }


def parse_input(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("input must use KIND=PATH")
    kind, raw_path = value.split("=", 1)
    if kind not in LOADERS:
        raise argparse.ArgumentTypeError(
            f"unsupported kind {kind}; choose {', '.join(sorted(LOADERS))}"
        )
    return kind, Path(raw_path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Manage resumable Blue Sec Hub Web assessments"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--target", required=True)
    init_parser.add_argument("--out", required=True, type=Path)

    compile_parser = subparsers.add_parser("compile")
    compile_parser.add_argument("--workspace", required=True, type=Path)
    compile_parser.add_argument(
        "--input",
        action="append",
        default=[],
        type=parse_input,
        help="Add SPA/HAR/OpenAPI/GraphQL/history/manual input as KIND=PATH",
    )
    compile_parser.add_argument(
        "--replace-inputs",
        action="store_true",
        help="Replace prior input sources and rebuild inventory from the supplied inputs",
    )

    next_parser = subparsers.add_parser("next")
    next_parser.add_argument("--workspace", required=True, type=Path)
    next_parser.add_argument("--json", action="store_true")

    event_parser = subparsers.add_parser("record-event")
    event_parser.add_argument("--workspace", required=True, type=Path)
    event_parser.add_argument("--event", required=True, type=Path)

    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("--workspace", required=True, type=Path)
    check_parser.add_argument("--json", action="store_true")

    migrate_parser = subparsers.add_parser("migrate")
    migrate_parser.add_argument("--workspace", required=True, type=Path)
    migrate_parser.add_argument("--target")

    reprioritize_parser = subparsers.add_parser("reprioritize")
    reprioritize_parser.add_argument("--workspace", required=True, type=Path)
    reprioritize_parser.add_argument("--dry-run", action="store_true")

    queue_parser = subparsers.add_parser("queue")
    queue_parser.add_argument("--workspace", required=True, type=Path)
    queue_parser.add_argument("--explain", action="store_true")

    args = parser.parse_args()
    try:
        if args.command == "init":
            initialize(args.out, args.target)
        elif args.command == "compile":
            result = compile_workspace(
                args.workspace,
                args.input,
                replace_inputs=args.replace_inputs,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif args.command == "next":
            cell = next_cell(args.workspace)
            if cell is None:
                print(json.dumps({"state": "complete"}, ensure_ascii=False))
                return
            if args.json:
                print(json.dumps(cell, ensure_ascii=False, indent=2))
            else:
                print(
                    f"{cell['id']} {cell.get('priority', 'P2')} "
                    f"{cell.get('family', cell.get('case_kind', 'case'))} "
                    f"actionable={str(cell['actionable']).lower()}"
                )
        elif args.command == "record-event":
            event = read_json(args.event, None)
            if not isinstance(event, dict):
                raise ValueError("event file must contain one JSON object")
            append_event(args.workspace, event)
            result = compile_workspace(args.workspace)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif args.command == "check":
            result = compile_workspace(args.workspace)
            if args.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print(
                    f"[{result['assessment_state']}] "
                    f"{result['unresolved']} unresolved test cells"
                )
            if result["assessment_state"] != "complete":
                raise SystemExit(2)
        elif args.command == "migrate":
            coverage = ensure_workspace(args.workspace, args.target)
            atomic_json(args.workspace / "coverage.json", coverage)
            result = compile_workspace(args.workspace)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif args.command == "reprioritize":
            result = reprioritize_workspace(args.workspace, apply=not args.dry_run)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif args.command == "queue":
            result = explain_queue(args.workspace)
            print(json.dumps(result, ensure_ascii=False, indent=2))
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
