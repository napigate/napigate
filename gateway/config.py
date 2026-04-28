from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
from pathlib import Path
from typing import Any

import yaml


CONFIG_PATH = Path("config/services.yaml")
PATH_TOKEN_PATTERN = re.compile(r"{([a-zA-Z_][a-zA-Z0-9_]*)(:path)?}")
SLUG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]*$")


@dataclass(slots=True)
class PreCallConfig:
    code: str
    cache_ttl_seconds: int = 0
    cache_key: str | None = None


@dataclass(slots=True)
class StaticResponseConfig:
    status_code: int = 200
    body: Any = ""
    content_type: str | None = None
    headers: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class CorsConfig:
    enabled: bool = False
    allow_origins: list[str] = field(default_factory=list)
    allow_methods: list[str] = field(default_factory=list)
    allow_headers: list[str] = field(default_factory=list)
    expose_headers: list[str] = field(default_factory=list)
    allow_credentials: bool = False
    max_age_seconds: int = 600


@dataclass(slots=True)
class RateLimitConfig:
    enabled: bool = False
    requests: int = 60
    window_seconds: int = 60
    scope: str = "client_or_ip"


@dataclass(slots=True)
class ResponseCacheConfig:
    enabled: bool = False
    ttl_seconds: int = 0
    vary_by_client: bool = True
    vary_headers: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=lambda: ["GET"])


@dataclass(slots=True)
class OutputProfileConfig:
    slug: str
    title: str
    type: str = "passthrough"
    enabled: bool = True
    success_key: str = "success"
    data_key: str = "data"
    message_key: str = "message"
    error_key: str = "error"
    passthrough_keys: list[str] = field(default_factory=list)
    source_success_key: str | None = None
    message_source_keys: list[str] = field(default_factory=list)
    error_source_keys: list[str] = field(default_factory=list)
    data_fields: dict[str, str] = field(default_factory=dict)
    empty_value: Any = ""
    jsonp_callback_param: str = "callback"
    jsonp_default_callback: str = "callback"
    headers: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class GatewayResponseConfig:
    enabled: bool = False
    success_key: str = "success"
    data_key: str = "data"
    message_key: str = "message"
    error_key: str = "error"
    empty_value: Any = ""
    headers: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class SuccessHookConfig:
    enabled: bool = False
    url: str = ""
    timeout_seconds: float = 5.0
    headers: dict[str, Any] = field(default_factory=dict)
    include_response_body: bool = False
    include_request_body: bool = False
    event_type: str = "financial"


@dataclass(slots=True)
class LogAggregatorConfig:
    code: str
    type: str
    enabled: bool = True
    url: str = ""
    headers: dict[str, Any] = field(default_factory=dict)
    timeout_seconds: float = 5.0
    labels: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AuthMethodConfig:
    code: str
    title: str
    type: str
    enabled: bool = True
    secret: str | None = None
    token: str | None = None
    username: str | None = None
    password: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    token_ttl_seconds: int = 3600
    header_name: str | None = None
    header_names: list[str] = field(default_factory=list)
    query_params: list[str] = field(default_factory=list)
    cookie_names: list[str] = field(default_factory=list)
    allow_authorization_header: bool = False
    script: str | None = None
    cache_ttl_seconds: int = 0
    cache_key: str | None = None


@dataclass(slots=True)
class ClientEndpointScope:
    service: str
    endpoint: str


@dataclass(slots=True)
class ClientAccessScope:
    mode: str = "all"
    services: list[str] = field(default_factory=list)
    endpoints: list[ClientEndpointScope] = field(default_factory=list)


@dataclass(slots=True)
class ClientConfig:
    slug: str
    code: str
    title: str
    enabled: bool = True
    ip_allowlist: list[str] = field(default_factory=list)
    access: ClientAccessScope = field(default_factory=ClientAccessScope)
    auth_methods: list[AuthMethodConfig] = field(default_factory=list)


@dataclass(slots=True)
class RouteAuthConfig:
    required: bool = False


@dataclass(slots=True)
class EndpointConfig:
    name: str
    slug: str
    upstream_path: str
    methods: list[str] = field(default_factory=lambda: ["GET"])
    gateway_path: str = ""
    headers: dict[str, Any] = field(default_factory=dict)
    query: dict[str, Any] = field(default_factory=dict)
    pre_call: PreCallConfig | None = None
    response: StaticResponseConfig | None = None
    output_profile: str | None = None
    response_cache: ResponseCacheConfig = field(default_factory=ResponseCacheConfig)
    success_hook: SuccessHookConfig | None = None
    compiled_pattern: re.Pattern[str] | None = None


@dataclass(slots=True)
class RouteTargetConfig:
    service: str
    endpoint: str


@dataclass(slots=True)
class RouteConfig:
    name: str
    slug: str
    methods: list[str]
    gateway_path: str
    strategy: str = "single"
    targets: list[RouteTargetConfig] = field(default_factory=list)
    pre_call: PreCallConfig | None = None
    output_profile: str | None = None
    response_cache: ResponseCacheConfig = field(default_factory=ResponseCacheConfig)
    success_hook: SuccessHookConfig | None = None
    compiled_pattern: re.Pattern[str] | None = None
    legacy_endpoint_config: bool = False


@dataclass(slots=True)
class ServiceConfig:
    name: str
    base_url: str
    timeout_seconds: float = 30.0
    verify_ssl: bool = True
    trust_env_proxy: bool = False
    forward_napigate_headers: bool = True
    variables: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, Any] = field(default_factory=dict)
    pre_call: PreCallConfig | None = None
    auth: RouteAuthConfig = field(default_factory=RouteAuthConfig)
    cors: CorsConfig = field(default_factory=CorsConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    endpoints: list[EndpointConfig] = field(default_factory=list)


@dataclass(slots=True)
class GatewayConfig:
    clients: dict[str, ClientConfig] = field(default_factory=dict)
    services: list[ServiceConfig] = field(default_factory=list)
    routes: list[RouteConfig] = field(default_factory=list)
    output_profiles: dict[str, OutputProfileConfig] = field(default_factory=dict)
    gateway_responses: GatewayResponseConfig = field(default_factory=GatewayResponseConfig)
    log_aggregators: list[LogAggregatorConfig] = field(default_factory=list)
    log_retention_hours: int | None = None


def compile_gateway_path(pattern: str) -> re.Pattern[str]:
    last_index = 0
    parts: list[str] = ["^"]

    for match in PATH_TOKEN_PATTERN.finditer(pattern):
        start, end = match.span()
        parts.append(re.escape(pattern[last_index:start]))
        name = match.group(1)
        path_mode = bool(match.group(2))
        if path_mode:
            parts.append(f"(?P<{name}>.+)")
        else:
            parts.append(f"(?P<{name}>[^/]+)")
        last_index = end

    parts.append(re.escape(pattern[last_index:]))
    parts.append("$")
    return re.compile("".join(parts))


def _normalize_methods(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.upper()]
    if isinstance(value, list) and value:
        return [str(item).upper() for item in value]
    raise ValueError("Endpoint methods must be a string or a non-empty list.")


def _normalize_string_list(value: Any, *, label: str) -> list[str]:
    if value in (None, "", []):
        return []
    if isinstance(value, str):
        items = [part.strip() for part in value.split(",")]
        return [item for item in items if item]
    if isinstance(value, list):
        normalized: list[str] = []
        for item in value:
            item_str = str(item).strip()
            if item_str and item_str not in normalized:
                normalized.append(item_str)
        return normalized
    raise ValueError(f"{label} must be a string or a list.")


def _normalize_slug(value: Any, *, label: str, fallback: str | None = None) -> str:
    slug = str(value or fallback or "").strip().lower()
    if not slug:
        raise ValueError(f"{label} is required.")
    if not SLUG_PATTERN.fullmatch(slug):
        raise ValueError(
            f"{label} must use lowercase letters, numbers, underscores, or dashes."
        )
    return slug


def _load_route_auth(value: Any, *, label: str) -> RouteAuthConfig:
    if value is None:
        return RouteAuthConfig()
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a mapping.")
    return RouteAuthConfig(required=bool(value.get("required", False)))


def _load_static_response(value: Any, *, label: str) -> StaticResponseConfig | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a mapping.")

    headers = value.get("headers") or {}
    if not isinstance(headers, dict):
        raise ValueError(f"{label}.headers must be a mapping.")

    status_code = int(value.get("status_code", 200) or 200)
    if status_code < 100 or status_code > 599:
        raise ValueError(f"{label}.status_code must be between 100 and 599.")

    content_type = str(value.get("content_type", "")).strip() or None
    return StaticResponseConfig(
        status_code=status_code,
        body=value.get("body", ""),
        content_type=content_type,
        headers=dict(headers),
    )


def _load_cors_config(value: Any, *, label: str) -> CorsConfig:
    if value is None:
        return CorsConfig()
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a mapping.")

    allow_origins = _normalize_string_list(
        value.get("allow_origins", []),
        label=f"{label}.allow_origins",
    )
    allow_methods = [
        item.upper()
        for item in _normalize_string_list(
            value.get("allow_methods", []),
            label=f"{label}.allow_methods",
        )
    ]
    allow_headers = _normalize_string_list(
        value.get("allow_headers", []),
        label=f"{label}.allow_headers",
    )
    expose_headers = _normalize_string_list(
        value.get("expose_headers", []),
        label=f"{label}.expose_headers",
    )

    max_age_seconds = int(value.get("max_age_seconds", 600) or 600)
    if max_age_seconds < 0:
        raise ValueError(f"{label}.max_age_seconds must be zero or positive.")

    enabled = bool(value.get("enabled", False))
    if enabled and not allow_origins:
        allow_origins = ["*"]

    return CorsConfig(
        enabled=enabled,
        allow_origins=allow_origins,
        allow_methods=allow_methods,
        allow_headers=allow_headers,
        expose_headers=expose_headers,
        allow_credentials=bool(value.get("allow_credentials", False)),
        max_age_seconds=max_age_seconds,
    )


def _load_rate_limit_config(value: Any, *, label: str) -> RateLimitConfig:
    if value is None:
        return RateLimitConfig()
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a mapping.")

    requests = int(value.get("requests", 60) or 60)
    window_seconds = int(value.get("window_seconds", 60) or 60)
    scope = str(value.get("scope", "client_or_ip")).strip().lower() or "client_or_ip"
    if requests <= 0:
        raise ValueError(f"{label}.requests must be positive.")
    if window_seconds <= 0:
        raise ValueError(f"{label}.window_seconds must be positive.")
    if scope not in {"client_or_ip", "client", "ip"}:
        raise ValueError(f"{label}.scope must be client_or_ip, client, or ip.")

    return RateLimitConfig(
        enabled=bool(value.get("enabled", False)),
        requests=requests,
        window_seconds=window_seconds,
        scope=scope,
    )


def _load_response_cache_config(value: Any, *, label: str) -> ResponseCacheConfig:
    if value is None:
        return ResponseCacheConfig()
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a mapping.")

    ttl_seconds = int(value.get("ttl_seconds", 0) or 0)
    if ttl_seconds < 0:
        raise ValueError(f"{label}.ttl_seconds must be zero or positive.")

    methods = _normalize_methods(value.get("methods", ["GET"]))
    return ResponseCacheConfig(
        enabled=bool(value.get("enabled", ttl_seconds > 0)),
        ttl_seconds=ttl_seconds,
        vary_by_client=bool(value.get("vary_by_client", True)),
        vary_headers=_normalize_string_list(
            value.get("vary_headers", []),
            label=f"{label}.vary_headers",
        ),
        methods=methods,
    )


def _load_pre_call_config(value: Any, *, label: str) -> PreCallConfig | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a mapping.")

    code = str(value.get("code", "")).rstrip()
    if not code:
        raise ValueError(f"{label} needs code.")

    pre_call = PreCallConfig(
        code=code,
        cache_ttl_seconds=int(value.get("cache_ttl_seconds", 0) or 0),
        cache_key=str(value.get("cache_key", "")).strip() or None,
    )
    if pre_call.cache_ttl_seconds < 0:
        raise ValueError(f"{label} must use a non-negative cache_ttl_seconds.")
    return pre_call


def _load_output_profile(
    value: Any,
    *,
    slug: str,
) -> OutputProfileConfig:
    label = f"Output profile '{slug}'"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a mapping.")

    profile_type = str(value.get("type", "passthrough")).strip().lower() or "passthrough"
    if profile_type not in {"passthrough", "json_envelope", "jsonp"}:
        raise ValueError(f"{label}.type must be passthrough, json_envelope, or jsonp.")

    headers = value.get("headers") or {}
    if not isinstance(headers, dict):
        raise ValueError(f"{label}.headers must be a mapping.")

    passthrough_keys = _normalize_string_list(
        value.get("passthrough_keys", []),
        label=f"{label}.passthrough_keys",
    )
    message_source_keys = _normalize_string_list(
        value.get("message_source_keys", []),
        label=f"{label}.message_source_keys",
    )
    error_source_keys = _normalize_string_list(
        value.get("error_source_keys", []),
        label=f"{label}.error_source_keys",
    )
    data_fields_raw = value.get("data_fields") or {}
    if not isinstance(data_fields_raw, dict):
        raise ValueError(f"{label}.data_fields must be a mapping.")
    data_fields = {
        str(field_name).strip(): str(source_path).strip()
        for field_name, source_path in data_fields_raw.items()
        if str(field_name).strip() and str(source_path).strip()
    }
    return OutputProfileConfig(
        slug=_normalize_slug(slug, label=f"{label} slug", fallback=slug),
        title=str(value.get("title", slug)).strip() or slug,
        type=profile_type,
        enabled=bool(value.get("enabled", True)),
        success_key=str(value.get("success_key", "success")).strip() or "success",
        data_key=str(value.get("data_key", "data")).strip() or "data",
        message_key=str(value.get("message_key", "message")).strip() or "message",
        error_key=str(value.get("error_key", "error")).strip() or "error",
        passthrough_keys=passthrough_keys,
        source_success_key=str(value.get("source_success_key", "")).strip() or None,
        message_source_keys=message_source_keys,
        error_source_keys=error_source_keys,
        data_fields=data_fields,
        empty_value=value.get("empty_value", ""),
        jsonp_callback_param=str(value.get("jsonp_callback_param", "callback")).strip()
        or "callback",
        jsonp_default_callback=str(value.get("jsonp_default_callback", "callback")).strip()
        or "callback",
        headers=dict(headers),
    )


def _load_output_profiles_block(output_profiles_block: Any) -> dict[str, OutputProfileConfig]:
    if output_profiles_block in (None, {}):
        return {}
    if not isinstance(output_profiles_block, dict):
        raise ValueError("Config 'output_profiles' must be a mapping.")

    profiles: dict[str, OutputProfileConfig] = {}
    for slug, payload in output_profiles_block.items():
        profile = _load_output_profile(payload, slug=str(slug))
        if profile.slug in profiles:
            raise ValueError(f"Duplicate output profile slug '{profile.slug}'.")
        profiles[profile.slug] = profile
    return profiles


def _load_gateway_response_config(value: Any) -> GatewayResponseConfig:
    if value in (None, {}):
        return GatewayResponseConfig()
    if not isinstance(value, dict):
        raise ValueError("Config 'gateway_responses' must be a mapping.")

    headers = value.get("headers") or {}
    if not isinstance(headers, dict):
        raise ValueError("Config 'gateway_responses.headers' must be a mapping.")

    return GatewayResponseConfig(
        enabled=bool(value.get("enabled", False)),
        success_key=str(value.get("success_key", "success")).strip() or "success",
        data_key=str(value.get("data_key", "data")).strip() or "data",
        message_key=str(value.get("message_key", "message")).strip() or "message",
        error_key=str(value.get("error_key", "error")).strip() or "error",
        empty_value=value.get("empty_value", ""),
        headers=dict(headers),
    )


def _load_success_hook_config(value: Any, *, label: str) -> SuccessHookConfig | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a mapping.")

    url = str(value.get("url", "")).strip()
    timeout_seconds = float(value.get("timeout_seconds", 5) or 5)
    if timeout_seconds <= 0:
        raise ValueError(f"{label}.timeout_seconds must be positive.")

    headers = value.get("headers") or {}
    if not isinstance(headers, dict):
        raise ValueError(f"{label}.headers must be a mapping.")

    return SuccessHookConfig(
        enabled=bool(value.get("enabled", bool(url))),
        url=url,
        timeout_seconds=timeout_seconds,
        headers=dict(headers),
        include_response_body=bool(value.get("include_response_body", False)),
        include_request_body=bool(value.get("include_request_body", False)),
        event_type=str(value.get("event_type", "financial")).strip() or "financial",
    )


def _load_log_aggregator(value: Any, *, code: str) -> LogAggregatorConfig:
    label = f"Log aggregator '{code}'"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a mapping.")

    aggregator_type = str(value.get("type", "")).strip().lower()
    if aggregator_type not in {"http_json", "loki"}:
        raise ValueError(f"{label}.type must be http_json or loki.")

    headers = value.get("headers") or {}
    if not isinstance(headers, dict):
        raise ValueError(f"{label}.headers must be a mapping.")
    labels = value.get("labels") or {}
    if not isinstance(labels, dict):
        raise ValueError(f"{label}.labels must be a mapping.")

    timeout_seconds = float(value.get("timeout_seconds", 5) or 5)
    if timeout_seconds <= 0:
        raise ValueError(f"{label}.timeout_seconds must be positive.")

    return LogAggregatorConfig(
        code=_normalize_slug(code, label=f"{label} code", fallback=code),
        type=aggregator_type,
        enabled=bool(value.get("enabled", True)),
        url=str(value.get("url", "")).strip(),
        headers=dict(headers),
        timeout_seconds=timeout_seconds,
        labels=dict(labels),
    )


def _load_log_aggregators_block(observability_block: Any) -> list[LogAggregatorConfig]:
    if observability_block in (None, {}):
        return []
    if not isinstance(observability_block, dict):
        raise ValueError("Config 'observability' must be a mapping.")

    aggregators_block = observability_block.get("log_aggregators") or {}
    if aggregators_block in (None, {}):
        return []
    if not isinstance(aggregators_block, dict):
        raise ValueError("Config 'observability.log_aggregators' must be a mapping.")

    return [
        _load_log_aggregator(value, code=str(code))
        for code, value in aggregators_block.items()
    ]


def _load_log_retention_hours(observability_block: Any) -> int | None:
    if observability_block in (None, {}):
        return None
    if not isinstance(observability_block, dict):
        raise ValueError("Config 'observability' must be a mapping.")

    raw_value = observability_block.get("log_retention_hours")
    if raw_value in (None, "", 0, "0"):
        return None
    retention_hours = int(raw_value)
    if retention_hours < 0:
        raise ValueError("Config 'observability.log_retention_hours' must be zero or positive.")
    return retention_hours or None


def _validate_ip_allowlist(ip_allowlist: list[str], *, label: str) -> list[str]:
    normalized: list[str] = []
    for entry in ip_allowlist:
        entry_str = str(entry).strip()
        if not entry_str:
            continue
        try:
            ipaddress.ip_network(entry_str, strict=False)
        except ValueError as exc:
            raise ValueError(f"{label} contains invalid IP/CIDR '{entry_str}'.") from exc
        if entry_str not in normalized:
            normalized.append(entry_str)
    return normalized


def _load_auth_method(value: Any, *, client_code: str, index: int) -> AuthMethodConfig:
    label = f"Client '{client_code}' auth method #{index}"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a mapping.")

    method_code = str(value.get("code", "")).strip()
    if not method_code:
        raise ValueError(f"{label} needs code.")

    title = str(value.get("title", method_code)).strip() or method_code
    auth_type = str(value.get("type", "")).strip().lower()
    allowed_types = {
        "api_key",
        "bearer",
        "basic",
        "header_key",
        "oauth_client_credentials",
        "external_service",
    }
    if auth_type not in allowed_types:
        raise ValueError(f"{label} has unsupported auth type '{auth_type}'.")

    header_names = _normalize_string_list(
        value.get("header_names", []),
        label=f"{label}.header_names",
    )
    query_params = _normalize_string_list(
        value.get("query_params", []),
        label=f"{label}.query_params",
    )
    cookie_names = _normalize_string_list(
        value.get("cookie_names", []),
        label=f"{label}.cookie_names",
    )

    method = AuthMethodConfig(
        code=method_code,
        title=title,
        type=auth_type,
        enabled=bool(value.get("enabled", True)),
        secret=str(value.get("secret", value.get("value", ""))).strip() or None,
        token=str(value.get("token", "")).strip() or None,
        username=str(value.get("username", "")).strip() or None,
        password=str(value.get("password", "")).strip() or None,
        client_id=str(value.get("client_id", "")).strip() or None,
        client_secret=str(value.get("client_secret", "")).strip() or None,
        token_ttl_seconds=int(value.get("token_ttl_seconds", 3600) or 3600),
        header_name=str(value.get("header_name", "")).strip() or None,
        header_names=header_names,
        query_params=query_params,
        cookie_names=cookie_names,
        allow_authorization_header=bool(value.get("allow_authorization_header", auth_type == "bearer")),
        script=str(value.get("script", "")).rstrip() or None,
        cache_ttl_seconds=int(value.get("cache_ttl_seconds", 0) or 0),
        cache_key=str(value.get("cache_key", "")).strip() or None,
    )

    if method.cache_ttl_seconds < 0:
        raise ValueError(f"{label} cache_ttl_seconds must be zero or positive.")

    if method.type == "api_key":
        if not method.secret:
            raise ValueError(f"{label} needs secret.")
        if not any((method.header_names, method.query_params, method.cookie_names)):
            method.header_names = ["X-API-Key"]
            method.query_params = ["api_key"]
    elif method.type == "bearer":
        if not method.token:
            raise ValueError(f"{label} needs token.")
    elif method.type == "basic":
        if not method.username or not method.password:
            raise ValueError(f"{label} needs username and password.")
    elif method.type == "header_key":
        if not method.header_name or not method.secret:
            raise ValueError(f"{label} needs header_name and secret.")
    elif method.type == "oauth_client_credentials":
        if not method.client_id or not method.client_secret:
            raise ValueError(f"{label} needs client_id and client_secret.")
        if method.token_ttl_seconds <= 0:
            raise ValueError(f"{label} needs a positive token_ttl_seconds.")
    elif method.type == "external_service":
        if not method.script:
            raise ValueError(f"{label} needs script.")

    return method


def _load_client(value: Any, *, index: int) -> ClientConfig:
    label = f"Client #{index}"
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a mapping.")

    code = str(value.get("code", "")).strip()
    title = str(value.get("title", "")).strip()
    if not code:
        raise ValueError(f"{label} needs code.")
    if not title:
        raise ValueError(f"{label} needs title.")
    slug = _normalize_slug(value.get("slug"), label=f"Client '{code}' slug", fallback=code)

    access_data = value.get("access") or {}
    if not isinstance(access_data, dict):
        raise ValueError(f"Client '{code}' access must be a mapping.")

    access_mode = str(access_data.get("mode", "all")).strip().lower() or "all"
    if access_mode not in {"all", "services", "endpoints"}:
        raise ValueError(f"Client '{code}' access.mode must be all, services, or endpoints.")

    access_services = _normalize_string_list(
        access_data.get("services", []),
        label=f"Client '{code}' access.services",
    )

    endpoints_raw = access_data.get("endpoints", [])
    access_endpoints: list[ClientEndpointScope] = []
    if endpoints_raw not in (None, "", []):
        if not isinstance(endpoints_raw, list):
            raise ValueError(f"Client '{code}' access.endpoints must be a list.")
        seen_endpoints: set[tuple[str, str]] = set()
        for endpoint_index, endpoint_data in enumerate(endpoints_raw, start=1):
            endpoint_label = f"Client '{code}' access endpoint #{endpoint_index}"
            if not isinstance(endpoint_data, dict):
                raise ValueError(f"{endpoint_label} must be a mapping.")
            service_name = str(endpoint_data.get("service", "")).strip()
            endpoint_name = str(endpoint_data.get("endpoint", "")).strip()
            if not service_name or not endpoint_name:
                raise ValueError(f"{endpoint_label} needs service and endpoint.")
            key = (service_name, endpoint_name)
            if key in seen_endpoints:
                continue
            seen_endpoints.add(key)
            access_endpoints.append(ClientEndpointScope(service=service_name, endpoint=endpoint_name))

    if access_mode != "services":
        access_services = []
    if access_mode != "endpoints":
        access_endpoints = []

    methods_raw = value.get("auth_methods", [])
    if not isinstance(methods_raw, list) or not methods_raw:
        raise ValueError(f"Client '{code}' needs a non-empty auth_methods list.")

    auth_methods: list[AuthMethodConfig] = []
    seen_method_codes: set[str] = set()
    for method_index, method_data in enumerate(methods_raw, start=1):
        method = _load_auth_method(method_data, client_code=code, index=method_index)
        if method.code in seen_method_codes:
            continue
        seen_method_codes.add(method.code)
        auth_methods.append(method)

    ip_allowlist = _validate_ip_allowlist(
        _normalize_string_list(value.get("ip_allowlist", []), label=f"Client '{code}' ip_allowlist"),
        label=f"Client '{code}' ip_allowlist",
    )

    return ClientConfig(
        slug=slug,
        code=code,
        title=title,
        enabled=bool(value.get("enabled", True)),
        ip_allowlist=ip_allowlist,
        access=ClientAccessScope(
            mode=access_mode,
            services=access_services,
            endpoints=access_endpoints,
        ),
        auth_methods=auth_methods,
    )


def _load_clients_block(clients_block: Any) -> dict[str, ClientConfig]:
    if clients_block in (None, []):
        return {}
    if not isinstance(clients_block, list):
        raise ValueError("Config 'clients' must be a list.")

    clients: dict[str, ClientConfig] = {}
    seen_slugs: set[str] = set()
    for index, client_data in enumerate(clients_block, start=1):
        client = _load_client(client_data, index=index)
        if client.code in clients:
            raise ValueError(f"Duplicate client code '{client.code}'.")
        if client.slug in seen_slugs:
            raise ValueError(f"Duplicate client slug '{client.slug}'.")
        seen_slugs.add(client.slug)
        clients[client.code] = client
    return clients


def load_config_document(config_path: Path | str = CONFIG_PATH) -> dict[str, Any]:
    config_path = Path(config_path)
    if not config_path.exists():
        return {"clients": [], "services": {}}

    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}

    clients_block = raw.get("clients")
    if clients_block is None:
        raw["clients"] = []
    elif not isinstance(clients_block, list):
        raise ValueError("Config 'clients' must be a list.")

    services_block = raw.get("services")
    if services_block is None:
        raw["services"] = {}
    elif not isinstance(services_block, dict):
        raise ValueError("Config must contain a 'services' mapping.")

    output_profiles_block = raw.get("output_profiles")
    if output_profiles_block is None:
        raw["output_profiles"] = {}
    elif not isinstance(output_profiles_block, dict):
        raise ValueError("Config 'output_profiles' must be a mapping.")

    observability_block = raw.get("observability")
    if observability_block is None:
        raw["observability"] = {}
    elif not isinstance(observability_block, dict):
        raise ValueError("Config 'observability' must be a mapping.")

    routes_block = raw.get("routes")
    if routes_block is None:
        raw["routes"] = []
    elif not isinstance(routes_block, list):
        raise ValueError("Config 'routes' must be a list.")

    return raw


def save_config_document(config_path: Path | str, document: dict[str, Any]) -> None:
    config_path = Path(config_path)
    serialized = yaml.safe_dump(
        document,
        sort_keys=False,
        allow_unicode=False,
    )
    config_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = config_path.with_name(f"{config_path.name}.tmp")
    temp_path.write_text(serialized, encoding="utf-8")
    load_gateway_config(temp_path)
    temp_path.replace(config_path)


def _load_services_block(
    services_block: dict[str, Any],
    *,
    output_profiles: dict[str, OutputProfileConfig],
) -> list[ServiceConfig]:
    services: list[ServiceConfig] = []

    for service_name, service_data in services_block.items():
        if not isinstance(service_data, dict):
            raise ValueError(f"Service '{service_name}' must be a mapping.")

        if "clients" in service_data:
            raise ValueError(
                f"Service '{service_name}' uses deprecated service-local clients. Define clients at the top-level 'clients' list."
            )

        base_url = str(service_data.get("base_url", "")).strip()
        if not base_url:
            raise ValueError(f"Service '{service_name}' is missing base_url.")

        endpoints_block = service_data.get("endpoints", [])
        if not isinstance(endpoints_block, list):
            raise ValueError(f"Service '{service_name}' endpoints must be a list.")

        service = ServiceConfig(
            name=service_name,
            base_url=base_url,
            timeout_seconds=float(service_data.get("timeout_seconds", 30)),
            verify_ssl=bool(service_data.get("verify_ssl", True)),
            trust_env_proxy=bool(service_data.get("trust_env_proxy", False)),
            forward_napigate_headers=bool(service_data.get("forward_napigate_headers", True)),
            variables=dict(service_data.get("variables") or {}),
            headers=dict(service_data.get("headers") or {}),
            pre_call=_load_pre_call_config(
                service_data.get("pre_call"),
                label=f"pre_call for service '{service_name}'",
            ),
            auth=_load_route_auth(
                service_data.get("auth"),
                label=f"Service '{service_name}' auth",
            ),
            cors=_load_cors_config(
                service_data.get("cors"),
                label=f"Service '{service_name}' cors",
            ),
            rate_limit=_load_rate_limit_config(
                service_data.get("rate_limit"),
                label=f"Service '{service_name}' rate_limit",
            ),
        )

        endpoint_names: set[str] = set()
        endpoint_slugs: set[str] = set()
        for index, endpoint_data in enumerate(endpoints_block, start=1):
            if not isinstance(endpoint_data, dict):
                raise ValueError(
                    f"Endpoint #{index} in service '{service_name}' must be a mapping."
                )

            if "auth" in endpoint_data:
                endpoint_name = str(endpoint_data.get("name") or f"{service_name}_{index}")
                raise ValueError(
                    f"Endpoint '{endpoint_name}' in service '{service_name}' uses deprecated endpoint auth. Auth is now service-level plus client access scope."
                )

            name = str(endpoint_data.get("name") or f"{service_name}_{index}")
            if name in endpoint_names:
                raise ValueError(f"Service '{service_name}' has duplicate endpoint name '{name}'.")
            endpoint_names.add(name)
            slug = _normalize_slug(
                endpoint_data.get("slug"),
                label=f"Endpoint '{name}' slug in service '{service_name}'",
                fallback=name,
            )
            if slug in endpoint_slugs:
                raise ValueError(
                    f"Service '{service_name}' has duplicate endpoint slug '{slug}'."
                )
            endpoint_slugs.add(slug)

            gateway_path = str(endpoint_data.get("gateway_path", "")).strip()
            upstream_path = str(endpoint_data.get("upstream_path", "")).strip()
            response = _load_static_response(
                endpoint_data.get("response"),
                label=f"response for endpoint '{name}' in service '{service_name}'",
            )

            if not upstream_path and response is None:
                raise ValueError(
                    f"Endpoint '{name}' in service '{service_name}' needs upstream_path or response."
                )

            pre_call = _load_pre_call_config(
                endpoint_data.get("pre_call"),
                label=f"pre_call for endpoint '{name}' in service '{service_name}'",
            )

            output_profile = str(endpoint_data.get("output_profile", "")).strip().lower() or None
            if output_profile is not None and output_profile not in output_profiles:
                output_profile = None

            response_cache = _load_response_cache_config(
                endpoint_data.get("response_cache"),
                label=f"response_cache for endpoint '{name}' in service '{service_name}'",
            )
            success_hook = _load_success_hook_config(
                endpoint_data.get("success_hook"),
                label=f"success_hook for endpoint '{name}' in service '{service_name}'",
            )
            if success_hook is not None and success_hook.enabled and not success_hook.url:
                raise ValueError(
                    f"success_hook for endpoint '{name}' in service '{service_name}' needs url."
                )

            endpoint = EndpointConfig(
                name=name,
                slug=slug,
                methods=_normalize_methods(endpoint_data.get("methods", endpoint_data.get("method", "GET"))),
                gateway_path=gateway_path,
                upstream_path=upstream_path,
                headers=dict(endpoint_data.get("headers") or {}),
                query=dict(endpoint_data.get("query") or {}),
                pre_call=pre_call,
                response=response,
                output_profile=output_profile,
                response_cache=response_cache,
                success_hook=success_hook,
                compiled_pattern=compile_gateway_path(gateway_path) if gateway_path else None,
            )
            service.endpoints.append(endpoint)

        services.append(service)

    return services


def _endpoint_lookup(services: list[ServiceConfig]) -> dict[tuple[str, str], EndpointConfig]:
    lookup: dict[tuple[str, str], EndpointConfig] = {}
    for service in services:
        for endpoint in service.endpoints:
            lookup[(service.name, endpoint.name)] = endpoint
            lookup[(service.name, endpoint.slug)] = endpoint
    return lookup


def _load_route_targets(value: Any, *, label: str) -> list[RouteTargetConfig]:
    if value in (None, "", []):
        return []
    if not isinstance(value, list):
        raise ValueError(f"{label}.targets must be a list.")
    targets: list[RouteTargetConfig] = []
    for index, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"{label}.targets[{index}] must be a mapping.")
        service_name = str(item.get("service", "")).strip()
        endpoint_name = str(item.get("endpoint", "")).strip()
        if not service_name or not endpoint_name:
            raise ValueError(f"{label}.targets[{index}] needs service and endpoint.")
        target = RouteTargetConfig(service=service_name, endpoint=endpoint_name)
        if target not in targets:
            targets.append(target)
    return targets


def _load_routes_block(
    routes_block: Any,
    *,
    services: list[ServiceConfig],
    output_profiles: dict[str, OutputProfileConfig],
) -> list[RouteConfig]:
    endpoint_lookup = _endpoint_lookup(services)
    routes: list[RouteConfig] = []
    route_slugs: set[str] = set()
    route_paths: set[tuple[str, str]] = set()

    if routes_block in (None, []):
        for service in services:
            for endpoint in service.endpoints:
                if not endpoint.gateway_path:
                    continue
                route = RouteConfig(
                    name=endpoint.name,
                    slug=endpoint.slug,
                    methods=endpoint.methods,
                    gateway_path=endpoint.gateway_path,
                    strategy="single",
                    targets=[RouteTargetConfig(service=service.name, endpoint=endpoint.name)],
                    pre_call=None,
                    output_profile=endpoint.output_profile,
                    response_cache=endpoint.response_cache,
                    success_hook=endpoint.success_hook,
                    compiled_pattern=compile_gateway_path(endpoint.gateway_path),
                    legacy_endpoint_config=True,
                )
                routes.append(route)
        return routes

    if not isinstance(routes_block, list):
        raise ValueError("Config 'routes' must be a list.")

    allowed_strategies = {"single", "round_robin", "failover", "parallel_race"}
    for index, route_data in enumerate(routes_block, start=1):
        if not isinstance(route_data, dict):
            raise ValueError(f"Route #{index} must be a mapping.")

        name = str(route_data.get("name") or f"route_{index}").strip()
        slug = _normalize_slug(route_data.get("slug"), label=f"Route '{name}' slug", fallback=name)
        if slug in route_slugs:
            raise ValueError(f"Duplicate route slug '{slug}'.")
        route_slugs.add(slug)

        methods = _normalize_methods(route_data.get("methods", route_data.get("method", "GET")))
        gateway_path = str(route_data.get("gateway_path", "")).strip()
        if not gateway_path:
            raise ValueError(f"Route '{name}' needs gateway_path.")
        strategy = str(route_data.get("strategy", "single")).strip().lower() or "single"
        if strategy == "parallel":
            strategy = "parallel_race"
        if strategy not in allowed_strategies:
            raise ValueError(
                f"Route '{name}' strategy must be single, round_robin, failover, or parallel_race."
            )

        targets = _load_route_targets(route_data.get("targets"), label=f"Route '{name}'")
        targets = [
            target
            for target in targets
            if (target.service, target.endpoint) in endpoint_lookup
        ]

        for method in methods:
            path_key = (method, gateway_path)
            if path_key in route_paths:
                raise ValueError(f"Duplicate route for {method} {gateway_path}.")
            route_paths.add(path_key)

        output_profile = str(route_data.get("output_profile", "")).strip().lower() or None
        if output_profile is not None and output_profile not in output_profiles:
            output_profile = None

        pre_call = _load_pre_call_config(
            route_data.get("pre_call"),
            label=f"pre_call for route '{name}'",
        )

        response_cache = _load_response_cache_config(
            route_data.get("response_cache"),
            label=f"response_cache for route '{name}'",
        )
        success_hook = _load_success_hook_config(
            route_data.get("success_hook"),
            label=f"success_hook for route '{name}'",
        )
        if success_hook is not None and success_hook.enabled and not success_hook.url:
            raise ValueError(f"success_hook for route '{name}' needs url.")

        routes.append(
            RouteConfig(
                name=name,
                slug=slug,
                methods=methods,
                gateway_path=gateway_path,
                strategy=strategy,
                targets=targets,
                pre_call=pre_call,
                output_profile=output_profile,
                response_cache=response_cache,
                success_hook=success_hook,
                compiled_pattern=compile_gateway_path(gateway_path),
            )
        )

    return routes


def load_gateway_config(config_path: Path | str = CONFIG_PATH) -> GatewayConfig:
    config_path = Path(config_path)
    raw = load_config_document(config_path)
    clients = _load_clients_block(raw.get("clients"))
    output_profiles = _load_output_profiles_block(raw.get("output_profiles"))
    gateway_responses = _load_gateway_response_config(raw.get("gateway_responses"))
    observability = raw.get("observability")
    log_aggregators = _load_log_aggregators_block(observability)
    log_retention_hours = _load_log_retention_hours(observability)
    services = _load_services_block(
        raw.get("services") or {},
        output_profiles=output_profiles,
    )
    routes = _load_routes_block(
        raw.get("routes") or [],
        services=services,
        output_profiles=output_profiles,
    )
    return GatewayConfig(
        clients=clients,
        services=services,
        routes=routes,
        output_profiles=output_profiles,
        gateway_responses=gateway_responses,
        log_aggregators=log_aggregators,
        log_retention_hours=log_retention_hours,
    )


def load_clients(config_path: Path | str = CONFIG_PATH) -> dict[str, ClientConfig]:
    return load_gateway_config(config_path).clients

def load_services(config_path: Path | str = CONFIG_PATH) -> list[ServiceConfig]:
    return load_gateway_config(config_path).services
