from __future__ import annotations

from typing import Any

from gateway.security import AuthenticatedPrincipal


def serialize_response_cache(source: dict[str, Any] | None) -> dict[str, Any]:
    cache = source or {}
    return {
        "enabled": bool(cache.get("enabled", False)),
        "ttl_seconds": int(cache.get("ttl_seconds", 0) or 0),
        "vary_by_client": bool(cache.get("vary_by_client", True)),
        "vary_headers": list(cache.get("vary_headers") or []),
        "methods": list(cache.get("methods") or ["GET"]),
    }


def serialize_success_hook(source: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(source, dict):
        return None
    return {
        "enabled": bool(source.get("enabled", False)),
        "url": str(source.get("url", "") or ""),
        "timeout_seconds": float(source.get("timeout_seconds", 5) or 5),
        "headers": source.get("headers") or {},
        "include_response_body": bool(source.get("include_response_body", False)),
        "include_request_body": bool(source.get("include_request_body", False)),
        "event_type": str(source.get("event_type", "financial") or "financial"),
    }


def serialize_pre_call(source: dict[str, Any] | None) -> dict[str, Any]:
    pre_call = source or {}
    return {
        "code": str(pre_call.get("code", "")),
        "cache_ttl_seconds": int(pre_call.get("cache_ttl_seconds", 0) or 0),
        "cache_key": str(pre_call.get("cache_key", "")),
    }


def serialize_services(document: dict[str, Any]) -> list[dict[str, Any]]:
    services_state: list[dict[str, Any]] = []
    services = document.get("services") or {}
    for service_name, service_data in services.items():
        endpoints_state = []
        for endpoint in service_data.get("endpoints") or []:
            response = endpoint.get("response")
            endpoints_state.append(
                {
                    "name": str(endpoint.get("name", "")),
                    "slug": str(endpoint.get("slug", endpoint.get("name", ""))).strip().lower(),
                    "upstream_path": str(endpoint.get("upstream_path", "")),
                    "headers": endpoint.get("headers") or {},
                    "query": endpoint.get("query") or {},
                    "pre_call": serialize_pre_call(endpoint.get("pre_call")),
                    "output_profile": str(endpoint.get("output_profile", "") or ""),
                    "response_cache": serialize_response_cache(endpoint.get("response_cache")),
                    "response": (
                        {
                            "status_code": int(response.get("status_code", 200) or 200),
                            "body": response.get("body", ""),
                            "content_type": str(response.get("content_type", "") or ""),
                            "headers": response.get("headers") or {},
                        }
                        if isinstance(response, dict)
                        else None
                    ),
                }
            )

        services_state.append(
            {
                "name": service_name,
                "base_url": str(service_data.get("base_url", "")),
                "timeout_seconds": float(service_data.get("timeout_seconds", 30)),
                "verify_ssl": bool(service_data.get("verify_ssl", True)),
                "trust_env_proxy": bool(service_data.get("trust_env_proxy", False)),
                "forward_napigate_headers": bool(service_data.get("forward_napigate_headers", True)),
                "variables": service_data.get("variables") or {},
                "headers": service_data.get("headers") or {},
                "pre_call": serialize_pre_call(service_data.get("pre_call")),
                "response_cache": serialize_response_cache(service_data.get("response_cache")),
                "auth": {
                    "required": bool((service_data.get("auth") or {}).get("required", False))
                },
                "cors": {
                    "enabled": bool((service_data.get("cors") or {}).get("enabled", False)),
                    "allow_origins": list((service_data.get("cors") or {}).get("allow_origins") or []),
                    "allow_methods": list((service_data.get("cors") or {}).get("allow_methods") or []),
                    "allow_headers": list((service_data.get("cors") or {}).get("allow_headers") or []),
                    "expose_headers": list((service_data.get("cors") or {}).get("expose_headers") or []),
                    "allow_credentials": bool((service_data.get("cors") or {}).get("allow_credentials", False)),
                    "max_age_seconds": int((service_data.get("cors") or {}).get("max_age_seconds", 600) or 600),
                },
                "rate_limit": {
                    "enabled": bool((service_data.get("rate_limit") or {}).get("enabled", False)),
                    "requests": int((service_data.get("rate_limit") or {}).get("requests", 60) or 60),
                    "window_seconds": int((service_data.get("rate_limit") or {}).get("window_seconds", 60) or 60),
                    "scope": str((service_data.get("rate_limit") or {}).get("scope", "client_or_ip") or "client_or_ip"),
                },
                "endpoints": endpoints_state,
            }
        )

    return services_state


def serialize_routes(document: dict[str, Any]) -> list[dict[str, Any]]:
    routes_block = document.get("routes") or []
    routes_state: list[dict[str, Any]] = []
    if isinstance(routes_block, list) and routes_block:
        for route in routes_block:
            if not isinstance(route, dict):
                continue
            routes_state.append(
                {
                    "name": str(route.get("name", "")),
                    "slug": str(route.get("slug", route.get("name", ""))).strip().lower(),
                    "methods": list(route.get("methods") or ["GET"]),
                    "gateway_path": str(route.get("gateway_path", "")),
                    "strategy": str(route.get("strategy", "single") or "single"),
                    "targets": [
                        {
                            "service": str(target.get("service", "")),
                            "endpoint": str(target.get("endpoint", "")),
                        }
                        for target in (route.get("targets") or [])
                        if isinstance(target, dict)
                    ],
                    "output_profile": str(route.get("output_profile", "") or ""),
                    "pre_call": serialize_pre_call(route.get("pre_call")),
                    "response_cache": serialize_response_cache(route.get("response_cache")),
                    "success_hook": serialize_success_hook(route.get("success_hook")),
                }
            )
        return routes_state

    for service_name, service_data in (document.get("services") or {}).items():
        for endpoint in service_data.get("endpoints") or []:
            if not isinstance(endpoint, dict) or not endpoint.get("gateway_path"):
                continue
            name = str(endpoint.get("name", ""))
            routes_state.append(
                {
                    "name": name,
                    "slug": str(endpoint.get("slug", name)).strip().lower(),
                    "methods": list(endpoint.get("methods") or ["GET"]),
                    "gateway_path": str(endpoint.get("gateway_path", "")),
                    "strategy": "single",
                    "targets": [{"service": str(service_name), "endpoint": name}],
                    "output_profile": str(endpoint.get("output_profile", "") or ""),
                    "pre_call": serialize_pre_call(endpoint.get("pre_call")),
                    "response_cache": serialize_response_cache(endpoint.get("response_cache")),
                    "success_hook": serialize_success_hook(endpoint.get("success_hook")),
                }
            )
    return routes_state


def serialize_clients(document: dict[str, Any]) -> list[dict[str, Any]]:
    clients_state: list[dict[str, Any]] = []
    for client_data in (document.get("clients") or []):
        if not isinstance(client_data, dict):
            continue
        access = client_data.get("access") or {}
        methods_state = []
        for method in client_data.get("auth_methods") or []:
            if not isinstance(method, dict):
                continue
            methods_state.append(
                {
                    "code": str(method.get("code", "")),
                    "title": str(method.get("title", "")),
                    "type": str(method.get("type", "")),
                    "enabled": bool(method.get("enabled", True)),
                    "secret": str(method.get("secret", method.get("value", "")) or ""),
                    "token": str(method.get("token", "") or ""),
                    "username": str(method.get("username", "") or ""),
                    "password": str(method.get("password", "") or ""),
                    "client_id": str(method.get("client_id", "") or ""),
                    "client_secret": str(method.get("client_secret", "") or ""),
                    "token_ttl_seconds": int(method.get("token_ttl_seconds", 3600) or 3600),
                    "header_name": str(method.get("header_name", "") or ""),
                    "header_names": list(method.get("header_names") or []),
                    "query_params": list(method.get("query_params") or []),
                    "cookie_names": list(method.get("cookie_names") or []),
                    "allow_authorization_header": bool(method.get("allow_authorization_header", False)),
                    "script": str(method.get("script", "") or ""),
                    "cache_ttl_seconds": int(method.get("cache_ttl_seconds", 0) or 0),
                    "cache_key": str(method.get("cache_key", "") or ""),
                }
            )
        clients_state.append(
            {
                "slug": str(client_data.get("slug", client_data.get("code", ""))).strip().lower(),
                "code": str(client_data.get("code", "")),
                "title": str(client_data.get("title", "")),
                "enabled": bool(client_data.get("enabled", True)),
                "ip_allowlist": list(client_data.get("ip_allowlist") or []),
                "access": {
                    "mode": str(access.get("mode", "all") or "all"),
                    "services": list(access.get("services") or []),
                    "endpoints": [
                        {
                            "service": str(item.get("service", "")),
                            "endpoint": str(item.get("endpoint", "")),
                        }
                        for item in (access.get("endpoints") or [])
                        if isinstance(item, dict)
                    ],
                },
                "auth_methods": methods_state,
            }
        )
    return clients_state


def serialize_output_profiles(document: dict[str, Any]) -> list[dict[str, Any]]:
    profiles_state: list[dict[str, Any]] = []
    for slug, profile in (document.get("output_profiles") or {}).items():
        if not isinstance(profile, dict):
            continue
        profiles_state.append(
            {
                "slug": str(slug).strip().lower(),
                "title": str(profile.get("title", slug) or slug),
                "enabled": bool(profile.get("enabled", True)),
                "type": str(profile.get("type", "passthrough") or "passthrough"),
                "success_key": str(profile.get("success_key", "success") or "success"),
                "data_key": str(profile.get("data_key", "data") or "data"),
                "message_key": str(profile.get("message_key", "message") or "message"),
                "error_key": str(profile.get("error_key", "error") or "error"),
                "passthrough_keys": list(profile.get("passthrough_keys") or []),
                "source_success_key": str(profile.get("source_success_key", "") or ""),
                "message_source_keys": list(profile.get("message_source_keys") or []),
                "error_source_keys": list(profile.get("error_source_keys") or []),
                "data_fields": profile.get("data_fields") or {},
                "empty_value": profile.get("empty_value", ""),
                "jsonp_callback_param": str(profile.get("jsonp_callback_param", "callback") or "callback"),
                "jsonp_default_callback": str(profile.get("jsonp_default_callback", "callback") or "callback"),
                "transform_code": str(profile.get("transform_code", "") or ""),
                "custom_validation": {
                    "mode": str(((profile.get("custom_validation") or {}).get("mode", "status_code")) or "status_code"),
                    "source_key": str(((profile.get("custom_validation") or {}).get("source_key", "")) or ""),
                    "expected_value": (profile.get("custom_validation") or {}).get("expected_value", True),
                    "error_source_keys": list(((profile.get("custom_validation") or {}).get("error_source_keys")) or []),
                },
                "headers": profile.get("headers") or {},
            }
        )
    profiles_state.sort(key=lambda item: item["slug"])
    return profiles_state


def serialize_gateway_settings(document: dict[str, Any]) -> dict[str, Any]:
    observability = document.get("observability") or {}
    if not isinstance(observability, dict):
        observability = {}
    gateway_responses = document.get("gateway_responses") or {}
    if not isinstance(gateway_responses, dict):
        gateway_responses = {}
    gateway_response_output_profile = (
        str(gateway_responses.get("output_profile", "") or "").strip().lower()
    )
    gateway_response_mode = str(gateway_responses.get("mode", "") or "").strip().lower()
    if gateway_response_mode not in {"default", "inline", "profile"}:
        if gateway_response_output_profile:
            gateway_response_mode = "profile"
        elif bool(gateway_responses.get("enabled", False)):
            gateway_response_mode = "inline"
        else:
            gateway_response_mode = "default"
    retention_hours = observability.get("log_retention_hours")
    return {
        "log_retention_hours": (
            str(int(retention_hours))
            if retention_hours not in (None, "", 0, "0")
            else ""
        ),
        "gateway_responses": {
            "enabled": gateway_response_mode != "default",
            "mode": gateway_response_mode,
            "output_profile": gateway_response_output_profile,
            "success_key": str(gateway_responses.get("success_key", "success") or "success"),
            "data_key": str(gateway_responses.get("data_key", "data") or "data"),
            "message_key": str(gateway_responses.get("message_key", "message") or "message"),
            "error_key": str(gateway_responses.get("error_key", "error") or "error"),
            "empty_value": gateway_responses.get("empty_value", ""),
            "headers": gateway_responses.get("headers") or {},
        },
    }


def build_admin_page_state(
    *,
    principal: AuthenticatedPrincipal,
    document: dict[str, Any],
    security_state: dict[str, Any],
    services_config_path: str,
    security_config_path: str,
    live_state: dict[str, Any] | None = None,
    audit_logs: list[dict[str, Any]] | None = None,
    network_state: dict[str, Any] | None = None,
    store_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "services": serialize_services(document),
        "routes": serialize_routes(document),
        "clients": serialize_clients(document),
        "output_profiles": serialize_output_profiles(document),
        "settings": serialize_gateway_settings(document),
        "audit_logs": audit_logs or [],
        "security": security_state,
        "principal": {
            "username": principal.username,
            "source": principal.source,
            "roles": principal.roles,
            "permissions": sorted(principal.permissions),
        },
        "config_paths": {
            "services": services_config_path,
            "security": security_config_path,
        },
        "oauth": {
            "token_url": "/__oauth/token",
        },
        "network": network_state or {},
        "store": store_state or {},
        "live": live_state or {},
    }
