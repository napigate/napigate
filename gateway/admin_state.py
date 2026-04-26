from __future__ import annotations

from typing import Any

from gateway.security import AuthenticatedPrincipal


def serialize_services(document: dict[str, Any]) -> list[dict[str, Any]]:
    services_state: list[dict[str, Any]] = []
    services = document.get("services") or {}
    for service_name, service_data in services.items():
        endpoints_state = []
        for endpoint in service_data.get("endpoints") or []:
            pre_call = endpoint.get("pre_call") or {}
            response = endpoint.get("response")
            endpoints_state.append(
                {
                    "name": str(endpoint.get("name", "")),
                    "slug": str(endpoint.get("slug", endpoint.get("name", ""))).strip().lower(),
                    "methods": list(endpoint.get("methods") or ["GET"]),
                    "gateway_path": str(endpoint.get("gateway_path", "")),
                    "upstream_path": str(endpoint.get("upstream_path", "")),
                    "headers": endpoint.get("headers") or {},
                    "query": endpoint.get("query") or {},
                    "pre_call": {
                        "code": str(pre_call.get("code", "")),
                        "cache_ttl_seconds": int(pre_call.get("cache_ttl_seconds", 0) or 0),
                        "cache_key": str(pre_call.get("cache_key", "")),
                    },
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
                    "output_profile": str(endpoint.get("output_profile", "") or ""),
                    "response_cache": {
                        "enabled": bool((endpoint.get("response_cache") or {}).get("enabled", False)),
                        "ttl_seconds": int((endpoint.get("response_cache") or {}).get("ttl_seconds", 0) or 0),
                        "vary_by_client": bool((endpoint.get("response_cache") or {}).get("vary_by_client", True)),
                        "vary_headers": list((endpoint.get("response_cache") or {}).get("vary_headers") or []),
                        "methods": list((endpoint.get("response_cache") or {}).get("methods") or ["GET"]),
                    },
                    "success_hook": (
                        {
                            "enabled": bool((endpoint.get("success_hook") or {}).get("enabled", False)),
                            "url": str((endpoint.get("success_hook") or {}).get("url", "") or ""),
                            "timeout_seconds": float((endpoint.get("success_hook") or {}).get("timeout_seconds", 5) or 5),
                            "headers": (endpoint.get("success_hook") or {}).get("headers") or {},
                            "include_response_body": bool((endpoint.get("success_hook") or {}).get("include_response_body", False)),
                            "include_request_body": bool((endpoint.get("success_hook") or {}).get("include_request_body", False)),
                            "event_type": str((endpoint.get("success_hook") or {}).get("event_type", "financial") or "financial"),
                        }
                        if isinstance(endpoint.get("success_hook"), dict)
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
                "variables": service_data.get("variables") or {},
                "headers": service_data.get("headers") or {},
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
                "jsonp_callback_param": str(profile.get("jsonp_callback_param", "callback") or "callback"),
                "jsonp_default_callback": str(profile.get("jsonp_default_callback", "callback") or "callback"),
                "headers": profile.get("headers") or {},
            }
        )
    profiles_state.sort(key=lambda item: item["slug"])
    return profiles_state


def build_admin_page_state(
    *,
    principal: AuthenticatedPrincipal,
    document: dict[str, Any],
    security_state: dict[str, Any],
    services_config_path: str,
    security_config_path: str,
    live_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "services": serialize_services(document),
        "clients": serialize_clients(document),
        "output_profiles": serialize_output_profiles(document),
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
        "live": live_state or {},
    }
