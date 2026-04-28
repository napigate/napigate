from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import quote_plus

from gateway.config import load_config_document, save_config_document
from gateway.security import (
    ALL_PERMISSIONS,
    hash_password,
    load_security_document,
    save_security_document,
)


def build_status_query(*, message: str = "", error: str = "") -> str:
    query: dict[str, str] = {}
    if message:
        query["message"] = message
    if error:
        query["error"] = error
    if not query:
        return "/__admin"
    encoded = "&".join(f"{key}={quote_plus(value)}" for key, value in query.items())
    return f"/__admin?{encoded}"


def _build_pre_call_payload(
    *,
    code: str,
    cache_ttl: int,
    cache_key: str,
) -> dict[str, Any] | None:
    if not code:
        return None
    payload: dict[str, Any] = {"code": code}
    if cache_ttl > 0:
        payload["cache_ttl_seconds"] = cache_ttl
    if cache_key:
        payload["cache_key"] = cache_key
    return payload


def _existing_routes_block(document: dict[str, Any]) -> list[dict[str, Any]] | None:
    routes = document.get("routes")
    if routes is None:
        return None
    if not isinstance(routes, list):
        raise ValueError("Config routes block must be a list.")
    return routes


def _remove_service_references(document: dict[str, Any], *, service_name: str) -> None:
    for client in document.get("clients") or []:
        if not isinstance(client, dict):
            continue
        access = client.get("access")
        if not isinstance(access, dict):
            continue
        access["services"] = [
            item
            for item in (access.get("services") or [])
            if str(item).strip() != service_name
        ]
        access["endpoints"] = [
            item
            for item in (access.get("endpoints") or [])
            if not (
                isinstance(item, dict)
                and str(item.get("service", "")).strip() == service_name
            )
        ]

    routes = _existing_routes_block(document)
    if routes is None:
        return
    for route in routes:
        if not isinstance(route, dict):
            continue
        route["targets"] = [
            target
            for target in (route.get("targets") or [])
            if not (
                isinstance(target, dict)
                and str(target.get("service", "")).strip() == service_name
            )
        ]


def _remove_endpoint_references(
    document: dict[str, Any],
    *,
    service_name: str,
    endpoint_refs: set[str],
) -> None:
    for client in document.get("clients") or []:
        if not isinstance(client, dict):
            continue
        access = client.get("access")
        if not isinstance(access, dict):
            continue
        access["endpoints"] = [
            item
            for item in (access.get("endpoints") or [])
            if not (
                isinstance(item, dict)
                and str(item.get("service", "")).strip() == service_name
                and str(item.get("endpoint", "")).strip() in endpoint_refs
            )
        ]

    routes = _existing_routes_block(document)
    if routes is None:
        return
    for route in routes:
        if not isinstance(route, dict):
            continue
        route["targets"] = [
            target
            for target in (route.get("targets") or [])
            if not (
                isinstance(target, dict)
                and str(target.get("service", "")).strip() == service_name
                and str(target.get("endpoint", "")).strip() in endpoint_refs
            )
        ]


def _clear_output_profile_references(document: dict[str, Any], *, profile_slug: str) -> None:
    for service_data in (document.get("services") or {}).values():
        if not isinstance(service_data, dict):
            continue
        for endpoint in service_data.get("endpoints") or []:
            if not isinstance(endpoint, dict):
                continue
            if str(endpoint.get("output_profile", "")).strip().lower() == profile_slug:
                endpoint.pop("output_profile", None)

    routes = _existing_routes_block(document)
    if routes is None:
        return
    for route in routes:
        if not isinstance(route, dict):
            continue
        if str(route.get("output_profile", "")).strip().lower() == profile_slug:
            route.pop("output_profile", None)


def save_gateway_settings(
    config_path: Path,
    *,
    log_retention_hours: int | None,
) -> str:
    document = load_config_document(config_path)
    observability = document.get("observability")
    if not isinstance(observability, dict):
        observability = {}
        document["observability"] = observability

    if log_retention_hours is None:
        observability.pop("log_retention_hours", None)
    else:
        observability["log_retention_hours"] = int(log_retention_hours)

    save_config_document(config_path, document)
    return "Gateway settings saved."


def save_service(
    config_path: Path,
    *,
    original_name: str,
    service_name: str,
    base_url: str,
    timeout_seconds: float,
    verify_ssl: bool,
    trust_env_proxy: bool,
    forward_napigate_headers: bool,
    variables: dict[str, Any],
    headers: dict[str, Any],
    pre_call_code: str,
    pre_call_cache_ttl: int,
    pre_call_cache_key: str,
    auth_required: bool,
    cors_enabled: bool,
    cors_allow_origins: list[str],
    cors_allow_methods: list[str],
    cors_allow_headers: list[str],
    cors_expose_headers: list[str],
    cors_allow_credentials: bool,
    cors_max_age_seconds: int,
    rate_limit_enabled: bool,
    rate_limit_requests: int,
    rate_limit_window_seconds: int,
    rate_limit_scope: str,
) -> str:
    document = load_config_document(config_path)
    services = document.setdefault("services", {})

    existing: dict[str, Any] = {}
    if original_name and original_name != service_name:
        if service_name in services:
            raise ValueError(f"Service '{service_name}' already exists.")
        existing = dict(services.pop(original_name, {}))
    elif service_name in services:
        existing = dict(services[service_name])

    payload: dict[str, Any] = {
        "base_url": base_url,
        "timeout_seconds": timeout_seconds,
        "verify_ssl": verify_ssl,
        "trust_env_proxy": trust_env_proxy,
        "forward_napigate_headers": forward_napigate_headers,
        "endpoints": list(existing.get("endpoints") or []),
        "auth": {
            "required": auth_required,
        },
    }
    if variables:
        payload["variables"] = variables
    if headers:
        payload["headers"] = headers
    pre_call_payload = _build_pre_call_payload(
        code=pre_call_code,
        cache_ttl=pre_call_cache_ttl,
        cache_key=pre_call_cache_key,
    )
    if pre_call_payload:
        payload["pre_call"] = pre_call_payload
    if cors_enabled:
        payload["cors"] = {
            "enabled": True,
            "allow_credentials": cors_allow_credentials,
            "max_age_seconds": cors_max_age_seconds,
        }
        if cors_allow_origins:
            payload["cors"]["allow_origins"] = cors_allow_origins
        if cors_allow_methods:
            payload["cors"]["allow_methods"] = cors_allow_methods
        if cors_allow_headers:
            payload["cors"]["allow_headers"] = cors_allow_headers
        if cors_expose_headers:
            payload["cors"]["expose_headers"] = cors_expose_headers
    if rate_limit_enabled:
        payload["rate_limit"] = {
            "enabled": True,
            "requests": rate_limit_requests,
            "window_seconds": rate_limit_window_seconds,
            "scope": rate_limit_scope,
        }

    services[service_name] = payload
    save_config_document(config_path, document)
    return f"Service '{service_name}' saved."


def delete_service(config_path: Path, *, service_name: str) -> str:
    document = load_config_document(config_path)
    services = document.setdefault("services", {})
    if service_name not in services:
        raise ValueError(f"Service '{service_name}' does not exist.")
    services.pop(service_name)
    _remove_service_references(document, service_name=service_name)
    save_config_document(config_path, document)
    return f"Service '{service_name}' deleted."


def save_client(
    config_path: Path,
    *,
    original_slug: str,
    client_slug: str,
    client_code: str,
    client_title: str,
    enabled: bool,
    ip_allowlist: list[str],
    access: dict[str, Any],
    auth_methods: list[dict[str, Any]],
) -> str:
    document = load_config_document(config_path)
    clients = list(document.setdefault("clients", []))
    if not isinstance(clients, list):
        raise ValueError("Config clients block must be a list.")

    payload: dict[str, Any] = {
        "slug": client_slug,
        "code": client_code,
        "title": client_title,
        "enabled": enabled,
        "access": access,
        "auth_methods": auth_methods,
    }
    if ip_allowlist:
        payload["ip_allowlist"] = ip_allowlist

    existing_index = None
    for index, item in enumerate(clients):
        item_slug = str(item.get("slug", item.get("code", ""))).strip().lower()
        if item_slug == (original_slug or client_slug):
            existing_index = index
            break

    for index, item in enumerate(clients):
        existing_code = str(item.get("code", "")).strip()
        existing_slug = str(item.get("slug", item.get("code", ""))).strip().lower()
        if existing_code == client_code and index != existing_index:
            raise ValueError(f"Client '{client_code}' already exists.")
        if existing_slug == client_slug and index != existing_index:
            raise ValueError(f"Client slug '{client_slug}' already exists.")

    if existing_index is None:
        clients.append(payload)
    else:
        clients[existing_index] = payload

    document["clients"] = clients
    save_config_document(config_path, document)
    return f"Client '{client_code}' saved."


def delete_client(config_path: Path, *, client_slug: str) -> str:
    document = load_config_document(config_path)
    clients = list(document.setdefault("clients", []))
    if not isinstance(clients, list):
        raise ValueError("Config clients block must be a list.")
    filtered = [
        item
        for item in clients
        if str(item.get("slug", item.get("code", ""))).strip().lower() != client_slug
    ]
    if len(filtered) == len(clients):
        raise ValueError(f"Client slug '{client_slug}' does not exist.")
    document["clients"] = filtered
    save_config_document(config_path, document)
    return f"Client '{client_slug}' deleted."


def _legacy_routes_from_endpoints(document: dict[str, Any]) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    for service_name, service_data in (document.get("services") or {}).items():
        if not isinstance(service_data, dict):
            continue
        for endpoint in service_data.get("endpoints") or []:
            if not isinstance(endpoint, dict):
                continue
            gateway_path = str(endpoint.get("gateway_path", "")).strip()
            if not gateway_path:
                continue
            route: dict[str, Any] = {
                "name": str(endpoint.get("name", "")),
                "slug": str(endpoint.get("slug", endpoint.get("name", ""))).strip().lower(),
                "methods": list(endpoint.get("methods") or ["GET"]),
                "gateway_path": gateway_path,
                "strategy": "single",
                "targets": [
                    {
                        "service": str(service_name),
                        "endpoint": str(endpoint.get("name", "")),
                    }
                ],
            }
            for key in ("output_profile", "response_cache", "success_hook"):
                if endpoint.get(key):
                    route[key] = endpoint[key]
            routes.append(route)
    return routes


def _ensure_routes_list(document: dict[str, Any]) -> list[dict[str, Any]]:
    routes = document.setdefault("routes", [])
    if not isinstance(routes, list):
        raise ValueError("Config routes block must be a list.")
    if routes:
        return list(routes)
    return _legacy_routes_from_endpoints(document)


def _strip_endpoint_route_fields(document: dict[str, Any]) -> None:
    for service_data in (document.get("services") or {}).values():
        if not isinstance(service_data, dict):
            continue
        for endpoint in service_data.get("endpoints") or []:
            if not isinstance(endpoint, dict):
                continue
            endpoint.pop("methods", None)
            endpoint.pop("gateway_path", None)
            endpoint.pop("output_profile", None)
            endpoint.pop("response_cache", None)
            endpoint.pop("success_hook", None)


def save_endpoint(
    config_path: Path,
    *,
    service_name: str,
    original_name: str,
    original_slug: str,
    endpoint_name: str,
    endpoint_slug: str,
    upstream_path: str,
    headers: dict[str, Any],
    query: dict[str, Any],
    pre_call_code: str,
    pre_call_cache_ttl: int,
    pre_call_cache_key: str,
) -> str:
    document = load_config_document(config_path)
    services = document.setdefault("services", {})
    service = services.get(service_name)
    if not isinstance(service, dict):
        raise ValueError(f"Service '{service_name}' does not exist.")

    endpoints = list(service.get("endpoints") or [])
    existing_endpoint: dict[str, Any] = {}
    target_name = original_name or endpoint_name
    target_slug = original_slug or endpoint_slug
    for index, item in enumerate(endpoints):
        if not isinstance(item, dict):
            continue
        item_slug = str(item.get("slug", item.get("name", ""))).strip().lower()
        if str(item.get("name")) == target_name or item_slug == target_slug:
            existing_endpoint = dict(item)
            break

    updated = False
    if original_name and original_name != endpoint_name:
        for item in endpoints:
            if not isinstance(item, dict):
                continue
            if str(item.get("name")) == endpoint_name:
                raise ValueError(f"Endpoint '{endpoint_name}' already exists in '{service_name}'.")
    for item in endpoints:
        if not isinstance(item, dict):
            continue
        item_slug = str(item.get("slug", item.get("name", ""))).strip().lower()
        if item_slug == endpoint_slug and (
            str(item.get("name")) != target_name and item_slug != target_slug
        ):
            raise ValueError(f"Endpoint slug '{endpoint_slug}' already exists in '{service_name}'.")

    if not upstream_path and not isinstance(existing_endpoint.get("response"), dict):
        raise ValueError("Upstream path is required unless the endpoint already uses a local response block.")

    payload: dict[str, Any] = dict(existing_endpoint)
    payload["name"] = endpoint_name
    payload["slug"] = endpoint_slug
    payload.pop("methods", None)
    payload.pop("gateway_path", None)
    if upstream_path:
        payload["upstream_path"] = upstream_path
    else:
        payload.pop("upstream_path", None)
    if headers:
        payload["headers"] = headers
    else:
        payload.pop("headers", None)
    if query:
        payload["query"] = query
    else:
        payload.pop("query", None)
    pre_call_payload = _build_pre_call_payload(
        code=pre_call_code,
        cache_ttl=pre_call_cache_ttl,
        cache_key=pre_call_cache_key,
    )
    if pre_call_payload:
        payload["pre_call"] = pre_call_payload
    else:
        payload.pop("pre_call", None)
    payload.pop("output_profile", None)
    payload.pop("response_cache", None)
    payload.pop("success_hook", None)

    for index, item in enumerate(endpoints):
        if not isinstance(item, dict):
            continue
        item_slug = str(item.get("slug", item.get("name", ""))).strip().lower()
        if str(item.get("name")) == target_name or item_slug == target_slug:
            endpoints[index] = payload
            updated = True
            break

    if not updated:
        endpoints.append(payload)

    service["endpoints"] = endpoints
    save_config_document(config_path, document)
    return f"Endpoint '{endpoint_name}' saved in '{service_name}'."


def save_route(
    config_path: Path,
    *,
    original_slug: str,
    route_name: str,
    route_slug: str,
    methods: list[str],
    gateway_path: str,
    strategy: str,
    targets: list[dict[str, Any]],
    pre_call_code: str,
    pre_call_cache_ttl: int,
    pre_call_cache_key: str,
    output_profile: str,
    response_cache_ttl: int,
    response_cache_vary_by_client: bool,
    response_cache_vary_headers: list[str],
    response_cache_methods: list[str],
    success_hook_url: str,
    success_hook_timeout_seconds: float,
    success_hook_event_type: str,
    success_hook_headers: dict[str, Any],
    success_hook_include_response_body: bool,
    success_hook_include_request_body: bool,
) -> str:
    document = load_config_document(config_path)
    routes = _ensure_routes_list(document)

    payload: dict[str, Any] = {
        "name": route_name,
        "slug": route_slug,
        "methods": methods,
        "gateway_path": gateway_path,
        "strategy": strategy,
        "targets": targets,
    }
    if output_profile:
        payload["output_profile"] = output_profile
    pre_call_payload = _build_pre_call_payload(
        code=pre_call_code,
        cache_ttl=pre_call_cache_ttl,
        cache_key=pre_call_cache_key,
    )
    if pre_call_payload:
        payload["pre_call"] = pre_call_payload
    if response_cache_ttl > 0:
        payload["response_cache"] = {
            "enabled": True,
            "ttl_seconds": response_cache_ttl,
            "vary_by_client": response_cache_vary_by_client,
        }
        if response_cache_vary_headers:
            payload["response_cache"]["vary_headers"] = response_cache_vary_headers
        if response_cache_methods:
            payload["response_cache"]["methods"] = response_cache_methods
    if success_hook_url:
        payload["success_hook"] = {
            "enabled": True,
            "url": success_hook_url,
            "timeout_seconds": success_hook_timeout_seconds,
            "event_type": success_hook_event_type or "financial",
            "include_response_body": success_hook_include_response_body,
            "include_request_body": success_hook_include_request_body,
        }
        if success_hook_headers:
            payload["success_hook"]["headers"] = success_hook_headers

    target_slug = original_slug or route_slug
    existing_index = None
    for index, item in enumerate(routes):
        if not isinstance(item, dict):
            continue
        item_slug = str(item.get("slug", item.get("name", ""))).strip().lower()
        if item_slug == target_slug:
            existing_index = index
            break

    for index, item in enumerate(routes):
        if not isinstance(item, dict):
            continue
        item_slug = str(item.get("slug", item.get("name", ""))).strip().lower()
        if item_slug == route_slug and index != existing_index:
            raise ValueError(f"Route slug '{route_slug}' already exists.")

    if existing_index is None:
        routes.append(payload)
    else:
        routes[existing_index] = payload

    document["routes"] = routes
    _strip_endpoint_route_fields(document)
    save_config_document(config_path, document)
    return f"Route '{route_name}' saved."


def delete_route(config_path: Path, *, route_slug: str) -> str:
    document = load_config_document(config_path)
    routes = _ensure_routes_list(document)
    filtered = [
        item
        for item in routes
        if str(item.get("slug", item.get("name", ""))).strip().lower() != route_slug
    ]
    if len(filtered) == len(routes):
        raise ValueError(f"Route '{route_slug}' does not exist.")

    document["routes"] = filtered
    _strip_endpoint_route_fields(document)
    save_config_document(config_path, document)
    return f"Route '{route_slug}' deleted."


def delete_endpoint(config_path: Path, *, service_name: str, endpoint_name: str) -> str:
    document = load_config_document(config_path)
    services = document.setdefault("services", {})
    service = services.get(service_name)
    if not isinstance(service, dict):
        raise ValueError(f"Service '{service_name}' does not exist.")

    endpoints = list(service.get("endpoints") or [])
    existing_endpoint = next(
        (
            item
            for item in endpoints
            if isinstance(item, dict) and str(item.get("name")) == endpoint_name
        ),
        None,
    )
    filtered = [item for item in endpoints if str(item.get("name")) != endpoint_name]
    if len(filtered) == len(endpoints):
        raise ValueError(f"Endpoint '{endpoint_name}' does not exist in '{service_name}'.")

    service["endpoints"] = filtered
    endpoint_refs = {endpoint_name}
    if isinstance(existing_endpoint, dict):
        endpoint_slug = str(existing_endpoint.get("slug", "")).strip()
        if endpoint_slug:
            endpoint_refs.add(endpoint_slug)
    _remove_endpoint_references(
        document,
        service_name=service_name,
        endpoint_refs=endpoint_refs,
    )
    save_config_document(config_path, document)
    return f"Endpoint '{endpoint_name}' deleted from '{service_name}'."


def save_output_profile(
    config_path: Path,
    *,
    original_slug: str,
    profile_slug: str,
    profile_title: str,
    enabled: bool,
    profile_type: str,
    success_key: str,
    data_key: str,
    message_key: str,
    error_key: str,
    passthrough_keys: list[str],
    jsonp_callback_param: str,
    jsonp_default_callback: str,
    headers: dict[str, Any],
) -> str:
    document = load_config_document(config_path)
    profiles = document.setdefault("output_profiles", {})
    if not isinstance(profiles, dict):
        raise ValueError("Config output_profiles block must be a mapping.")

    if original_slug and original_slug != profile_slug:
        if profile_slug in profiles:
            raise ValueError(f"Output profile '{profile_slug}' already exists.")
        payload = dict(profiles.pop(original_slug, {}))
    else:
        payload = dict(profiles.get(profile_slug, {}))

    payload.update(
        {
            "title": profile_title,
            "enabled": enabled,
            "type": profile_type,
            "success_key": success_key,
            "data_key": data_key,
            "message_key": message_key,
            "error_key": error_key,
            "jsonp_callback_param": jsonp_callback_param,
            "jsonp_default_callback": jsonp_default_callback,
        }
    )
    if passthrough_keys:
        payload["passthrough_keys"] = passthrough_keys
    else:
        payload.pop("passthrough_keys", None)
    if headers:
        payload["headers"] = headers
    else:
        payload.pop("headers", None)

    profiles[profile_slug] = payload
    save_config_document(config_path, document)
    return f"Output profile '{profile_slug}' saved."


def delete_output_profile(config_path: Path, *, profile_slug: str) -> str:
    document = load_config_document(config_path)
    profiles = document.setdefault("output_profiles", {})
    if not isinstance(profiles, dict):
        raise ValueError("Config output_profiles block must be a mapping.")
    if profile_slug not in profiles:
        raise ValueError(f"Output profile '{profile_slug}' does not exist.")

    _clear_output_profile_references(document, profile_slug=profile_slug)
    profiles.pop(profile_slug)
    save_config_document(config_path, document)
    return f"Output profile '{profile_slug}' deleted."


def save_role(
    config_path: Path,
    *,
    original_name: str,
    role_name: str,
    permissions: list[str],
) -> str:
    document = load_security_document(config_path)
    roles = document.setdefault("roles", {})
    users = document.setdefault("users", {})

    normalized_permissions = []
    for permission in permissions:
        permission_name = str(permission).strip()
        if permission_name in ALL_PERMISSIONS and permission_name not in normalized_permissions:
            normalized_permissions.append(permission_name)

    if original_name and original_name != role_name:
        if role_name in roles:
            raise ValueError(f"Role '{role_name}' already exists.")
        role_payload = roles.pop(original_name, {"permissions": []})
        roles[role_name] = role_payload

        for user_data in users.values():
            user_roles = [
                role_name if role == original_name else role
                for role in user_data.get("roles", [])
            ]
            user_data["roles"] = list(dict.fromkeys(user_roles))

    roles[role_name] = {"permissions": normalized_permissions}
    save_security_document(config_path, document)
    return f"Role '{role_name}' saved."


def delete_role(config_path: Path, *, role_name: str) -> str:
    document = load_security_document(config_path)
    roles = document.setdefault("roles", {})
    users = document.setdefault("users", {})

    if role_name not in roles:
        raise ValueError(f"Role '{role_name}' does not exist.")

    for username, user_data in users.items():
        if role_name in (user_data.get("roles") or []):
            raise ValueError(f"Role '{role_name}' is still assigned to user '{username}'.")

    roles.pop(role_name)
    save_security_document(config_path, document)
    return f"Role '{role_name}' deleted."


def save_user(
    config_path: Path,
    *,
    original_username: str,
    username: str,
    password: str,
    roles: list[str],
    enabled: bool,
) -> str:
    document = load_security_document(config_path)
    users = document.setdefault("users", {})
    roles_map = document.setdefault("roles", {})

    normalized_roles = []
    for role_name in roles:
        role_name_str = str(role_name).strip()
        if role_name_str:
            if role_name_str not in roles_map:
                raise ValueError(f"Role '{role_name_str}' does not exist.")
            if role_name_str not in normalized_roles:
                normalized_roles.append(role_name_str)

    existing = dict(users.get(original_username or username, {}))
    if original_username and original_username != username:
        if username in users:
            raise ValueError(f"User '{username}' already exists.")
        users.pop(original_username, None)

    payload: dict[str, Any] = {
        "roles": normalized_roles,
        "enabled": enabled,
    }

    if password:
        payload["password_hash"] = hash_password(password)
    elif existing.get("password_hash"):
        payload["password_hash"] = existing["password_hash"]
    else:
        raise ValueError("Password is required for a new user.")

    users[username] = payload
    save_security_document(config_path, document)
    return f"User '{username}' saved."


def delete_user(config_path: Path, *, username: str) -> str:
    document = load_security_document(config_path)
    users = document.setdefault("users", {})
    if username not in users:
        raise ValueError(f"User '{username}' does not exist.")
    users.pop(username)
    save_security_document(config_path, document)
    return f"User '{username}' deleted."
