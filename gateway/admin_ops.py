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


def save_service(
    config_path: Path,
    *,
    original_name: str,
    service_name: str,
    base_url: str,
    timeout_seconds: float,
    verify_ssl: bool,
    trust_env_proxy: bool,
    variables: dict[str, Any],
    headers: dict[str, Any],
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
        "endpoints": list(existing.get("endpoints") or []),
        "auth": {
            "required": auth_required,
        },
    }
    if variables:
        payload["variables"] = variables
    if headers:
        payload["headers"] = headers
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


def save_endpoint(
    config_path: Path,
    *,
    service_name: str,
    original_name: str,
    original_slug: str,
    endpoint_name: str,
    endpoint_slug: str,
    methods: list[str],
    gateway_path: str,
    upstream_path: str,
    headers: dict[str, Any],
    query: dict[str, Any],
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
    payload["methods"] = methods
    payload["gateway_path"] = gateway_path
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
    if pre_call_code:
        pre_call_payload: dict[str, Any] = {"code": pre_call_code}
        if pre_call_cache_ttl > 0:
            pre_call_payload["cache_ttl_seconds"] = pre_call_cache_ttl
        if pre_call_cache_key:
            pre_call_payload["cache_key"] = pre_call_cache_key
        payload["pre_call"] = pre_call_payload
    else:
        payload.pop("pre_call", None)
    if output_profile:
        payload["output_profile"] = output_profile
    else:
        payload.pop("output_profile", None)
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
    else:
        payload.pop("response_cache", None)
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
    else:
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


def delete_endpoint(config_path: Path, *, service_name: str, endpoint_name: str) -> str:
    document = load_config_document(config_path)
    services = document.setdefault("services", {})
    service = services.get(service_name)
    if not isinstance(service, dict):
        raise ValueError(f"Service '{service_name}' does not exist.")

    endpoints = list(service.get("endpoints") or [])
    filtered = [item for item in endpoints if str(item.get("name")) != endpoint_name]
    if len(filtered) == len(endpoints):
        raise ValueError(f"Endpoint '{endpoint_name}' does not exist in '{service_name}'.")

    service["endpoints"] = filtered
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

    services = document.get("services") or {}
    for service_name, service_data in services.items():
        for endpoint in (service_data.get("endpoints") or []):
            if not isinstance(endpoint, dict):
                continue
            if str(endpoint.get("output_profile", "")).strip() == profile_slug:
                raise ValueError(
                    f"Output profile '{profile_slug}' is still used by endpoint '{service_name}.{endpoint.get('name', '')}'."
                )

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
