from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import hmac
import logging
import secrets
import threading
from pathlib import Path
from typing import Any

import yaml


LOGGER = logging.getLogger("gateway.security")
SECURITY_CONFIG_PATH = Path("config/security.yaml")
PASSWORD_ALGORITHM = "pbkdf2_sha256"
PASSWORD_ITERATIONS = 200_000
ALL_PERMISSIONS = {
    "monitor_access",
    "admin_access",
    "services_manage",
    "security_manage",
}
PERMISSION_LABELS = {
    "monitor_access": "Access monitor",
    "admin_access": "Access admin panel",
    "services_manage": "View and manage services and endpoints",
    "security_manage": "Manage users and roles",
}
DEFAULT_SECURITY_DOCUMENT: dict[str, Any] = {
    "roles": {
        "admin": {
            "permissions": sorted(ALL_PERMISSIONS),
        },
        "operator": {
            "permissions": [
                "monitor_access",
                "admin_access",
                "services_manage",
            ],
        },
        "monitor": {
            "permissions": [
                "monitor_access",
            ],
        },
    },
    "users": {},
}


@dataclass(slots=True)
class AuthenticatedPrincipal:
    username: str
    source: str
    roles: list[str]
    permissions: set[str]

    def can(self, permission: str) -> bool:
        return permission in self.permissions


def _copy_default_security() -> dict[str, Any]:
    return deepcopy(DEFAULT_SECURITY_DOCUMENT)


def hash_password(password: str) -> str:
    if not password:
        raise ValueError("Password cannot be empty.")
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        PASSWORD_ITERATIONS,
    ).hex()
    return f"{PASSWORD_ALGORITHM}${PASSWORD_ITERATIONS}${salt}${digest}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iterations_raw, salt, expected_digest = password_hash.split("$", 3)
        if algorithm != PASSWORD_ALGORITHM:
            return False
        iterations = int(iterations_raw)
    except ValueError:
        return False

    calculated = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        iterations,
    ).hex()
    return hmac.compare_digest(calculated, expected_digest)


def load_security_document(config_path: Path | str = SECURITY_CONFIG_PATH) -> dict[str, Any]:
    config_path = Path(config_path)
    if not config_path.exists():
        return _copy_default_security()

    raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    roles = raw.get("roles")
    users = raw.get("users")
    if roles is None:
        raw["roles"] = deepcopy(DEFAULT_SECURITY_DOCUMENT["roles"])
    elif not isinstance(roles, dict):
        raise ValueError("Security config 'roles' must be a mapping.")
    if users is None:
        raw["users"] = {}
    elif not isinstance(users, dict):
        raise ValueError("Security config 'users' must be a mapping.")
    return raw


def _validate_security_document(document: dict[str, Any]) -> dict[str, Any]:
    roles = document.get("roles")
    users = document.get("users")
    if not isinstance(roles, dict):
        raise ValueError("Security config 'roles' must be a mapping.")
    if not isinstance(users, dict):
        raise ValueError("Security config 'users' must be a mapping.")

    normalized_roles: dict[str, Any] = {}
    for role_name, role_data in roles.items():
        if not isinstance(role_data, dict):
            raise ValueError(f"Role '{role_name}' must be a mapping.")
        permissions = role_data.get("permissions") or []
        if not isinstance(permissions, list):
            raise ValueError(f"Role '{role_name}' permissions must be a list.")
        normalized_permissions = []
        for permission in permissions:
            permission_name = str(permission).strip()
            if permission_name not in ALL_PERMISSIONS:
                raise ValueError(f"Unknown permission '{permission_name}' in role '{role_name}'.")
            if permission_name not in normalized_permissions:
                normalized_permissions.append(permission_name)
        normalized_roles[str(role_name)] = {"permissions": normalized_permissions}

    normalized_users: dict[str, Any] = {}
    for username, user_data in users.items():
        if not isinstance(user_data, dict):
            raise ValueError(f"User '{username}' must be a mapping.")
        roles_list = user_data.get("roles") or []
        if not isinstance(roles_list, list):
            raise ValueError(f"User '{username}' roles must be a list.")
        normalized_user_roles = []
        for role_name in roles_list:
            role_name_str = str(role_name).strip()
            if role_name_str not in normalized_roles:
                raise ValueError(
                    f"User '{username}' references unknown role '{role_name_str}'."
                )
            if role_name_str not in normalized_user_roles:
                normalized_user_roles.append(role_name_str)

        password_hash = str(user_data.get("password_hash", "")).strip()
        if password_hash and password_hash.count("$") != 3:
            raise ValueError(f"User '{username}' has an invalid password hash format.")

        normalized_users[str(username)] = {
            "roles": normalized_user_roles,
            "enabled": bool(user_data.get("enabled", True)),
        }
        if password_hash:
            normalized_users[str(username)]["password_hash"] = password_hash

    return {
        "roles": normalized_roles,
        "users": normalized_users,
    }


def save_security_document(config_path: Path | str, document: dict[str, Any]) -> None:
    config_path = Path(config_path)
    normalized = _validate_security_document(document)
    serialized = yaml.safe_dump(
        normalized,
        sort_keys=False,
        allow_unicode=False,
    )
    config_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = config_path.with_name(f"{config_path.name}.tmp")
    temp_path.write_text(serialized, encoding="utf-8")
    load_security_document(temp_path)
    temp_path.replace(config_path)


class SecurityManager:
    def __init__(self, config_path: Path | str = SECURITY_CONFIG_PATH) -> None:
        self.config_path = Path(config_path)
        self._lock = threading.RLock()
        self.roles: dict[str, dict[str, Any]] = {}
        self.users: dict[str, dict[str, Any]] = {}
        self._config_signature: tuple[int, int] | None = None

    def load(self) -> None:
        document = _validate_security_document(load_security_document(self.config_path))
        signature = self._file_signature(self.config_path)
        with self._lock:
            self.roles = document["roles"]
            self.users = document["users"]
            self._config_signature = signature

    def maybe_reload(self) -> None:
        current_signature = self._file_signature(self.config_path)
        with self._lock:
            known_signature = self._config_signature
        if current_signature == known_signature:
            return
        try:
            self.load()
        except Exception:  # noqa: BLE001
            LOGGER.exception("Failed to reload security config from %s", self.config_path)
            with self._lock:
                self._config_signature = known_signature

    def authenticate(
        self,
        username: str,
        password: str,
        *,
        bootstrap_username: str,
        bootstrap_password: str,
    ) -> AuthenticatedPrincipal | None:
        if bootstrap_username and bootstrap_password:
            if hmac.compare_digest(username, bootstrap_username) and hmac.compare_digest(
                password, bootstrap_password
            ):
                return AuthenticatedPrincipal(
                    username=username,
                    source="bootstrap",
                    roles=["bootstrap_admin"],
                    permissions=set(ALL_PERMISSIONS),
                )

        with self._lock:
            user = deepcopy(self.users.get(username))
            roles = deepcopy(self.roles)

        if not user or not user.get("enabled", True):
            return None

        password_hash = str(user.get("password_hash", "")).strip()
        if not password_hash or not verify_password(password, password_hash):
            return None

        role_names = [str(role) for role in user.get("roles") or []]
        permissions: set[str] = set()
        for role_name in role_names:
            role = roles.get(role_name) or {}
            permissions.update(str(item) for item in role.get("permissions") or [])

        return AuthenticatedPrincipal(
            username=username,
            source="config",
            roles=role_names,
            permissions=permissions,
        )

    def public_state(self) -> dict[str, Any]:
        with self._lock:
            roles = deepcopy(self.roles)
            users = deepcopy(self.users)

        public_users = []
        for username, user_data in users.items():
            public_users.append(
                {
                    "username": username,
                    "roles": list(user_data.get("roles") or []),
                    "enabled": bool(user_data.get("enabled", True)),
                    "source": "config",
                }
            )

        public_roles = []
        for role_name, role_data in roles.items():
            public_roles.append(
                {
                    "name": role_name,
                    "permissions": list(role_data.get("permissions") or []),
                }
            )

        return {
            "roles": public_roles,
            "users": public_users,
            "permission_labels": dict(PERMISSION_LABELS),
        }

    def _file_signature(self, path: Path) -> tuple[int, int] | None:
        try:
            stat = path.stat()
        except FileNotFoundError:
            return None
        return stat.st_mtime_ns, stat.st_size
