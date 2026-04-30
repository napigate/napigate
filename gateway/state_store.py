from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
import logging
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any
from urllib.parse import urlsplit

import yaml

from gateway.config import (
    CONFIG_PATH,
    _config_file_revision,
    _load_config_document_from_file,
    _save_config_document_to_file,
    load_gateway_config_document,
    normalize_config_document,
)
from gateway.security import (
    SECURITY_CONFIG_PATH,
    _load_security_document_from_file,
    _save_security_document_to_file,
    _security_file_revision,
    validate_security_document,
)


LOGGER = logging.getLogger("gateway.state_store")


@dataclass(slots=True)
class AdminAuditLogEntry:
    created_at: str
    principal_username: str
    principal_source: str
    listener: str
    action: str
    target_kind: str
    target_ref: str
    message: str
    client_ip: str
    details: dict[str, Any]


class FileStateStore:
    mode = "file"
    audit_enabled = True

    def __init__(
        self,
        *,
        config_path: Path | str = CONFIG_PATH,
        security_path: Path | str = SECURITY_CONFIG_PATH,
        audit_db_path: Path | str = "data/monitor.db",
    ) -> None:
        self.config_path = Path(config_path)
        self.security_path = Path(security_path)
        self.config_source_label = str(self.config_path)
        self.security_source_label = str(self.security_path)
        audit_db_path = Path(audit_db_path)
        audit_db_path.parent.mkdir(parents=True, exist_ok=True)
        self._audit_connection = sqlite3.connect(
            audit_db_path,
            check_same_thread=False,
            timeout=5,
        )
        self._audit_connection.row_factory = sqlite3.Row
        self._audit_lock = threading.Lock()
        self._init_audit_db()

    def _init_audit_db(self) -> None:
        with self._audit_lock:
            self._audit_connection.execute(
                """
                CREATE TABLE IF NOT EXISTS admin_change_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    principal_username TEXT NOT NULL,
                    principal_source TEXT NOT NULL,
                    listener TEXT NOT NULL DEFAULT '',
                    action TEXT NOT NULL,
                    target_kind TEXT NOT NULL,
                    target_ref TEXT NOT NULL,
                    message TEXT NOT NULL,
                    client_ip TEXT NOT NULL DEFAULT '',
                    details_json TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            self._audit_connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_admin_change_logs_created_at
                ON admin_change_logs (created_at DESC)
                """
            )
            self._audit_connection.commit()

    def load_config_document(self) -> dict[str, Any]:
        return _load_config_document_from_file(self.config_path)

    def save_config_document(self, document: dict[str, Any]) -> None:
        _save_config_document_to_file(self.config_path, document)

    def load_security_document(self) -> dict[str, Any]:
        return _load_security_document_from_file(self.security_path)

    def save_security_document(self, document: dict[str, Any]) -> None:
        _save_security_document_to_file(self.security_path, document)

    def config_revision(self) -> Any:
        return _config_file_revision(self.config_path)

    def security_revision(self) -> Any:
        return _security_file_revision(self.security_path)

    def list_admin_change_logs(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._audit_lock:
            rows = self._audit_connection.execute(
                """
                SELECT
                    created_at,
                    principal_username,
                    principal_source,
                    listener,
                    action,
                    target_kind,
                    target_ref,
                    message,
                    client_ip,
                    details_json
                FROM admin_change_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        entries: list[dict[str, Any]] = []
        for row in rows:
            details_raw = row["details_json"]
            try:
                details = json.loads(str(details_raw or "{}"))
            except json.JSONDecodeError:
                details = {}
            entries.append(
                {
                    "created_at": str(row["created_at"]),
                    "principal_username": str(row["principal_username"]),
                    "principal_source": str(row["principal_source"]),
                    "listener": str(row["listener"]),
                    "action": str(row["action"]),
                    "target_kind": str(row["target_kind"]),
                    "target_ref": str(row["target_ref"]),
                    "message": str(row["message"]),
                    "client_ip": str(row["client_ip"]),
                    "details": details if isinstance(details, dict) else {},
                }
            )
        return entries

    def log_admin_change(
        self,
        *,
        principal_username: str,
        principal_source: str,
        listener: str,
        action: str,
        target_kind: str,
        target_ref: str,
        message: str,
        client_ip: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        payload = json.dumps(details or {}, ensure_ascii=False)
        with self._audit_lock:
            self._audit_connection.execute(
                """
                INSERT INTO admin_change_logs (
                    created_at,
                    principal_username,
                    principal_source,
                    listener,
                    action,
                    target_kind,
                    target_ref,
                    message,
                    client_ip,
                    details_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(UTC).isoformat(),
                    principal_username,
                    principal_source,
                    listener,
                    action,
                    target_kind,
                    target_ref,
                    message,
                    client_ip,
                    payload,
                ),
            )
            self._audit_connection.commit()

    def close(self) -> None:
        with self._audit_lock:
            self._audit_connection.close()


class PostgresStateStore:
    mode = "postgres"
    audit_enabled = True

    def __init__(
        self,
        *,
        dsn: str,
        config_path: Path | str = CONFIG_PATH,
        security_path: Path | str = SECURITY_CONFIG_PATH,
        sync_interval_seconds: float = 2.0,
    ) -> None:
        if not dsn.strip():
            raise ValueError("NAPIGATE_POSTGRES_DSN is required when state store mode is postgres.")
        self._dsn = dsn.strip()
        self._config_bootstrap_path = Path(config_path)
        self._security_bootstrap_path = Path(security_path)
        self._sync_interval_seconds = max(sync_interval_seconds, 0.5)
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._revisions: dict[str, int | None] = {"config": None, "security": None}
        self.config_source_label = f"{self._dsn_label()}/config"
        self.security_source_label = f"{self._dsn_label()}/security"
        self._ensure_schema()
        self._bootstrap_documents()
        self._refresh_revisions()
        self._poller = threading.Thread(
            target=self._poll_revisions_loop,
            name="napigate-state-sync",
            daemon=True,
        )
        self._poller.start()

    def _import_psycopg(self):
        try:
            import psycopg  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - depends on optional extra
            raise RuntimeError(
                "PostgreSQL state store requires the 'psycopg[binary]' dependency. "
                "Install with pip install \".[postgres]\"."
            ) from exc
        return psycopg

    def _connect(self):
        psycopg = self._import_psycopg()
        return psycopg.connect(self._dsn)

    def _dsn_label(self) -> str:
        if self._dsn.startswith(("postgres://", "postgresql://")):
            try:
                parsed = urlsplit(self._dsn)
            except ValueError:
                LOGGER.warning(
                    "Could not parse PostgreSQL DSN for source label. Falling back to a generic label."
                )
                return "postgresql"
            host = parsed.hostname or "postgres"
            database = parsed.path.lstrip("/") or "postgres"
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            return f"postgresql://{host}/{database}"
        return "postgresql"

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS gateway_state_revisions (
                        scope TEXT PRIMARY KEY,
                        revision BIGINT NOT NULL DEFAULT 1,
                        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS gateway_config_settings (
                        id SMALLINT PRIMARY KEY,
                        gateway_responses_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                        observability_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                        extras_json JSONB NOT NULL DEFAULT '{}'::jsonb
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS gateway_services (
                        service_name TEXT PRIMARY KEY,
                        position INTEGER NOT NULL DEFAULT 0,
                        service_json JSONB NOT NULL DEFAULT '{}'::jsonb
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS gateway_service_endpoints (
                        service_name TEXT NOT NULL REFERENCES gateway_services(service_name) ON DELETE CASCADE,
                        endpoint_ref TEXT NOT NULL,
                        position INTEGER NOT NULL DEFAULT 0,
                        endpoint_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                        PRIMARY KEY (service_name, endpoint_ref)
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS gateway_routes (
                        route_slug TEXT PRIMARY KEY,
                        position INTEGER NOT NULL DEFAULT 0,
                        route_json JSONB NOT NULL DEFAULT '{}'::jsonb
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS gateway_clients (
                        client_slug TEXT PRIMARY KEY,
                        position INTEGER NOT NULL DEFAULT 0,
                        client_json JSONB NOT NULL DEFAULT '{}'::jsonb
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS gateway_output_profiles (
                        profile_slug TEXT PRIMARY KEY,
                        position INTEGER NOT NULL DEFAULT 0,
                        profile_json JSONB NOT NULL DEFAULT '{}'::jsonb
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS gateway_security_settings (
                        id SMALLINT PRIMARY KEY,
                        extras_json JSONB NOT NULL DEFAULT '{}'::jsonb
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS gateway_roles (
                        role_name TEXT PRIMARY KEY,
                        position INTEGER NOT NULL DEFAULT 0,
                        role_json JSONB NOT NULL DEFAULT '{}'::jsonb
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS gateway_users (
                        username TEXT PRIMARY KEY,
                        position INTEGER NOT NULL DEFAULT 0,
                        user_json JSONB NOT NULL DEFAULT '{}'::jsonb
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS admin_change_logs (
                        id BIGSERIAL PRIMARY KEY,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        principal_username TEXT NOT NULL,
                        principal_source TEXT NOT NULL,
                        listener TEXT NOT NULL DEFAULT '',
                        action TEXT NOT NULL,
                        target_kind TEXT NOT NULL,
                        target_ref TEXT NOT NULL,
                        message TEXT NOT NULL,
                        client_ip TEXT NOT NULL DEFAULT '',
                        details_json JSONB NOT NULL DEFAULT '{}'::jsonb
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_admin_change_logs_created_at
                    ON admin_change_logs (created_at DESC)
                    """
                )
            conn.commit()

    def _table_exists(self, cur, table_name: str) -> bool:
        cur.execute("SELECT to_regclass(%s)", (f"public.{table_name}",))
        row = cur.fetchone()
        return row is not None and row[0] is not None

    def _coerce_json_cell(self, value: Any, default: Any) -> Any:
        if value is None:
            return default
        if isinstance(value, (dict, list, bool, int, float)):
            return value
        if isinstance(value, memoryview):
            value = value.tobytes()
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return default
        return value

    def _state_scope_exists(self, cur, scope: str) -> bool:
        cur.execute("SELECT 1 FROM gateway_state_revisions WHERE scope = %s", (scope,))
        return cur.fetchone() is not None

    def _legacy_scope_document(self, cur, scope: str) -> dict[str, Any] | None:
        if not self._table_exists(cur, "gateway_documents"):
            return None
        cur.execute("SELECT document_yaml FROM gateway_documents WHERE scope = %s", (scope,))
        row = cur.fetchone()
        if row is None:
            return None
        return yaml.safe_load(str(row[0])) or {}

    def _bootstrap_documents(self) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                if not self._state_scope_exists(cur, "config"):
                    config_document = self._legacy_scope_document(cur, "config")
                    if config_document is None:
                        config_document = _load_config_document_from_file(self._config_bootstrap_path)
                    normalized_config = normalize_config_document(config_document)
                    load_gateway_config_document(normalized_config)
                    self._write_config_document(cur, normalized_config)
                    self._set_revision(cur, "config", revision=1)

                if not self._state_scope_exists(cur, "security"):
                    security_document = self._legacy_scope_document(cur, "security")
                    if security_document is None:
                        security_document = _load_security_document_from_file(self._security_bootstrap_path)
                    normalized_security = validate_security_document(security_document)
                    self._write_security_document(cur, normalized_security)
                    self._set_revision(cur, "security", revision=1)
            conn.commit()

    def _set_revision(self, cur, scope: str, *, revision: int) -> None:
        cur.execute(
            """
            INSERT INTO gateway_state_revisions (scope, revision, updated_at)
            VALUES (%s, %s, NOW())
            ON CONFLICT (scope) DO UPDATE
            SET
                revision = EXCLUDED.revision,
                updated_at = NOW()
            """,
            (scope, revision),
        )

    def _bump_revision(self, cur, scope: str) -> int:
        cur.execute(
            """
            INSERT INTO gateway_state_revisions (scope, revision, updated_at)
            VALUES (%s, 1, NOW())
            ON CONFLICT (scope) DO UPDATE
            SET
                revision = gateway_state_revisions.revision + 1,
                updated_at = NOW()
            RETURNING revision
            """,
            (scope,),
        )
        row = cur.fetchone()
        return int(row[0]) if row else 1

    def _service_endpoint_ref(self, endpoint: dict[str, Any], position: int) -> str:
        raw = str(endpoint.get("slug") or endpoint.get("name") or f"endpoint-{position}").strip()
        return raw.lower() or f"endpoint-{position}"

    def _route_ref(self, route: dict[str, Any], position: int) -> str:
        raw = str(route.get("slug") or route.get("name") or f"route-{position}").strip()
        return raw.lower() or f"route-{position}"

    def _client_ref(self, client: dict[str, Any], position: int) -> str:
        raw = str(client.get("slug") or client.get("code") or f"client-{position}").strip()
        return raw.lower() or f"client-{position}"

    def _write_config_document(self, cur, document: dict[str, Any]) -> None:
        reserved_keys = {
            "clients",
            "routes",
            "output_profiles",
            "gateway_responses",
            "observability",
            "services",
        }
        extras = {
            key: value
            for key, value in document.items()
            if key not in reserved_keys
        }
        gateway_responses = document.get("gateway_responses") or {}
        observability = document.get("observability") or {}
        services = document.get("services") or {}
        routes = document.get("routes") or []
        clients = document.get("clients") or []
        output_profiles = document.get("output_profiles") or {}

        cur.execute("DELETE FROM gateway_service_endpoints")
        cur.execute("DELETE FROM gateway_services")
        cur.execute("DELETE FROM gateway_routes")
        cur.execute("DELETE FROM gateway_clients")
        cur.execute("DELETE FROM gateway_output_profiles")
        cur.execute("DELETE FROM gateway_config_settings")

        cur.execute(
            """
            INSERT INTO gateway_config_settings (
                id,
                gateway_responses_json,
                observability_json,
                extras_json
            )
            VALUES (1, %s::jsonb, %s::jsonb, %s::jsonb)
            """,
            (
                json.dumps(gateway_responses, ensure_ascii=False),
                json.dumps(observability, ensure_ascii=False),
                json.dumps(extras, ensure_ascii=False),
            ),
        )

        for service_position, (service_name, service_data_raw) in enumerate(services.items()):
            service_data = dict(service_data_raw or {})
            endpoints = list(service_data.pop("endpoints", []) or [])
            cur.execute(
                """
                INSERT INTO gateway_services (service_name, position, service_json)
                VALUES (%s, %s, %s::jsonb)
                """,
                (
                    str(service_name),
                    service_position,
                    json.dumps(service_data, ensure_ascii=False),
                )
            )
            for endpoint_position, endpoint in enumerate(endpoints):
                cur.execute(
                    """
                    INSERT INTO gateway_service_endpoints (
                        service_name,
                        endpoint_ref,
                        position,
                        endpoint_json
                    )
                    VALUES (%s, %s, %s, %s::jsonb)
                    """,
                    (
                        str(service_name),
                        self._service_endpoint_ref(endpoint, endpoint_position),
                        endpoint_position,
                        json.dumps(endpoint, ensure_ascii=False),
                    ),
                )
        for route_position, route in enumerate(routes):
            cur.execute(
                """
                INSERT INTO gateway_routes (route_slug, position, route_json)
                VALUES (%s, %s, %s::jsonb)
                """,
                (
                    self._route_ref(route, route_position),
                    route_position,
                    json.dumps(route, ensure_ascii=False),
                ),
            )
        for client_position, client in enumerate(clients):
            cur.execute(
                """
                INSERT INTO gateway_clients (client_slug, position, client_json)
                VALUES (%s, %s, %s::jsonb)
                """,
                (
                    self._client_ref(client, client_position),
                    client_position,
                    json.dumps(client, ensure_ascii=False),
                ),
            )
        for profile_position, (profile_slug, profile) in enumerate(output_profiles.items()):
            cur.execute(
                """
                INSERT INTO gateway_output_profiles (profile_slug, position, profile_json)
                VALUES (%s, %s, %s::jsonb)
                """,
                (
                    str(profile_slug).strip().lower(),
                    profile_position,
                    json.dumps(profile, ensure_ascii=False),
                ),
            )

    def _load_config_document_from_tables(self, cur) -> dict[str, Any]:
        document: dict[str, Any] = {}
        cur.execute(
            """
            SELECT gateway_responses_json, observability_json, extras_json
            FROM gateway_config_settings
            WHERE id = 1
            """
        )
        settings_row = cur.fetchone()
        if settings_row is not None:
            extras = self._coerce_json_cell(settings_row[2], {})
            if isinstance(extras, dict):
                document.update(extras)
            document["gateway_responses"] = self._coerce_json_cell(settings_row[0], {})
            document["observability"] = self._coerce_json_cell(settings_row[1], {})

        services: dict[str, Any] = {}
        cur.execute(
            """
            SELECT service_name, service_json
            FROM gateway_services
            ORDER BY position ASC, service_name ASC
            """
        )
        for service_name, service_json in cur.fetchall():
            service_data = self._coerce_json_cell(service_json, {})
            if not isinstance(service_data, dict):
                service_data = {}
            service_data.pop("endpoints", None)
            service_data["endpoints"] = []
            services[str(service_name)] = service_data

        cur.execute(
            """
            SELECT service_name, endpoint_json
            FROM gateway_service_endpoints
            ORDER BY service_name ASC, position ASC, endpoint_ref ASC
            """
        )
        for service_name, endpoint_json in cur.fetchall():
            endpoint_data = self._coerce_json_cell(endpoint_json, {})
            if not isinstance(endpoint_data, dict):
                endpoint_data = {}
            services.setdefault(str(service_name), {"endpoints": []}).setdefault("endpoints", []).append(endpoint_data)

        cur.execute(
            """
            SELECT route_json
            FROM gateway_routes
            ORDER BY position ASC, route_slug ASC
            """
        )
        routes = []
        for (route_json,) in cur.fetchall():
            route_data = self._coerce_json_cell(route_json, {})
            routes.append(route_data if isinstance(route_data, dict) else {})

        cur.execute(
            """
            SELECT client_json
            FROM gateway_clients
            ORDER BY position ASC, client_slug ASC
            """
        )
        clients = []
        for (client_json,) in cur.fetchall():
            client_data = self._coerce_json_cell(client_json, {})
            clients.append(client_data if isinstance(client_data, dict) else {})

        cur.execute(
            """
            SELECT profile_slug, profile_json
            FROM gateway_output_profiles
            ORDER BY position ASC, profile_slug ASC
            """
        )
        output_profiles: dict[str, Any] = {}
        for profile_slug, profile_json in cur.fetchall():
            profile_data = self._coerce_json_cell(profile_json, {})
            output_profiles[str(profile_slug)] = profile_data if isinstance(profile_data, dict) else {}

        document["clients"] = clients
        document["routes"] = routes
        document["output_profiles"] = output_profiles
        document["services"] = services
        document.setdefault("gateway_responses", {})
        document.setdefault("observability", {})
        return document

    def _refresh_revisions(self) -> None:
        revisions: dict[str, int | None] = {"config": None, "security": None}
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT scope, revision FROM gateway_state_revisions WHERE scope IN ('config', 'security')"
                )
                for scope, revision in cur.fetchall():
                    revisions[str(scope)] = int(revision)
        with self._lock:
            self._revisions.update(revisions)

    def _poll_revisions_loop(self) -> None:
        while not self._stop_event.wait(self._sync_interval_seconds):
            try:
                self._refresh_revisions()
            except Exception:  # noqa: BLE001
                LOGGER.exception("Failed to refresh Postgres state revisions.")

    def _write_security_document(self, cur, document: dict[str, Any]) -> None:
        reserved_keys = {"roles", "users"}
        extras = {
            key: value
            for key, value in document.items()
            if key not in reserved_keys
        }
        roles = document.get("roles") or {}
        users = document.get("users") or {}

        cur.execute("DELETE FROM gateway_roles")
        cur.execute("DELETE FROM gateway_users")
        cur.execute("DELETE FROM gateway_security_settings")

        cur.execute(
            """
            INSERT INTO gateway_security_settings (id, extras_json)
            VALUES (1, %s::jsonb)
            """,
            (json.dumps(extras, ensure_ascii=False),),
        )

        for role_position, (role_name, role_data) in enumerate(roles.items()):
            cur.execute(
                """
                INSERT INTO gateway_roles (role_name, position, role_json)
                VALUES (%s, %s, %s::jsonb)
                """,
                (
                    str(role_name),
                    role_position,
                    json.dumps(role_data, ensure_ascii=False),
                ),
            )
        for user_position, (username, user_data) in enumerate(users.items()):
            cur.execute(
                """
                INSERT INTO gateway_users (username, position, user_json)
                VALUES (%s, %s, %s::jsonb)
                """,
                (
                    str(username),
                    user_position,
                    json.dumps(user_data, ensure_ascii=False),
                ),
            )

    def _load_security_document_from_tables(self, cur) -> dict[str, Any]:
        document: dict[str, Any] = {}

        cur.execute(
            """
            SELECT extras_json
            FROM gateway_security_settings
            WHERE id = 1
            """
        )
        row = cur.fetchone()
        if row is not None:
            extras = self._coerce_json_cell(row[0], {})
            if isinstance(extras, dict):
                document.update(extras)

        roles: dict[str, Any] = {}
        cur.execute(
            """
            SELECT role_name, role_json
            FROM gateway_roles
            ORDER BY position ASC, role_name ASC
            """
        )
        for role_name, role_json in cur.fetchall():
            role_data = self._coerce_json_cell(role_json, {})
            roles[str(role_name)] = role_data if isinstance(role_data, dict) else {}

        users: dict[str, Any] = {}
        cur.execute(
            """
            SELECT username, user_json
            FROM gateway_users
            ORDER BY position ASC, username ASC
            """
        )
        for username, user_json in cur.fetchall():
            user_data = self._coerce_json_cell(user_json, {})
            users[str(username)] = user_data if isinstance(user_data, dict) else {}

        document["roles"] = roles
        document["users"] = users
        return document

    def load_config_document(self) -> dict[str, Any]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                document = self._load_config_document_from_tables(cur)
                cur.execute(
                    "SELECT revision FROM gateway_state_revisions WHERE scope = %s",
                    ("config",),
                )
                row = cur.fetchone()
        revision = int(row[0]) if row else 1
        normalized = normalize_config_document(document)
        load_gateway_config_document(normalized)
        with self._lock:
            self._revisions["config"] = revision
        return normalized

    def save_config_document(self, document: dict[str, Any]) -> None:
        normalized = normalize_config_document(document)
        load_gateway_config_document(normalized)
        with self._connect() as conn:
            with conn.cursor() as cur:
                self._write_config_document(cur, normalized)
                revision = self._bump_revision(cur, "config")
            conn.commit()
        with self._lock:
            self._revisions["config"] = revision

    def load_security_document(self) -> dict[str, Any]:
        with self._connect() as conn:
            with conn.cursor() as cur:
                document = self._load_security_document_from_tables(cur)
                cur.execute(
                    "SELECT revision FROM gateway_state_revisions WHERE scope = %s",
                    ("security",),
                )
                row = cur.fetchone()
        revision = int(row[0]) if row else 1
        normalized = validate_security_document(document)
        with self._lock:
            self._revisions["security"] = revision
        return normalized

    def save_security_document(self, document: dict[str, Any]) -> None:
        normalized = validate_security_document(document)
        with self._connect() as conn:
            with conn.cursor() as cur:
                self._write_security_document(cur, normalized)
                revision = self._bump_revision(cur, "security")
            conn.commit()
        with self._lock:
            self._revisions["security"] = revision

    def config_revision(self) -> Any:
        with self._lock:
            return self._revisions["config"]

    def security_revision(self) -> Any:
        with self._lock:
            return self._revisions["security"]

    def list_admin_change_logs(self, limit: int = 200) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        created_at,
                        principal_username,
                        principal_source,
                        listener,
                        action,
                        target_kind,
                        target_ref,
                        message,
                        client_ip,
                        details_json
                    FROM admin_change_logs
                    ORDER BY id DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
                for row in cur.fetchall():
                    details = row[9]
                    if isinstance(details, str):
                        try:
                            details = json.loads(details)
                        except json.JSONDecodeError:
                            details = {}
                    rows.append(
                        {
                            "created_at": row[0].isoformat() if hasattr(row[0], "isoformat") else str(row[0]),
                            "principal_username": str(row[1]),
                            "principal_source": str(row[2]),
                            "listener": str(row[3]),
                            "action": str(row[4]),
                            "target_kind": str(row[5]),
                            "target_ref": str(row[6]),
                            "message": str(row[7]),
                            "client_ip": str(row[8]),
                            "details": details if isinstance(details, dict) else {},
                        }
                    )
        return rows

    def log_admin_change(
        self,
        *,
        principal_username: str,
        principal_source: str,
        listener: str,
        action: str,
        target_kind: str,
        target_ref: str,
        message: str,
        client_ip: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        payload = details or {}
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO admin_change_logs (
                        principal_username,
                        principal_source,
                        listener,
                        action,
                        target_kind,
                        target_ref,
                        message,
                        client_ip,
                        details_json
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                    """,
                    (
                        principal_username,
                        principal_source,
                        listener,
                        action,
                        target_kind,
                        target_ref,
                        message,
                        client_ip,
                        json.dumps(payload, ensure_ascii=False),
                    ),
                )
            conn.commit()

    def close(self) -> None:
        self._stop_event.set()
        self._poller.join(timeout=2)


def build_state_store(
    *,
    mode: str,
    config_path: Path | str = CONFIG_PATH,
    security_path: Path | str = SECURITY_CONFIG_PATH,
    postgres_dsn: str = "",
    sync_interval_seconds: float = 2.0,
):
    normalized_mode = str(mode or "file").strip().lower() or "file"
    if normalized_mode == "postgres":
        return PostgresStateStore(
            dsn=postgres_dsn,
            config_path=config_path,
            security_path=security_path,
            sync_interval_seconds=sync_interval_seconds,
        )
    return FileStateStore(config_path=config_path, security_path=security_path)
