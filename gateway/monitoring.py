from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3
import threading
from typing import Any


@dataclass(slots=True)
class LogEntry:
    request_id: str
    method: str
    gateway_path: str
    service_name: str
    endpoint_name: str
    upstream_url: str
    status_code: int
    duration_ms: int
    client_ip: str
    error: str
    created_at: str


class RequestLogStore:
    def __init__(self, db_path: Path | str = "data/monitor.db") -> None:
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._lock:
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS request_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    method TEXT NOT NULL,
                    gateway_path TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    endpoint_name TEXT NOT NULL,
                    upstream_url TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    client_ip TEXT NOT NULL,
                    error TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            self._connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_request_logs_created_at
                ON request_logs (created_at DESC)
                """
            )
            self._connection.commit()

    def cleanup_old(self, days_to_keep: int = 30) -> None:
        cutoff = datetime.now(UTC) - timedelta(days=days_to_keep)
        with self._lock:
            self._connection.execute(
                "DELETE FROM request_logs WHERE created_at < ?",
                (cutoff.isoformat(),),
            )
            self._connection.commit()

    def write(self, entry: LogEntry) -> None:
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO request_logs (
                    request_id,
                    method,
                    gateway_path,
                    service_name,
                    endpoint_name,
                    upstream_url,
                    status_code,
                    duration_ms,
                    client_ip,
                    error,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.request_id,
                    entry.method,
                    entry.gateway_path,
                    entry.service_name,
                    entry.endpoint_name,
                    entry.upstream_url,
                    entry.status_code,
                    entry.duration_ms,
                    entry.client_ip,
                    entry.error,
                    entry.created_at,
                ),
            )
            self._connection.commit()

    def recent(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT
                    request_id,
                    method,
                    gateway_path,
                    service_name,
                    endpoint_name,
                    upstream_url,
                    status_code,
                    duration_ms,
                    client_ip,
                    error,
                    created_at
                FROM request_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        with self._lock:
            self._connection.close()
