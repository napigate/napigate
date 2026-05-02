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
    upstream_curl: str
    status_code: int
    duration_ms: float
    duration_us: int
    client_ip: str
    error: str
    response_body: str
    created_at: str


def _format_duration(duration_ms: float, duration_us: int) -> str:
    millis = float(duration_ms or 0)
    if millis <= 0 and duration_us > 0:
        millis = duration_us / 1000
    return f"{millis:.3f} ms"


class RequestLogStore:
    def __init__(self, db_path: Path | str = "data/monitor.db") -> None:
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._retention_hours: int | None = None
        self._stop_event = threading.Event()
        self._cleanup_wakeup = threading.Event()
        self._init_db()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            name="napigate-monitor-retention",
            daemon=True,
        )
        self._cleanup_thread.start()

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
                    upstream_curl TEXT NOT NULL DEFAULT '',
                    status_code INTEGER NOT NULL,
                    duration_ms REAL NOT NULL,
                    duration_us INTEGER NOT NULL DEFAULT 0,
                    client_ip TEXT NOT NULL,
                    error TEXT NOT NULL,
                    response_body TEXT NOT NULL DEFAULT '',
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
            self._ensure_column(
                "request_logs",
                "upstream_curl",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                "request_logs",
                "response_body",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                "request_logs",
                "duration_us",
                "INTEGER NOT NULL DEFAULT 0",
            )
            self._connection.commit()

    def _ensure_column(self, table_name: str, column_name: str, definition: str) -> None:
        existing_columns = {
            str(row["name"])
            for row in self._connection.execute(f"PRAGMA table_info({table_name})").fetchall()
        }
        if column_name in existing_columns:
            return
        self._connection.execute(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"
        )

    def _delete_before(self, cutoff: datetime) -> None:
        with self._lock:
            self._connection.execute(
                "DELETE FROM request_logs WHERE created_at < ?",
                (cutoff.isoformat(),),
            )
            self._connection.commit()

    def _cleanup_loop(self) -> None:
        while not self._stop_event.is_set():
            self._cleanup_wakeup.wait(timeout=3600)
            self._cleanup_wakeup.clear()
            if self._stop_event.is_set():
                return
            self.cleanup_old()

    def configure_retention_hours(self, retention_hours: int | None) -> None:
        self._retention_hours = retention_hours if retention_hours and retention_hours > 0 else None
        self.cleanup_old()
        self._cleanup_wakeup.set()

    def cleanup_old(self) -> None:
        if self._retention_hours is None:
            return
        cutoff = datetime.now(UTC) - timedelta(hours=self._retention_hours)
        self._delete_before(cutoff)

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
                    upstream_curl,
                    status_code,
                    duration_ms,
                    duration_us,
                    client_ip,
                    error,
                    response_body,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.request_id,
                    entry.method,
                    entry.gateway_path,
                    entry.service_name,
                    entry.endpoint_name,
                    entry.upstream_url,
                    entry.upstream_curl,
                    entry.status_code,
                    entry.duration_ms,
                    entry.duration_us,
                    entry.client_ip,
                    entry.error,
                    entry.response_body,
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
                    upstream_curl,
                    status_code,
                    duration_ms,
                    duration_us,
                    client_ip,
                    error,
                    response_body,
                    created_at
                FROM request_logs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [
            {
                **dict(row),
                "duration_ms": round(float(row["duration_ms"] or 0), 3),
                "duration_us": int(row["duration_us"] or round(float(row["duration_ms"] or 0) * 1000)),
                "duration_display": _format_duration(
                    round(float(row["duration_ms"] or 0), 3),
                    int(row["duration_us"] or round(float(row["duration_ms"] or 0) * 1000)),
                ),
                "success": int(row["status_code"]) < 400,
                "response_source": (
                    "cache"
                    if str(row["upstream_url"]) == "cache://response"
                    else "local"
                    if str(row["upstream_url"]).startswith("local://")
                    else "upstream"
                ),
                "cached": str(row["upstream_url"]) == "cache://response",
            }
            for row in rows
        ]

    def close(self) -> None:
        self._stop_event.set()
        self._cleanup_wakeup.set()
        self._cleanup_thread.join(timeout=1)
        with self._lock:
            self._connection.close()
