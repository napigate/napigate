from __future__ import annotations

from collections import Counter
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

    def report(self, *, hours: int = 24, bucket_minutes: int = 60, top_limit: int = 5) -> dict[str, Any]:
        normalized_hours = max(1, int(hours or 24))
        normalized_bucket_minutes = max(1, int(bucket_minutes or 60))
        bucket_count = max(1, (normalized_hours * 60 + normalized_bucket_minutes - 1) // normalized_bucket_minutes)

        now = datetime.now(UTC)
        current_bucket_start = now.replace(second=0, microsecond=0)
        minute_remainder = current_bucket_start.minute % normalized_bucket_minutes
        current_bucket_start -= timedelta(minutes=minute_remainder)
        first_bucket_start = current_bucket_start - timedelta(
            minutes=normalized_bucket_minutes * (bucket_count - 1)
        )
        cutoff = now - timedelta(hours=normalized_hours)
        query_cutoff = min(cutoff, first_bucket_start)

        with self._lock:
            rows = self._connection.execute(
                """
                SELECT
                    created_at,
                    gateway_path,
                    service_name,
                    status_code,
                    duration_ms,
                    upstream_url
                FROM request_logs
                WHERE created_at >= ?
                ORDER BY created_at ASC
                """,
                (query_cutoff.isoformat(),),
            ).fetchall()

        buckets = []
        bucket_index: dict[str, dict[str, Any]] = {}
        for offset in range(bucket_count):
            bucket_start = first_bucket_start + timedelta(minutes=normalized_bucket_minutes * offset)
            entry = {
                "bucket_start": bucket_start.isoformat(),
                "bucket_end": (bucket_start + timedelta(minutes=normalized_bucket_minutes)).isoformat(),
                "label": bucket_start.strftime("%H:%M"),
                "requests": 0,
                "failures": 0,
                "cache_hits": 0,
                "avg_duration_ms": 0.0,
                "_duration_sum_ms": 0.0,
            }
            buckets.append(entry)
            bucket_index[entry["bucket_start"]] = entry

        total_requests = 0
        total_failures = 0
        total_cache_hits = 0
        total_duration_ms = 0.0
        durations_ms: list[float] = []
        requests_last_hour = 0
        failures_last_hour = 0
        status_breakdown: Counter[str] = Counter()
        service_stats: dict[str, dict[str, float | int | str]] = {}
        path_stats: dict[str, dict[str, float | int | str]] = {}
        last_hour_cutoff = now - timedelta(hours=1)

        for row in rows:
            created_at_raw = str(row["created_at"] or "").strip()
            if not created_at_raw:
                continue
            try:
                created_at = datetime.fromisoformat(created_at_raw)
            except ValueError:
                continue
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=UTC)
            if created_at < cutoff:
                continue

            status_code = int(row["status_code"] or 0)
            duration_ms = round(float(row["duration_ms"] or 0), 3)
            service_name = str(row["service_name"] or "").strip() or "-"
            gateway_path = str(row["gateway_path"] or "").strip() or "-"
            cache_hit = str(row["upstream_url"] or "") == "cache://response"
            failed = status_code >= 400

            total_requests += 1
            total_failures += int(failed)
            total_cache_hits += int(cache_hit)
            total_duration_ms += duration_ms
            durations_ms.append(duration_ms)
            if created_at >= last_hour_cutoff:
                requests_last_hour += 1
                failures_last_hour += int(failed)

            if status_code >= 500:
                status_breakdown["5xx"] += 1
            elif status_code >= 400:
                status_breakdown["4xx"] += 1
            elif status_code >= 300:
                status_breakdown["3xx"] += 1
            elif status_code >= 200:
                status_breakdown["2xx"] += 1
            else:
                status_breakdown["other"] += 1

            bucket_floor = created_at.replace(second=0, microsecond=0)
            bucket_floor -= timedelta(minutes=bucket_floor.minute % normalized_bucket_minutes)
            bucket = bucket_index.get(bucket_floor.isoformat())
            if bucket is not None:
                bucket["requests"] += 1
                bucket["failures"] += int(failed)
                bucket["cache_hits"] += int(cache_hit)
                bucket["_duration_sum_ms"] += duration_ms

            service_entry = service_stats.setdefault(
                service_name,
                {
                    "name": service_name,
                    "requests": 0,
                    "failures": 0,
                    "_duration_sum_ms": 0.0,
                },
            )
            service_entry["requests"] += 1
            service_entry["failures"] += int(failed)
            service_entry["_duration_sum_ms"] += duration_ms

            path_entry = path_stats.setdefault(
                gateway_path,
                {
                    "path": gateway_path,
                    "requests": 0,
                    "failures": 0,
                    "_duration_sum_ms": 0.0,
                },
            )
            path_entry["requests"] += 1
            path_entry["failures"] += int(failed)
            path_entry["_duration_sum_ms"] += duration_ms

        for bucket in buckets:
            requests = int(bucket["requests"] or 0)
            duration_sum = float(bucket.pop("_duration_sum_ms", 0.0) or 0.0)
            bucket["avg_duration_ms"] = round(duration_sum / requests, 3) if requests else 0.0

        def _finalize_top_items(
            source: dict[str, dict[str, float | int | str]],
            *,
            key_name: str,
        ) -> list[dict[str, Any]]:
            ordered = sorted(
                source.values(),
                key=lambda item: (
                    -int(item.get("requests", 0) or 0),
                    str(item.get(key_name, "") or ""),
                ),
            )[:top_limit]
            finalized: list[dict[str, Any]] = []
            for item in ordered:
                requests = int(item.get("requests", 0) or 0)
                finalized.append(
                    {
                        key_name: str(item.get(key_name, "") or "-"),
                        "requests": requests,
                        "failures": int(item.get("failures", 0) or 0),
                        "avg_duration_ms": round(
                            float(item.get("_duration_sum_ms", 0.0) or 0.0) / requests,
                            3,
                        )
                        if requests
                        else 0.0,
                    }
                )
            return finalized

        durations_ms.sort()
        p95_duration_ms = 0.0
        if durations_ms:
            p95_index = max(0, min(len(durations_ms) - 1, int(round((len(durations_ms) - 1) * 0.95))))
            p95_duration_ms = round(durations_ms[p95_index], 3)

        return {
            "hours": normalized_hours,
            "bucket_minutes": normalized_bucket_minutes,
            "generated_at": now.isoformat(),
            "window_start": cutoff.isoformat(),
            "window_end": now.isoformat(),
            "totals": {
                "requests": total_requests,
                "failures": total_failures,
                "successes": max(0, total_requests - total_failures),
                "failure_rate": round((total_failures / total_requests) * 100, 2) if total_requests else 0.0,
                "cache_hits": total_cache_hits,
                "cache_hit_rate": round((total_cache_hits / total_requests) * 100, 2) if total_requests else 0.0,
                "avg_duration_ms": round(total_duration_ms / total_requests, 3) if total_requests else 0.0,
                "p95_duration_ms": p95_duration_ms,
                "requests_last_hour": requests_last_hour,
                "failures_last_hour": failures_last_hour,
                "peak_bucket_requests": max((int(bucket["requests"]) for bucket in buckets), default=0),
            },
            "status_breakdown": [
                {"label": label, "count": int(status_breakdown.get(label, 0))}
                for label in ("2xx", "3xx", "4xx", "5xx", "other")
            ],
            "top_services": _finalize_top_items(service_stats, key_name="name"),
            "top_paths": _finalize_top_items(path_stats, key_name="path"),
            "hourly": buckets,
        }

    def close(self) -> None:
        self._stop_event.set()
        self._cleanup_wakeup.set()
        self._cleanup_thread.join(timeout=1)
        with self._lock:
            self._connection.close()
