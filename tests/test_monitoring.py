import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3
from types import SimpleNamespace

from gateway.monitoring import LogEntry, RequestLogStore
from gateway.runtime import GatewayRuntime, IncomingRequest


class MonitoringTests(unittest.TestCase):
    def test_existing_log_database_adds_request_curl_column(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "monitor.db"
            connection = sqlite3.connect(database_path)
            try:
                connection.execute(
                    """
                    CREATE TABLE request_logs (
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
                connection.commit()
            finally:
                connection.close()

            store = RequestLogStore(database_path)
            try:
                columns = {
                    row[1]
                    for row in store._connection.execute("PRAGMA table_info(request_logs)").fetchall()
                }
            finally:
                store.close()

        self.assertIn("request_curl", columns)

    def test_report_aligns_hourly_buckets_to_requested_timezone(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            store = RequestLogStore(Path(temporary_directory) / "monitor.db")
            try:
                store.write(
                    LogEntry(
                        request_id="request-1",
                        method="GET",
                        gateway_path="/cached",
                        service_name="demo",
                        endpoint_name="cached",
                        upstream_url="cache://response",
                        upstream_curl="",
                        request_curl="curl -X GET https://gateway.test/cached",
                        status_code=200,
                        duration_ms=1.25,
                        duration_us=1250,
                        client_ip="127.0.0.1",
                        error="",
                        response_body='{"ok": true}',
                        created_at=(datetime.now(UTC) - timedelta(minutes=5)).isoformat(),
                    )
                )

                report = store.report(
                    hours=24,
                    bucket_minutes=60,
                    timezone_offset_minutes=210,
                )
            finally:
                store.close()

        self.assertEqual(report["timezone_offset_minutes"], 210)
        self.assertEqual(report["totals"]["requests"], 1)
        populated_bucket = next(bucket for bucket in report["hourly"] if bucket["requests"] == 1)
        bucket_start = datetime.fromisoformat(populated_bucket["bucket_start"])
        self.assertEqual(bucket_start.utcoffset(), timedelta(minutes=210))
        self.assertEqual(bucket_start.minute, 0)
        self.assertEqual(populated_bucket["label"], bucket_start.strftime("%H:%M"))

    def test_cache_log_keeps_replayable_incoming_request_curl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            runtime = GatewayRuntime.__new__(GatewayRuntime)
            runtime.log_store = RequestLogStore(Path(temporary_directory) / "monitor.db")
            emitted_logs = []
            runtime.dispatcher = SimpleNamespace(emit_request_log=emitted_logs.append)
            request = IncomingRequest(
                method="POST",
                path="/payments",
                query={"reference": "A-42"},
                headers={
                    "Host": "gateway.test",
                    "Content-Type": "application/json",
                    "X-Trace": "trace-1",
                },
                body=b'{"amount":42}',
                client_ip="127.0.0.1",
                url="https://gateway.test/payments?reference=A-42",
                json_body={"amount": 42},
            )
            matched = SimpleNamespace(
                route=SimpleNamespace(name="payments", slug="payments", strategy="single"),
                service=SimpleNamespace(name="billing"),
                endpoint=SimpleNamespace(name="create-payment", slug="create-payment"),
            )

            try:
                runtime._write_log(
                    request_id="request-2",
                    request=request,
                    matched=matched,
                    upstream_url="cache://response",
                    upstream_curl="",
                    status_code=200,
                    duration_ms=0.5,
                    duration_us=500,
                    error_message="",
                    response_body='{"ok": true}',
                )
                row = runtime.log_store.recent(limit=1)[0]
            finally:
                runtime.log_store.close()

        self.assertIn("-X POST", row["request_curl"])
        self.assertIn("Content-Type: application/json", row["request_curl"])
        self.assertIn("X-Trace: trace-1", row["request_curl"])
        self.assertIn("--data-binary", row["request_curl"])
        self.assertIn('{"amount":42}', row["request_curl"])
        self.assertIn("https://gateway.test/payments?reference=A-42", row["request_curl"])
        self.assertNotIn("request_curl", emitted_logs[0])


if __name__ == "__main__":
    unittest.main()
