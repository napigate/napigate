from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
import logging
import queue
import threading
import time
from typing import Any

import requests

from gateway.config import LogAggregatorConfig, SuccessHookConfig


LOGGER = logging.getLogger("gateway.integrations")


@dataclass(slots=True)
class IntegrationJob:
    kind: str
    payload: dict[str, Any]
    aggregator: LogAggregatorConfig | None = None
    success_hook: SuccessHookConfig | None = None


class IntegrationDispatcher:
    def __init__(self) -> None:
        self._queue: queue.Queue[IntegrationJob | None] = queue.Queue()
        self._stop_event = threading.Event()
        self._lock = threading.RLock()
        self._log_aggregators: list[LogAggregatorConfig] = []
        self._worker = threading.Thread(
            target=self._run,
            name="napigate-integrations",
            daemon=True,
        )
        self._worker.start()

    def configure(self, *, log_aggregators: list[LogAggregatorConfig]) -> None:
        with self._lock:
            self._log_aggregators = [
                item
                for item in log_aggregators
                if item.enabled and item.url
            ]

    def emit_request_log(self, payload: dict[str, Any]) -> None:
        with self._lock:
            aggregators = list(self._log_aggregators)
        for aggregator in aggregators:
            self._queue.put(
                IntegrationJob(
                    kind="request_log",
                    aggregator=aggregator,
                    payload=dict(payload),
                )
            )

    def enqueue_success_hook(
        self,
        *,
        success_hook: SuccessHookConfig | None,
        payload: dict[str, Any],
    ) -> None:
        if success_hook is None or not success_hook.enabled or not success_hook.url:
            return
        self._queue.put(
            IntegrationJob(
                kind="success_hook",
                success_hook=success_hook,
                payload=dict(payload),
            )
        )

    def close(self) -> None:
        if self._stop_event.is_set():
            return
        self._stop_event.set()
        self._queue.put(None)
        self._worker.join(timeout=2)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                job = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if job is None:
                return
            try:
                self._dispatch_job(job)
            except Exception:  # noqa: BLE001
                LOGGER.exception("Failed to dispatch integration job kind=%s", job.kind)

    def _dispatch_job(self, job: IntegrationJob) -> None:
        if job.kind == "request_log" and job.aggregator is not None:
            self._dispatch_log(job.aggregator, job.payload)
            return
        if job.kind == "success_hook" and job.success_hook is not None:
            self._dispatch_success_hook(job.success_hook, job.payload)

    def _dispatch_log(
        self,
        aggregator: LogAggregatorConfig,
        payload: dict[str, Any],
    ) -> None:
        if aggregator.type == "http_json":
            self._post_json(
                url=aggregator.url,
                payload={
                    "event": "request_log",
                    "sent_at": datetime.now(UTC).isoformat(),
                    "entry": payload,
                },
                headers=aggregator.headers,
                timeout=aggregator.timeout_seconds,
            )
            return

        if aggregator.type == "loki":
            labels = {
                "app": "napigate",
                "event": "request_log",
                **{str(key): str(value) for key, value in aggregator.labels.items()},
            }
            line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            timestamp_ns = str(int(time.time() * 1_000_000_000))
            self._post_json(
                url=aggregator.url,
                payload={
                    "streams": [
                        {
                            "stream": labels,
                            "values": [[timestamp_ns, line]],
                        }
                    ]
                },
                headers=aggregator.headers,
                timeout=aggregator.timeout_seconds,
            )

    def _dispatch_success_hook(
        self,
        success_hook: SuccessHookConfig,
        payload: dict[str, Any],
    ) -> None:
        self._post_json(
            url=success_hook.url,
            payload=payload,
            headers=success_hook.headers,
            timeout=success_hook.timeout_seconds,
        )

    def _post_json(
        self,
        *,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, Any],
        timeout: float,
    ) -> None:
        final_headers = {
            "Content-Type": "application/json; charset=utf-8",
            **{str(key): str(value) for key, value in headers.items()},
        }
        with requests.Session() as session:
            response = session.post(
                url,
                headers=final_headers,
                data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                timeout=timeout,
                allow_redirects=False,
            )
        response.raise_for_status()
