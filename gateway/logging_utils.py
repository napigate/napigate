from __future__ import annotations

from datetime import UTC, datetime, timedelta
import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
import threading


_RETENTION_LOCK = threading.Lock()
_RETENTION_DIRECTORY = Path("logs")
_RETENTION_HOURS: int | None = None
_RETENTION_STOP = threading.Event()
_RETENTION_WAKEUP = threading.Event()
_RETENTION_THREAD: threading.Thread | None = None


def _cleanup_rotated_logs() -> None:
    if _RETENTION_HOURS is None:
        return
    cutoff = datetime.now(UTC) - timedelta(hours=_RETENTION_HOURS)
    base_log = _RETENTION_DIRECTORY / "napigate.log"
    for candidate in _RETENTION_DIRECTORY.glob("napigate.log*"):
        if candidate == base_log or not candidate.is_file():
            continue
        try:
            modified_at = datetime.fromtimestamp(candidate.stat().st_mtime, tz=UTC)
        except FileNotFoundError:
            continue
        if modified_at < cutoff:
            candidate.unlink(missing_ok=True)


def _retention_loop() -> None:
    while not _RETENTION_STOP.is_set():
        _RETENTION_WAKEUP.wait(timeout=3600)
        _RETENTION_WAKEUP.clear()
        if _RETENTION_STOP.is_set():
            return
        with _RETENTION_LOCK:
            _cleanup_rotated_logs()


def _ensure_retention_thread() -> None:
    global _RETENTION_THREAD
    if _RETENTION_THREAD and _RETENTION_THREAD.is_alive():
        return
    _RETENTION_THREAD = threading.Thread(
        target=_retention_loop,
        name="napigate-file-log-retention",
        daemon=True,
    )
    _RETENTION_THREAD.start()


def configure_log_retention_hours(
    retention_hours: int | None,
    *,
    log_dir: Path | str | None = None,
) -> None:
    global _RETENTION_DIRECTORY, _RETENTION_HOURS
    with _RETENTION_LOCK:
        if log_dir is not None:
            _RETENTION_DIRECTORY = Path(log_dir)
            _RETENTION_DIRECTORY.mkdir(parents=True, exist_ok=True)
        _RETENTION_HOURS = retention_hours if retention_hours and retention_hours > 0 else None
        _cleanup_rotated_logs()
    _ensure_retention_thread()
    _RETENTION_WAKEUP.set()


def shutdown_logging() -> None:
    _RETENTION_STOP.set()
    _RETENTION_WAKEUP.set()
    if _RETENTION_THREAD is not None:
        _RETENTION_THREAD.join(timeout=1)


def setup_logging(log_dir: Path | str = "logs") -> None:
    directory = Path(log_dir)
    directory.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger()
    if getattr(root_logger, "_napigate_configured", False):
        configure_log_retention_hours(_RETENTION_HOURS, log_dir=directory)
        return

    root_logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )

    file_handler = TimedRotatingFileHandler(
        filename=directory / "napigate.log",
        when="midnight",
        interval=1,
        backupCount=0,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)

    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    root_logger._napigate_configured = True
    configure_log_retention_hours(_RETENTION_HOURS, log_dir=directory)
