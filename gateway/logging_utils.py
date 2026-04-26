from __future__ import annotations

import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path


def setup_logging(log_dir: Path | str = "logs") -> None:
    directory = Path(log_dir)
    directory.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger()
    if getattr(root_logger, "_napigate_configured", False):
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
        backupCount=14,
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
