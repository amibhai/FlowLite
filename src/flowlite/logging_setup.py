"""Logging configuration.

Three deliberate choices:

* **The console handler and the dashboard never fight.** When the live dashboard
  is active it owns the terminal; console logging is raised to WARNING and the
  dashboard renders recent events from an in-memory ring buffer instead. The old
  implementation let both write to the same terminal, which garbled both.
* **An unwritable log directory is not fatal.** ``/var/log`` being root-owned
  should degrade FlowLite to console logging, not stop a capture pipeline.
* **``propagate`` is off.** FlowLite never duplicates records into a host
  application's root logger.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
import threading
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

__all__ = ["setup_logging", "get_logger", "RingBufferHandler", "ring_buffer"]

ROOT_NAME = "flowlite"

_TEXT_FORMAT = "%(asctime)s  %(levelname)-7s  %(name)-22s  %(message)s"
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"

_configured = False
_config_lock = threading.Lock()


class RingBufferHandler(logging.Handler):
    """Keeps the most recent records in memory for the dashboard to render."""

    def __init__(self, capacity: int = 200) -> None:
        super().__init__(level=logging.INFO)
        self.capacity = capacity
        self._records: Deque[Dict[str, Any]] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self.counts: Dict[str, int] = {}

    def emit(self, record: logging.LogRecord) -> None:
        try:
            entry = {
                "time": record.created,
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
        except Exception:  # pragma: no cover - never let logging kill a thread
            return
        with self._lock:
            self._records.append(entry)
            self.counts[record.levelname] = self.counts.get(record.levelname, 0) + 1

    def snapshot(self, limit: int = 10) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._records)
        return items[-limit:] if limit else items

    def error_count(self) -> int:
        with self._lock:
            return self.counts.get("ERROR", 0) + self.counts.get("CRITICAL", 0)


_RING = RingBufferHandler()


def ring_buffer() -> RingBufferHandler:
    """The process-wide ring buffer of recent log records."""
    return _RING


class JsonFormatter(logging.Formatter):
    """One JSON object per line, for shipping into a log aggregator."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.threadName and record.threadName != "MainThread":
            payload["thread"] = record.threadName
        for key, value in getattr(record, "extra_fields", {}).items():
            payload[key] = value
        return json.dumps(payload, default=str)


def _level(name: str, default: int = logging.INFO) -> int:
    resolved = logging.getLevelName(str(name).upper())
    return resolved if isinstance(resolved, int) else default


def setup_logging(
    cfg: Any, *, dashboard_active: bool = False, force: bool = False
) -> logging.Logger:
    """Configure and return the FlowLite root logger.

    Safe to call more than once; later calls are no-ops unless ``force`` is set.
    """
    global _configured
    with _config_lock:
        logger = logging.getLogger(ROOT_NAME)
        if _configured and not force:
            return logger

        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            if handler is not _RING:
                try:
                    handler.close()
                except Exception:
                    pass

        log_cfg = cfg.logging
        console_level = _level(log_cfg.level)
        file_level = _level(log_cfg.file_level, logging.DEBUG)

        logger.setLevel(min(console_level, file_level, logging.INFO))
        logger.propagate = False

        formatter: logging.Formatter
        if getattr(log_cfg, "format", "text") == "json":
            formatter = JsonFormatter()
        else:
            formatter = logging.Formatter(_TEXT_FORMAT, datefmt=_DATE_FORMAT)

        if log_cfg.console:
            stream = logging.StreamHandler(sys.stderr)
            # The dashboard owns the terminal; only surface problems there.
            stream.setLevel(
                max(console_level, logging.WARNING) if dashboard_active else console_level
            )
            stream.setFormatter(formatter)
            logger.addHandler(stream)

        log_dir = Path(cfg.paths.logs_dir)
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            file_handler = logging.handlers.RotatingFileHandler(
                log_dir / "flowlite.log",
                maxBytes=int(log_cfg.max_bytes),
                backupCount=int(log_cfg.backups),
                encoding="utf-8",
                delay=True,
            )
            file_handler.setLevel(file_level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except OSError as exc:
            logger.addHandler(_RING)
            _configured = True
            logger.warning(
                "File logging disabled: cannot use %s (%s). Continuing with console logging only.",
                log_dir,
                exc,
            )
            return logger

        logger.addHandler(_RING)
        _configured = True
        return logger


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Return a child of the FlowLite root logger."""
    if not name or name == ROOT_NAME:
        return logging.getLogger(ROOT_NAME)
    if name.startswith(ROOT_NAME + "."):
        return logging.getLogger(name)
    return logging.getLogger(f"{ROOT_NAME}.{name}")
