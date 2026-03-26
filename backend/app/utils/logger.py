import asyncio
import json
import logging
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Set

LOG_HISTORY_LIMIT = 100
STREAM_QUEUE_LIMIT = 200

_log_history: Deque[Dict[str, Any]] = deque(maxlen=LOG_HISTORY_LIMIT)
_subscribers: Set[asyncio.Queue[Dict[str, Any]]] = set()


class SimpleJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage(),
        }
        extras = {k: v for k, v in record.__dict__.items() if k not in ("name", "msg", "args", "levelname", "levelno", "pathname", "filename", "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName", "created", "msecs", "relativeCreated", "thread", "threadName", "processName", "process")}
        if extras:
            payload.update(extras)
        return json.dumps(payload)


def get_logger(name: str) -> logging.Logger:
    """Return a structured JSON logger for the given name."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(SimpleJsonFormatter())
    logger.addHandler(handler)
    return logger


# Module-level logger for convenience across the app
logger = get_logger(__name__)


def _normalize_level(level: str) -> str:
    normalized = (level or "INFO").upper()
    if normalized not in {"DEBUG", "INFO", "WARN", "ERROR"}:
        return "INFO"
    return normalized


def build_log_entry(level: str, message: str, **fields: Any) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": _normalize_level(level),
        "message": message,
    }
    for key, value in fields.items():
        if value is not None:
            entry[key] = value
    return entry


def _emit_to_python_logger(entry: Dict[str, Any]) -> None:
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARN": logging.WARNING,
        "ERROR": logging.ERROR,
    }
    logger.log(level_map.get(entry["level"], logging.INFO), json.dumps(entry))


def _broadcast(entry: Dict[str, Any]) -> None:
    disconnected: List[asyncio.Queue[Dict[str, Any]]] = []
    for queue in list(_subscribers):
        try:
            queue.put_nowait(entry)
        except asyncio.QueueFull:
            try:
                queue.get_nowait()
                queue.put_nowait(entry)
            except Exception:
                disconnected.append(queue)
        except Exception:
            disconnected.append(queue)

    for queue in disconnected:
        _subscribers.discard(queue)


def log_event(level: str, message: str, **fields: Any) -> Dict[str, Any]:
    entry = build_log_entry(level, message, **fields)
    _log_history.append(entry)
    _emit_to_python_logger(entry)
    _broadcast(entry)
    return entry


def get_log_history() -> List[Dict[str, Any]]:
    return list(_log_history)


def subscribe() -> asyncio.Queue[Dict[str, Any]]:
    queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=STREAM_QUEUE_LIMIT)
    _subscribers.add(queue)
    return queue


def unsubscribe(queue: asyncio.Queue[Dict[str, Any]]) -> None:
    _subscribers.discard(queue)

