"""Audit and run logging.

Every outbound HTTP request is recorded as JSON Lines in the audit log,
including timestamp, module, method, target, status and duration. This file is
append-only by default and is intentionally separate from console output.
"""

from __future__ import annotations

import json
import logging as pylogging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import get_settings

_AUDIT_LOCK = threading.Lock()
_LOGGER_LOCK = threading.Lock()
_LOGGER: pylogging.Logger | None = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False, default=str)
    with _AUDIT_LOCK:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def audit_event(event: str, module: str = "core", **fields: Any) -> None:
    """Write one audit record. Failures never abort a scan."""
    record = {"timestamp": utc_now_iso(), "event": event, "module": module, **fields}
    try:
        _append_jsonl(get_settings().audit_log, record)
    except OSError:
        # A full disk or unwritable data directory should not take down a scan.
        return


def audit_http(
    *,
    module: str,
    method: str,
    url: str,
    status: int | None,
    duration_ms: float,
    error: str | None = None,
    attempt: int = 1,
) -> None:
    audit_event(
        "http_request",
        module=module,
        method=method.upper(),
        target=url,
        status=status,
        duration_ms=round(duration_ms, 2),
        attempt=attempt,
        error=error,
    )


def audit_network(*, module: str, target: str, action: str, **fields: Any) -> None:
    audit_event("network", module=module, target=target, action=action, **fields)


def get_logger() -> pylogging.Logger:
    """Return the shared file logger for operational messages."""
    global _LOGGER
    if _LOGGER is not None:
        return _LOGGER
    with _LOGGER_LOCK:
        if _LOGGER is not None:
            return _LOGGER
        logger = pylogging.getLogger("nemesis_toolkit")
        logger.setLevel(pylogging.INFO)
        logger.propagate = False
        if not logger.handlers:
            path = get_settings().run_log
            path.parent.mkdir(parents=True, exist_ok=True)
            handler = pylogging.FileHandler(path, encoding="utf-8")
            handler.setFormatter(
                pylogging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
            )
            logger.addHandler(handler)
        _LOGGER = logger
        return logger


def reset_logger() -> None:
    """Reset cached logger state (test helper)."""
    global _LOGGER
    with _LOGGER_LOCK:
        if _LOGGER is not None:
            for handler in list(_LOGGER.handlers):
                handler.close()
                _LOGGER.removeHandler(handler)
        _LOGGER = None
