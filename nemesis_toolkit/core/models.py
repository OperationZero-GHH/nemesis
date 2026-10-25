"""Shared finding model used by every module and the persistence layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(slots=True)
class Finding:
    """A structured result.

    Scanner modules populate ``url``, ``param``, ``evidence``, ``severity`` and
    ``confidence``. Recon modules use the same class so every output format and
    the SQLite history stay consistent.
    """

    type: str
    evidence: str
    severity: str = "info"
    confidence: str = "high"
    url: str | None = None
    param: str | None = None
    target: str = ""
    module: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_now_iso)

    def __post_init__(self) -> None:
        self.severity = str(self.severity or "info").lower()
        self.confidence = str(self.confidence or "low").lower()
        if self.severity not in SEVERITIES:
            self.severity = "info"
        if self.confidence not in CONFIDENCES:
            self.confidence = "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "module": self.module,
            "type": self.type,
            "severity": self.severity,
            "confidence": self.confidence,
            "url": self.url,
            "param": self.param,
            "evidence": self.evidence,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_row(cls, row: Any) -> "Finding":
        import json

        try:
            metadata = json.loads(row["metadata_json"] or "{}")
        except (TypeError, ValueError):
            metadata = {}
        return cls(
            type=row["type"],
            evidence=row["evidence"] or "",
            severity=row["severity"] or "info",
            confidence=row["confidence"] or "low",
            url=row["url"],
            param=row["param"],
            target=row["target"] or "",
            module=row["module"] or "",
            metadata=metadata if isinstance(metadata, dict) else {},
            timestamp=row["created_at"] or utc_now_iso(),
        )
