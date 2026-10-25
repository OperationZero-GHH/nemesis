"""SQLite persistence for scan history, findings, targets and web snapshots."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .config import get_settings
from .logging import get_logger
from .models import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    module TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    options_json TEXT NOT NULL DEFAULT '{}',
    result_count INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    duration_seconds REAL
);
CREATE INDEX IF NOT EXISTS idx_scan_runs_target ON scan_runs(target, id DESC);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES scan_runs(id) ON DELETE SET NULL,
    target TEXT NOT NULL,
    module TEXT NOT NULL,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    url TEXT,
    param TEXT,
    evidence TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target, id DESC);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);

CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_url ON snapshots(url, id DESC);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _path(db_path: Path | None = None) -> Path:
    return Path(db_path) if db_path else get_settings().database


@contextmanager
def connect(db_path: Path | None = None) -> Iterator[sqlite3.Connection]:
    path = _path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path), timeout=20)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def init_db(db_path: Path | None = None) -> None:
    with connect(db_path) as connection:
        connection.executescript(SCHEMA)


def _upsert_target(connection: sqlite3.Connection, target: str) -> None:
    now = _now()
    connection.execute(
        """
        INSERT INTO targets (name, created_at, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET updated_at = excluded.updated_at
        """,
        (target, now, now),
    )


def persist_run(
    *,
    target: str,
    module: str,
    findings: list[Finding],
    options: dict[str, Any] | None = None,
    started_at: str | None = None,
    duration_seconds: float | None = None,
    status: str = "completed",
    error: str | None = None,
    db_path: Path | None = None,
) -> int:
    """Persist one run and all of its findings; return the run id."""
    init_db(db_path)
    started_at = started_at or _now()
    finished_at = _now()
    safe_options = _json_safe(options or {})
    with connect(db_path) as connection:
        _upsert_target(connection, target)
        cursor = connection.execute(
            """
            INSERT INTO scan_runs
                (target, module, started_at, finished_at, status, options_json,
                 result_count, error, duration_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target,
                module,
                started_at,
                finished_at,
                status,
                json.dumps(safe_options, ensure_ascii=False),
                len(findings),
                error,
                duration_seconds,
            ),
        )
        run_id = int(cursor.lastrowid)
        for finding in findings:
            finding.target = finding.target or target
            finding.module = finding.module or module
            connection.execute(
                """
                INSERT INTO findings
                    (run_id, target, module, type, severity, confidence, url,
                     param, evidence, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    finding.target,
                    finding.module,
                    finding.type,
                    finding.severity,
                    finding.confidence,
                    finding.url,
                    finding.param,
                    finding.evidence,
                    json.dumps(_json_safe(finding.metadata), ensure_ascii=False),
                    finding.timestamp,
                ),
            )
    get_logger().info(
        "run completed target=%s module=%s findings=%d duration=%s status=%s",
        target,
        module,
        len(findings),
        duration_seconds,
        status,
    )
    return run_id


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except TypeError:
        if isinstance(value, dict):
            return {str(k): _json_safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [_json_safe(v) for v in value]
        return str(value)


def get_runs(target: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    init_db()
    query = "SELECT * FROM scan_runs"
    args: list[Any] = []
    if target:
        query += " WHERE target = ?"
        args.append(target)
    query += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with connect() as connection:
        return [dict(row) for row in connection.execute(query, args).fetchall()]


def get_findings(target: str | None = None, limit: int = 500) -> list[Finding]:
    init_db()
    query = "SELECT * FROM findings"
    args: list[Any] = []
    if target:
        query += " WHERE target = ?"
        args.append(target)
    query += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with connect() as connection:
        rows = connection.execute(query, args).fetchall()
    return [Finding.from_row(row) for row in rows]


def list_targets() -> list[dict[str, Any]]:
    init_db()
    with connect() as connection:
        rows = connection.execute(
            """
            SELECT t.name, t.created_at, t.updated_at,
                   COUNT(DISTINCT r.id) AS runs,
                   COUNT(f.id) AS findings
            FROM targets t
            LEFT JOIN scan_runs r ON r.target = t.name
            LEFT JOIN findings f ON f.target = t.name
            GROUP BY t.name ORDER BY t.updated_at DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def dashboard(target: str | None = None, finding_limit: int = 500) -> dict[str, Any]:
    """Return consolidated target history for the tracker module."""
    init_db()
    with connect() as connection:
        target_rows = connection.execute(
            "SELECT * FROM targets ORDER BY updated_at DESC"
        ).fetchall()
        target_row = None
        if target:
            target_row = connection.execute(
                "SELECT * FROM targets WHERE name = ?", (target,)
            ).fetchone()
        runs_query = "SELECT * FROM scan_runs"
        findings_query = "SELECT * FROM findings"
        counts_query = (
            "SELECT severity, COUNT(*) AS count FROM findings "
            + ("WHERE target = ? " if target else "")
            + "GROUP BY severity"
        )
        args: tuple[Any, ...] = (target,) if target else ()
        if target:
            runs_query += " WHERE target = ?"
            findings_query += " WHERE target = ?"
        runs_query += " ORDER BY id DESC LIMIT 100"
        findings_query += " ORDER BY id DESC LIMIT ?"
        runs = [dict(row) for row in connection.execute(runs_query, args).fetchall()]
        finding_args = (*args, finding_limit)
        finding_rows = connection.execute(findings_query, finding_args).fetchall()
        severity_counts = {
            row["severity"]: row["count"] for row in connection.execute(counts_query, args).fetchall()
        }
    return {
        "target": target,
        "target_record": dict(target_row) if target_row else None,
        "targets": [dict(row) for row in target_rows],
        "runs": runs,
        "findings": [Finding.from_row(row) for row in finding_rows],
        "severity_counts": severity_counts,
    }


def save_snapshot(
    url: str,
    content: str,
    *,
    db_path: Path | None = None,
) -> tuple[bool, str | None, str]:
    """Store a content snapshot.

    Returns ``(changed, previous_content, content_hash)``. The first observation
    counts as ``changed=True`` with no previous content.
    """
    init_db(db_path)
    digest = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
    previous: str | None = None
    previous_hash: str | None = None
    with connect(db_path) as connection:
        row = connection.execute(
            "SELECT content, content_hash FROM snapshots WHERE url = ? ORDER BY id DESC LIMIT 1",
            (url,),
        ).fetchone()
        if row:
            previous = row["content"]
            previous_hash = row["content_hash"]
        connection.execute(
            "INSERT INTO snapshots (url, content_hash, content, created_at) VALUES (?, ?, ?, ?)",
            (url, digest, content, _now()),
        )
    changed = previous_hash != digest
    return changed, previous, digest


def latest_snapshot(url: str, *, db_path: Path | None = None) -> dict[str, Any] | None:
    init_db(db_path)
    with connect(db_path) as connection:
        row = connection.execute(
            "SELECT * FROM snapshots WHERE url = ? ORDER BY id DESC LIMIT 1", (url,)
        ).fetchone()
    return dict(row) if row else None


def snapshot_history(url: str, limit: int = 25, *, db_path: Path | None = None) -> list[dict[str, Any]]:
    init_db(db_path)
    with connect(db_path) as connection:
        rows = connection.execute(
            "SELECT id, url, content_hash, created_at FROM snapshots "
            "WHERE url = ? ORDER BY id DESC LIMIT ?",
            (url, limit),
        ).fetchall()
    return [dict(row) for row in rows]
