"""Tests for SQLite persistence and history aggregation."""

from __future__ import annotations

from nemesis_toolkit.core.db import (
    dashboard,
    get_findings,
    get_runs,
    latest_snapshot,
    list_targets,
    persist_run,
    save_snapshot,
)
from nemesis_toolkit.core.models import Finding


def _finding(**overrides):
    values = {
        "type": "reflected_xss",
        "evidence": "payload reflected",
        "severity": "high",
        "confidence": "high",
        "url": "https://example.test/search?q=x",
        "param": "q",
        "target": "example.test",
        "module": "xss",
    }
    values.update(overrides)
    return Finding(**values)


def test_persist_and_query_history():
    run_id = persist_run(
        target="example.test",
        module="xss",
        findings=[_finding()],
        options={"demo": True},
        duration_seconds=0.5,
    )
    assert run_id > 0
    runs = get_runs("example.test")
    assert runs and runs[0]["module"] == "xss"
    assert runs[0]["result_count"] == 1
    findings = get_findings("example.test")
    assert findings[0].type == "reflected_xss"
    assert findings[0].param == "q"
    assert list_targets()[0]["name"] == "example.test"
    data = dashboard("example.test")
    assert data["severity_counts"]["high"] == 1
    assert len(data["findings"]) == 1


def test_snapshots_track_changes():
    changed, previous, digest = save_snapshot("https://example.test/", "version one")
    assert changed is True
    assert previous is None
    assert len(digest) == 64
    changed, previous, _ = save_snapshot("https://example.test/", "version one")
    assert changed is False
    assert previous == "version one"
    changed, previous, _ = save_snapshot("https://example.test/", "version two")
    assert changed is True
    assert previous == "version one"
    latest = latest_snapshot("https://example.test/")
    assert latest and latest["content"] == "version two"
