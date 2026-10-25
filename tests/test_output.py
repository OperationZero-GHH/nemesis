"""Tests for shared JSON output rendering."""

from __future__ import annotations

import json

from nemesis_toolkit.core.models import Finding
from nemesis_toolkit.core.output import result_payload, write_json


def test_json_payload_and_file(tmp_path):
    findings = [
        Finding(
            type="reflected_xss",
            evidence="payload reflected",
            severity="high",
            confidence="high",
            url="https://example.test/?q=1",
            param="q",
            target="example.test",
            module="xss",
        ),
        Finding(
            type="open_port",
            evidence="port 443 open",
            severity="info",
            target="example.test",
            module="portscan",
        ),
    ]
    payload = result_payload("example.test", "xss", findings)
    assert payload["count"] == 2
    assert payload["severity_counts"]["high"] == 1
    path = tmp_path / "result.json"
    write_json(path, payload)
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["findings"][0]["param"] == "q"
    assert loaded["module"] == "xss"
