"""End-to-end auto-scan pipeline tests against the local test server."""

from __future__ import annotations

import pytest

from nemesis_toolkit.core.models import Finding
from nemesis_toolkit.scanner import auto_scan


@pytest.mark.asyncio
async def test_auto_scan_pipeline_against_local_server(scanner_server, monkeypatch):
    port = int(scanner_server.rsplit(":", 1)[1])

    async def no_subdomains(*args, **kwargs):
        return []

    async def local_portscan(target, **kwargs):
        return [
            Finding(
                type="open_port",
                target=target,
                module="portscan",
                url=f"tcp://{target}:{port}",
                evidence=f"port {port}/tcp open — http",
                severity="info",
                confidence="high",
                metadata={"host": target, "port": port, "state": "open", "service": "http"},
            )
        ]

    monkeypatch.setattr(auto_scan.subdomain, "run", no_subdomains)
    monkeypatch.setattr(auto_scan.portscan, "run", local_portscan)

    findings = await auto_scan.run(
        "127.0.0.1",
        authorized=True,
        max_hosts=2,
        max_urls=10,
        time_based=False,
    )

    types = {finding.type for finding in findings}
    assert "open_port" in types
    assert "web_endpoints" in types
    assert "parameter" in types
    assert "reflected_xss" in types
    assert "clickjacking" in types
    assert "auto_scan_summary" in types

    summary = next(finding for finding in findings if finding.type == "auto_scan_summary")
    assert summary.metadata["detection_only"] is True
    assert summary.metadata["scanner_calls"] >= 1
    assert scanner_server in " ".join(summary.metadata["bases"])
    assert "scanners" in summary.metadata["steps"]


@pytest.mark.asyncio
async def test_auto_scan_requires_authorization():
    from nemesis_toolkit.core.auth_gate import AuthorizationRequired

    with pytest.raises(AuthorizationRequired):
        await auto_scan.run("example.test", authorized=False)
