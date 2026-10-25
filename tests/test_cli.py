"""CLI smoke tests including the authorization gate and report output."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from nemesis_toolkit.core.db import get_findings, get_runs
from nemesis_toolkit.core.models import Finding
from nemesis_toolkit.main import app

runner = CliRunner()


def test_help_lists_command_groups():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    output = result.output.lower()
    assert "recon" in output
    assert "scan" in output
    assert "config" in output


def test_scan_help_is_available():
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "xss" in result.output
    assert "auto" in result.output


def test_config_show_redacts_keys():
    result = runner.invoke(app, ["config", "show", "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["serpapi_key"] in (None, "***configured***")
    assert "paths" in payload


def test_scanner_requires_confirmation(scanner_server):
    result = runner.invoke(
        app,
        ["scan", "xss", "-u", f"{scanner_server}/xss?q=test"],
    )
    assert result.exit_code == 2
    combined = result.output + (getattr(result, "stderr", "") or "")
    assert "authorization" in combined.lower()


def test_scanner_json_output_and_persistence(scanner_server):
    target = f"{scanner_server}/xss?q=hello"
    result = runner.invoke(
        app,
        ["scan", "xss", "-u", target, "--confirm-authorized", "--json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["module"] == "xss"
    assert payload["count"] >= 1
    assert any(item["type"] == "reflected_xss" for item in payload["findings"])

    runs = get_runs(target)
    assert runs and runs[0]["module"] == "xss"
    findings = get_findings(target)
    assert any(finding.type == "reflected_xss" for finding in findings)


def test_scanner_writes_json_file(scanner_server, tmp_path):
    target = f"{scanner_server}/xss?q=hello"
    output = tmp_path / "nested" / "xss.json"
    result = runner.invoke(
        app,
        [
            "scan",
            "xss",
            "-u",
            target,
            "--confirm-authorized",
            "--json",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["module"] == "xss"
    assert payload["findings"]
    # stdout must remain valid JSON even when --output is used.
    assert json.loads(result.stdout)["count"] == payload["count"]


def test_recon_cli_json(scanner_server):
    result = runner.invoke(
        app,
        ["recon", "loginfind", "-d", scanner_server, "--json", "--concurrency", "4"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["module"] == "loginfind"
    assert any(item["type"] == "login_endpoint" for item in payload["findings"])


def test_track_cli_reads_history(scanner_server):
    target = f"{scanner_server}/xss?q=track"
    scan = runner.invoke(
        app,
        ["scan", "xss", "-u", target, "--confirm-authorized", "--json"],
    )
    assert scan.exit_code == 0, scan.output

    result = runner.invoke(app, ["recon", "track", "--target", target, "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["run_count"] >= 1
    assert payload["finding_count"] >= 1


def test_auto_scan_html_report(scanner_server, tmp_path, monkeypatch):
    from nemesis_toolkit.scanner import auto_scan

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

    report_path = tmp_path / "auto-report.html"
    result = runner.invoke(
        app,
        [
            "scan",
            "auto",
            "-d",
            "127.0.0.1",
            "--max-hosts",
            "2",
            "--max-urls",
            "10",
            "--no-time-based",
            "--report",
            "html",
            "--output",
            str(report_path),
            "--confirm-authorized",
        ],
    )
    assert result.exit_code == 0, result.output
    html = report_path.read_text(encoding="utf-8")
    assert "<!doctype html>" in html.lower()
    assert "Nemesis" in html
    assert "127.0.0.1" in html
    assert "reflected_xss" in html


@pytest.mark.asyncio
async def test_auto_scan_requires_authorization():
    from nemesis_toolkit.scanner import auto_scan
    from nemesis_toolkit.core.auth_gate import AuthorizationRequired

    with pytest.raises(AuthorizationRequired):
        await auto_scan.run("example.test", authorized=False)
