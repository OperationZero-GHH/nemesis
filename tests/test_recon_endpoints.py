"""Tests for endpoint discovery, WAF fingerprinting and monitoring modules."""

from __future__ import annotations

import httpx
import pytest
import respx

from nemesis_toolkit.core.db import get_findings, get_runs
from nemesis_toolkit.recon import (
    login_finder,
    param_finder,
    pro_tracker,
    register_finder,
    waf_check,
    web_monitor,
)


@pytest.mark.asyncio
async def test_login_finder_discovers_password_form(scanner_server):
    findings = await login_finder.run(scanner_server, concurrency=4)
    assert findings
    assert all(finding.type == "login_endpoint" for finding in findings)
    assert any(finding.metadata["password_fields"] == 1 for finding in findings)
    assert any(finding.confidence == "high" for finding in findings)


@pytest.mark.asyncio
async def test_register_finder_discovers_signup_form(scanner_server):
    findings = await register_finder.run(scanner_server, concurrency=4)
    assert findings
    assert all(finding.type == "registration_endpoint" for finding in findings)
    assert any(
        finding.metadata["title"] == "Create account" and finding.metadata["password_fields"] == 1
        for finding in findings
    )


@pytest.mark.asyncio
async def test_register_finder_missing_wordlist(tmp_path):
    with pytest.raises(ValueError, match="Path list not found"):
        await register_finder.run("https://example.test", extra_paths=tmp_path / "missing.txt")


@pytest.mark.asyncio
async def test_param_finder_discovers_query_and_form_parameters(scanner_server):
    findings = await param_finder.run(scanner_server, depth=1, max_pages=6)
    methods = {(finding.url, finding.metadata["method"]) for finding in findings}
    assert any(url.endswith("/xss?q=hello") and method == "GET" for url, method in methods)
    form = next(
        finding
        for finding in findings
        if finding.metadata["method"] == "POST" and finding.url.endswith("/account/update")
    )
    assert form.metadata["parameters"] == ["email", "role"]
    assert form.metadata["injectable"] == ["email", "role"]


@pytest.mark.asyncio
async def test_param_finder_can_skip_forms(scanner_server):
    findings = await param_finder.run(
        scanner_server,
        depth=1,
        max_pages=4,
        include_forms=False,
    )
    assert findings
    assert all(finding.metadata["method"] == "GET" for finding in findings)


@pytest.mark.asyncio
async def test_waf_fingerprints_cloudflare_block(scanner_server):
    findings = await waf_check.run(f"{scanner_server}/waf")
    assert findings
    assert findings[0].type == "waf_detected"
    assert "Cloudflare" in findings[0].metadata["vendors"]
    assert findings[0].metadata["blocked_probes"] >= 1


@pytest.mark.asyncio
async def test_waf_reports_not_detected(scanner_server):
    findings = await waf_check.run(f"{scanner_server}/xss?q=hello")
    assert findings
    assert findings[0].type in {"waf_not_detected", "waf_suspected"}


@pytest.mark.asyncio
async def test_web_monitor_tracks_snapshot_changes(scanner_server):
    url = f"{scanner_server}/monitor?asset=test"
    first = await web_monitor.run(url, once=True)
    assert first and first[0].type == "snapshot_initial"
    second = await web_monitor.run(url, once=True)
    assert second and second[0].type == "content_change"
    assert "Version 1" in second[0].metadata["diff"]
    assert "Version 2" in second[0].metadata["diff"]


@pytest.mark.asyncio
async def test_web_monitor_reports_http_errors(scanner_server):
    findings = await web_monitor.run(f"{scanner_server}/missing", once=True)
    assert findings
    assert findings[0].type == "monitor_error"


@pytest.mark.asyncio
async def test_web_monitor_requires_target():
    with pytest.raises(ValueError, match="At least one URL"):
        await web_monitor.run([], once=True)


def test_pro_tracker_reads_persisted_history():
    from nemesis_toolkit.core.db import persist_run
    from nemesis_toolkit.core.models import Finding

    persist_run(
        target="history.example",
        module="xss",
        findings=[
            Finding(
                type="reflected_xss",
                evidence="reflected",
                severity="high",
                confidence="high",
                url="https://history.example/?q=1",
                param="q",
                target="history.example",
                module="xss",
            )
        ],
    )
    findings = pro_tracker.run("history.example")
    assert findings and findings[0].type == "reflected_xss"
    assert findings[0].metadata["tracker"] == "historical_finding"
    payload = pro_tracker.payload("history.example")
    assert payload["run_count"] == 1
    assert payload["finding_count"] == 1
    assert payload["severity_counts"]["high"] == 1
    # Tracker reads only; it must not create new runs or findings.
    assert len(get_runs("history.example")) == 1
    assert len(get_findings("history.example")) == 1


@pytest.mark.asyncio
async def test_mail_scraper_discovers_public_email_without_search_key(monkeypatch):
    from nemesis_toolkit.recon import mail_scraper

    pages = {
        "/": "<html><body><a href='/contact'>Contact</a>"
        "<a href='mailto:hello@example.test'>hello@example.test</a></body></html>",
        "/contact": "<html><body>Security: security@example.test</body></html>",
    }

    def respond(request: httpx.Request) -> httpx.Response:
        path = request.url.path or "/"
        if path in pages:
            return httpx.Response(200, text=pages[path], headers={"content-type": "text/html"})
        return httpx.Response(404, text="not found")

    with respx.mock(assert_all_called=False) as mock:
        mock.get(url__startswith="https://example.test/").mock(side_effect=respond)
        findings = await mail_scraper.run("example.test", sources="web", max_pages=5)

    emails = {finding.metadata["email"] for finding in findings if finding.type == "email"}
    assert "hello@example.test" in emails
    assert "security@example.test" in emails


@pytest.mark.asyncio
async def test_mail_scraper_reports_missing_search_key():
    from nemesis_toolkit.recon import mail_scraper

    findings = await mail_scraper.run("example.test", sources="search")
    assert findings
    assert findings[0].type == "search_unavailable"
    assert "serpapi_key" in findings[0].evidence.lower()


@pytest.mark.asyncio
async def test_mail_scraper_breach_check_degrades_without_key(monkeypatch):
    from nemesis_toolkit.recon import mail_scraper

    def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text="<html><body>contact: test@example.test</body></html>",
            headers={"content-type": "text/html"},
        )

    with respx.mock(assert_all_called=False) as mock:
        mock.get(url__startswith="https://example.test/").mock(side_effect=respond)
        findings = await mail_scraper.run(
            "example.test",
            sources="web",
            check_breaches=True,
            max_pages=1,
        )

    assert any(finding.type == "breach_check_unavailable" for finding in findings)
