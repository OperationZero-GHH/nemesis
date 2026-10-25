"""Detection-only scanner tests against the local vulnerable test server."""

from __future__ import annotations

import pytest

from nemesis_toolkit.scanner import (
    clickjacking,
    cmd_inject,
    csrf,
    path_traversal,
    sql_injection as sqli,
    xss,
)


@pytest.mark.asyncio
async def test_xss_detects_verbatim_reflection(scanner_server):
    findings = await xss.run(f"{scanner_server}/xss?q=hello", authorized=True)
    assert any(
        finding.type == "reflected_xss" and finding.param == "q" and finding.severity == "high"
        for finding in findings
    )


@pytest.mark.asyncio
async def test_xss_reports_encoded_reflection_as_info(scanner_server):
    findings = await xss.run(f"{scanner_server}/xss-safe?q=hello", authorized=True)
    assert not any(finding.severity == "high" for finding in findings)
    encoded = [finding for finding in findings if finding.type == "input_reflection_encoded"]
    assert encoded
    assert encoded[0].metadata.get("encoded") is True


@pytest.mark.asyncio
async def test_xss_static_dom_scan(scanner_server):
    findings = await xss.run(
        f"{scanner_server}/dom?q=hello",
        check_dom=True,
        authorized=True,
    )
    assert any(finding.type == "dom_xss_indicator" for finding in findings)


@pytest.mark.asyncio
async def test_xss_requires_parameter_or_params(scanner_server):
    with pytest.raises(ValueError, match="No query parameters"):
        await xss.run(f"{scanner_server}/xss", authorized=True)


@pytest.mark.asyncio
async def test_path_traversal_detects_known_file_signature(scanner_server):
    findings = await path_traversal.run(
        f"{scanner_server}/traversal?file=readme",
        authorized=True,
    )
    assert findings
    assert findings[0].type == "path_traversal"
    assert findings[0].severity == "high"
    assert "passwd" in findings[0].metadata["payload"]


@pytest.mark.asyncio
async def test_path_traversal_safe_endpoint_has_no_findings(scanner_server):
    findings = await path_traversal.run(
        f"{scanner_server}/xss?q=readme",
        authorized=True,
    )
    assert findings == []


@pytest.mark.asyncio
async def test_sqli_detects_error_based_indicator(scanner_server):
    findings = await sqli.run(
        f"{scanner_server}/sqli?id=1",
        authorized=True,
    )
    assert any(
        finding.type == "sqli_error_based" and finding.metadata.get("database") == "MySQL"
        for finding in findings
    )


@pytest.mark.asyncio
async def test_sqli_safe_endpoint_has_no_findings(scanner_server):
    findings = await sqli.run(
        f"{scanner_server}/sqli-safe?id=1",
        authorized=True,
    )
    assert findings == []


@pytest.mark.asyncio
async def test_sqli_detects_boolean_divergence(scanner_server):
    findings = await sqli.run(
        f"{scanner_server}/sqli-bool?id=1",
        authorized=True,
    )
    assert any(finding.type == "sqli_boolean_blind" for finding in findings)


@pytest.mark.asyncio
async def test_cmdi_detects_echo_marker(scanner_server):
    findings = await cmd_inject.run(
        f"{scanner_server}/cmdi?host=127.0.0.1",
        time_based=False,
        authorized=True,
    )
    assert any(
        finding.type == "command_injection" and finding.severity == "critical"
        for finding in findings
    )


@pytest.mark.asyncio
async def test_cmdi_safe_endpoint_has_no_findings(scanner_server):
    findings = await cmd_inject.run(
        f"{scanner_server}/cmd-safe?host=127.0.0.1",
        time_based=False,
        authorized=True,
    )
    assert findings == []


@pytest.mark.asyncio
async def test_clickjacking_detects_missing_protections(scanner_server):
    findings = await clickjacking.run(f"{scanner_server}/clickjacked", authorized=True)
    assert len(findings) == 1
    assert findings[0].type == "clickjacking"
    assert findings[0].severity == "medium"


@pytest.mark.asyncio
async def test_clickjacking_respects_protections(scanner_server):
    findings = await clickjacking.run(f"{scanner_server}/clickjacked-safe", authorized=True)
    assert findings == []


@pytest.mark.asyncio
async def test_clickjacking_writes_local_poc(scanner_server, tmp_path):
    poc_path = tmp_path / "nested" / "poc.html"
    findings = await clickjacking.run(
        f"{scanner_server}/clickjacked",
        poc=poc_path,
        authorized=True,
    )
    assert findings
    assert poc_path.exists()
    content = poc_path.read_text(encoding="utf-8")
    assert "<iframe" in content
    assert scanner_server in content
    assert findings[0].metadata["poc_file"] == str(poc_path)


@pytest.mark.asyncio
async def test_csrf_detects_missing_token(scanner_server):
    findings = await csrf.run(f"{scanner_server}/csrf", authorized=True)
    assert findings
    assert findings[0].type == "csrf"
    assert "no detected anti-CSRF token" in findings[0].evidence


@pytest.mark.asyncio
async def test_csrf_accepts_token_and_samesite(scanner_server):
    findings = await csrf.run(f"{scanner_server}/csrf-safe", authorized=True)
    assert findings == []


@pytest.mark.asyncio
async def test_scanners_enforce_gate_before_network():
    from nemesis_toolkit.core.auth_gate import AuthorizationRequired

    with pytest.raises(AuthorizationRequired):
        await clickjacking.run("https://example.test/", authorized=False)
