"""Tests for network-facing recon modules that are mocked or locally bound."""

from __future__ import annotations

import socket

import httpx
import pytest
import respx

from nemesis_toolkit.core.config import get_settings
from nemesis_toolkit.recon import dorking, ip_location, osint_human, osint_social, portscan, subdomain


def test_parse_ports_supports_ranges_and_validation():
    assert portscan.parse_ports("443,80,8080-8082") == [80, 443, 8080, 8081, 8082]
    assert portscan.parse_ports("8082-8080") == [8080, 8081, 8082]
    with pytest.raises(ValueError, match="between 1 and 65535"):
        portscan.parse_ports("0")
    with pytest.raises(ValueError, match="Invalid port range"):
        portscan.parse_ports("abc-def")
    with pytest.raises(ValueError, match="No valid ports"):
        portscan.parse_ports(" , ")


def test_port_compression():
    assert portscan._compress_port_list([22, 80, 81, 82, 443]) == "22,80-82,443"


@pytest.mark.asyncio
async def test_portscan_finds_local_open_port(scanner_server, monkeypatch):
    monkeypatch.setattr(portscan.shutil, "which", lambda _name: None)
    port = int(scanner_server.rsplit(":", 1)[1])

    closed_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    closed_socket.bind(("127.0.0.1", 0))
    closed_port = closed_socket.getsockname()[1]
    closed_socket.close()

    findings = await portscan.run(
        "127.0.0.1",
        ports=f"{port},{closed_port}",
        timeout=0.5,
        concurrency=4,
    )
    assert [finding.metadata["port"] for finding in findings] == [port]
    assert findings[0].type == "open_port"
    assert findings[0].metadata["scanner"] == "asyncio"


@pytest.mark.asyncio
async def test_portscan_rejects_invalid_host():
    with pytest.raises(ValueError, match="Invalid host"):
        await portscan.run("-oops")


def test_subdomain_candidate_validation():
    assert subdomain._valid_candidate("api.example.test", "example.test")
    assert not subdomain._valid_candidate("example.test", "example.test")
    assert not subdomain._valid_candidate("api.example.other", "example.test")
    assert not subdomain._valid_candidate("bad@label.example.test", "example.test")


@pytest.mark.asyncio
async def test_subdomain_bruteforce_and_wildcard_filter(tmp_path, monkeypatch):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("www\napi\n*.wild\n", encoding="utf-8")

    async def passive(domain, client):
        return {"passive.example.test": {"crt.sh"}}

    async def resolve(resolver, host, semaphore):
        if host == "www.example.test":
            return ["93.184.216.34"]
        if host == "api.example.test":
            return ["10.0.0.5"]
        return []

    monkeypatch.setattr(subdomain, "_passive_sources", passive)
    monkeypatch.setattr(subdomain, "_resolve_host", resolve)

    findings = await subdomain.run("example.test", wordlist=wordlist, concurrency=4)
    hosts = {finding.metadata["host"] for finding in findings if finding.type == "subdomain"}
    assert hosts == {"www.example.test", "api.example.test", "passive.example.test"}
    passive_finding = next(
        finding for finding in findings if finding.metadata.get("host") == "passive.example.test"
    )
    assert passive_finding.metadata["sources"] == ["crt.sh"]
    assert passive_finding.metadata["wildcard_dns"] is False


@pytest.mark.asyncio
async def test_subdomain_wildcard_dns_is_reported(tmp_path, monkeypatch):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("www\n", encoding="utf-8")

    async def passive(domain, client):
        return {}

    async def resolve(resolver, host, semaphore):
        if host.startswith("rt-wildcard-"):
            return ["203.0.113.9"]
        if host.endswith(".example.test"):
            return ["203.0.113.9"]
        return []

    monkeypatch.setattr(subdomain, "_passive_sources", passive)
    monkeypatch.setattr(subdomain, "_resolve_host", resolve)

    findings = await subdomain.run("example.test", wordlist=wordlist)
    assert any(finding.type == "wildcard_dns" for finding in findings)
    # The brute-force hit is entirely explained by wildcard DNS.
    assert not any(
        finding.type == "subdomain" and "brute-force" in finding.metadata.get("sources", [])
        for finding in findings
    )


@pytest.mark.asyncio
async def test_ip_location_handles_private_addresses():
    findings = await ip_location.run("10.1.2.3")
    assert findings
    assert findings[0].metadata["private"] is True
    assert "private" in findings[0].evidence.lower()


@pytest.mark.asyncio
async def test_ip_location_uses_ipinfo_for_public_ip(monkeypatch):
    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://ipinfo.io/8.8.8.8/json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "ip": "8.8.8.8",
                    "city": "Mountain View",
                    "region": "California",
                    "country": "US",
                    "org": "AS15169 Google LLC",
                    "loc": "37.4056,-122.0775",
                    "timezone": "America/Los_Angeles",
                },
            )
        )
        findings = await ip_location.run("8.8.8.8")

    assert findings
    metadata = findings[0].metadata
    assert metadata["source"] == "ipinfo"
    assert metadata["hosting"] is True
    assert metadata["latitude"] == "37.4056"
    assert metadata["longitude"] == "-122.0775"
    assert metadata["asn"] == "AS15169"


@pytest.mark.asyncio
async def test_ip_location_reports_ipinfo_rate_limit():
    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://ipinfo.io/1.1.1.1/json").mock(return_value=httpx.Response(429))
        with pytest.raises(RuntimeError, match="rate limit"):
            await ip_location.run("1.1.1.1")


@pytest.mark.asyncio
async def test_dorking_without_key_degrades_gracefully(monkeypatch):
    monkeypatch.delenv("NEMESIS_SERPAPI_KEY", raising=False)
    get_settings.cache_clear()
    findings = await dorking.run("example.test", max_dorks=2)
    assert findings
    assert findings[0].type == "search_unavailable"
    assert "serpapi_key" in findings[0].evidence.lower()
    assert len(findings[0].metadata["queries"]) == 2


@pytest.mark.asyncio
async def test_dorking_uses_serpapi_when_configured(monkeypatch):
    monkeypatch.setenv("NEMESIS_SERPAPI_KEY", "test-key")
    get_settings.cache_clear()
    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://serpapi.com/search.json").mock(
            return_value=httpx.Response(
                200,
                json={
                    "organic_results": [
                        {
                            "title": "Example admin",
                            "link": "https://example.test/admin",
                            "snippet": "admin panel",
                        }
                    ]
                },
            )
        )
        findings = await dorking.run("example.test", max_dorks=1, max_results=1)

    assert len(findings) == 1
    assert findings[0].type == "dork_result"
    assert findings[0].url == "https://example.test/admin"
    assert findings[0].metadata["search_source"] == "serpapi"


@pytest.mark.asyncio
async def test_osint_social_uses_public_github_api(monkeypatch):
    with respx.mock(assert_all_called=True) as mock:
        mock.get("https://api.github.com/users/octocat").mock(
            return_value=httpx.Response(
                200,
                json={
                    "login": "octocat",
                    "name": "The Octocat",
                    "html_url": "https://github.com/octocat",
                    "bio": "GitHub mascot",
                    "public_repos": 8,
                },
            )
        )
        mock.get("https://www.reddit.com/user/octocat").mock(return_value=httpx.Response(404))
        findings = await osint_social.run(
            "octocat",
            platforms="github,reddit",
            concurrency=2,
        )

    assert len(findings) == 1
    assert findings[0].metadata["platform"] == "github"
    assert findings[0].metadata["public_bio"] == "GitHub mascot"
    assert findings[0].url == "https://github.com/octocat"
    assert osint_social.supported_platforms()


@pytest.mark.asyncio
async def test_osint_social_rejects_unsupported_platforms():
    with pytest.raises(ValueError, match="No supported platforms"):
        await osint_social.run("octocat", platforms="myspace")


@pytest.mark.asyncio
async def test_osint_human_missing_keys_are_reported():
    name_findings = await osint_human.run(name="Jane Doe")
    assert any(finding.type == "search_unavailable" for finding in name_findings)

    email_findings = await osint_human.run(email="person@example.test")
    assert any(finding.type == "breach_check_unavailable" for finding in email_findings)


@pytest.mark.asyncio
async def test_osint_human_requires_identifier():
    with pytest.raises(ValueError, match="at least one"):
        await osint_human.run()
