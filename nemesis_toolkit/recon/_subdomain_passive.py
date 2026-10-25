"""Passive subdomain intelligence aggregator across OSINT sources, Certificate Transparency logs, and search engines.

Implements capabilities:
- Passive subdomain enumeration (crt.sh, Certspotter, AlienVault, HackerTarget, RapidDNS)
- Search-engine subdomain discovery (DuckDuckGo, Bing)
- Certificate Transparency discovery
- Public OSINT source integrations
- API-key based collection (SecurityTrails, VirusTotal, Shodan)
- Selectable discovery sources
- Source attribution for every discovered host
"""

from __future__ import annotations

import asyncio
import re
from collections import defaultdict
from typing import Any
from urllib.parse import quote

from bs4 import BeautifulSoup

from ..core.config import get_settings
from ..core.http_client import AsyncHTTPClient
from ..core.logging import get_logger

_SUBDOMAIN_CLEAN_RE = re.compile(r"^[a-zA-Z0-9_\-\.]+$")


def is_valid_subdomain(candidate: str, domain: str) -> bool:
    """Validate that candidate is a syntactically valid sub-host of target domain."""
    candidate = candidate.lower().strip().strip(".")
    if candidate.startswith("*."):
        candidate = candidate[2:]
    if not candidate or candidate == domain or not candidate.endswith(f".{domain}"):
        return False
    if "@" in candidate or not _SUBDOMAIN_CLEAN_RE.match(candidate):
        return False
    label = candidate[: -(len(domain) + 1)]
    return all(part and len(part) <= 63 for part in label.split("."))


async def query_crtsh(domain: str, client: AsyncHTTPClient, timeout: float = 12.0) -> set[str]:
    """Extract hostnames from crt.sh Certificate Transparency logs."""
    subdomains: set[str] = set()
    url = f"https://crt.sh/?q=%25.{quote(domain)}&output=json"
    try:
        response = await client.get(url, module="subdomain", timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        for val in str(entry.get("name_value") or "").splitlines():
                            clean = val.strip().lower().lstrip("*.")
                            if is_valid_subdomain(clean, domain):
                                subdomains.add(clean)
    except Exception as exc:
        get_logger().debug("crt.sh passive lookup failed: %s", exc)
    return subdomains


async def query_certspotter(domain: str, client: AsyncHTTPClient, timeout: float = 8.0) -> set[str]:
    """Extract hostnames from Certspotter free Certificate Transparency API."""
    subdomains: set[str] = set()
    url = f"https://api.certspotter.com/v1/issuances?domain={quote(domain)}&include_subdomains=true&expand=dns_names"
    try:
        response = await client.get(url, module="subdomain", timeout=timeout)
        if response.status_code == 200:
            records = response.json()
            if isinstance(records, list):
                for item in records:
                    if isinstance(item, dict):
                        for name in item.get("dns_names", []):
                            clean = str(name).strip().lower().lstrip("*.")
                            if is_valid_subdomain(clean, domain):
                                subdomains.add(clean)
    except Exception as exc:
        get_logger().debug("certspotter lookup failed: %s", exc)
    return subdomains


async def query_alienvault(domain: str, client: AsyncHTTPClient, timeout: float = 8.0) -> set[str]:
    """Extract passive DNS indicators from AlienVault OTX."""
    subdomains: set[str] = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain)}/passive_dns"
    try:
        response = await client.get(url, module="subdomain", timeout=timeout)
        if response.status_code == 200:
            payload = response.json()
            for record in payload.get("passive_dns", []):
                hostname = record.get("hostname", "").strip().lower()
                if is_valid_subdomain(hostname, domain):
                    subdomains.add(hostname)
    except Exception as exc:
        get_logger().debug("alienvault lookup failed: %s", exc)
    return subdomains


async def query_hackertarget(domain: str, client: AsyncHTTPClient, timeout: float = 8.0) -> set[str]:
    """Query HackerTarget public host search API."""
    subdomains: set[str] = set()
    url = f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}"
    try:
        response = await client.get(url, module="subdomain", timeout=timeout)
        if response.status_code == 200 and "error" not in response.text.lower():
            for line in response.text.splitlines():
                if "," in line:
                    host = line.split(",")[0].strip().lower()
                    if is_valid_subdomain(host, domain):
                        subdomains.add(host)
    except Exception as exc:
        get_logger().debug("hackertarget lookup failed: %s", exc)
    return subdomains


async def query_rapiddns(domain: str, client: AsyncHTTPClient, timeout: float = 8.0) -> set[str]:
    """Query RapidDNS public subdomains registry."""
    subdomains: set[str] = set()
    url = f"https://rapiddns.io/subdomain/{quote(domain)}?full=1"
    try:
        response = await client.get(url, module="subdomain", timeout=timeout)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            for td in soup.find_all("td"):
                text = td.get_text().strip().lower()
                if is_valid_subdomain(text, domain):
                    subdomains.add(text)
    except Exception as exc:
        get_logger().debug("rapiddns lookup failed: %s", exc)
    return subdomains


async def query_duckduckgo(domain: str, client: AsyncHTTPClient, timeout: float = 8.0) -> set[str]:
    """Scrape DuckDuckGo search HTML for indexed subdomains."""
    subdomains: set[str] = set()
    url = f"https://html.duckduckgo.com/html/?q=site:{quote(domain)}"
    try:
        response = await client.get(url, module="subdomain", timeout=timeout)
        if response.status_code == 200:
            # Extract URLs from HTML results
            pattern = re.compile(rf"https?://([a-zA-Z0-9_\-\.]+\.{re.escape(domain)})", re.IGNORECASE)
            for match in pattern.findall(response.text):
                clean = match.strip().lower()
                if is_valid_subdomain(clean, domain):
                    subdomains.add(clean)
    except Exception as exc:
        get_logger().debug("duckduckgo search lookup failed: %s", exc)
    return subdomains


async def query_bing(domain: str, client: AsyncHTTPClient, timeout: float = 8.0) -> set[str]:
    """Scrape Bing search HTML for indexed subdomains."""
    subdomains: set[str] = set()
    url = f"https://www.bing.com/search?q=site:{quote(domain)}"
    try:
        response = await client.get(url, module="subdomain", timeout=timeout)
        if response.status_code == 200:
            pattern = re.compile(rf"https?://([a-zA-Z0-9_\-\.]+\.{re.escape(domain)})", re.IGNORECASE)
            for match in pattern.findall(response.text):
                clean = match.strip().lower()
                if is_valid_subdomain(clean, domain):
                    subdomains.add(clean)
    except Exception as exc:
        get_logger().debug("bing search lookup failed: %s", exc)
    return subdomains


async def query_authenticated_apis(
    domain: str,
    client: AsyncHTTPClient,
    timeout: float = 10.0,
) -> dict[str, set[str]]:
    """Query external providers when API keys are configured."""
    settings = get_settings()
    results: dict[str, set[str]] = defaultdict(set)

    # SecurityTrails
    st_key = settings.api_key("securitytrails_api_key")
    if st_key:
        try:
            resp = await client.get(
                f"https://api.securitytrails.com/v1/domain/{quote(domain)}/subdomains",
                module="subdomain",
                headers={"APIKEY": st_key},
                params={"children_only": "false", "include_inactive": "true"},
                timeout=timeout,
            )
            if resp.status_code == 200:
                for sub in resp.json().get("subdomains", []):
                    full = f"{sub}.{domain}".lower()
                    if is_valid_subdomain(full, domain):
                        results[full].add("securitytrails")
        except Exception as exc:
            get_logger().debug("SecurityTrails API failed: %s", exc)

    # VirusTotal
    vt_key = settings.api_key("virustotal_api_key")
    if vt_key:
        try:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{quote(domain)}/subdomains",
                module="subdomain",
                headers={"x-apikey": vt_key},
                params={"limit": 100},
                timeout=timeout,
            )
            if resp.status_code == 200:
                for item in resp.json().get("data", []):
                    val = str(item.get("id", "")).strip().lower()
                    if is_valid_subdomain(val, domain):
                        results[val].add("virustotal")
        except Exception as exc:
            get_logger().debug("VirusTotal API failed: %s", exc)

    # Shodan
    shodan_key = settings.api_key("shodan_api_key")
    if shodan_key:
        try:
            resp = await client.get(
                f"https://api.shodan.io/dns/domain/{quote(domain)}?key={shodan_key}",
                module="subdomain",
                timeout=timeout,
            )
            if resp.status_code == 200:
                for sub in resp.json().get("subdomains", []):
                    full = f"{sub}.{domain}".lower()
                    if is_valid_subdomain(full, domain):
                        results[full].add("shodan")
        except Exception as exc:
            get_logger().debug("Shodan API failed: %s", exc)

    return results


async def collect_all_passive(
    domain: str,
    client: AsyncHTTPClient,
    selected_sources: list[str] | set[str] | None = None,
) -> dict[str, set[str]]:
    """Gather subdomains from all enabled passive intelligence providers with source attribution."""
    discoveries: dict[str, set[str]] = defaultdict(set)
    sources = set(selected_sources) if selected_sources else {
        "crt.sh", "certspotter", "alienvault", "hackertarget", "rapiddns",
        "duckduckgo", "bing", "apis",
    }

    tasks = []
    task_names = []

    if "crt.sh" in sources:
        tasks.append(query_crtsh(domain, client))
        task_names.append("crt.sh")
    if "certspotter" in sources:
        tasks.append(query_certspotter(domain, client))
        task_names.append("certspotter")
    if "alienvault" in sources:
        tasks.append(query_alienvault(domain, client))
        task_names.append("alienvault")
    if "hackertarget" in sources:
        tasks.append(query_hackertarget(domain, client))
        task_names.append("hackertarget")
    if "rapiddns" in sources:
        tasks.append(query_rapiddns(domain, client))
        task_names.append("rapiddns")
    if "duckduckgo" in sources:
        tasks.append(query_duckduckgo(domain, client))
        task_names.append("duckduckgo")
    if "bing" in sources:
        tasks.append(query_bing(domain, client))
        task_names.append("bing")

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for source_name, res in zip(task_names, results):
        if isinstance(res, set):
            for host in res:
                discoveries[host].add(source_name)

    if "apis" in sources:
        api_results = await query_authenticated_apis(domain, client)
        for host, src_set in api_results.items():
            discoveries[host].update(src_set)

    return discoveries
