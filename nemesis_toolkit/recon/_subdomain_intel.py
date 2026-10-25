"""Attack surface intelligence, permutations, cloud storage discovery, virtual hosts, and inventory tracking.

Implements capabilities:
- Subdomain permutations and alterations (altdns style)
- Cloud storage bucket enumeration (AWS S3, Azure Blob, Google Cloud Storage)
- HTTP virtual host discovery
- Quick port checking on discovered hosts (80, 443, 8080, 8443)
- Network and attack surface clustering (by ASN & /24 subnet)
- Historical scan comparison & inventory change tracking (new vs removed)
- Result visualization formatting (domain tree diagram)
- Bulk domain parsing
"""

from __future__ import annotations

import asyncio
import socket
from collections import defaultdict
from typing import Any

from ..core.db import get_findings
from ..core.http_client import AsyncHTTPClient
from ..core.logging import get_logger

PERMUTATION_WORDS = [
    "dev", "prod", "stage", "staging", "test", "demo", "uat", "qa",
    "api", "app", "corp", "internal", "vpn", "admin", "portal",
    "v1", "v2", "beta", "old", "new", "bak", "edge", "cloud",
]

COMMON_WEB_PORTS = [80, 443, 8080, 8443]


def generate_permutations(known_subdomains: list[str], apex_domain: str, limit: int = 250) -> list[str]:
    """Generate realistic permutation variants from known subdomains."""
    candidates: set[str] = set()

    for host in known_subdomains:
        if not host.endswith(f".{apex_domain}"):
            continue
        prefix = host[: -(len(apex_domain) + 1)]
        labels = prefix.split(".")
        main_label = labels[0]

        for word in PERMUTATION_WORDS:
            candidates.add(f"{word}-{main_label}.{apex_domain}")
            candidates.add(f"{main_label}-{word}.{apex_domain}")
            candidates.add(f"{word}.{prefix}.{apex_domain}")
            candidates.add(f"{main_label}{word}.{apex_domain}")
            if len(candidates) >= limit:
                break
        if len(candidates) >= limit:
            break

    return sorted(candidates)[:limit]


def parse_bulk_domains(target_input: str) -> list[str]:
    """Parse comma, space, or newline-separated domains."""
    domains = []
    for item in target_input.replace(",", " ").split():
        clean = item.strip().lower()
        if clean and "." in clean and not clean.startswith("-"):
            domains.append(clean)
    return sorted(set(domains)) or [target_input.strip()]


async def probe_ports(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 0.8,
) -> list[int]:
    """Quickly probe standard HTTP/HTTPS ports on a discovered host."""
    open_ports = []
    check_ports = ports or COMMON_WEB_PORTS

    async def _test_port(p: int) -> int | None:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, p),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return p
        except Exception:
            return None

    results = await asyncio.gather(*(_test_port(p) for p in check_ports), return_exceptions=True)
    for res in results:
        if isinstance(res, int):
            open_ports.append(res)
    return open_ports


async def check_cloud_buckets(
    domain: str,
    client: AsyncHTTPClient,
    timeout: float = 5.0,
) -> list[dict[str, str]]:
    """Enumerate public AWS S3, Google Cloud, and Azure buckets named after the domain."""
    name_clean = domain.replace(".", "-").replace("_", "-")
    candidates = [
        ("AWS S3", f"http://{domain}.s3.amazonaws.com"),
        ("AWS S3", f"http://{name_clean}.s3.amazonaws.com"),
        ("Google Cloud Storage", f"https://storage.googleapis.com/{domain}"),
        ("Google Cloud Storage", f"https://storage.googleapis.com/{name_clean}"),
        ("Azure Blob", f"https://{name_clean.replace('-', '')}.blob.core.windows.net"),
    ]

    findings = []
    for provider, url in candidates:
        try:
            resp = await client.get(url, module="subdomain", timeout=timeout)
            if resp.status_code in (200, 403):
                status_text = "Publicly readable (open)" if resp.status_code == 200 else "Exists (protected/access denied)"
                findings.append({
                    "provider": provider,
                    "url": url,
                    "status": status_text,
                    "code": resp.status_code,
                })
        except Exception:
            continue

    return findings


async def check_virtual_hosts(
    ip: str,
    domain: str,
    candidate_subdomains: list[str],
    client: AsyncHTTPClient,
    limit: int = 15,
) -> list[str]:
    """Probe an IP directly using Host: header manipulation to discover hidden vhosts."""
    detected = []
    for cand in candidate_subdomains[:limit]:
        try:
            resp = await client.get(
                f"http://{ip}/",
                module="subdomain",
                headers={"Host": cand},
                timeout=4.0,
            )
            if resp.status_code not in (404, 400, 502, 503):
                detected.append(cand)
        except Exception:
            continue
    return detected


def cluster_network_surface(host_ip_map: dict[str, list[str]]) -> dict[str, list[str]]:
    """Cluster discovered hosts by /24 subnet."""
    clusters: dict[str, list[str]] = defaultdict(list)
    for host, ips in host_ip_map.items():
        for ip in ips:
            if "." in ip:  # IPv4
                subnet = ".".join(ip.split(".")[:3]) + ".0/24"
                clusters[subnet].append(f"{host} ({ip})")
            else:
                clusters["IPv6"].append(f"{host} ({ip})")
    return dict(clusters)


def compare_historical_inventory(domain: str, current_hosts: set[str]) -> dict[str, Any]:
    """Compare discovered hosts with prior scan runs in the local database."""
    prior_hosts: set[str] = set()
    try:
        past_findings = get_findings(target=domain, limit=500)
        for finding in past_findings:
            if finding.module == "subdomain" and finding.type == "subdomain":
                host = finding.metadata.get("host")
                if host:
                    prior_hosts.add(host)
    except Exception:
        pass

    if not prior_hosts:
        return {"has_history": False, "new_hosts": list(current_hosts), "removed_hosts": []}

    new_hosts = sorted(current_hosts - prior_hosts)
    removed_hosts = sorted(prior_hosts - current_hosts)

    return {
        "has_history": True,
        "new_hosts": new_hosts,
        "removed_hosts": removed_hosts,
        "prior_count": len(prior_hosts),
    }


def render_attack_surface_tree(
    domain: str,
    host_data: dict[str, dict[str, Any]],
) -> str:
    """Generate a clean ASCII tree of the discovered domain infrastructure."""
    lines = [f"[bold bright_cyan]{domain}[/bold bright_cyan]"]
    hosts = sorted(host_data.keys())

    for idx, host in enumerate(hosts):
        is_last = idx == len(hosts) - 1
        branch = "└── " if is_last else "├── "
        pipe = "    " if is_last else "│   "

        info = host_data[host]
        ips = ", ".join(info.get("ips", [])) or "no IP"
        cnames = f" -> {info['cname']}" if info.get("cname") else ""
        ports = f" [ports: {','.join(map(str, info.get('ports', [])))}]" if info.get("ports") else ""
        sources = f" ({','.join(info.get('sources', []))})"

        lines.append(f"{branch}[bold green]{host}[/bold green]{cnames} [{ips}]{ports}{sources}")

    return "\n".join(lines)
