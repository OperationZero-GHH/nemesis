"""Comprehensive DNS record inspection, zone transfer, and DNSSEC walking.

Implements capabilities:
- A, AAAA record retrieval
- CNAME alias chain resolution
- NS authoritative name server discovery
- SOA zone metadata inspection
- MX mail exchanger record retrieval
- TXT and SPF/DMARC inspection
- CAA certificate authority authorization checks
- SRV service-record enumeration
- PTR reverse DNS lookup
- AXFR DNS zone-transfer check
- DNS cache snooping check
- DNSSEC zone walking via NSEC
- TLD expansion checks
- Custom resolver selection
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

from ..core.logging import get_logger
from ..core.models import Finding

DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"]

COMMON_SRV_PREFIXES = [
    "_sip._tcp",
    "_sip._udp",
    "_sips._tcp",
    "_xmpp-server._tcp",
    "_xmpp-client._tcp",
    "_autodiscover._tcp",
    "_ldap._tcp",
    "_kerberos._tcp",
    "_kpasswd._tcp",
    "_caldav._tcp",
    "_carddav._tcp",
]

COMMON_TLDS = [".com", ".net", ".org", ".io", ".co", ".dev", ".ai", ".app", ".security"]


def create_resolver(
    custom_resolvers: list[str] | str | None = None,
    timeout: float = 2.0,
    lifetime: float = 4.0,
) -> dns.asyncresolver.Resolver:
    """Create a configured async DNS resolver with fast public fallbacks."""
    resolver = dns.asyncresolver.Resolver(configure=False)
    if isinstance(custom_resolvers, str):
        resolvers = [r.strip() for r in custom_resolvers.split(",") if r.strip()]
    elif custom_resolvers:
        resolvers = [str(r).strip() for r in custom_resolvers if str(r).strip()]
    else:
        resolvers = list(DEFAULT_RESOLVERS)
    resolver.nameservers = resolvers or list(DEFAULT_RESOLVERS)
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    return resolver


async def query_records(
    resolver: dns.asyncresolver.Resolver,
    host: str,
    record_type: str,
    semaphore: asyncio.Semaphore | None = None,
) -> list[str]:
    """Query a specific DNS record type asynchronously."""
    sem = semaphore or asyncio.Semaphore(50)
    results: list[str] = []
    async with sem:
        try:
            answer = await resolver.resolve(host, record_type, raise_on_no_answer=False)
            if answer.rrset is not None:
                for item in answer.rrset:
                    text = str(item).strip().strip('"')
                    if text:
                        results.append(text)
        except (dns.exception.DNSException, asyncio.TimeoutError, OSError):
            pass
    return sorted(set(results))


async def inspect_full_dns(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
    semaphore: asyncio.Semaphore,
) -> dict[str, Any]:
    """Gather comprehensive DNS zone records for the apex domain."""
    dns_data: dict[str, Any] = {}

    # Parallel query for apex records
    record_types = ["A", "AAAA", "CNAME", "NS", "SOA", "MX", "TXT", "CAA"]
    tasks = [query_records(resolver, domain, rtype, semaphore) for rtype in record_types]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for rtype, res in zip(record_types, results):
        dns_data[rtype] = res if isinstance(res, list) else []

    # Parse SOA metadata
    soa_list = dns_data.get("SOA", [])
    if soa_list:
        soa_parts = soa_list[0].split()
        if len(soa_parts) >= 7:
            dns_data["SOA_PARSED"] = {
                "primary_ns": soa_parts[0],
                "admin_email": soa_parts[1].replace(".", "@", 1),
                "serial": soa_parts[2],
                "refresh": soa_parts[3],
                "retry": soa_parts[4],
                "expire": soa_parts[5],
                "minimum_ttl": soa_parts[6],
            }

    # Query SRV records in parallel
    async def probe_srv(prefix: str) -> tuple[str, list[str]]:
        srv_name = f"{prefix}.{domain}"
        srv_records = await query_records(resolver, srv_name, "SRV", semaphore)
        return srv_name, srv_records

    srv_results = await asyncio.gather(
        *(probe_srv(prefix) for prefix in COMMON_SRV_PREFIXES),
        return_exceptions=True,
    )
    srv_dict: dict[str, list[str]] = {}
    for item in srv_results:
        if isinstance(item, tuple) and item[1]:
            srv_dict[item[0]] = item[1]
    dns_data["SRV"] = srv_dict

    return dns_data


async def check_zone_transfer(
    domain: str,
    nameservers: list[str],
    timeout: float = 4.0,
) -> list[str]:
    """Test whether any authoritative nameservers allow an AXFR zone transfer."""
    exposed_records: list[str] = []
    loop = asyncio.get_running_loop()

    def _sync_axfr(ns_ip: str) -> list[str]:
        records: list[str] = []
        try:
            xfr = dns.query.xfr(ns_ip, domain, timeout=timeout, lifetime=timeout)
            z = dns.zone.from_xfr(xfr)
            for name, node in z.nodes.items():
                r_name = str(name)
                full = domain if r_name in ("@", "") else f"{r_name}.{domain}"
                records.append(full)
        except Exception:
            pass
        return records

    for ns in nameservers:
        ns_clean = ns.rstrip(".")
        try:
            # Resolve NS IP address
            addr_info = socket.getaddrinfo(ns_clean, 53, socket.AF_INET, socket.SOCK_STREAM)
            if not addr_info:
                continue
            ns_ip = addr_info[0][4][0]
            zone_records = await loop.run_in_executor(None, _sync_axfr, ns_ip)
            if zone_records:
                exposed_records.extend(zone_records)
        except Exception:
            continue

    return sorted(set(exposed_records))


async def check_dnssec_walking(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
) -> list[str]:
    """Inspect NSEC records to detect whether DNSSEC zone walking is possible."""
    discovered: list[str] = []
    try:
        query = dns.message.make_query(domain, dns.rdatatype.NSEC, want_dnssec=True)
        # Use first configured resolver
        ns = resolver.nameservers[0] if resolver.nameservers else "1.1.1.1"
        loop = asyncio.get_running_loop()
        response = await loop.run_in_executor(None, lambda: dns.query.udp(query, ns, timeout=3.0))
        for rrset in response.authority:
            if rrset.rdtype == dns.rdatatype.NSEC:
                for item in rrset:
                    next_domain = str(getattr(item, "next", "")).strip().rstrip(".")
                    if next_domain and next_domain.endswith(f".{domain}") and next_domain != domain:
                        discovered.append(next_domain)
    except Exception:
        pass
    return sorted(set(discovered))


async def reverse_dns_lookup(
    ips: list[str],
    semaphore: asyncio.Semaphore,
) -> dict[str, list[str]]:
    """Perform reverse PTR lookups for a list of IP addresses."""
    loop = asyncio.get_running_loop()
    mapping: dict[str, list[str]] = {}

    async def _lookup_ptr(ip: str) -> tuple[str, list[str]]:
        async with semaphore:
            try:
                name, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
                return ip, [name.lower()]
            except (socket.herror, OSError, Exception):
                return ip, []

    results = await asyncio.gather(*(_lookup_ptr(ip) for ip in set(ips)), return_exceptions=True)
    for res in results:
        if isinstance(res, tuple) and res[1]:
            mapping[res[0]] = res[1]
    return mapping


async def check_tld_expansion(
    base_name: str,
    resolver: dns.asyncresolver.Resolver,
    semaphore: asyncio.Semaphore,
) -> list[str]:
    """Test alternative TLD variations of a root domain."""
    name_root = base_name.split(".")[0]
    tld_candidates = [f"{name_root}{tld}" for tld in COMMON_TLDS if not base_name.endswith(tld)]

    async def _probe_tld(candidate: str) -> str | None:
        async with semaphore:
            try:
                ans = await resolver.resolve(candidate, "A", raise_on_no_answer=False)
                if ans.rrset:
                    return candidate
            except Exception:
                pass
        return None

    results = await asyncio.gather(*(_probe_tld(c) for c in tld_candidates), return_exceptions=True)
    return [r for r in results if isinstance(r, str) and r]
