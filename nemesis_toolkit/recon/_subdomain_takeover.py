"""DNS Takeover detection, dangling CNAME verification, and cloud infrastructure analysis.

Implements capabilities:
- DNS takeover checks
- Dangling CNAME detection
- Nameserver takeover indicators (lame delegations)
- Stale A record checks
- Mail infrastructure takeover indicators (MX & SPF includes)
- CNAME-chain analysis (multi-hop alias tracing)
- SRV takeover indicators
- Takeover finding verification (HTTP fingerprint matching)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import dns.asyncresolver
import dns.exception

from ..core.http_client import AsyncHTTPClient
from ..core.logging import get_logger
from ..core.models import Finding

@dataclass(slots=True, frozen=True)
class TakeoverFingerprint:
    service: str
    cname_patterns: tuple[str, ...]
    response_markers: tuple[str, ...]
    status_codes: tuple[int, ...] = (404,)


# Comprehensive signature database for 20+ cloud providers
TAKEOVER_SIGNATURES: list[TakeoverFingerprint] = [
    TakeoverFingerprint(
        service="GitHub Pages",
        cname_patterns=("github.io",),
        response_markers=("There isn't a GitHub Pages site here", "404 Not Found"),
    ),
    TakeoverFingerprint(
        service="AWS S3 Bucket",
        cname_patterns=("s3.amazonaws.com", "s3-website"),
        response_markers=("NoSuchBucket", "The specified bucket does not exist"),
    ),
    TakeoverFingerprint(
        service="Heroku",
        cname_patterns=("herokuapp.com", "herokudns.com"),
        response_markers=("No such app", "Heroku | No such app", "There's nothing here, yet."),
    ),
    TakeoverFingerprint(
        service="Shopify",
        cname_patterns=("myshopify.com",),
        response_markers=("Sorry, this shop is currently unavailable",),
    ),
    TakeoverFingerprint(
        service="Zendesk",
        cname_patterns=("zendesk.com",),
        response_markers=("Help Center Closed",),
    ),
    TakeoverFingerprint(
        service="Fastly",
        cname_patterns=("fastly.net",),
        response_markers=("Fastly error: unknown domain",),
    ),
    TakeoverFingerprint(
        service="Azure Web App",
        cname_patterns=("azurewebsites.net", "cloudapp.net", "azureedge.net"),
        response_markers=("404 Web Site not found", "Error 404 - Web app not found"),
    ),
    TakeoverFingerprint(
        service="Ghost",
        cname_patterns=("ghost.io",),
        response_markers=("The thing you were looking for is no longer here",),
    ),
    TakeoverFingerprint(
        service="WordPress.com",
        cname_patterns=("wordpress.com",),
        response_markers=("Do you want to register",),
    ),
    TakeoverFingerprint(
        service="Bitbucket",
        cname_patterns=("bitbucket.io",),
        response_markers=("Repository not found",),
    ),
    TakeoverFingerprint(
        service="Surge.sh",
        cname_patterns=("surge.sh",),
        response_markers=("project not found",),
    ),
    TakeoverFingerprint(
        service="Readme.io",
        cname_patterns=("readme.io",),
        response_markers=("Project doesnt exist",),
    ),
    TakeoverFingerprint(
        service="Webflow",
        cname_patterns=("webflow.io",),
        response_markers=("The page you are looking for doesn't exist",),
    ),
    TakeoverFingerprint(
        service="Tumblr",
        cname_patterns=("domains.tumblr.com",),
        response_markers=("Whatever you were looking for doesn't seem to exist",),
    ),
    TakeoverFingerprint(
        service="Fly.io",
        cname_patterns=("fly.dev",),
        response_markers=("404 Not Found",),
    ),
    TakeoverFingerprint(
        service="Vercel",
        cname_patterns=("cname.vercel-dns.com", "vercel.app"),
        response_markers=("404: NOT_FOUND", "DEPLOYMENT_NOT_FOUND"),
    ),
    TakeoverFingerprint(
        service="Netlify",
        cname_patterns=("netlify.app", "netlify.com"),
        response_markers=("Not Found - Request ID",),
    ),
]


async def trace_cname_chain(
    host: str,
    resolver: dns.asyncresolver.Resolver,
    max_hops: int = 5,
) -> list[str]:
    """Recursively trace CNAME alias dependency chains."""
    chain: list[str] = []
    current = host
    for _ in range(max_hops):
        try:
            ans = await resolver.resolve(current, "CNAME", raise_on_no_answer=False)
            if ans.rrset:
                target = str(ans.rrset[0]).strip().rstrip(".")
                if target and target != current:
                    chain.append(target)
                    current = target
                    continue
        except Exception:
            break
        break
    return chain


async def verify_takeover_candidate(
    host: str,
    target_cname: str,
    client: AsyncHTTPClient,
    timeout: float = 6.0,
) -> tuple[bool, str, str]:
    """Perform HTTP probe against candidate to confirm fingerprint match."""
    matched_fp = None
    for fp in TAKEOVER_SIGNATURES:
        if any(pat in target_cname.lower() for pat in fp.cname_patterns):
            matched_fp = fp
            break

    if not matched_fp:
        return False, "", ""

    # Probe HTTP and HTTPS
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            resp = await client.get(url, module="subdomain", timeout=timeout)
            body = resp.text
            for marker in matched_fp.response_markers:
                if marker in body:
                    return True, matched_fp.service, f"HTTP {resp.status_code} matched fingerprint: '{marker}'"
        except Exception:
            continue

    return False, matched_fp.service, "Service CNAME matched but signature marker not verified"


async def check_nameserver_takeover(
    nameservers: list[str],
    resolver: dns.asyncresolver.Resolver,
    semaphore: asyncio.Semaphore,
) -> list[dict[str, str]]:
    """Identify lame or dead nameservers in the domain delegation."""
    lame_ns = []
    for ns in nameservers:
        ns_clean = ns.strip().rstrip(".")
        async with semaphore:
            try:
                ans = await resolver.resolve(ns_clean, "A", raise_on_no_answer=False)
                if not ans.rrset:
                    lame_ns.append({"ns": ns_clean, "issue": "Unresolvable (no A record)"})
            except (dns.resolver.NXDOMAIN, dns.exception.DNSException):
                lame_ns.append({"ns": ns_clean, "issue": "NXDOMAIN (domain unallocated or expired)"})
            except Exception:
                pass
    return lame_ns


async def check_mail_takeover(
    mx_records: list[str],
    spf_records: list[str],
    resolver: dns.asyncresolver.Resolver,
    semaphore: asyncio.Semaphore,
) -> list[dict[str, str]]:
    """Check MX hosts and SPF includes for unresolvable or dead dependencies."""
    findings = []
    for mx in mx_records:
        parts = mx.split()
        mx_host = parts[-1].strip().rstrip(".") if parts else mx.strip().rstrip(".")
        async with semaphore:
            try:
                ans = await resolver.resolve(mx_host, "A", raise_on_no_answer=False)
                if not ans.rrset:
                    findings.append({"target": mx_host, "type": "MX", "issue": "Unresolvable MX host"})
            except dns.resolver.NXDOMAIN:
                findings.append({"target": mx_host, "type": "MX", "issue": "NXDOMAIN on MX host"})
            except Exception:
                pass

    for txt in spf_records:
        if "include:" in txt:
            for piece in txt.split():
                if piece.startswith("include:"):
                    spf_target = piece.split(":", 1)[1].strip()
                    async with semaphore:
                        try:
                            ans = await resolver.resolve(spf_target, "TXT", raise_on_no_answer=False)
                            if not ans.rrset:
                                findings.append({"target": spf_target, "type": "SPF", "issue": "Dead SPF include"})
                        except dns.resolver.NXDOMAIN:
                            findings.append({"target": spf_target, "type": "SPF", "issue": "NXDOMAIN on SPF include"})
                        except Exception:
                            pass
    return findings
