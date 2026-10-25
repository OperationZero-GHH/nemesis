"""Orchestrated, detection-only assessment pipeline."""

from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from ..core.auth_gate import require_authorized
from ..core.http_client import AsyncHTTPClient, RobotsDenied
from ..core.logging import audit_event, get_logger
from ..core.models import Finding
from ..core.utils import ensure_url, normalize_domain, unique_strings
from ..recon import nportscan, param_finder, subdomain, waf_check
from . import clickjacking, cmd_inject, csrf, path_traversal, sql_injection as sqli, xss
portscan = nportscan

WEB_PORTS = (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 10000)


def _url_for_port(host: str, port: int) -> str:
    if port in (443, 8443):
        return f"https://{host}/" if port == 443 else f"https://{host}:{port}/"
    if port == 80:
        return f"http://{host}/"
    return f"http://{host}:{port}/"


def _fallback_scheme(url: str) -> str:
    parsed = urlparse(url)
    scheme = "http" if parsed.scheme == "https" else "https"
    port = f":{parsed.port}" if parsed.port else ""
    return f"{scheme}://{parsed.hostname}{port}/"


async def _probe_bases(
    candidates: list[str],
    *,
    aggressive: bool,
    limit: int = 12,
) -> list[str]:
    working: list[str] = []
    seen: set[str] = set()
    async with AsyncHTTPClient(module="auto", aggressive=aggressive) as client:
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            try:
                response = await client.get(candidate, module="auto", timeout=12.0)
            except RobotsDenied:
                working.append(candidate)
                continue
            except Exception:
                alternate = _fallback_scheme(candidate)
                if alternate not in seen:
                    seen.add(alternate)
                    try:
                        response = await client.get(alternate, module="auto", timeout=12.0)
                        candidate = alternate
                    except Exception:
                        continue
            if response.status_code < 500:
                working.append(candidate)
            if len(working) >= limit:
                break
    return unique_strings(working)


async def _discover_ports(
    hosts: list[str],
    *,
    max_hosts: int,
    aggressive: bool,
) -> tuple[list[Finding], dict[str, list[int]]]:
    findings: list[Finding] = []
    open_by_host: dict[str, list[int]] = {}
    semaphore = asyncio.Semaphore(4)
    ports_spec = ",".join(str(port) for port in WEB_PORTS)

    async def scan(host: str) -> list[Finding]:
        async with semaphore:
            try:
                return await portscan.run(
                    host,
                    ports=ports_spec,
                    service_detect=False,
                    concurrency=200,
                    aggressive=aggressive,
                )
            except Exception as exc:
                get_logger().warning("auto portscan failed for %s: %s", host, exc)
                return []

    results = await asyncio.gather(*(scan(host) for host in hosts[:max_hosts]))
    for result in results:
        findings.extend(result)
        for finding in result:
            host = str(finding.metadata.get("host") or "")
            port = finding.metadata.get("port")
            if host and isinstance(port, int):
                open_by_host.setdefault(host, []).append(port)
    return findings, open_by_host


def _collect_scan_targets(parameter_findings: list[Finding], limit: int) -> list[tuple[str, list[str]]]:
    targets: list[tuple[str, list[str]]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()
    for finding in parameter_findings:
        if not finding.url:
            continue
        method = str(finding.metadata.get("method") or "GET").upper()
        if method != "GET":
            continue  # Detection modules only mutate query parameters.
        injectable = finding.metadata.get("injectable")
        if not isinstance(injectable, list) or not injectable:
            injectable = finding.metadata.get("parameters")
        if not isinstance(injectable, list):
            injectable = [name.strip() for name in (finding.param or "").split(",") if name.strip()]
        names = [str(name) for name in injectable if str(name).strip()]
        if not names:
            continue
        key = (finding.url, tuple(sorted(names)))
        if key in seen:
            continue
        seen.add(key)
        targets.append((finding.url, names))
        if len(targets) >= limit:
            break
    return targets


async def run(
    target: str,
    *,
    authorized: bool = False,
    max_hosts: int = 20,
    max_urls: int = 40,
    skip_portscan: bool = False,
    passive_only: bool = False,
    aggressive: bool = False,
    time_based: bool = True,
) -> list[Finding]:
    """Run subdomain discovery, portscan, WAF detection, parameter discovery,
    and every detection module. This never exploits a finding.

    All modules are imported and called directly; auto-scan contains no duplicate
    scanning logic.
    """
    require_authorized(authorized, "auto", target)
    domain = normalize_domain(target)
    aggregate: list[Finding] = []
    steps: list[str] = []
    waf_vendors: list[str] = []

    steps.append("subdomain")
    subdomains: list[Finding] = []
    try:
        subdomains = await subdomain.run(
            domain,
            passive_only=passive_only,
            resolve=True,
            concurrency=50,
            aggressive=aggressive,
        )
        aggregate.extend(subdomains)
    except Exception as exc:
        get_logger().warning("auto subdomain stage failed: %s", exc)
        aggregate.append(
            Finding(
                type="pipeline_stage_error",
                target=domain,
                module="auto",
                evidence=f"Subdomain stage failed: {type(exc).__name__}: {exc}",
                severity="info",
                confidence="high",
                metadata={"stage": "subdomain"},
            )
        )

    hosts = [domain]
    for finding in subdomains:
        host = str(finding.metadata.get("host") or "")
        if host and host not in hosts:
            hosts.append(host)
    hosts = hosts[:max_hosts]
    steps.append("portscan")
    open_by_host: dict[str, list[int]] = {}
    if not skip_portscan:
        port_findings, open_by_host = await _discover_ports(
            hosts,
            max_hosts=max_hosts,
            aggressive=aggressive,
        )
        aggregate.extend(port_findings)
    else:
        aggregate.append(
            Finding(
                type="pipeline_note",
                target=domain,
                module="auto",
                evidence="Port scan skipped by request; using root web endpoints only.",
                severity="info",
                confidence="high",
            )
        )

    candidates: list[str] = []
    for host in hosts:
        ports = open_by_host.get(host, [])
        for port in ports:
            candidates.append(_url_for_port(host, port))
        if not ports:
            candidates.extend([f"https://{host}/", f"http://{host}/"])
    candidates = unique_strings(candidates)[:24]
    steps.append("web-probe")
    bases = await _probe_bases(candidates, aggressive=aggressive, limit=8)
    if not bases:
        bases = [f"https://{domain}/"]
    aggregate.append(
        Finding(
            type="web_endpoints",
            target=domain,
            module="auto",
            evidence=f"Reachable web origins: {', '.join(bases)}",
            severity="info",
            confidence="high",
            metadata={"bases": bases},
        )
    )

    steps.append("waf")
    waf_suspected = False
    for base in bases[:3]:
        try:
            waf_results = await waf_check.run(base, aggressive=aggressive)
        except Exception as exc:
            get_logger().warning("auto WAF stage failed for %s: %s", base, exc)
            continue
        aggregate.extend(waf_results)
        for result in waf_results:
            if result.type in ("waf_detected", "waf_suspected"):
                waf_suspected = True
                if result.type == "waf_detected":
                    vendors = result.metadata.get("vendors")
                    if isinstance(vendors, list):
                        waf_vendors.extend(str(vendor) for vendor in vendors)
    if waf_suspected:
        # Slower is the only automatic adjustment. The toolkit deliberately does
        # not implement WAF-evasion or payload obfuscation.
        max_urls = min(max_urls, 20)
        audit_event("waf_pacing_adjusted", module="auto", target=domain, vendors=sorted(set(waf_vendors)))

    steps.append("paramfind")
    parameter_findings: list[Finding] = []
    for base in bases[:6]:
        try:
            results = await param_finder.run(
                base,
                depth=1,
                max_pages=8,
                aggressive=aggressive,
            )
            parameter_findings.extend(results)
            aggregate.extend(results)
        except Exception as exc:
            get_logger().warning("auto parameter stage failed for %s: %s", base, exc)
            aggregate.append(
                Finding(
                    type="pipeline_stage_error",
                    target=base,
                    module="auto",
                    evidence=f"Parameter discovery failed: {type(exc).__name__}: {exc}",
                    severity="info",
                    confidence="high",
                    metadata={"stage": "paramfind"},
                )
            )

    scan_targets = _collect_scan_targets(parameter_findings, max_urls)
    steps.append("scanners")
    scanner_calls = 0
    for page_url, params in scan_targets:
        for label, runner in (
            ("xss", xss.run),
            ("traversal", path_traversal.run),
            ("cmdi", cmd_inject.run),
            ("sqli", sqli.run),
        ):
            try:
                if label == "cmdi":
                    results = await runner(
                        page_url,
                        params=params,
                        aggressive=aggressive,
                        authorized=True,
                        time_based=time_based,
                    )
                else:
                    results = await runner(
                        page_url,
                        params=params,
                        aggressive=aggressive,
                        authorized=True,
                    )
                aggregate.extend(results)
                scanner_calls += 1
            except RobotsDenied:
                continue
            except Exception as exc:
                get_logger().warning("auto %s failed on %s: %s", label, page_url, exc)
                aggregate.append(
                    Finding(
                        type="pipeline_scanner_error",
                        target=page_url,
                        module="auto",
                        url=page_url,
                        evidence=f"{label} failed: {type(exc).__name__}: {exc}",
                        severity="info",
                        confidence="high",
                        metadata={"scanner": label, "stage": "scanners"},
                    )
                )

    steps.append("clickjacking-csrf")
    for base in bases:
        for label, runner in (("clickjack", clickjacking.run), ("csrf", csrf.run)):
            try:
                results = await runner(
                    base,
                    aggressive=aggressive,
                    authorized=True,
                )
                aggregate.extend(results)
            except RobotsDenied:
                continue
            except Exception as exc:
                get_logger().warning("auto %s failed on %s: %s", label, base, exc)

    steps.append("summary")
    severity_counts = {}
    for finding in aggregate:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
    aggregate.append(
        Finding(
            type="auto_scan_summary",
            target=domain,
            module="auto",
            evidence=(
                f"Pipeline completed. {len(hosts)} host(s), {len(bases)} web origin(s), "
                f"{len(scan_targets)} parameterized endpoint(s), {scanner_calls} scanner call(s), "
                f"{len(aggregate)} finding(s)."
            ),
            severity="info",
            confidence="high",
            metadata={
                "steps": steps,
                "hosts": hosts,
                "bases": bases,
                "scan_targets": [{"url": url, "params": params} for url, params in scan_targets],
                "scanner_calls": scanner_calls,
                "waf_detected": waf_suspected,
                "waf_vendors": sorted(set(waf_vendors)),
                "severity_counts": severity_counts,
                "detection_only": True,
            },
        )
    )
    return aggregate
