"""Reflected and heuristic DOM XSS detection (detection only)."""

from __future__ import annotations

import html
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..core.auth_gate import require_authorized
from ..core.http_client import AsyncHTTPClient, RobotsDenied
from ..core.models import Finding
from ..core.utils import ensure_url, extract_title, probe_token, truncate
from ._common import (
    extract_between,
    is_html_response,
    parameter_values,
    raw_replace_query,
    response_text,
)

DOM_SINKS = (
    "innerhtml",
    "outerhtml",
    "document.write",
    "insertadjacenthtml",
    "eval(",
    "settimeout(",
    "setinterval(",
    "srcdoc",
)
DOM_SOURCES = ("location.hash", "location.search", "location.href", "document.url", "document.referrer", "window.name")


def _dom_indicators(script: str) -> list[str]:
    lowered = script.lower()
    found = []
    for source in DOM_SOURCES:
        source_index = lowered.find(source)
        if source_index < 0:
            continue
        for sink in DOM_SINKS:
            sink_index = lowered.find(sink, max(0, source_index - 600))
            if sink_index >= 0 and abs(sink_index - source_index) <= 1200:
                found.append(f"{source} -> {sink}")
                break
    return found


async def _static_dom_scan(
    client: AsyncHTTPClient,
    url: str,
    body: str,
    *,
    authorized: bool,
) -> list[Finding]:
    findings: list[Finding] = []
    try:
        soup = BeautifulSoup(body, "html.parser")
    except Exception:
        return findings
    scripts_inline = [script.get_text()[:500_000] for script in soup.find_all("script") if not script.get("src")]
    script_urls = []
    for script in soup.find_all("script", src=True):
        candidate = urljoin(url, str(script["src"]))
        if urlparse(candidate).hostname == urlparse(url).hostname and candidate not in script_urls:
            script_urls.append(candidate)
    for script_url in script_urls[:10]:
        try:
            response = await client.get(script_url, module="xss", timeout=20.0)
        except RobotsDenied:
            continue
        except Exception:
            continue
        if response.status_code == 200:
            scripts_inline.append(response.text[:1_000_000])
    for script in scripts_inline:
        for indicator in _dom_indicators(script)[:3]:
            findings.append(
                Finding(
                    type="dom_xss_indicator",
                    target=url,
                    module="xss",
                    url=url,
                    evidence=(
                        f"Static JavaScript heuristic matched {indicator}. "
                        "This is an indicator only; browser-driven validation is recommended."
                    ),
                    severity="low",
                    confidence="low",
                    metadata={"indicator": indicator, "note": "static analysis heuristic"},
                )
            )
    return findings


async def run(
    target: str,
    *,
    params: list[str] | str | None = None,
    check_dom: bool = False,
    aggressive: bool = False,
    authorized: bool = False,
    concurrency: int = 6,
) -> list[Finding]:
    """Inject marker payloads and detect unescaped reflection."""
    require_authorized(authorized, "xss", target)
    url = ensure_url(target)
    values = parameter_values(url, params)
    token = probe_token("RTXSS")
    payloads = [
        f"<script>alert('{token}')</script>",
        f"'><svg/onload=alert('{token}')>",
        f"'><img src=x onerror=alert('{token}')>",
    ]
    findings: list[Finding] = []
    encoded_reflections: dict[str, str] = {}

    async with AsyncHTTPClient(module="xss", aggressive=aggressive) as client:
        baseline_body = ""
        baseline_url = url
        try:
            baseline = await client.get(url, module="xss", timeout=20.0)
            baseline_body = response_text(baseline)
            baseline_url = str(baseline.url)
        except RobotsDenied:
            raise
        except Exception:
            pass

        for name, _baseline_value in values[:25]:
            vulnerable = False
            for payload in payloads:
                injected_url = raw_replace_query(url, name, payload)
                try:
                    response = await client.get(injected_url, module="xss", timeout=20.0)
                except RobotsDenied:
                    raise
                except Exception:
                    continue
                body = response_text(response)
                if not is_html_response(response.headers, body):
                    continue
                if payload in body:
                    findings.append(
                        Finding(
                            type="reflected_xss",
                            target=url,
                            module="xss",
                            url=str(response.url),
                            param=name,
                            evidence=(
                                f"Payload reflected verbatim in HTML for parameter '{name}'. "
                                f"Context: …{extract_between(body, payload, radius=100)}…"
                            ),
                            severity="high",
                            confidence="high",
                            metadata={
                                "payload": payload,
                                "status": response.status_code,
                                "context": truncate(extract_between(body, payload), 1500),
                            },
                        )
                    )
                    vulnerable = True
                    break
                if token in body:
                    escaped = html.escape(payload, quote=True)
                    escaped_no_quotes = html.escape(payload, quote=False)
                    if escaped in body or escaped_no_quotes in body:
                        encoded_reflections.setdefault(
                            name,
                            f"Marker for parameter '{name}' was reflected but the payload was HTML-encoded; "
                            "this is generally not executable XSS but warrants review.",
                        )
                    else:
                        encoded_reflections.setdefault(
                            name,
                            f"Marker for parameter '{name}' was present with altered encoding. "
                            "No verbatim payload reflection was confirmed.",
                        )
            if vulnerable:
                continue

        if check_dom:
            findings.extend(
                await _static_dom_scan(client, baseline_url, baseline_body, authorized=authorized)
            )

    for name, evidence in encoded_reflections.items():
        findings.append(
            Finding(
                type="input_reflection_encoded",
                target=url,
                module="xss",
                url=url,
                param=name,
                evidence=evidence,
                severity="info",
                confidence="medium",
                metadata={"encoded": True},
            )
        )
    return findings
