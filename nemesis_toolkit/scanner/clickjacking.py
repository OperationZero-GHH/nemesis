"""Clickjacking header checks with local-only PoC generation."""

from __future__ import annotations

import html
from pathlib import Path

from ..core.auth_gate import require_authorized
from ..core.http_client import AsyncHTTPClient
from ..core.models import Finding
from ..core.utils import ensure_url


def _csp_frame_ancestors(csp_values: list[str]) -> list[str]:
    values: list[str] = []
    for header in csp_values:
        for directive in header.split(";"):
            directive = directive.strip()
            if directive.lower().startswith("frame-ancestors"):
                rest = directive[len("frame-ancestors") :].strip()
                values.extend(token.strip() for token in rest.split() if token.strip())
    return values


def _make_poc(path: Path, target: str) -> Path:
    output = Path(path).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    escaped = html.escape(target, quote=True)
    output.write_text(
        "<!doctype html>\n"
        "<html><head><meta charset='utf-8'><title>Clickjacking test (local PoC)</title>\n"
        "<style>body{font-family:sans-serif;background:#111;color:#eee}"
        "iframe{width:100%;height:85vh;border:2px solid #e33;background:#fff}</style></head>\n"
        "<body><h1>Clickjacking framing test</h1>\n"
        "<p>This file is local only. It frames an authorized target for manual verification; "
        "do not host or distribute it.</p>\n"
        f"<iframe src='{escaped}' referrerpolicy='no-referrer'></iframe>\n"
        "</body></html>\n",
        encoding="utf-8",
    )
    return output


async def run(
    target: str,
    *,
    poc: Path | str | None = None,
    aggressive: bool = False,
    authorized: bool = False,
) -> list[Finding]:
    """Flag responses that can be framed by a third-party origin."""
    require_authorized(authorized, "clickjack", target)
    url = ensure_url(target)
    async with AsyncHTTPClient(module="clickjack", aggressive=aggressive) as client:
        response = await client.get(url, module="clickjack", timeout=20.0)
    headers = response.headers
    xfo_values = headers.get_list("x-frame-options")
    csp_values = headers.get_list("content-security-policy")
    xfo_tokens = [value.strip().lower() for value in xfo_values]
    valid_xfo = any(token in ("deny", "sameorigin") for token in xfo_tokens)
    frame_ancestors = _csp_frame_ancestors(csp_values)
    csp_protected = bool(frame_ancestors) and "*" not in frame_ancestors
    protections = []
    if valid_xfo:
        protections.append("X-Frame-Options=" + ", ".join(xfo_values))
    if csp_protected:
        protections.append("CSP frame-ancestors=" + " ".join(frame_ancestors))
    if protections:
        return []

    findings: list[Finding] = []
    metadata = {
        "x_frame_options": xfo_values,
        "csp": csp_values,
        "frame_ancestors": frame_ancestors,
        "status": response.status_code,
    }
    if xfo_tokens and not valid_xfo:
        evidence = (
            f"X-Frame-Options is present but does not use DENY or SAMEORIGIN "
            f"({', '.join(xfo_values)}), and no restrictive CSP frame-ancestors directive was found."
        )
        confidence = "medium"
    else:
        evidence = (
            "Neither X-Frame-Options (DENY/SAMEORIGIN) nor a restrictive CSP "
            "frame-ancestors directive was returned; the page may be embeddable."
        )
        confidence = "high"
    finding = Finding(
        type="clickjacking",
        target=url,
        module="clickjack",
        url=url,
        evidence=evidence
        + (" No anti-framing CSP directive was present." if not frame_ancestors else ""),
        severity="medium",
        confidence=confidence,
        metadata=metadata,
    )
    if poc:
        try:
            poc_path = _make_poc(Path(poc), url)
            finding.metadata["poc_file"] = str(poc_path)
            finding.evidence += f" Local PoC written to {poc_path} (not hosted)."
        except OSError as exc:
            finding.metadata["poc_error"] = str(exc)
    findings.append(finding)
    return findings
