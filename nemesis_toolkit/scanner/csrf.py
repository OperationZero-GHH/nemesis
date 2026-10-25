"""CSRF protection checks for state-changing HTML forms."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..core.auth_gate import require_authorized
from ..core.http_client import AsyncHTTPClient
from ..core.models import Finding
from ..core.utils import ensure_url, same_origin

TOKEN_FIELD_RE = re.compile(
    r"(csrf|xsrf|authenticity|requestverification|anti[-_]?forgery|__requestverificationtoken|_token|nonce)",
    re.IGNORECASE,
)
USER_FACING_FIELDS = re.compile(r"(password|email|username|account|amount|role|admin|delete|update|profile)", re.I)


def _cookie_samesite(headers: object) -> tuple[set[str], bool]:
    values: list[str] = []
    try:
        values = headers.get_list("set-cookie")  # type: ignore[attr-defined]
    except Exception:
        pass
    modes: set[str] = set()
    for value in values:
        match = re.search(r"(?i)samesite\s*=\s*([^;]+)", value)
        if match:
            modes.add(match.group(1).strip().lower())
        else:
            modes.add("absent")
    return modes, bool(values)


async def run(
    target: str,
    *,
    aggressive: bool = False,
    authorized: bool = False,
) -> list[Finding]:
    """Flag POST/PUT/DELETE forms lacking an anti-CSRF token and SameSite cookies."""
    require_authorized(authorized, "csrf", target)
    url = ensure_url(target)
    async with AsyncHTTPClient(module="csrf", aggressive=aggressive) as client:
        response = await client.get(url, module="csrf", timeout=20.0)
    body = response.text[:2_000_000]
    try:
        soup = BeautifulSoup(body, "html.parser")
    except Exception:
        return []
    samesite_modes, had_set_cookie = _cookie_samesite(response.headers)
    strict_or_lax = bool(samesite_modes & {"strict", "lax"})
    meta_token = bool(
        soup.find(
            "meta",
            attrs={"name": re.compile(r"(csrf|xsrf|token)", re.IGNORECASE)},
        )
    )
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for form in soup.find_all("form"):
        method = str(form.get("method") or "GET").upper()
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            continue
        action_raw = str(form.get("action") or "").strip()
        action = urljoin(str(response.url), action_raw or str(response.url))
        if not same_origin(action, str(response.url)):
            continue
        fields: list[str] = []
        token_fields: list[str] = []
        for field in form.find_all(["input", "textarea", "select"]):
            name = str(field.get("name") or "").strip()
            if not name:
                continue
            fields.append(name)
            if TOKEN_FIELD_RE.search(name):
                token_fields.append(name)
            if str(field.get("type") or "").lower() == "hidden" and TOKEN_FIELD_RE.search(
                str(field.get("id") or "")
            ):
                token_fields.append(name)
        key = (action, method)
        if key in seen:
            continue
        seen.add(key)
        if token_fields or meta_token:
            continue
        # If all cookies observed on this response are SameSite=Lax/Strict,
        # cross-site POSTs should not carry them.
        if strict_or_lax:
            continue
        user_facing = any(USER_FACING_FIELDS.search(name) for name in fields) or bool(
            re.search(r"(delete|update|account|profile|password|email|admin|checkout|order)", action, re.I)
        )
        confidence = "medium"
        severity = "medium"
        if not had_set_cookie:
            confidence = "low"
            severity = "low"
        elif user_facing:
            confidence = "medium"
        evidence = (
            f"State-changing {method} form at {action} has no detected anti-CSRF token field. "
            f"Observed Set-Cookie attributes: "
            f"{', '.join(sorted(samesite_modes)) if samesite_modes else 'no cookies set on this response'}."
        )
        if not had_set_cookie:
            evidence += (
                " Session cookies may be set elsewhere; this is a low-confidence indicator and "
                "requires authenticated manual verification."
            )
        findings.append(
            Finding(
                type="csrf",
                target=url,
                module="csrf",
                url=action,
                evidence=evidence,
                severity=severity,
                confidence=confidence,
                metadata={
                    "method": method,
                    "fields": fields,
                    "token_fields": token_fields,
                    "meta_csrf_token": meta_token,
                    "samesite_modes": sorted(samesite_modes),
                    "set_cookie_observed": had_set_cookie,
                    "user_facing_form": user_facing,
                    "note": "CSRF exploitability requires an authenticated session; not tested.",
                },
            )
        )
    return findings
