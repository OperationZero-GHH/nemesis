"""Shared concurrent endpoint probing for login and registration discovery."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from ..core.http_client import AsyncHTTPClient, RobotsDenied
from ..core.models import Finding
from ..core.utils import ensure_url, extract_title, origin_of


@dataclass(slots=True)
class EndpointHit:
    path: str
    url: str
    final_url: str
    status: int
    title: str
    password_fields: int
    form_actions: list[str]
    redirects: list[str]


def _inspect_html(body: str) -> tuple[int, list[str]]:
    try:
        soup = BeautifulSoup(body, "html.parser")
    except Exception:
        return 0, []
    password_fields = len(soup.select('input[type="password"]'))
    actions = []
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        if action and action not in actions:
            actions.append(action)
    return password_fields, actions[:10]


async def probe_paths(
    base_url: str,
    paths: list[str],
    *,
    module: str,
    kind: str,
    aggressive: bool = False,
    concurrency: int = 10,
) -> list[Finding]:
    base = ensure_url(base_url)
    origin = origin_of(base)
    unique_paths = []
    seen: set[str] = set()
    for path in paths:
        path = "/" + path.strip().lstrip("/")
        if path not in seen:
            seen.add(path)
            unique_paths.append(path)

    semaphore = asyncio.Semaphore(max(1, concurrency))
    root_signature: str | None = None

    async with AsyncHTTPClient(module=module, aggressive=aggressive) as client:
        try:
            root = await client.get(origin + "/", module=module, timeout=20.0)
            if root.status_code == 200:
                text = root.text
                root_signature = f"{len(text)}:{extract_title(text)}"
        except (RobotsDenied, Exception):
            root_signature = None

        async def probe(path: str) -> EndpointHit | None:
            url = origin + path
            async with semaphore:
                try:
                    response = await client.get(url, module=module, timeout=20.0)
                except RobotsDenied:
                    return None
                except Exception:
                    return None
            if response.status_code >= 500 or response.status_code == 404:
                return None
            if response.status_code >= 400 and response.status_code not in (401, 403, 405):
                return None
            body = response.text[:1_500_000]
            title = extract_title(body)
            password_fields, actions = _inspect_html(body)
            final_url = str(response.url)
            if (
                root_signature
                and response.status_code == 200
                and urlparse(final_url).path.rstrip("/") != urlparse(origin + "/").path.rstrip("/")
                and f"{len(body)}:{title}" == root_signature
                and not password_fields
            ):
                # A single-page app returning the same shell for every path.
                return None
            redirects = [
                f"{item.status_code} -> {item.headers.get('location', '')}"
                for item in getattr(response, "history", [])
            ]
            return EndpointHit(
                path=path,
                url=url,
                final_url=final_url,
                status=response.status_code,
                title=title,
                password_fields=password_fields,
                form_actions=actions,
                redirects=redirects,
            )

        hits = await asyncio.gather(*(probe(path) for path in unique_paths))
        findings: list[Finding] = []
        for hit in hits:
            if hit is None:
                continue
            likely = bool(hit.password_fields)
            if kind == "login":
                if not likely and not any(
                    token in (hit.title + " " + hit.final_url).lower()
                    for token in ("login", "sign in", "signin", "admin", "auth")
                ):
                    continue
            else:
                if not likely and not any(
                    token in (hit.title + " " + hit.final_url).lower()
                    for token in ("register", "sign up", "signup", "create account", "join")
                ):
                    continue
            evidence_parts = [
                f"HTTP {hit.status}",
                f"title={hit.title or '(none)'}",
                f"password_fields={hit.password_fields}",
            ]
            if hit.redirects:
                evidence_parts.append("redirects: " + "; ".join(hit.redirects[:4]))
            if hit.final_url != hit.url:
                evidence_parts.append(f"final={hit.final_url}")
            confidence = "high" if likely else "medium"
            if hit.status in (401, 403):
                confidence = "medium" if likely else "low"
            findings.append(
                Finding(
                    type="login_endpoint" if kind == "login" else "registration_endpoint",
                    target=base,
                    module=module,
                    url=hit.final_url,
                    evidence=" — ".join(evidence_parts),
                    severity="info",
                    confidence=confidence,
                    metadata={
                        "path": hit.path,
                        "status": hit.status,
                        "title": hit.title,
                        "password_fields": hit.password_fields,
                        "form_actions": hit.form_actions,
                        "redirects": hit.redirects,
                    },
                )
            )
        findings.sort(key=lambda finding: str(finding.metadata.get("path", "")))
        return findings
