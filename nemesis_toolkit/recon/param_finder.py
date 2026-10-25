"""Crawl a target and enumerate query/form parameters."""

from __future__ import annotations

from collections import deque
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from ..core.http_client import AsyncHTTPClient, RobotsDenied
from ..core.logging import get_logger
from ..core.models import Finding
from ..core.utils import (
    ensure_url,
    extract_title,
    query_param_names,
    same_host,
    unique_strings,
    url_join,
)

_SKIP_EXTENSIONS = (
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".rar",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".css",
    ".js",
    ".woff",
    ".woff2",
    ".ttf",
    ".mp4",
    ".mp3",
    ".avi",
)
_NON_INJECTABLE = {
    "csrf",
    "_csrf",
    "csrf_token",
    "_csrf_token",
    "xsrf",
    "_xsrf",
    "authenticity_token",
    "__requestverificationtoken",
    "_token",
    "submit",
    "button",
    "file",
    "upload",
}


def _is_page_url(url: str) -> bool:
    return not urlparse(url).path.lower().endswith(_SKIP_EXTENSIONS)


def _injectable(name: str) -> bool:
    lowered = name.lower()
    return lowered not in _NON_INJECTABLE and "csrf" not in lowered and "token" not in lowered


async def run(
    target: str,
    *,
    depth: int = 2,
    max_pages: int = 30,
    aggressive: bool = False,
    include_forms: bool = True,
) -> list[Finding]:
    """Return parameter discoveries grouped by URL and HTTP method."""
    start = ensure_url(target)
    origin_host = urlparse(start).hostname or ""
    queue: deque[tuple[str, int]] = deque([(start, 0)])
    visited: set[str] = set()
    findings: list[Finding] = []
    seen_keys: set[tuple[str, str]] = set()
    pages_read = 0

    async with AsyncHTTPClient(module="paramfind", aggressive=aggressive) as client:
        while queue and pages_read < max_pages:
            url, current_depth = queue.popleft()
            normalized = url.split("#", 1)[0]
            if normalized in visited or not _is_page_url(normalized):
                continue
            visited.add(normalized)
            try:
                response = await client.get(normalized, module="paramfind", timeout=20.0)
            except RobotsDenied:
                get_logger().warning("robots.txt skipped %s during parameter crawl", normalized)
                continue
            except Exception as exc:
                get_logger().warning("parameter crawl failed for %s: %s", normalized, type(exc).__name__)
                continue
            content_type = response.headers.get("content-type", "").lower()
            if content_type and "html" not in content_type and "text/" not in content_type:
                continue
            pages_read += 1
            final_url = str(response.url)
            if not same_host(final_url, start):
                continue
            body = response.text[:2_000_000]
            title = extract_title(body)
            try:
                soup = BeautifulSoup(body, "html.parser")
            except Exception:
                continue

            query_names = query_param_names(final_url)
            if query_names:
                key = (final_url, "GET")
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append(
                        Finding(
                            type="parameter",
                            target=start,
                            module="paramfind",
                            url=final_url,
                            param=", ".join(query_names),
                            evidence=f"GET query parameters: {', '.join(query_names)}"
                            + (f" — page title: {title}" if title else ""),
                            severity="info",
                            confidence="high",
                            metadata={
                                "method": "GET",
                                "parameters": query_names,
                                "source": "link",
                                "page_title": title,
                                "injectable": [name for name in query_names if _injectable(name)],
                            },
                        )
                    )

            if include_forms:
                for form in soup.find_all("form"):
                    action = str(form.get("action") or "").strip()
                    action_url = url_join(final_url, action) or final_url
                    if not same_host(action_url, start):
                        continue
                    method = str(form.get("method") or "GET").upper()
                    names: list[str] = []
                    for field in form.find_all(["input", "select", "textarea"]):
                        name = str(field.get("name") or "").strip()
                        if name and name not in names:
                            names.append(name)
                    if not names:
                        continue
                    key = (action_url, method)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    injectable = [name for name in names if _injectable(name)]
                    findings.append(
                        Finding(
                            type="parameter",
                            target=start,
                            module="paramfind",
                            url=action_url,
                            param=", ".join(names),
                            evidence=f"{method} form fields: {', '.join(names)} — action: {action_url}",
                            severity="info",
                            confidence="high",
                            metadata={
                                "method": method,
                                "parameters": names,
                                "source": "form",
                                "injectable": injectable,
                                "page_url": final_url,
                                "page_title": title,
                            },
                        )
                    )

            if current_depth >= depth:
                continue
            for anchor in soup.find_all("a", href=True):
                link = url_join(final_url, str(anchor["href"]))
                if not link or not same_host(link, start) or link in visited:
                    continue
                if not _is_page_url(link):
                    continue
                if len(visited) + len(queue) >= max_pages * 4:
                    break
                queue.append((link, current_depth + 1))

    # De-duplicate equivalent discoveries while preserving the richer form entry.
    deduped: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        key = (finding.url or "", str(finding.metadata.get("method", "GET")))
        existing = deduped.get(key)
        if existing is None or (
            existing.metadata.get("source") == "link" and finding.metadata.get("source") == "form"
        ):
            deduped[key] = finding
    return sorted(deduped.values(), key=lambda item: ((item.url or ""), str(item.metadata.get("method", ""))))
