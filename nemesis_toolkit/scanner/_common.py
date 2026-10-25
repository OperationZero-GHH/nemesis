"""Shared helpers for non-destructive scanner modules."""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from urllib.parse import quote, urlparse

from ..core.http_client import AsyncHTTPClient
from ..core.utils import query_pairs, response_text, truncate, unique_strings


def parameter_values(url: str, params: list[str] | str | None = None) -> list[tuple[str, str]]:
    """Return parameter names and baseline values to test."""
    pairs = query_pairs(url)
    selected: list[str] = []
    if isinstance(params, str):
        selected = [name.strip() for name in params.split(",") if name.strip()]
    elif params:
        selected = [str(name).strip() for name in params if str(name).strip()]
    if selected:
        values = {name: value for name, value in pairs}
        return [(name, values.get(name, "test")) for name in unique_strings(selected)]
    unique: dict[str, str] = {}
    for name, value in pairs:
        unique.setdefault(name, value)
    if not unique:
        raise ValueError(
            "No query parameters were found. Supply an injectable URL such as "
            "'https://example.com/page?id=1' or pass --params."
        )
    return list(unique.items())


def raw_replace_query(url: str, name: str, payload: str) -> str:
    """Replace a parameter value while preserving pre-encoded payload bytes.

    Characters in the payload are percent-encoded except for '%' so encoded
    traversal/SQL payloads (for example %2e%2e%2f) can be tested deliberately.
    Existing query values are re-encoded once.
    """
    parsed = urlparse(url)
    pairs = query_pairs(url)
    if not any(key == name for key, _ in pairs):
        pairs.append((name, "test"))
    pieces = []
    for key, value in pairs:
        encoded_key = quote(key, safe="")
        if key == name:
            encoded_value = quote(payload, safe="%")
        else:
            encoded_value = quote(value, safe="")
        pieces.append(f"{encoded_key}={encoded_value}")
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}" + (
        f"?{'&'.join(pieces)}" if pieces else ""
    )


def normalized_body(text: str, limit: int = 250_000) -> str:
    text = re.sub(r"\s+", " ", text[:limit]).strip().lower()
    return text


def body_similarity(left: str, right: str) -> float:
    left_norm = normalized_body(left)
    right_norm = normalized_body(right)
    if not left_norm and not right_norm:
        return 1.0
    return SequenceMatcher(None, left_norm, right_norm, autojunk=False).ratio()


def is_html_response(headers: object, body: str) -> bool:
    try:
        content_type = headers.get("content-type", "")  # type: ignore[attr-defined]
    except Exception:
        content_type = ""
    if content_type:
        return any(kind in content_type.lower() for kind in ("text/html", "application/xhtml"))
    return "<html" in body[:5000].lower()


def finding_evidence(body: str, needle: str, radius: int = 120) -> str:
    index = body.find(needle)
    if index < 0:
        return truncate(body, radius * 2)
    start = max(0, index - radius)
    end = min(len(body), index + len(needle) + radius)
    return truncate(body[start:end], radius * 4)


def extract_between(body: str, needle: str, radius: int = 150) -> str:
    return finding_evidence(body, needle, radius=radius)


async def fetch_text(
    client: AsyncHTTPClient,
    url: str,
    *,
    module: str,
    timeout: float = 20.0,
) -> tuple[str, int, str, int]:
    """Fetch a URL and return (body, status, final_url, elapsed_ms)."""
    import time

    started = time.perf_counter()
    response = await client.get(url, module=module, timeout=timeout)
    elapsed = (time.perf_counter() - started) * 1000
    return response_text(response), response.status_code, str(response.url), int(elapsed)


async def fetch_timed(
    client: AsyncHTTPClient,
    url: str,
    *,
    module: str,
    timeout: float = 30.0,
) -> tuple[object, int]:
    """Return an httpx response and elapsed milliseconds."""
    import time

    started = time.perf_counter()
    response = await client.get(url, module=module, timeout=timeout)
    return response, int((time.perf_counter() - started) * 1000)
