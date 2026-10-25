"""Optional HaveIBeenPwned breach lookups."""

from __future__ import annotations

import asyncio
from typing import Any

from .config import Settings, get_settings
from .http_client import AsyncHTTPClient
from .logging import get_logger

_hibp_lock = asyncio.Lock()
_last_request: float = 0.0


def hibp_configured(settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    return bool(settings.api_key("hibp_api_key"))


async def hibp_breaches(
    email: str,
    client: AsyncHTTPClient,
    *,
    settings: Settings | None = None,
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Return public breach metadata for an email.

    ``(None, message)`` indicates a configuration/API problem. ``([], None)``
    means the address was not found in any configured breach response.
    """
    global _last_request
    settings = settings or get_settings()
    key = settings.api_key("hibp_api_key")
    if not key:
        return None, (
            "HaveIBeenPwned checks require a hibp_api_key in ~/.toolconfig.yaml "
            "(paid API key from haveibeenpwned.com/API/Key)."
        )

    # Be gentle with HIBP's rate limit even when other modules are faster.
    async with _hibp_lock:
        loop = asyncio.get_running_loop()
        wait = max(0.0, 1.6 - (loop.time() - _last_request))
        if wait:
            await asyncio.sleep(wait)
        try:
            response = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                module="hibp",
                params={"truncateResponse": "true"},
                headers={
                    "hibp-api-key": key,
                    "User-Agent": "nemesis-hibp-client",
                },
                timeout=20.0,
            )
        finally:
            _last_request = loop.time()
    if response.status_code == 404:
        return [], None
    if response.status_code == 401:
        return None, "HaveIBeenPwned rejected the configured API key."
    if response.status_code == 429:
        retry = response.headers.get("retry-after", "a short while")
        return None, f"HaveIBeenPwned rate limit reached (retry after {retry})."
    if response.status_code != 200:
        return None, f"HaveIBeenPwned returned HTTP {response.status_code}."
    try:
        payload = response.json()
    except ValueError:
        return None, "HaveIBeenPwned returned invalid JSON."
    if not isinstance(payload, list):
        return None, "HaveIBeenPwned returned an unexpected response."
    results: list[dict[str, Any]] = []
    for item in payload:
        if isinstance(item, dict):
            results.append(
                {
                    "name": item.get("Name") or item.get("Title") or "unknown",
                    "domain": item.get("Domain"),
                    "breach_date": item.get("BreachDate"),
                    "data_classes": item.get("DataClasses", []),
                    "is_verified": item.get("IsVerified"),
                }
            )
        elif isinstance(item, str):
            results.append({"name": item})
    get_logger().info("HIBP lookup for %s found %d breach records", email, len(results))
    return results, None
