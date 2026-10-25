"""Optional search-engine providers.

Google's ordinary HTML results are intentionally not scraped. Users must supply
either a SerpAPI key or Google Programmable Search Engine credentials.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import Settings, get_settings
from .http_client import AsyncHTTPClient
from .logging import get_logger


@dataclass(slots=True)
class SearchResult:
    title: str
    url: str
    snippet: str
    source: str

    def to_dict(self) -> dict[str, str]:
        return {
            "title": self.title,
            "url": self.url,
            "snippet": self.snippet,
            "source": self.source,
        }


def search_configured(settings: Settings | None = None) -> bool:
    settings = settings or get_settings()
    return bool(
        settings.api_key("serpapi_key")
        or (settings.api_key("google_cse_api_key") and settings.api_key("google_cse_cx"))
    )


def search_configuration_help() -> str:
    return (
        "Search requires SerpAPI (serpapi_key) or Google Custom Search "
        "(google_cse_api_key + google_cse_cx) in ~/.toolconfig.yaml. "
        "Direct Google scraping is intentionally unsupported."
    )


async def web_search(
    query: str,
    client: AsyncHTTPClient,
    *,
    max_results: int = 10,
    settings: Settings | None = None,
) -> tuple[list[SearchResult], str | None]:
    """Run a search through the configured provider.

    Returns results and an optional human-readable error/configuration message.
    Missing credentials are not an exception.
    """
    settings = settings or get_settings()
    if not search_configured(settings):
        return [], search_configuration_help()

    serp_key = settings.api_key("serpapi_key")
    if serp_key:
        try:
            response = await client.get(
                "https://serpapi.com/search.json",
                module="search",
                params={
                    "engine": "google",
                    "q": query,
                    "num": min(max(max_results, 1), 20),
                    "api_key": serp_key,
                },
                timeout=30.0,
            )
        except Exception as exc:
            get_logger().warning("SerpAPI request failed: %s", exc)
            return [], f"SerpAPI request failed: {exc}"
        if response.status_code in (401, 403):
            return [], "SerpAPI rejected the configured API key."
        if response.status_code == 429:
            return [], "SerpAPI rate limit reached."
        if response.status_code != 200:
            return [], f"SerpAPI returned HTTP {response.status_code}."
        try:
            payload: dict[str, Any] = response.json()
        except ValueError:
            return [], "SerpAPI returned invalid JSON."
        results = []
        for item in (payload.get("organic_results") or [])[:max_results]:
            url = (item.get("link") or "").strip()
            if not url:
                continue
            results.append(
                SearchResult(
                    title=(item.get("title") or "").strip(),
                    url=url,
                    snippet=(item.get("snippet") or "").strip(),
                    source="serpapi",
                )
            )
        return results, None

    google_key = settings.api_key("google_cse_api_key")
    google_cx = settings.api_key("google_cse_cx")
    if google_key and google_cx:
        try:
            response = await client.get(
                "https://www.googleapis.com/customsearch/v1",
                module="search",
                params={
                    "key": google_key,
                    "cx": google_cx,
                    "q": query,
                    "num": min(max(max_results, 1), 10),
                },
                timeout=30.0,
            )
        except Exception as exc:
            get_logger().warning("Google CSE request failed: %s", exc)
            return [], f"Google CSE request failed: {exc}"
        if response.status_code in (401, 403):
            return [], "Google CSE rejected the configured API key."
        if response.status_code == 429:
            return [], "Google CSE rate limit reached."
        if response.status_code != 200:
            return [], f"Google CSE returned HTTP {response.status_code}."
        try:
            payload = response.json()
        except ValueError:
            return [], "Google CSE returned invalid JSON."
        results = []
        for item in (payload.get("items") or [])[:max_results]:
            url = (item.get("link") or "").strip()
            if not url:
                continue
            results.append(
                SearchResult(
                    title=(item.get("title") or "").strip(),
                    url=url,
                    snippet=(item.get("snippet") or "").strip(),
                    source="google_cse",
                )
            )
        return results, None

    return [], search_configuration_help()
