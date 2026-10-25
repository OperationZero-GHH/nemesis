"""Public email discovery and optional breach exposure checks."""

from __future__ import annotations

from collections import defaultdict
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from ..core.apis import hibp_breaches, hibp_configured
from ..core.http_client import AsyncHTTPClient, RobotsDenied
from ..core.logging import get_logger
from ..core.models import Finding
from ..core.search import search_configured, search_configuration_help, web_search
from ..core.utils import ensure_url, extract_emails, host_of, origin_of, same_host, unique_strings, url_join

PRIORITY_HINTS = ("contact", "about", "team", "support", "impressum", "legal", "security", "privacy")


def _same_site_urls(body: str, page_url: str, limit: int = 100) -> list[str]:
    try:
        soup = BeautifulSoup(body, "html.parser")
    except Exception:
        return []
    urls = []
    for anchor in soup.find_all("a", href=True):
        url = url_join(page_url, str(anchor["href"]))
        if not url or not same_host(page_url, url):
            continue
        path = urlparse(url).path.lower()
        if any(path.endswith(ext) for ext in (".pdf", ".zip", ".png", ".jpg", ".jpeg", ".gif", ".css", ".js")):
            continue
        urls.append(url)
        if len(urls) >= limit:
            break
    return unique_strings(urls)


async def _fetch_page(
    client: AsyncHTTPClient,
    url: str,
    *,
    aggressive: bool,
) -> tuple[str, str] | None:
    try:
        response = await client.get(url, module="mail", timeout=20.0)
    except RobotsDenied:
        get_logger().warning("robots.txt skipped %s during mail crawl", url)
        return None
    except Exception as exc:
        get_logger().warning("mail crawl failed for %s: %s", url, type(exc).__name__)
        return None
    if response.status_code != 200:
        return None
    content_type = response.headers.get("content-type", "").lower()
    if content_type and not any(kind in content_type for kind in ("text/html", "text/plain", "application/xhtml")):
        return None
    body = response.text
    if len(body) > 2_000_000:
        body = body[:2_000_000]
    return str(response.url), body


async def run(
    target: str,
    *,
    sources: str = "web,search",
    check_breaches: bool = False,
    max_pages: int = 20,
    aggressive: bool = False,
) -> list[Finding]:
    """Discover publicly posted email addresses for a domain."""
    domain = host_of(ensure_url(target))
    if domain.startswith("www.") and domain.count(".") >= 2:
        domain = domain[4:]
    domain = domain.lower().lstrip(".")
    if not domain or "." not in domain:
        raise ValueError(f"Invalid domain: {target!r}")
    requested_sources = {part.strip().lower() for part in sources.split(",") if part.strip()}
    if not requested_sources:
        requested_sources = {"web"}
    findings: list[Finding] = []
    email_sources: dict[str, set[str]] = defaultdict(set)
    queued: set[str] = set()
    pages: list[str] = []

    base = ensure_url(target if "://" in target else domain, scheme="https")
    base_origin = origin_of(base)
    if requested_sources & {"web", "search"}:
        if "web" in requested_sources:
            pages.append(base)
            for path in (
                "/contact",
                "/contact-us",
                "/about",
                "/about-us",
                "/team",
                "/support",
                "/imprint",
                "/impressum",
                "/legal",
            ):
                pages.append(base_origin + path)
        queued.update(pages)
        # URLs found by search are fetched later when web crawling is enabled.

    settings_help_shown = False
    async with AsyncHTTPClient(module="mail", aggressive=aggressive) as client:
        if "search" in requested_sources:
            if not search_configured():
                findings.append(
                    Finding(
                        type="search_unavailable",
                        target=domain,
                        module="mail",
                        evidence=search_configuration_help(),
                        severity="info",
                        confidence="high",
                    )
                )
                settings_help_shown = True
            else:
                for query in (f'"@{domain}"', f'site:{domain} "@{domain}"'):
                    results, search_error = await web_search(query, client, max_results=10)
                    if search_error:
                        get_logger().warning("email search failed: %s", search_error)
                        continue
                    for result in results:
                        for email in extract_emails(f"{result.title} {result.snippet} {result.url}", domain):
                            email_sources[email].add(f"search:{result.source}")
                        if "web" in requested_sources and same_host(result.url, base) and result.url not in queued:
                            queued.add(result.url)
                            pages.append(result.url)

        if "web" in requested_sources:
            crawled = 0
            index = 0
            while index < len(pages) and crawled < max_pages:
                url = pages[index]
                index += 1
                if url in {"queued"}:
                    continue
                fetched = await _fetch_page(client, url, aggressive=aggressive)
                if not fetched:
                    continue
                final_url, body = fetched
                crawled += 1
                for email in extract_emails(body, domain):
                    email_sources[email].add(f"web:{urlparse(final_url).path or '/'}")
                for link in _same_site_urls(body, final_url):
                    if link in queued:
                        continue
                    parsed = urlparse(link)
                    haystack = (parsed.path + "?" + parsed.query).lower()
                    if any(hint in haystack for hint in PRIORITY_HINTS):
                        queued.add(link)
                        pages.append(link)

    if not email_sources:
        return findings

    for email in sorted(email_sources):
        source_list = sorted(email_sources[email])
        findings.append(
            Finding(
                type="email",
                target=domain,
                module="mail",
                evidence=f"{email} — source: {', '.join(source_list)}",
                severity="info",
                confidence="medium" if any(source.startswith("search") for source in source_list) else "high",
                metadata={"email": email, "sources": source_list},
            )
        )

    if check_breaches and email_sources:
        if not hibp_configured():
            findings.append(
                Finding(
                    type="breach_check_unavailable",
                    target=domain,
                    module="mail",
                    evidence=(
                        "Breach checks were requested but no hibp_api_key is configured. "
                        "Add a HaveIBeenPwned API key to ~/.toolconfig.yaml."
                    ),
                    severity="info",
                    confidence="high",
                )
            )
        else:
            async with AsyncHTTPClient(module="hibp", aggressive=aggressive) as client:
                for email in sorted(email_sources)[:25]:
                    breaches, error = await hibp_breaches(email, client)
                    if error:
                        get_logger().warning("HIBP lookup for %s: %s", email, error)
                        continue
                    if breaches:
                        names = [str(item.get("name")) for item in breaches]
                        findings.append(
                            Finding(
                                type="breach_exposure",
                                target=domain,
                                module="mail",
                                url="https://haveibeenpwned.com/",
                                evidence=f"{email} appears in {len(breaches)} public breach record(s): "
                                + ", ".join(names[:12]),
                                severity="medium",
                                confidence="high",
                                metadata={"email": email, "breaches": breaches},
                            )
                        )
    return findings
