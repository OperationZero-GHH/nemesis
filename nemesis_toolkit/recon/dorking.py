"""Curated search-engine dorks executed through a user-supplied search API."""

from __future__ import annotations

from pathlib import Path

from ..core.http_client import AsyncHTTPClient
from ..core.models import Finding
from ..core.search import search_configuration_help, search_configured, web_search
from ..core.utils import normalize_domain, unique_strings

BUILTIN_DORKS = [
    'site:{domain} ext:env OR ext:ini "password"',
    'site:{domain} intitle:"index of"',
    'site:{domain} (ext:bak OR ext:backup OR ext:old OR ext:sql)',
    'site:{domain} inurl:admin OR inurl:login OR inurl:dashboard',
    'site:{domain} "phpinfo()"',
    'site:{domain} inurl:"/.git" OR inurl:"/.svn"',
    'site:{domain} ext:log OR ext:txt "password"',
    'site:{domain} ext:pdf OR ext:doc "confidential"',
    'site:{domain} "internal use only"',
    'site:{domain} ("api_key" OR "apikey" OR "secret_key" OR "access_token")',
    'site:{domain} ext:xml (inurl:sitemap OR inurl:config)',
    'site:{domain} "error" ("stack trace" OR "SQL syntax")',
    'site:{domain} inurl:upload OR inurl:download',
    'site:{domain} intitle:"directory listing"',
]


def _load_dorks(path: Path | str | None, domain: str) -> list[str]:
    if not path:
        templates = list(BUILTIN_DORKS)
    else:
        file_path = Path(path).expanduser()
        if not file_path.exists():
            raise ValueError(f"Dork file not found: {file_path}")
        templates = []
        for line in file_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            templates.append(line)
    if not templates:
        raise ValueError("No dork templates were provided.")
    return unique_strings(template.format(domain=domain) for template in templates)


async def run(
    target: str,
    *,
    dork_file: Path | str | None = None,
    max_results: int = 8,
    max_dorks: int = 8,
    aggressive: bool = False,
) -> list[Finding]:
    """Run dorks only through SerpAPI or Google Custom Search."""
    domain = normalize_domain(target)
    queries = _load_dorks(dork_file, domain)[:max_dorks]
    if not search_configured():
        return [
            Finding(
                type="search_unavailable",
                target=domain,
                module="dork",
                evidence=search_configuration_help()
                + " The built-in dork library is ready but cannot be executed without a search API.",
                severity="info",
                confidence="high",
                metadata={"queries": queries},
            )
        ]
    findings: list[Finding] = []
    seen: set[str] = set()
    errors: list[str] = []
    async with AsyncHTTPClient(module="dork", aggressive=aggressive) as client:
        for query in queries:
            results, error = await web_search(query, client, max_results=max_results)
            if error:
                errors.append(error)
                continue
            for result in results:
                if result.url in seen:
                    continue
                seen.add(result.url)
                findings.append(
                    Finding(
                        type="dork_result",
                        target=domain,
                        module="dork",
                        url=result.url,
                        evidence=(
                            f"{result.title} — {result.snippet[:400]} "
                            f"(query: {query}; source: {result.source})"
                        ),
                        severity="info",
                        confidence="medium",
                        metadata={
                            "query": query,
                            "title": result.title,
                            "snippet": result.snippet,
                            "search_source": result.source,
                        },
                    )
                )
    if errors and not findings:
        findings.append(
            Finding(
                type="search_error",
                target=domain,
                module="dork",
                evidence="; ".join(unique_strings(errors))[:1000],
                severity="info",
                confidence="high",
                metadata={"queries": queries},
            )
        )
    return findings
