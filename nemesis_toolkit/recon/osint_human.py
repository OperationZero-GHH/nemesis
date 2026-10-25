"""Human-focused OSINT from explicitly supplied public identifiers."""

from __future__ import annotations

from ..core.apis import hibp_breaches, hibp_configured
from ..core.config import get_settings
from ..core.http_client import AsyncHTTPClient
from ..core.models import Finding
from ..core.search import search_configured, search_configuration_help, web_search
from .osint_social import run as social_username_scan


async def run(
    target: str | None = None,
    *,
    name: str | None = None,
    email: str | None = None,
    username: str | None = None,
    aggressive: bool = False,
    concurrency: int = 8,
) -> list[Finding]:
    """Aggregate only already-public information about a person.

    Username checks use public profile pages/APIs. Name searches use a configured
    search API. Email breach exposure is optional and requires an HIBP key.
    """
    target = (target or name or email or username or "").strip()
    if not any((name, email, username)):
        raise ValueError("Provide at least one of --name, --email or --username.")
    findings: list[Finding] = []

    if username:
        profile_findings = await social_username_scan(
            username.lstrip("@"),
            aggressive=aggressive,
            concurrency=concurrency,
            module="osinthuman",
        )
        for finding in profile_findings:
            finding.target = target or username
            finding.type = "public_profile"
            finding.metadata["input"] = "username"
        findings.extend(profile_findings)

    if email:
        email = email.strip()
        if "@" not in email:
            raise ValueError(f"Invalid email address: {email!r}")
        if not hibp_configured():
            findings.append(
                Finding(
                    type="breach_check_unavailable",
                    target=target,
                    module="osinthuman",
                    evidence=(
                        f"No breach check was performed for {email}: add hibp_api_key to "
                        "~/.toolconfig.yaml to enable HaveIBeenPwned lookups."
                    ),
                    severity="info",
                    confidence="high",
                    metadata={"email": email},
                )
            )
        else:
            async with AsyncHTTPClient(module="osinthuman", aggressive=aggressive) as client:
                breaches, error = await hibp_breaches(email, client)
            if error:
                findings.append(
                    Finding(
                        type="breach_check_error",
                        target=target,
                        module="osinthuman",
                        evidence=f"Breach lookup for {email} failed: {error}",
                        severity="info",
                        confidence="high",
                        metadata={"email": email},
                    )
                )
            elif breaches:
                findings.append(
                    Finding(
                        type="breach_exposure",
                        target=target,
                        module="osinthuman",
                        url="https://haveibeenpwned.com/",
                        evidence=(
                            f"{email} appears in {len(breaches)} public breach record(s): "
                            + ", ".join(str(item.get("name")) for item in breaches[:12])
                        ),
                        severity="medium",
                        confidence="high",
                        metadata={"email": email, "breaches": breaches},
                    )
                )

    name_or_email_query = name or email
    if name_or_email_query and search_configured():
        settings = get_settings()
        async with AsyncHTTPClient(module="osinthuman", aggressive=aggressive) as client:
            query = f'"{name}"' if name else f'"{email}"'
            if email and name:
                query = f'"{name}" "{email}"'
            results, error = await web_search(query, client, max_results=10, settings=settings)
        if error:
            findings.append(
                Finding(
                    type="search_error",
                    target=target,
                    module="osinthuman",
                    evidence=error,
                    severity="info",
                    confidence="high",
                )
            )
        for result in results:
            findings.append(
                Finding(
                    type="search_result",
                    target=target,
                    module="osinthuman",
                    url=result.url,
                    evidence=f"{result.title} — {result.snippet}".strip(" —"),
                    severity="info",
                    confidence="low",
                    metadata={
                        "source": result.source,
                        "query": query,
                        "note": "Search hit only; identity match is not verified.",
                    },
                )
            )
    elif name and not search_configured():
        findings.append(
            Finding(
                type="search_unavailable",
                target=target,
                module="osinthuman",
                evidence=(
                    "Name-only searches require a configured search API. "
                    + search_configuration_help()
                ),
                severity="info",
                confidence="high",
            )
        )

    return findings
