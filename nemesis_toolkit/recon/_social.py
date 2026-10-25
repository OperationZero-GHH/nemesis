"""Public-profile checks for OSINT username modules.

Only public pages and openly accessible APIs are queried. The toolkit does not
attempt to bypass login walls, rate limits or privacy controls.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from urllib.parse import quote

from bs4 import BeautifulSoup

from ..core.http_client import AsyncHTTPClient, RobotsDenied
from ..core.models import Finding
from ..core.utils import extract_meta, extract_title

PLATFORMS: dict[str, str] = {
    "github": "https://github.com/{username}",
    "gitlab": "https://gitlab.com/{username}",
    "bitbucket": "https://bitbucket.org/{username}/",
    "codeberg": "https://codeberg.org/{username}",
    "twitter": "https://x.com/{username}",
    "x": "https://x.com/{username}",
    "instagram": "https://www.instagram.com/{username}/",
    "facebook": "https://www.facebook.com/{username}",
    "linkedin": "https://www.linkedin.com/in/{username}",
    "tiktok": "https://www.tiktok.com/@{username}",
    "youtube": "https://www.youtube.com/@{username}",
    "reddit": "https://www.reddit.com/user/{username}",
    "pinterest": "https://www.pinterest.com/{username}/",
    "snapchat": "https://www.snapchat.com/add/{username}",
    "twitch": "https://www.twitch.tv/{username}",
    "telegram": "https://t.me/{username}",
    "mastodon": "https://mastodon.social/@{username}",
    "threads": "https://www.threads.net/@{username}",
    "medium": "https://medium.com/@{username}",
    "devto": "https://dev.to/{username}",
    "stackoverflow": "https://stackoverflow.com/users?tab=Reputation&filter=all&search={username}",
    "hackernews": "https://news.ycombinator.com/user?id={username}",
    "keybase": "https://keybase.io/{username}",
    "kaggle": "https://www.kaggle.com/{username}",
    "dockerhub": "https://hub.docker.com/u/{username}",
    "npm": "https://www.npmjs.com/~{username}",
    "pypi": "https://pypi.org/user/{username}/",
    "soundcloud": "https://soundcloud.com/{username}",
    "spotify": "https://open.spotify.com/user/{username}",
    "steam": "https://steamcommunity.com/id/{username}",
    "behance": "https://www.behance.net/{username}",
    "dribbble": "https://dribbble.com/{username}",
}

DEFAULT_PLATFORMS = [
    "github",
    "gitlab",
    "bitbucket",
    "codeberg",
    "reddit",
    "medium",
    "devto",
    "keybase",
    "hackernews",
    "stackoverflow",
    "twitter",
    "instagram",
    "linkedin",
    "tiktok",
]

NOT_FOUND_MARKERS = (
    "page not found",
    "user not found",
    "profile not found",
    "could not find",
    "couldn't find",
    "does not exist",
    "no such user",
    "account suspended",
    "404 not found",
    "not found |",
    "| not found",
    "sorry, this page",
)


@dataclass(slots=True)
class ProfileCheck:
    platform: str
    url: str
    exists: bool | None
    status: int | None
    title: str = ""
    description: str = ""
    detail: str = ""


def _looks_missing(status: int, title: str, body: str) -> bool:
    if status == 404:
        return True
    if status in (401, 403, 429):
        return False
    haystack = f"{title}\n{body[:5000]}".lower()
    return any(marker in haystack for marker in NOT_FOUND_MARKERS)


def _public_subset(platform: str, body: str, title: str) -> tuple[str, str, str]:
    if platform == "github":
        return title, extract_meta(body, "description"), ""
    description = extract_meta(body, "description") or extract_meta(body, "og:description")
    try:
        soup = BeautifulSoup(body, "html.parser")
        image = soup.find("meta", attrs={"property": "og:image"})
        image_url = str(image.get("content")) if image and image.get("content") else ""
    except Exception:
        image_url = ""
    return title, description, image_url


async def _check_github(
    username: str,
    client: AsyncHTTPClient,
) -> ProfileCheck:
    api_url = f"https://api.github.com/users/{quote(username)}"
    try:
        response = await client.get(
            api_url,
            module="osintsocial",
            headers={"Accept": "application/vnd.github+json"},
            timeout=20.0,
        )
    except RobotsDenied:
        # GitHub's robots.txt does not govern its API, but this branch is a safe
        # fallback if a custom HTTP client is configured differently.
        return ProfileCheck("github", f"https://github.com/{username}", None, None, detail="robots.txt blocked")
    except Exception as exc:
        return ProfileCheck("github", f"https://github.com/{username}", None, None, detail=str(exc))
    if response.status_code == 404:
        return ProfileCheck("github", f"https://github.com/{username}", False, 404)
    if response.status_code != 200:
        return ProfileCheck(
            "github",
            f"https://github.com/{username}",
            None,
            response.status_code,
            detail="GitHub API unavailable",
        )
    try:
        data = response.json()
    except ValueError:
        return ProfileCheck("github", f"https://github.com/{username}", None, response.status_code)
    details = []
    if data.get("name"):
        details.append(f"name: {data['name']}")
    if data.get("bio"):
        details.append(f"bio: {data['bio']}")
    if data.get("company"):
        details.append(f"company: {data['company']}")
    if data.get("location"):
        details.append(f"location: {data['location']}")
    if data.get("public_repos") is not None:
        details.append(f"public_repos: {data['public_repos']}")
    if data.get("followers") is not None:
        details.append(f"followers: {data['followers']}")
    return ProfileCheck(
        "github",
        str(data.get("html_url") or f"https://github.com/{username}"),
        True,
        200,
        title=str(data.get("name") or data.get("login") or username),
        description=str(data.get("bio") or ""),
        detail="; ".join(details),
    )


async def check_profile(
    platform: str,
    username: str,
    client: AsyncHTTPClient,
) -> ProfileCheck:
    platform = platform.lower().strip()
    template = PLATFORMS.get(platform)
    if not template:
        raise ValueError(f"Unsupported platform: {platform}")
    if platform == "github":
        return await _check_github(username, client)
    url = template.format(username=quote(username, safe=""))
    try:
        response = await client.get(url, module="osintsocial", timeout=20.0)
    except RobotsDenied:
        return ProfileCheck(platform, url, None, None, detail="robots.txt blocked")
    except Exception as exc:
        return ProfileCheck(platform, url, None, None, detail=f"{type(exc).__name__}: {exc}")
    body = response.text[:1_500_000]
    title = extract_title(body)
    if _looks_missing(response.status_code, title, body):
        return ProfileCheck(platform, url, False, response.status_code, title=title)
    final_url = str(response.url)
    if any(part in final_url.lower() for part in ("/login", "/signin", "/authwall", "/accounts/login")):
        return ProfileCheck(platform, url, None, response.status_code, title=title, detail="login wall")
    exists = response.status_code in (200, 301, 302)
    if response.status_code in (401, 403, 429):
        exists = None
    description, image = "", ""
    if exists:
        title, description, image = _public_subset(platform, body, title)
    detail_parts = []
    if description:
        detail_parts.append(description)
    if image:
        detail_parts.append("public avatar")
    return ProfileCheck(
        platform,
        final_url,
        exists,
        response.status_code,
        title=title,
        description=description,
        detail="; ".join(detail_parts),
    )


async def username_scan(
    username: str,
    *,
    platforms: list[str] | None = None,
    aggressive: bool = False,
    concurrency: int = 8,
    module: str = "osintsocial",
) -> list[Finding]:
    selected = platforms or DEFAULT_PLATFORMS
    normalized: list[str] = []
    for platform in selected:
        name = platform.strip().lower()
        if name == "x":
            name = "twitter"
        if name in PLATFORMS and name not in normalized:
            normalized.append(name)
    if not normalized:
        raise ValueError("No supported platforms were selected.")
    semaphore = asyncio.Semaphore(max(1, min(concurrency, 30)))
    findings: list[Finding] = []
    async with AsyncHTTPClient(module=module, aggressive=aggressive) as client:
        async def limited(platform: str) -> ProfileCheck:
            async with semaphore:
                return await check_profile(platform, username, client)

        results = await asyncio.gather(*(limited(name) for name in normalized))
    for result in results:
        if not result.exists:
            continue
        evidence_parts = [f"{result.platform}: {result.url}", f"HTTP {result.status}"]
        if result.title:
            evidence_parts.append(f"title: {result.title}")
        if result.description:
            evidence_parts.append(f"bio: {result.description[:240]}")
        if result.detail and result.detail not in result.description:
            evidence_parts.append(result.detail[:300])
        findings.append(
            Finding(
                type="social_profile",
                target=username,
                module=module,
                url=result.url,
                evidence=" — ".join(evidence_parts),
                severity="info",
                confidence="high" if result.status == 200 else "medium",
                metadata={
                    "platform": result.platform,
                    "username": username,
                    "status": result.status,
                    "title": result.title,
                    "public_bio": result.description,
                },
            )
        )
    return sorted(findings, key=lambda finding: str(finding.metadata.get("platform", "")))
