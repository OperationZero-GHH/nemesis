"""Public username discovery across major platforms."""

from __future__ import annotations

from ..core.models import Finding
from ._social import DEFAULT_PLATFORMS, username_scan


def supported_platforms() -> list[str]:
    return sorted(set(DEFAULT_PLATFORMS))


async def run(
    target: str | None = None,
    *,
    username: str | None = None,
    platforms: str | list[str] | None = None,
    aggressive: bool = False,
    concurrency: int = 8,
) -> list[Finding]:
    username = (username or target or "").strip().lstrip("@")
    if not username or len(username) > 200:
        raise ValueError("A username is required (for example: --username johndoe).")
    if isinstance(platforms, str):
        selected = [part.strip() for part in platforms.split(",") if part.strip()]
    elif platforms:
        selected = list(platforms)
    else:
        selected = list(DEFAULT_PLATFORMS)
    return await username_scan(
        username,
        platforms=selected,
        aggressive=aggressive,
        concurrency=concurrency,
        module="osintsocial",
    )
