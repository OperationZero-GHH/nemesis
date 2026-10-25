"""Discover public registration and signup endpoints."""

from __future__ import annotations

from pathlib import Path

from ..core.models import Finding
from ._endpoint_finder import probe_paths

REGISTER_PATHS = [
    "/register",
    "/signup",
    "/sign-up",
    "/sign_up",
    "/account/create",
    "/account/register",
    "/user/register",
    "/users/sign_up",
    "/auth/register",
    "/join",
    "/create-account",
    "/register.php",
    "/register.aspx",
    "/register.html",
    "/members/register",
    "/enroll",
]


def _extra_paths(path: Path | str | None) -> list[str]:
    if not path:
        return []
    file_path = Path(path).expanduser()
    if not file_path.exists():
        raise ValueError(f"Path list not found: {file_path}")
    return [
        line.strip()
        for line in file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


async def run(
    target: str,
    *,
    extra_paths: Path | str | None = None,
    aggressive: bool = False,
    concurrency: int = 10,
) -> list[Finding]:
    """Probe common registration paths and flag pages with password fields."""
    return await probe_paths(
        target,
        REGISTER_PATHS + _extra_paths(extra_paths),
        module="registerfind",
        kind="register",
        aggressive=aggressive,
        concurrency=concurrency,
    )
