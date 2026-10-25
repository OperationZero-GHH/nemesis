"""Discover public login endpoints."""

from __future__ import annotations

from pathlib import Path

from ..core.models import Finding
from ._endpoint_finder import probe_paths

LOGIN_PATHS = [
    "/login",
    "/signin",
    "/sign-in",
    "/sign_in",
    "/admin",
    "/admin/login",
    "/administrator",
    "/wp-login.php",
    "/wp-admin",
    "/user/login",
    "/users/sign_in",
    "/account/login",
    "/account/signin",
    "/auth/login",
    "/auth/signin",
    "/session/new",
    "/portal",
    "/cpanel",
    "/login.aspx",
    "/login.php",
    "/login.html",
    "/console",
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
    """Probe common authentication paths and identify forms with password fields."""
    return await probe_paths(
        target,
        LOGIN_PATHS + _extra_paths(extra_paths),
        module="loginfind",
        kind="login",
        aggressive=aggressive,
        concurrency=concurrency,
    )
