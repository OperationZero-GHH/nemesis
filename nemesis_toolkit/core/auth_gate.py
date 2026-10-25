"""Authorization gate for all active scanner modules."""

from __future__ import annotations

import threading

from rich.console import Console

from .config import get_settings
from .logging import audit_event


class AuthorizationRequired(RuntimeError):
    """Raised when an active scanner is invoked without authorization."""


AUTHORIZATION_BANNER = """[bold red]AUTHORIZED SECURITY TESTING ONLY[/bold red]

This toolkit performs active requests that may be logged or blocked by the
target. Use it only on systems you own or have explicit, written permission to
test. Scanner modules are detection-only: they do not exploit, extract data, or
chain vulnerabilities.

Confirm authorization with [bold]--confirm-authorized[/bold] or set
[bold]authorized_by_default: true[/bold] in ~/.toolconfig.yaml.
"""

_banner_lock = threading.Lock()
_banner_printed = False


def show_authorization_banner(console: Console | None = None) -> None:
    """Print the legal banner once per process, to stderr when possible."""
    global _banner_printed
    with _banner_lock:
        if _banner_printed:
            return
        _banner_printed = True
    target_console = console or Console(stderr=True)
    target_console.print(AUTHORIZATION_BANNER)


def reset_banner() -> None:
    """Reset banner state (test helper)."""
    global _banner_printed
    with _banner_lock:
        _banner_printed = False


def is_authorized(confirmed: bool = False) -> bool:
    """Return whether confirmation was supplied or configured."""
    return bool(confirmed or get_settings().authorized_by_default)


def require_authorized(confirmed: bool, module: str, target: str) -> None:
    """Enforce the gate inside a scanner's public ``run`` function.

    This is deliberately duplicated at the module boundary so programmatic
    callers cannot bypass the CLI gate.
    """
    if not is_authorized(confirmed):
        raise AuthorizationRequired(
            f"{module} requires authorization confirmation for '{target}'. "
            "Pass authorized=True programmatically or --confirm-authorized on the CLI "
            "(or set authorized_by_default in configuration)."
        )
    audit_event(
        "authorization_confirmed",
        module=module,
        target=target,
        source="config" if not confirmed else "flag",
    )
