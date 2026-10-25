"""Tests for authorization gating and banner behavior."""

from __future__ import annotations

import pytest
from rich.console import Console

from nemesis_toolkit.core.auth_gate import (
    AuthorizationRequired,
    reset_banner,
    require_authorized,
    show_authorization_banner,
)
from nemesis_toolkit.core.config import get_settings
from nemesis_toolkit.scanner import xss


def test_gate_rejects_without_confirmation():
    with pytest.raises(AuthorizationRequired):
        require_authorized(False, "xss", "https://example.test")


def test_gate_allows_confirmation():
    require_authorized(True, "xss", "https://example.test")


def test_config_flag_allows(monkeypatch):
    monkeypatch.setenv("NEMESIS_AUTHORIZED_BY_DEFAULT", "true")
    get_settings.cache_clear()
    require_authorized(False, "xss", "https://example.test")


def test_banner_prints_once(monkeypatch):
    import io

    reset_banner()
    stream = io.StringIO()
    console = Console(file=stream, force_terminal=False)
    show_authorization_banner(console)
    first = stream.getvalue()
    show_authorization_banner(console)
    assert "AUTHORIZED SECURITY TESTING ONLY" in first.replace("\n", " ")
    assert first == stream.getvalue()


@pytest.mark.asyncio
async def test_scanner_run_enforces_gate_before_network():
    with pytest.raises(AuthorizationRequired):
        await xss.run("https://example.test/?q=1", authorized=False)
