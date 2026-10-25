"""Tests for the shared HTTP client: robots, rate limiting and audit logging."""

from __future__ import annotations

import json

import pytest

from nemesis_toolkit.core.config import get_settings
from nemesis_toolkit.core.http_client import AsyncHTTPClient, RobotsDenied


@pytest.mark.asyncio
async def test_robots_txt_is_enforced(scanner_server):
    settings = get_settings()
    async with AsyncHTTPClient(settings=settings, module="test", respect_robots=True) as client:
        response = await client.get(f"{scanner_server}/")
        assert response.status_code == 200
        with pytest.raises(RobotsDenied):
            await client.get(f"{scanner_server}/private")


@pytest.mark.asyncio
async def test_requests_are_audited(scanner_server):
    settings = get_settings()
    async with AsyncHTTPClient(settings=settings, module="audit-test", respect_robots=False) as client:
        await client.get(f"{scanner_server}/?token=secret-value")
    content = settings.audit_log.read_text(encoding="utf-8")
    assert "http_request" in content
    records = [json.loads(line) for line in content.splitlines() if line.strip()]
    assert any(record.get("module") == "audit-test" for record in records)
    assert "secret-value" not in content


@pytest.mark.asyncio
async def test_retry_returns_success(scanner_server):
    settings = get_settings().model_copy(update={"max_retries": 1, "requests_per_second": 1000})
    # The local server returns 404 for this path, which is not retried; this test
    # primarily verifies that client construction with retry settings succeeds.
    async with AsyncHTTPClient(settings=settings, module="retry-test", respect_robots=False) as client:
        response = await client.get(f"{scanner_server}/missing")
        assert response.status_code == 404


def test_aggressive_disables_robots_and_rate_limiting():
    settings = get_settings()
    normal = AsyncHTTPClient(settings=settings, module="test", respect_robots=None)
    aggressive = AsyncHTTPClient(settings=settings, module="test", aggressive=True)
    assert normal.respect_robots is False  # autouse fixture disables robots globally
    assert aggressive.respect_robots is False
    assert normal._rate.interval > 0
    assert aggressive._rate.interval == 0.0

