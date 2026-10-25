"""Asset integrity monitoring with SQLite snapshots and optional webhooks."""

from __future__ import annotations

import asyncio
import difflib
import hashlib
from datetime import datetime, timezone
from typing import Any

import httpx

from ..core.db import save_snapshot
from ..core.http_client import AsyncHTTPClient
from ..core.logging import audit_event, get_logger
from ..core.models import Finding
from ..core.utils import ensure_url


async def _check_one(
    url: str,
    *,
    client: AsyncHTTPClient,
    diff_content: bool,
    webhook: str | None,
) -> list[Finding]:
    normalized = ensure_url(url)
    try:
        response = await client.get(normalized, module="webmonitor", timeout=30.0)
    except Exception as exc:
        return [
            Finding(
                type="monitor_error",
                target=normalized,
                module="webmonitor",
                url=normalized,
                evidence=f"Fetch failed: {type(exc).__name__}: {exc}",
                severity="info",
                confidence="high",
                metadata={"error": str(exc)},
            )
        ]
    body = response.text[:2_000_000]
    if response.status_code != 200:
        return [
            Finding(
                type="monitor_error",
                target=normalized,
                module="webmonitor",
                url=normalized,
                evidence=f"HTTP {response.status_code} while monitoring {normalized}",
                severity="info",
                confidence="high",
                metadata={"status": response.status_code},
            )
        ]
    changed, previous, digest = save_snapshot(normalized, body)
    if previous is None:
        return [
            Finding(
                type="snapshot_initial",
                target=normalized,
                module="webmonitor",
                url=normalized,
                evidence=f"Initial snapshot stored (sha256 {digest[:16]}…, {len(body)} bytes).",
                severity="info",
                confidence="high",
                metadata={"sha256": digest, "bytes": len(body)},
            )
        ]
    if not changed:
        return []
    diff_text = ""
    if diff_content and previous is not None:
        diff_lines = list(
            difflib.unified_diff(
                previous.splitlines()[:4000],
                body.splitlines()[:4000],
                fromfile="previous",
                tofile="current",
                lineterm="",
                n=2,
            )
        )
        diff_text = "\n".join(diff_lines[:200])
    evidence = (
        f"Content changed at {normalized} (sha256 {digest[:16]}…).\n"
        f"{diff_text[:1500] if diff_text else 'Content hash changed.'}"
    )
    finding = Finding(
        type="content_change",
        target=normalized,
        module="webmonitor",
        url=normalized,
        evidence=evidence,
        severity="info",
        confidence="high",
        metadata={
            "sha256": digest,
            "bytes": len(body),
            "diff": diff_text[:8000],
            "detected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        },
    )
    if webhook:
        payload: dict[str, Any] = {
            "event": "web_content_changed",
            "url": normalized,
            "detected_at": finding.metadata["detected_at"],
            "sha256": digest,
            "diff": diff_text[:4000],
        }
        try:
            webhook_response = await client.post(
                webhook,
                module="webmonitor",
                json=payload,
                timeout=20.0,
            )
            finding.metadata["webhook_status"] = webhook_response.status_code
            if webhook_response.status_code >= 400:
                get_logger().warning("webhook returned HTTP %s", webhook_response.status_code)
        except (httpx.HTTPError, OSError) as exc:
            finding.metadata["webhook_error"] = f"{type(exc).__name__}: {exc}"
            get_logger().warning("webhook delivery failed: %s", exc)
    audit_event(
        "content_change",
        module="webmonitor",
        target=normalized,
        sha256=digest,
    )
    return [finding]


async def run(
    target: str | list[str],
    *,
    interval: int = 300,
    diff_content: bool = True,
    webhook: str | None = None,
    once: bool = False,
    aggressive: bool = False,
) -> list[Finding]:
    """Poll one or more URLs.

    ``once=True`` performs a single snapshot pass and returns immediately. With
    ``once=False`` this loops forever until interrupted; use the CLI's
    ``--once`` flag for scripted checks.

    Note: this function intentionally performs a single pass; the CLI owns the
    long-running loop so each interval can be rendered and persisted.
    """
    targets = [target] if isinstance(target, str) else list(target)
    if not targets:
        raise ValueError("At least one URL is required.")
    all_findings: list[Finding] = []
    async with AsyncHTTPClient(module="webmonitor", aggressive=aggressive) as client:
        for url in targets:
            all_findings.extend(
                await _check_one(
                    url,
                    client=client,
                    diff_content=diff_content,
                    webhook=webhook,
                )
            )
    return all_findings
