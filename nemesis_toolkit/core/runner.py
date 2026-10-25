"""Helpers that connect CLI invocations to persistence and rendering."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, TypeVar

import typer

from .auth_gate import AuthorizationRequired
from .db import persist_run
from .http_client import RobotsDenied
from .logging import audit_event
from .models import Finding
from .output import emit_findings, error, status, warning

T = TypeVar("T")


def fetch_async(coro: Awaitable[list[Finding]]) -> list[Finding]:
    """Run an async module and convert known failures to friendly CLI errors."""
    try:
        return asyncio.run(coro)  # type: ignore[arg-type]
    except AuthorizationRequired as exc:
        error(str(exc))
        raise typer.Exit(code=2) from exc
    except RobotsDenied as exc:
        error(str(exc))
        raise typer.Exit(code=3) from exc
    except KeyboardInterrupt:
        status("Interrupted.")
        raise typer.Exit(code=130) from None
    except ValueError as exc:
        error(str(exc))
        raise typer.Exit(code=2) from exc
    except Exception as exc:  # network failures and configuration errors
        error(f"{type(exc).__name__}: {exc}")
        if isinstance(exc, KeyboardInterrupt):
            raise
        raise typer.Exit(code=1) from exc


def started_now() -> tuple[str, float]:
    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds"),
        time.perf_counter(),
    )


def finish(
    findings: list[Finding],
    *,
    target: str,
    module: str,
    started_at: str,
    timer: float,
    options: dict[str, Any],
    json_output: bool = False,
    output: Path | None = None,
    title: str | None = None,
) -> None:
    duration = time.perf_counter() - timer
    try:
        persist_run(
            target=target,
            module=module,
            findings=findings,
            options=options,
            started_at=started_at,
            duration_seconds=duration,
        )
    except Exception as exc:
        warning(f"Could not persist results to the local database: {exc}")
    audit_event(
        "module_completed",
        module=module,
        target=target,
        finding_count=len(findings),
        duration_seconds=round(duration, 3),
    )
    emit_findings(
        findings,
        target=target,
        module=module,
        title=title or f"{module} — {target}",
        json_output=json_output,
        output=output,
    )
