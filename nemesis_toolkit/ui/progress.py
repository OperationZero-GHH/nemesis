"""Rich progress helpers for module execution.

Every long-running module can report progress through a callback. This module
provides the wrapper that creates a consistent rich.progress bar experience.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from ..core.models import Finding


def run_with_progress(
    func: Callable[..., Awaitable[list[Finding]]],
    console: Console,
    *,
    description: str = "Running...",
    **kwargs: Any,
) -> list[Finding]:
    """Execute an async module function with a live progress display.

    For modules that accept a ``progress_cb(done, total, msg)`` kwarg,
    progress is tracked accurately. Otherwise an indeterminate spinner is shown.
    """
    results: list[Finding] = []
    error_holder: list[Exception] = []

    async def _run() -> list[Finding]:
        return await func(**kwargs)

    with Progress(
        SpinnerColumn(spinner_name="dots", style="green"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        TextColumn("[progress.percentage]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(description, total=None)

        try:
            results = asyncio.run(_run())
        except Exception as exc:
            error_holder.append(exc)

        progress.update(task, completed=1, total=1)

    if error_holder:
        raise error_holder[0]

    return results


def run_with_spinner(
    func: Callable[..., Any],
    console: Console,
    *,
    description: str = "Working...",
    **kwargs: Any,
) -> Any:
    """Run a synchronous function with an indeterminate spinner."""
    from rich.status import Status

    result = None
    error_holder: list[Exception] = []

    with Status(
        f"[bold green]{description}[/bold green]",
        spinner="dots",
        spinner_style="green",
        console=console,
    ):
        try:
            result = func(**kwargs)
        except Exception as exc:
            error_holder.append(exc)

    if error_holder:
        raise error_holder[0]
    return result
