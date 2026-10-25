"""Rich and machine-readable output formatting."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import Finding
from .utils import severity_rank, truncate

console = Console()
err_console = Console(stderr=True)

SEVERITY_STYLES = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "cyan",
    "info": "dim",
}
SEVERITY_COLORS = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "white",
}


def status(message: str) -> None:
    err_console.print(message)


def error(message: str) -> None:
    err_console.print(f"[bold red]Error:[/bold red] {message}")


def warning(message: str) -> None:
    err_console.print(f"[bold yellow]Warning:[/bold yellow] {message}")


def result_payload(target: str, module: str, findings: list[Finding]) -> dict[str, object]:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return {
        "target": target,
        "module": module,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "count": len(findings),
        "severity_counts": {key: counts.get(key, 0) for key in ("critical", "high", "medium", "low", "info")},
        "findings": [finding.to_dict() for finding in findings],
    }


def write_json(path: Path, payload: dict[str, object]) -> None:
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def _summary(findings: list[Finding]) -> Text:
    counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    summary = Text()
    summary.append(f"{len(findings)} finding(s)  ", style="bold")
    for key in ("critical", "high", "medium", "low", "info"):
        if counts[key]:
            summary.append(f"{key}: {counts[key]}  ", style=SEVERITY_STYLES.get(key, ""))
    return summary


def _render_table(findings: list[Finding], title: str) -> None:
    table = Table(
        title=title,
        header_style="bold magenta",
        show_lines=False,
        expand=True,
        safe_box=True,
    )
    table.add_column("Severity", style="bold", width=9)
    table.add_column("Type", width=22)
    table.add_column("URL", overflow="fold")
    table.add_column("Param", width=14)
    table.add_column("Confidence", width=10)
    table.add_column("Evidence", overflow="fold")
    for finding in sorted(findings, key=lambda item: (severity_rank(item.severity), item.module, item.type)):
        table.add_row(
            Text(finding.severity.upper(), style=SEVERITY_STYLES.get(finding.severity, "")),
            Text(finding.type),
            Text(finding.url or ""),
            Text(finding.param or ""),
            Text(finding.confidence),
            Text(truncate(finding.evidence, 420)),
        )
    console.print(table)
    console.print(_summary(findings))


def emit_findings(
    findings: list[Finding],
    *,
    target: str,
    module: str,
    title: str | None = None,
    json_output: bool = False,
    output: Path | None = None,
) -> None:
    """Render results and optionally write the same machine-readable payload."""
    payload = result_payload(target, module, findings)
    if output:
        try:
            write_json(Path(output), payload)
            status(f"JSON results written to [bold]{Path(output).expanduser()}[/bold]")
        except OSError as exc:
            error(f"Could not write {output}: {exc}")
    if json_output:
        # Keep stdout valid JSON when --json is requested.
        console.print_json(data=payload)
        return
    if not findings:
        console.print(f"[bold]{title or module}[/bold] — no findings for [cyan]{target}[/cyan].")
        return
    _render_table(findings, title or f"{module} — {target}")


def render_banner(title: str, body: str, style: str = "cyan") -> None:
    console.print(Panel(body, title=title, border_style=style, expand=False))


def print_json_stdout(payload: object) -> None:
    """Print a JSON document to stdout without Rich formatting."""
    sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False, default=str) + "\n")
