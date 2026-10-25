"""Target-centric history dashboard backed by the local SQLite database."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..core.db import dashboard
from ..core.models import Finding, SEVERITIES

console = Console()


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    return finding.to_dict()


def run(target: str | None = None, *, limit: int = 500) -> list[Finding]:
    """Return prior findings for a target (or all targets) from SQLite."""
    data = dashboard(target, finding_limit=limit)
    findings: list[Finding] = []
    for item in data["findings"]:
        if isinstance(item, Finding):
            item.metadata.setdefault("tracker", "historical_finding")
            findings.append(item)
    return findings


def payload(target: str | None = None, *, limit: int = 500) -> dict[str, Any]:
    data = dashboard(target, finding_limit=limit)
    return {
        "target": target,
        "targets": data["targets"],
        "runs": data["runs"],
        "severity_counts": data["severity_counts"],
        "findings": [_finding_to_dict(finding) for finding in data["findings"]],
        "run_count": len(data["runs"]),
        "finding_count": len(data["findings"]),
    }


def render_dashboard(target: str | None = None, *, limit: int = 500) -> None:
    data = dashboard(target, finding_limit=limit)
    heading = f"Target history — {target}" if target else "All targets"
    console.print(f"[bold magenta]{heading}[/bold magenta]")
    if target and not data.get("target_record") and not data["runs"]:
        console.print(f"[yellow]No prior scans or findings for {target}.[/yellow]")
        return

    counts = data["severity_counts"]
    summary = "  ".join(
        f"{severity}: {counts.get(severity, 0)}" for severity in SEVERITIES if counts.get(severity)
    )
    console.print(
        f"{len(data['runs'])} run(s), {len(data['findings'])} historical finding(s)"
        + (f"  ·  {summary}" if summary else "")
    )

    if not target and data["targets"]:
        targets_table = Table(title="Known targets", header_style="bold magenta", expand=True)
        targets_table.add_column("Target")
        targets_table.add_column("Runs", justify="right")
        targets_table.add_column("Findings", justify="right")
        targets_table.add_column("Last seen")
        for item in data["targets"]:
            targets_table.add_row(
                Text(str(item.get("name") or "")),
                Text(str(item.get("runs") or 0)),
                Text(str(item.get("findings") or 0)),
                Text(str(item.get("updated_at") or "")),
            )
        console.print(targets_table)

    if data["runs"]:
        runs_table = Table(title="Scan timeline", header_style="bold magenta", expand=True)
        runs_table.add_column("When", width=20)
        runs_table.add_column("Module")
        runs_table.add_column("Status")
        runs_table.add_column("Results", justify="right")
        runs_table.add_column("Duration", justify="right")
        for run in data["runs"]:
            duration = run.get("duration_seconds")
            runs_table.add_row(
                Text(str(run.get("started_at") or "")),
                Text(str(run.get("module") or "")),
                Text(str(run.get("status") or "")),
                Text(str(run.get("result_count") or 0)),
                Text(f"{duration:.2f}s" if isinstance(duration, (int, float)) else ""),
            )
        console.print(runs_table)

    if data["findings"]:
        findings_table = Table(title="Historical findings", header_style="bold magenta", expand=True)
        findings_table.add_column("When", width=20)
        findings_table.add_column("Severity", width=9)
        findings_table.add_column("Module", width=14)
        findings_table.add_column("Type", width=20)
        findings_table.add_column("URL", overflow="fold")
        findings_table.add_column("Evidence", overflow="fold")
        for finding in data["findings"]:
            findings_table.add_row(
                Text(finding.timestamp[:19]),
                Text(finding.severity.upper()),
                Text(finding.module),
                Text(finding.type),
                Text(finding.url or ""),
                Text(finding.evidence[:300]),
            )
        console.print(findings_table)
