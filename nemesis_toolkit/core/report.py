"""Self-contained HTML report generation for auto-scan results."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import Finding
from .output import error, status
from .utils import severity_rank

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def render_html_report(
    findings: list[Finding],
    *,
    target: str,
    metadata: dict[str, Any] | None = None,
) -> str:
    environment = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = environment.get_template("report.html.j2")
    counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    ordered = sorted(
        findings,
        key=lambda finding: (
            severity_rank(finding.severity),
            finding.module,
            finding.type,
            finding.url or "",
        ),
    )
    return template.render(
        target=target,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        findings=[finding.to_dict() for finding in ordered],
        counts=counts,
        total=len(findings),
        metadata=metadata or {},
    )


def write_html_report(
    findings: list[Finding],
    *,
    target: str,
    output: Path,
    metadata: dict[str, Any] | None = None,
) -> Path:
    path = Path(output).expanduser()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            render_html_report(findings, target=target, metadata=metadata),
            encoding="utf-8",
        )
    except OSError as exc:
        error(f"Could not write HTML report {path}: {exc}")
        raise
    status(f"HTML report written to [bold]{path}[/bold]")
    return path
