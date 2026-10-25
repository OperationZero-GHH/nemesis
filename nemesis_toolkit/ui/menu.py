"""Interactive cyberpunk-styled module selection menu and dispatch loop.

Displays all 20 modules (13 recon + 7 scanner) in a two-column table with
icons, colored text, and a bottom status bar matching the hacker-tool aesthetic.
"""

from __future__ import annotations

import asyncio
import sys
import time
from typing import Any

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from .. import __version__
from ..core.auth_gate import show_authorization_banner
from ..core.models import Finding
from ..core.output import emit_findings, error, status
from ..core.runner import started_now, finish
from .registry import (
    ALL_MODULES,
    MODULE_BY_KEY,
    MODULE_BY_SLUG,
    RECON_MODULES,
    SCANNER_MODULES,
    ModuleInfo,
    get_run_function,
)

# ── Module icons for the hacker aesthetic ──────────────────────────────
_RECON_ICONS = {
    "subdomain":    "🔗",
    "portscan":     "⊕",
    "mailscrape":   "✉",
    "loginfind":    "🔐",
    "registerfind": "📋",
    "paramfind":    "⚙",
    "dork":         "🔍",
    "osinthuman":   "👁",
    "osintsocial":  "🌐",
    "webmonitor":   "📡",
    "waf":          "🛡",
    "iplocation":   "📍",
    "track":        "📊",
}

_SCANNER_ICONS = {
    "xss":        "💉",
    "traversal":  "📂",
    "autoscan":   "⚡",
    "sqli":       "🗄",
    "clickjack":  "🖱",
    "csrf":       "🔄",
    "cmdi":       "💻",
}


def _build_menu_table() -> Table:
    """Build the module grid table with exactly 4 modules per column."""
    from rich import box

    table = Table(
        show_header=True,
        show_lines=False,
        box=box.ROUNDED,
        border_style="bright_cyan",
        header_style="bold bright_white",
        padding=(0, 1),
        expand=True,
        title="[bold bright_cyan][?] Select a Module >[/bold bright_cyan]",
        title_style="bold",
        title_justify="left",
    )

    # 5 columns: 4 modules each = 20 modules total
    headers = [
        "RECON [1-4]",
        "RECON [5-8]",
        "RECON [9-12]",
        "AUDIT [13-16]",
        "SCANNERS [17-20]",
    ]
    for h in headers:
        table.add_column(h, ratio=1, no_wrap=True)

    short_labels = {
        "1": "Subdomain",
        "2": "Port Scan",
        "3": "Mail Scrape",
        "4": "Login Find",
        "5": "Reg Finder",
        "6": "Param Find",
        "7": "Dorking",
        "8": "OSINT Human",
        "9": "OSINT Social",
        "10": "Web Monitor",
        "11": "WAF Check",
        "12": "IP Location",
        "13": "Pro Tracker",
        "14": "XSS Scanner",
        "15": "Path Trav",
        "16": "Auto Scan",
        "17": "SQLi Scan",
        "18": "Clickjacking",
        "19": "CSRF Check",
        "20": "CMD Inject",
    }

    num_rows = 4
    num_cols = 5

    for row_idx in range(num_rows):
        cells = []
        for col_idx in range(num_cols):
            module_idx = col_idx * num_rows + row_idx
            if module_idx < len(ALL_MODULES):
                mod = ALL_MODULES[module_idx]
                label = short_labels.get(mod.key, mod.label)
                cell = Text()
                cell.append(f"[{mod.key:>2}] ", style="bold bright_cyan")
                color = "bold green" if mod.group == "recon" else "bold red"
                cell.append(label, style=color)
                cells.append(cell)
            else:
                cells.append(Text(""))
        table.add_row(*cells)

    return table


def _render_status_bar(console: Console) -> None:
    """Print the bottom status bar with prompt and version."""
    bar = Text()
    bar.append("[+] Ready.", style="bold bright_green")
    bar.append("  |  ", style="dim")
    bar.append("Type a number (1-20) to select a module or ", style="dim white")
    bar.append("'exit'", style="bold bright_yellow underline")
    bar.append(" to quit.", style="dim white")

    version_tag = Text()
    version_tag.append("NEMESIS", style="bold bright_cyan")
    version_tag.append(f"  |  v{__version__}", style="dim cyan")

    # Use a grid to place status left and version right
    status_table = Table.grid(expand=True)
    status_table.add_column(ratio=3)
    status_table.add_column(ratio=1, justify="right")
    status_table.add_row(bar, version_tag)
    console.print(status_table)


def _prompt_input(prompt_text: str, required: bool = True, default: str = "") -> str:
    """Prompt the user for a text input with basic validation."""
    while True:
        suffix = f" [{default}]" if default else ""
        try:
            raw = input(f"  → {prompt_text}{suffix}: ").strip()
        except (EOFError, KeyboardInterrupt):
            raise KeyboardInterrupt
        value = raw or default
        if value or not required:
            return value
        print("    ⚠  This field is required. Please enter a value.")


def _collect_inputs(module: ModuleInfo, console: Console) -> dict[str, Any]:
    """Collect all required inputs for a module from the user."""
    from rich.panel import Panel

    header = Text()
    header.append("Module     : ", style="bold bright_cyan")
    header.append(f"{module.label}\n", style="bold white")
    header.append("Description: ", style="bold bright_cyan")
    header.append(f"{module.description}", style="dim white")

    tag_color = "bright_green" if module.group == "recon" else "bright_red"
    console.print()
    console.print(
        Panel(
            header,
            border_style=tag_color,
            title=f"[bold {tag_color}][ #{module.key} - {module.label} ][/bold {tag_color}]",
            title_align="left",
        )
    )

    inputs: dict[str, Any] = {}
    for prompt_spec in module.prompts:
        console.print(f"\n[bold bright_yellow]?[/bold bright_yellow] [bold white]{prompt_spec.label}[/bold white]")
        if prompt_spec.example:
            console.print(f"   [dim cyan]Example format →[/dim cyan] [bold bright_cyan]{prompt_spec.example}[/bold bright_cyan]")

        value = _prompt_input(
            "Enter value",
            required=prompt_spec.required,
            default=prompt_spec.default,
        )
        if value:
            inputs[prompt_spec.name] = value
    return inputs


def _resolve_choice(raw: str) -> ModuleInfo | None:
    """Match user input to a module by key number or slug prefix."""
    raw = raw.strip().lower()
    if not raw:
        return None

    # Exact key match (number)
    if raw in MODULE_BY_KEY:
        return MODULE_BY_KEY[raw]

    # Exact slug match
    if raw in MODULE_BY_SLUG:
        return MODULE_BY_SLUG[raw]

    # Fuzzy prefix match on slug or label
    candidates = [
        m for m in ALL_MODULES
        if m.slug.startswith(raw) or m.label.lower().startswith(raw)
    ]
    if len(candidates) == 1:
        return candidates[0]

    return None


def _dispatch_module(module: ModuleInfo, inputs: dict[str, Any], console: Console) -> None:
    """Execute a module and display results."""
    from .progress import run_with_progress

    # Scanner authorization gate
    if module.needs_auth:
        show_authorization_banner(console)
        console.print(
            "[bold yellow]⚠  This is an active scanner module. "
            "Only use on targets you own or have written permission to test.[/bold yellow]"
        )
        try:
            confirm = input("  → Type 'yes' to confirm authorization: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            raise KeyboardInterrupt
        if confirm not in ("yes", "y"):
            console.print("[red]Scan cancelled — authorization not confirmed.[/red]")
            return

    # Special case: pro_tracker is synchronous
    if module.slug == "track":
        from ..recon import pro_tracker
        target = inputs.get("target") or None
        pro_tracker.render_dashboard(target)
        return

    # Build kwargs for the module's run() function
    kwargs = _build_run_kwargs(module, inputs)

    # Determine the primary target string for output/persistence
    target = (
        inputs.get("domain")
        or inputs.get("url")
        or inputs.get("target")
        or inputs.get("username")
        or inputs.get("name")
        or "unknown"
    )

    # For parameter-dependent scanners, ensure there is an injectable parameter
    if module.slug in ("xss", "traversal", "sqli", "cmdi"):
        t = kwargs.get("target", "")
        if "?" not in t:
            default_param = "?file=test" if module.slug == "traversal" else "?q=test"
            kwargs["target"] = t.rstrip("/") + default_param
            console.print(f"[dim cyan]ℹ  No query param in URL — testing parameter '{kwargs['target']}'[/dim cyan]")

    started_at, timer = started_now()

    try:
        run_func = get_run_function(module.slug)
        findings = run_with_progress(
            run_func,
            console,
            description=f"Running {module.label}...",
            **kwargs,
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Module interrupted.[/yellow]")
        return
    except Exception as exc:
        console.print(f"\n[bold red]Error:[/bold red] {type(exc).__name__}: {exc}")
        return

    # Persist and display results
    try:
        finish(
            findings,
            target=target,
            module=module.slug,
            started_at=started_at,
            timer=timer,
            options=inputs,
            json_output=False,
            output=None,
            title=f"{module.label} — {target}",
        )
    except Exception:
        # If persistence fails, still show findings
        emit_findings(
            findings,
            target=target,
            module=module.slug,
            title=f"{module.label} — {target}",
        )


def _build_run_kwargs(module: ModuleInfo, inputs: dict[str, Any]) -> dict[str, Any]:
    """Map collected inputs to the actual run() function keyword arguments."""
    kwargs: dict[str, Any] = {}

    target = (
        inputs.get("domain")
        or inputs.get("url")
        or inputs.get("target")
        or inputs.get("username")
        or inputs.get("name")
        or ""
    )
    kwargs["target"] = target

    match module.slug:
        case "subdomain":
            pass
        case "portscan":
            if inputs.get("ports"):
                kwargs["ports"] = inputs["ports"]
            if inputs.get("scan_type"):
                kwargs["scan_type"] = inputs["scan_type"]
            if inputs.get("timing"):
                try:
                    kwargs["timing"] = int(inputs["timing"])
                except ValueError:
                    pass
            if inputs.get("service_detect"):
                val = str(inputs["service_detect"]).lower()
                kwargs["service_detect"] = val in ("y", "yes", "true", "1")
            if inputs.get("os_detect"):
                val = str(inputs["os_detect"]).lower()
                kwargs["os_detect"] = val in ("y", "yes", "true", "1")
        case "mailscrape":
            pass
        case "loginfind":
            pass
        case "registerfind":
            pass
        case "paramfind":
            pass
        case "dork":
            pass
        case "osinthuman":
            if inputs.get("name"):
                kwargs["name"] = inputs["name"]
            if inputs.get("username"):
                kwargs["username"] = inputs["username"]
            if inputs.get("email"):
                kwargs["email"] = inputs["email"]
        case "osintsocial":
            if inputs.get("username"):
                kwargs["username"] = inputs["username"]
        case "webmonitor":
            kwargs["once"] = True
        case "waf":
            pass
        case "iplocation":
            pass
        case "xss":
            kwargs["authorized"] = True
        case "traversal":
            kwargs["authorized"] = True
        case "autoscan":
            kwargs["authorized"] = True
        case "sqli":
            kwargs["authorized"] = True
        case "clickjack":
            kwargs["authorized"] = True
        case "csrf":
            kwargs["authorized"] = True
        case "cmdi":
            kwargs["authorized"] = True

    return kwargs


def show_menu(console: Console) -> None:
    """Display the cyberpunk module table and status bar."""
    console.print(_build_menu_table())
    console.print()
    _render_status_bar(console)


def interactive_loop(console: Console | None = None) -> None:
    """Main interactive menu loop — shows banner, presents menu, dispatches."""
    import sys
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    from .banner import show_banner

    con = console or Console(legacy_windows=False)
    show_banner(con)

    while True:
        show_menu(con)

        try:
            raw = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            con.print("\n[bold bright_cyan]Goodbye! 👋[/bold bright_cyan]")
            break

        if raw.lower() in ("q", "quit", "exit", "0"):
            con.print("[bold bright_cyan]Goodbye! 👋[/bold bright_cyan]")
            break

        if not raw:
            continue

        module = _resolve_choice(raw)
        if module is None:
            con.print(f"[red]Invalid selection: '{raw}'. Enter 1-20 or a module name.[/red]")
            continue

        try:
            inputs = _collect_inputs(module, con)
            _dispatch_module(module, inputs, con)
        except KeyboardInterrupt:
            con.print("\n[yellow]Returning to menu...[/yellow]")
            continue

        # After module completes, pause before returning to menu
        con.print()
        try:
            input("  Press Enter to return to menu...")
        except (EOFError, KeyboardInterrupt):
            con.print("\n[bold bright_cyan]Goodbye! 👋[/bold bright_cyan]")
            break
