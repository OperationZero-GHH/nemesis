"""Cyberpunk-styled ASCII banner with side-by-side info panel.

Renders:
  - Custom blocky NEMESIS ASCII art with 《 》decorative brackets (cyan)
  - Right-side info panel with GitHub, Instagram, Author (boxed)
  - Tagline and version below the banner
  - Animated loading spinner
"""

from __future__ import annotations

import time

from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group
from rich.panel import Panel
from rich.status import Status
from rich.table import Table
from rich.text import Text

from .. import __version__

# ── Custom ASCII art — blocky cyberpunk style ──────────────────────────
# Each line is carefully crafted for a menacing, angular look.
_NEMESIS_ART = r"""
 《  _   __________  _______________ _________   》
 《 / | / / ____/  |/  / ____/ ___//  _/ ___/   》
 《/  |/ / __/ / /|_/ / __/  \__ \ / / \__ \    》
 《   / / /___/ /  / / /___ ___/ // / ___/ /    》
 《/_/|_/_____/_/  /_/_____//____/___//____/     》
"""


def _render_ascii_art() -> Text:
    """Apply cyan gradient coloring to the ASCII art."""
    art = Text()
    for line in _NEMESIS_ART.strip().splitlines():
        for ch in line:
            if ch in ("《", "》"):
                art.append(ch, style="bold bright_yellow")
            elif ch in ("/", "\\", "|", "_"):
                art.append(ch, style="bold cyan")
            elif ch == " ":
                art.append(ch)
            else:
                art.append(ch, style="bold bright_cyan")
        art.append("\n")
    return art


def _render_info_panel() -> Panel:
    """Build the right-side info box with GitHub, Instagram, Author."""
    info = Text()
    # GitHub
    info.append("  ⬡  ", style="bold bright_cyan")
    info.append("GitHub     ", style="bold white")
    info.append(": ", style="dim")
    info.append("https://github.com/OperationZero-GHH\n", style="bold cyan underline")
    # Instagram
    info.append("  ◉  ", style="bold bright_magenta")
    info.append("Instagram  ", style="bold white")
    info.append(": ", style="dim")
    info.append("https://www.instagram.com/shayanahmed806\n", style="bold magenta underline")
    # Author
    info.append("\n")
    info.append("  👤 ", style="bold bright_yellow")
    info.append("Author / Owner : ", style="bold white")
    info.append("Shayan Ahmed", style="bold bright_yellow")

    return Panel(
        info,
        border_style="bright_cyan",
        padding=(0, 1),
        expand=True,
    )


def show_banner(console: Console | None = None) -> None:
    """Render the full startup banner sequence.

    Layout:
        ┌─ ASCII ART ──────────────────┐  ┌─ INFO PANEL ───────────────┐
        │  《 NEMESIS 》                │  │  GitHub: ...               │
        │                              │  │  Instagram: ...            │
        │                              │  │  Author: Shayan Ahmed      │
        └──────────────────────────────┘  └────────────────────────────┘
                Cybersecurity Reconnaissance & Vulnerability Detection
                                      v1.0
    """
    con = console or Console()
    con.clear()
    con.print()

    # ── Side-by-side: ASCII art (left) + Info panel (right) ──
    ascii_art = _render_ascii_art()
    info_panel = _render_info_panel()

    # Use a table to create the side-by-side layout
    layout = Table.grid(padding=(0, 2))
    layout.add_column(ratio=3)
    layout.add_column(ratio=2)
    layout.add_row(ascii_art, info_panel)
    con.print(layout)

    # ── Tagline and version ──
    tagline = Text()
    tagline.append("    Cybersecurity Reconnaissance & Vulnerability Detection\n", style="bold bright_cyan")
    tagline.append(f"    v{__version__}", style="dim cyan")
    con.print(tagline)
    con.print()

    # ── Loading spinner ──
    try:
        with Status(
            "[bold green]  Initializing modules...[/bold green]",
            spinner="dots",
            spinner_style="bright_green",
            console=con,
        ):
            time.sleep(1.0)
    except (UnicodeEncodeError, OSError):
        con.print("[bold green]  Initializing modules...[/bold green]")
        time.sleep(0.6)

    con.print()
