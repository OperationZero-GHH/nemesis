#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════╗
║                         NEMESIS TOOLKIT                              ║
║         Cybersecurity Reconnaissance & Vulnerability Detection        ║
║                                                                       ║
║  Author : Shayan Ahmed                                                ║
║  GitHub : https://github.com/OperationZero-GHH                       ║
║  License: MIT — Authorized security testing only.                     ║
╚═══════════════════════════════════════════════════════════════════════╝

Run this file to launch the Nemesis Toolkit in interactive or direct mode.

Usage:
    nemesis                                    # Interactive cyberpunk menu
    python nemesis.py                          # Interactive cyberpunk menu
    python nemesis.py <module_#_or_name>       # Direct module run with prompts
    python nemesis.py 1 example.com            # Run subdomain on example.com
    python nemesis.py 2 127.0.0.1 80,443       # Run portscan on target
    python nemesis.py waf https://example.com  # Run WAF detection
    python nemesis.py xss https://target?q=x   # Run XSS scanner
    python nemesis.py track                    # Show Pro Tracker history
    python nemesis.py --help                   # Show advanced CLI options
"""

from __future__ import annotations

import os
import sys

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path so `nemesis_toolkit` is importable
# ---------------------------------------------------------------------------
_project_root = os.path.dirname(os.path.abspath(__file__))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


def _configure_windows_console() -> None:
    """Enable UTF-8 output on Windows consoles."""
    if os.name == "nt":
        for stream in (sys.stdout, sys.stderr):
            reconfigure = getattr(stream, "reconfigure", None)
            if callable(reconfigure):
                try:
                    reconfigure(encoding="utf-8", errors="replace")
                except (LookupError, OSError, ValueError):
                    pass


def _try_shorthand_execution(args: list[str]) -> bool:
    """Check if the CLI command is a direct shorthand (e.g. `nemesis 1 example.com`)."""
    if len(args) < 2:
        return False

    cmd = args[1].strip().lower()

    # Pass standard Typer commands through to Typer
    if cmd in ("-h", "--help", "-v", "--version", "recon", "scan", "config"):
        return False

    try:
        from rich.console import Console
        from nemesis_toolkit.ui.registry import MODULE_BY_KEY, MODULE_BY_SLUG, ALL_MODULES
        from nemesis_toolkit.ui.menu import _collect_inputs, _dispatch_module
    except ImportError:
        return False

    # Resolve module by number, slug, or label prefix
    module = MODULE_BY_KEY.get(cmd) or MODULE_BY_SLUG.get(cmd)
    if module is None:
        for m in ALL_MODULES:
            if m.slug.startswith(cmd) or m.label.lower().startswith(cmd):
                module = m
                break

    if module is None:
        return False

    console = Console(legacy_windows=False)

    # Shorthand target provided in CLI arguments
    target_arg = args[2] if len(args) > 2 else ""

    if target_arg:
        inputs: dict[str, str] = {}
        # Map target to first prompt name
        if module.prompts:
            first_name = module.prompts[0].name
            inputs[first_name] = target_arg

        # If portscan has ports specified in arg 3
        if module.slug == "portscan" and len(args) > 3:
            inputs["ports"] = args[3]

        _dispatch_module(module, inputs, console)
    else:
        # Prompt user with example formats
        inputs = _collect_inputs(module, console)
        _dispatch_module(module, inputs, console)

    return True


def main() -> None:
    """Entry point — handles shorthand commands and delegates to Typer."""
    _configure_windows_console()

    # Check for direct shorthand syntax: python nemesis.py 1 example.com
    try:
        if _try_shorthand_execution(sys.argv):
            return
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user. Exiting.")
        sys.exit(130)

    # Standard Typer CLI execution / Interactive menu
    try:
        from nemesis_toolkit.main import main as toolkit_main
        toolkit_main()
    except ImportError as exc:
        print(
            f"\n[!] Failed to import nemesis_toolkit: {exc}\n"
            f"\n    Make sure dependencies are installed:\n"
            f"        pip install -r requirements.txt\n"
            f"\n    Or install the package in editable mode:\n"
            f"        pip install -e .\n",
            file=sys.stderr,
        )
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user. Exiting.")
        sys.exit(130)


if __name__ == "__main__":
    main()
