"""Typer command-line entry point for Nemesis Toolkit.

Dual-mode operation:
  - ``nemesis`` (no subcommand)  → Interactive banner + two-column menu
  - ``nemesis recon subdomain -d ...`` → Direct CLI execution
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.markdown import Markdown
from rich.panel import Panel

from . import __version__
from .core.auth_gate import (
    is_authorized,
    show_authorization_banner,
)
from .core.config import get_settings
from .core.output import (
    console,
    emit_findings,
    err_console,
    error,
    print_json_stdout,
    status,
)
from .core.report import write_html_report
from .core.runner import fetch_async, finish, started_now
from .recon import (
    dorking,
    ip_location,
    login_finder,
    mail_scraper,
    nportscan,
    osint_human,
    osint_social,
    param_finder,
    pro_tracker,
    register_finder,
    subdomain,
    waf_check,
    web_monitor,
)
from .scanner import (
    auto_scan,
    clickjacking,
    cmd_inject,
    csrf,
    path_traversal,
    sql_injection as sqli,
    xss,
)

LEGAL = (
    "Authorized security testing only. Use this software exclusively against assets you own or "
    "have explicit written permission to test. Scanner modules detect and report indicators; they "
    "do not exploit or extract data."
)

app = typer.Typer(
    name="nemesis",
    help=(
        "Authorized-use reconnaissance and non-destructive vulnerability detection.\n\n"
        f"[bold yellow]{LEGAL}[/bold yellow]\n\n"
        "Run [bold]nemesis recon --help[/bold] or [bold]nemesis scan --help[/bold].\n\n"
        "Launch with no subcommand for the interactive menu."
    ),
    no_args_is_help=False,
    invoke_without_command=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)
recon_app = typer.Typer(
    help="Passive/active reconnaissance. Recon does not require the active-scan authorization gate.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
scan_app = typer.Typer(
    help="Active detection-only scanners. Requires --confirm-authorized or configuration approval.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
config_app = typer.Typer(
    help="Inspect configuration and data paths.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
app.add_typer(recon_app, name="recon")
app.add_typer(scan_app, name="scan")
app.add_typer(config_app, name="config")

JsonOpt = Annotated[bool, typer.Option("--json", help="Print machine-readable JSON to stdout.")]
OutputOpt = Annotated[
    Optional[Path], typer.Option("--output", "-o", help="Write JSON results to this file.")
]
AggressiveOpt = Annotated[
    bool,
    typer.Option(
        "--aggressive",
        help="Disable robots.txt and per-host rate limiting. Only for assets you are authorized to test.",
    ),
]
ConfirmOpt = Annotated[
    bool,
    typer.Option(
        "--confirm-authorized",
        help="Confirm that you own the target or have explicit written authorization to test it.",
    ),
]
ParamsOpt = Annotated[
    Optional[str],
    typer.Option("--params", help="Comma-separated input parameter names to test."),
]


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", help="Show version and exit."),
) -> None:
    if version:
        console.print(f"nemesis {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        # No subcommand → launch interactive mode
        _launch_interactive()


def _launch_interactive() -> None:
    """Start the interactive banner + menu loop."""
    from .ui.menu import interactive_loop
    try:
        interactive_loop(console)
    except KeyboardInterrupt:
        console.print("\n[bold green]Goodbye! 👋[/bold green]")
    raise typer.Exit()


def _scan_gate(confirm: bool) -> None:
    show_authorization_banner(err_console)
    if not is_authorized(confirm):
        error(
            "Active scanner refused: authorization was not confirmed. Re-run with "
            "--confirm-authorized only if you own this target or have written permission."
        )
        raise typer.Exit(code=2)


def _run(
    coro,
    *,
    target: str,
    module: str,
    options: dict[str, object],
    json_output: bool,
    output: Path | None,
    title: str,
) -> None:
    started_at, timer = started_now()
    findings = fetch_async(coro)
    finish(
        findings,
        target=target,
        module=module,
        started_at=started_at,
        timer=timer,
        options=options,
        json_output=json_output,
        output=output,
        title=title,
    )


# ---------------------------------------------------------------------------
# Recon commands
# ---------------------------------------------------------------------------


@recon_app.command("subdomain")
def recon_subdomain(
    domain: str = typer.Option(..., "-d", "--domain", help="Apex domain to enumerate."),
    wordlist: Optional[Path] = typer.Option(None, "--wordlist", help="DNS brute-force wordlist."),
    passive_only: bool = typer.Option(False, "--passive-only", help="Use only passive sources."),
    resolve: bool = typer.Option(True, "--resolve/--no-resolve", help="Resolve discovered hostnames."),
    concurrency: int = typer.Option(50, "--concurrency", min=1, max=200),
    aggressive: AggressiveOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Enumerate subdomains via crt.sh/optional APIs and DNS brute-force."""
    _run(
        subdomain.run(
            domain,
            wordlist=wordlist,
            passive_only=passive_only,
            resolve=resolve,
            concurrency=concurrency,
            aggressive=aggressive,
        ),
        target=domain,
        module="subdomain",
        options={
            "wordlist": str(wordlist) if wordlist else None,
            "passive_only": passive_only,
            "resolve": resolve,
            "concurrency": concurrency,
            "aggressive": aggressive,
        },
        json_output=json_output,
        output=output,
        title=f"Subdomains — {domain}",
    )


@recon_app.command("portscan")
def recon_portscan(
    target: str = typer.Option(..., "-t", "--target", help="Host or IP to scan."),
    ports: Optional[str] = typer.Option(None, "--ports", "-p", help="Port spec, e.g. 22,80,443 or 1-1024."),
    top_1000: bool = typer.Option(False, "--top-1000", help="Scan the top 1000 TCP ports."),
    fast_scan: bool = typer.Option(False, "-F", "--fast", help="Fast mode (top 100 ports)."),
    all_ports: bool = typer.Option(False, "--all-ports", help="Scan all 65535 ports."),
    scan_type: str = typer.Option("connect", "-s", "--scan-type", help="syn|connect|ack|window|maimon|null|fin|xmas|udp"),
    service_detect: bool = typer.Option(False, "-sV", "--service-detect", help="Banner/version detection (slower)."),
    os_detect: bool = typer.Option(False, "-O", "--os-detect", help="OS detection."),
    timing: int = typer.Option(3, "-T", "--timing", min=0, max=5, help="Timing template (0-5)."),
    concurrency: int = typer.Option(500, "--concurrency", min=1, max=1000),
    timeout: float = typer.Option(1.5, "--timeout", min=0.1, max=15.0),
    aggressive: AggressiveOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Advanced port scanner powered by the Nemesis C++ engine."""
    _run(
        nportscan.run(
            target,
            ports=ports,
            top_1000=top_1000,
            fast_scan=fast_scan,
            all_ports=all_ports,
            scan_type=scan_type,
            service_detect=service_detect,
            os_detect=os_detect,
            timing=timing,
            concurrency=concurrency,
            timeout=timeout,
            aggressive=aggressive,
        ),
        target=target,
        module="portscan",
        options={
            "ports": ports,
            "top_1000": top_1000,
            "fast_scan": fast_scan,
            "all_ports": all_ports,
            "scan_type": scan_type,
            "service_detect": service_detect,
            "os_detect": os_detect,
            "timing": timing,
            "concurrency": concurrency,
            "timeout": timeout,
            "aggressive": aggressive,
        },
        json_output=json_output,
        output=output,
        title=f"Open ports — {target}",
    )


@recon_app.command("mail")
def recon_mail(
    domain: str = typer.Option(..., "-d", "--domain", help="Domain whose public emails to discover."),
    sources: str = typer.Option("web,search", "--sources", help="Comma-separated: web,search."),
    breaches: bool = typer.Option(False, "--breaches/--no-breaches", help="Check emails against HIBP."),
    max_pages: int = typer.Option(20, "--max-pages", min=1, max=100),
    aggressive: AggressiveOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Crawl public pages and optional search APIs for published email addresses."""
    _run(
        mail_scraper.run(
            domain,
            sources=sources,
            check_breaches=breaches,
            max_pages=max_pages,
            aggressive=aggressive,
        ),
        target=domain,
        module="mail",
        options={"sources": sources, "breaches": breaches, "max_pages": max_pages, "aggressive": aggressive},
        json_output=json_output,
        output=output,
        title=f"Public emails — {domain}",
    )


@recon_app.command("loginfind")
def recon_loginfind(
    domain: str = typer.Option(..., "-d", "--domain", help="Base URL or domain."),
    extra_paths: Optional[Path] = typer.Option(None, "--paths", help="Additional path wordlist."),
    concurrency: int = typer.Option(10, "--concurrency", min=1, max=50),
    aggressive: AggressiveOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Probe common login paths and detect password forms."""
    _run(
        login_finder.run(
            domain,
            extra_paths=extra_paths,
            aggressive=aggressive,
            concurrency=concurrency,
        ),
        target=domain,
        module="loginfind",
        options={"extra_paths": str(extra_paths) if extra_paths else None, "concurrency": concurrency},
        json_output=json_output,
        output=output,
        title=f"Login endpoints — {domain}",
    )


@recon_app.command("registerfind")
def recon_registerfind(
    domain: str = typer.Option(..., "-d", "--domain", help="Base URL or domain."),
    extra_paths: Optional[Path] = typer.Option(None, "--paths", help="Additional path wordlist."),
    concurrency: int = typer.Option(10, "--concurrency", min=1, max=50),
    aggressive: AggressiveOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Probe common registration paths and detect signup forms."""
    _run(
        register_finder.run(
            domain,
            extra_paths=extra_paths,
            aggressive=aggressive,
            concurrency=concurrency,
        ),
        target=domain,
        module="registerfind",
        options={"extra_paths": str(extra_paths) if extra_paths else None, "concurrency": concurrency},
        json_output=json_output,
        output=output,
        title=f"Registration endpoints — {domain}",
    )


@recon_app.command("paramfind")
def recon_paramfind(
    url: str = typer.Option(..., "-u", "--url", help="Starting URL."),
    depth: int = typer.Option(2, "--depth", min=0, max=6),
    max_pages: int = typer.Option(30, "--max-pages", min=1, max=200),
    no_forms: bool = typer.Option(False, "--no-forms", help="Do not extract form fields."),
    aggressive: AggressiveOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Crawl same-host pages and enumerate URL/form parameters."""
    _run(
        param_finder.run(
            url,
            depth=depth,
            max_pages=max_pages,
            aggressive=aggressive,
            include_forms=not no_forms,
        ),
        target=url,
        module="paramfind",
        options={"depth": depth, "max_pages": max_pages, "include_forms": not no_forms},
        json_output=json_output,
        output=output,
        title=f"Parameters — {url}",
    )


@recon_app.command("dork")
def recon_dork(
    domain: str = typer.Option(..., "-d", "--domain", help="Domain to dork."),
    dork_file: Optional[Path] = typer.Option(None, "--dork-file", help="Custom dork templates ({domain})."),
    max_results: int = typer.Option(8, "--max-results", min=1, max=20),
    max_dorks: int = typer.Option(8, "--max-dorks", min=1, max=50),
    aggressive: AggressiveOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Run public-search dorks through your own SerpAPI/Google CSE credentials."""
    _run(
        dorking.run(
            domain,
            dork_file=dork_file,
            max_results=max_results,
            max_dorks=max_dorks,
            aggressive=aggressive,
        ),
        target=domain,
        module="dork",
        options={
            "dork_file": str(dork_file) if dork_file else None,
            "max_results": max_results,
            "max_dorks": max_dorks,
        },
        json_output=json_output,
        output=output,
        title=f"Dork results — {domain}",
    )


@recon_app.command("osinthuman")
def recon_osinthuman(
    name: Optional[str] = typer.Option(None, "--name", help="Full name (public search)."),
    email: Optional[str] = typer.Option(None, "--email", help="Email for optional HIBP checks."),
    username: Optional[str] = typer.Option(None, "--username", help="Username across platforms."),
    concurrency: int = typer.Option(8, "--concurrency", min=1, max=30),
    aggressive: AggressiveOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Aggregate already-public information about a person from explicit identifiers."""
    target = name or email or username or "osinthuman"
    _run(
        osint_human.run(
            target,
            name=name,
            email=email,
            username=username,
            aggressive=aggressive,
            concurrency=concurrency,
        ),
        target=target,
        module="osinthuman",
        options={"name": name, "email": email, "username": username},
        json_output=json_output,
        output=output,
        title=f"Public OSINT — {target}",
    )


@recon_app.command("osintsocial")
def recon_osintsocial(
    username: str = typer.Option(..., "-u", "--username", help="Public username/handle."),
    platforms: str = typer.Option(
        "github,gitlab,bitbucket,codeberg,reddit,medium,devto,keybase,hackernews,twitter,instagram,linkedin,tiktok",
        "--platforms",
        help="Comma-separated platform list.",
    ),
    concurrency: int = typer.Option(8, "--concurrency", min=1, max=30),
    aggressive: AggressiveOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Check public username availability across major platforms."""
    _run(
        osint_social.run(
            username=username,
            platforms=platforms,
            aggressive=aggressive,
            concurrency=concurrency,
        ),
        target=username,
        module="osintsocial",
        options={"platforms": platforms, "concurrency": concurrency},
        json_output=json_output,
        output=output,
        title=f"Public profiles — {username}",
    )


@recon_app.command("webmonitor")
def recon_webmonitor(
    urls: list[str] = typer.Option(..., "-u", "--url", help="URL to monitor; repeat for multiple."),
    interval: int = typer.Option(300, "--interval", min=5, help="Seconds between checks."),
    diff_content: bool = typer.Option(True, "--diff-content/--no-diff-content"),
    webhook: Optional[str] = typer.Option(None, "--webhook", help="POST JSON alerts to this webhook."),
    once: bool = typer.Option(False, "--once", help="Perform one check and exit."),
    aggressive: AggressiveOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Snapshot assets on an interval and report changes; initial check is always one-pass."""
    if once:
        _run(
            web_monitor.run(
                urls if len(urls) > 1 else urls[0],
                interval=interval,
                diff_content=diff_content,
                webhook=webhook,
                once=True,
                aggressive=aggressive,
            ),
            target=", ".join(urls),
            module="webmonitor",
            options={
                "interval": interval,
                "diff_content": diff_content,
                "webhook": bool(webhook),
                "once": True,
            },
            json_output=json_output,
            output=output,
            title="Web monitor",
        )
        return
    if json_output:
        error("--json streaming mode is not supported for a long-running monitor. Use --once for JSON.")
        raise typer.Exit(code=2)
    status(f"Monitoring {len(urls)} URL(s) every {interval}s. Press Ctrl+C to stop.")
    try:
        while True:
            started_at, timer = started_now()
            findings = fetch_async(
                web_monitor.run(
                    urls if len(urls) > 1 else urls[0],
                    interval=interval,
                    diff_content=diff_content,
                    webhook=webhook,
                    once=True,
                    aggressive=aggressive,
                )
            )
            if findings:
                finish(
                    findings,
                    target=", ".join(urls),
                    module="webmonitor",
                    started_at=started_at,
                    timer=timer,
                    options={"interval": interval, "diff_content": diff_content},
                    json_output=False,
                    output=output,
                    title=f"Web monitor — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                )
            else:
                status(f"[{datetime.now().strftime('%H:%M:%S')}] No changes detected.")
            time.sleep(interval)
    except KeyboardInterrupt:
        status("Stopping web monitor.")
        raise typer.Exit(code=0)


@recon_app.command("waf")
def recon_waf(
    url: str = typer.Option(..., "-u", "--url", help="Target URL."),
    aggressive: AggressiveOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Fingerprint a WAF/CDN using benign conventional probes."""
    _run(
        waf_check.run(url, aggressive=aggressive),
        target=url,
        module="waf",
        options={"aggressive": aggressive},
        json_output=json_output,
        output=output,
        title=f"WAF check — {url}",
    )


@recon_app.command("iplocation")
def recon_iplocation(
    target: str = typer.Option(..., "-t", "--target", help="IP address or hostname."),
    aggressive: AggressiveOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Geolocate an IP using MaxMind GeoLite2 or ipinfo.io."""
    _run(
        ip_location.run(target, aggressive=aggressive),
        target=target,
        module="iplocation",
        options={"aggressive": aggressive},
        json_output=json_output,
        output=output,
        title=f"IP location — {target}",
    )


@recon_app.command("track")
def recon_track(
    target: Optional[str] = typer.Option(None, "--target", help="Target whose history to show."),
    limit: int = typer.Option(500, "--limit", min=1, max=5000),
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Show the SQLite-backed history/timeline for a target or all targets."""
    payload = pro_tracker.payload(target, limit=limit)
    if output:
        try:
            output.expanduser().parent.mkdir(parents=True, exist_ok=True)
            import json

            output.expanduser().write_text(json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
            status(f"JSON history written to [bold]{output}[/bold]")
        except OSError as exc:
            error(f"Could not write {output}: {exc}")
    if json_output:
        print_json_stdout(payload)
    else:
        pro_tracker.render_dashboard(target, limit=limit)


# ---------------------------------------------------------------------------
# Scanner commands
# ---------------------------------------------------------------------------


@scan_app.command("xss")
def scan_xss(
    url: str = typer.Option(..., "-u", "--url", help="URL with an injectable query parameter."),
    params: ParamsOpt = None,
    dom: bool = typer.Option(False, "--dom/--no-dom", help="Enable static DOM-XSS sink heuristics."),
    aggressive: AggressiveOpt = False,
    confirm: ConfirmOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Detect reflected XSS indicators by injecting unique markers."""
    _scan_gate(confirm)
    _run(
        xss.run(
            url,
            params=params,
            check_dom=dom,
            aggressive=aggressive,
            authorized=True,
        ),
        target=url,
        module="xss",
        options={"params": params, "dom": dom, "aggressive": aggressive},
        json_output=json_output,
        output=output,
        title=f"XSS scan — {url}",
    )


@scan_app.command("traversal")
def scan_traversal(
    url: str = typer.Option(..., "-u", "--url", help="URL with an injectable file/path parameter."),
    params: ParamsOpt = None,
    aggressive: AggressiveOpt = False,
    confirm: ConfirmOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Detect local path traversal via known-file and error signatures."""
    _scan_gate(confirm)
    _run(
        path_traversal.run(
            url,
            params=params,
            aggressive=aggressive,
            authorized=True,
        ),
        target=url,
        module="traversal",
        options={"params": params, "aggressive": aggressive},
        json_output=json_output,
        output=output,
        title=f"Path traversal scan — {url}",
    )


@scan_app.command("sqli")
def scan_sqli(
    url: str = typer.Option(..., "-u", "--url", help="Target URL; inputs can come from query, body, cookies, or headers."),
    params: ParamsOpt = None,
    method: Optional[str] = typer.Option(None, "--method", help="GET or POST; defaults to POST when a body is supplied."),
    data: Optional[str] = typer.Option(None, "--data", help="Form values, such as 'id=1&name=book'."),
    json_data: Optional[str] = typer.Option(None, "--json-data", help="JSON request body to inspect."),
    xml_data: Optional[str] = typer.Option(None, "--xml-data", help="XML/SOAP request body to inspect."),
    cookie: Optional[str] = typer.Option(None, "--cookie", help="Cookie values, such as 'session=abc; theme=dark'."),
    header: Optional[list[str]] = typer.Option(None, "--header", help="Repeatable request header, such as 'Referer: https://example.com'."),
    concurrency: int = typer.Option(2, "--concurrency", min=1, max=3, help="Maximum parameter workers (1–3)."),
    aggressive: AggressiveOpt = False,
    confirm: ConfirmOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Check scoped GET/POST inputs for SQL/NoSQL error and boolean indicators."""
    _scan_gate(confirm)
    try:
        form_values = _parse_sqli_pairs(data, "&")
        cookies = _parse_sqli_pairs(cookie, ";")
        json_body = json.loads(json_data) if json_data is not None else None
        headers: dict[str, str] = {}
        for item in header or []:
            if ":" not in item:
                raise ValueError(f"Invalid header {item!r}; use 'Name: value'.")
            key, value = item.split(":", 1)
            headers[key.strip()] = value.strip()
    except (ValueError, json.JSONDecodeError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    if method and method.upper() not in {"GET", "POST"}:
        raise typer.BadParameter("--method must be GET or POST.")
    if sum((bool(form_values), json_data is not None, xml_data is not None)) > 1:
        raise typer.BadParameter("Choose only one body format: --data, --json-data, or --xml-data.")
    if method and method.upper() == "GET" and (form_values or json_data is not None or xml_data is not None):
        raise typer.BadParameter("Request bodies require --method POST.")
    _run(
        sqli.run(
            url,
            params=params,
            method=method,
            data=form_values,
            json_body=json_body,
            xml_body=xml_data,
            headers=headers,
            cookies=cookies,
            concurrency=concurrency,
            aggressive=aggressive,
            authorized=True,
        ),
        target=url,
        module="sqli",
        options={
            "params": params,
            "method": method,
            "form_fields": sorted(form_values),
            "json_body": json_data is not None,
            "xml_body": xml_data is not None,
            "cookie_names": sorted(cookies),
            "header_names": sorted(headers),
            "concurrency": concurrency,
        },
        json_output=json_output,
        output=output,
        title=f"SQL injection scan — {url}",
    )


def _parse_sqli_pairs(raw: str | None, separator: str) -> dict[str, str]:
    """Parse simple CLI key/value input without storing values in scan options."""
    if not raw:
        return {}
    output: dict[str, str] = {}
    for item in raw.split(separator):
        key, delimiter, value = item.strip().partition("=")
        if not delimiter or not key.strip():
            raise ValueError(f"Invalid key/value item {item!r}; use name=value.")
        output[key.strip()] = value
    return output


@scan_app.command("clickjack")
def scan_clickjack(
    url: str = typer.Option(..., "-u", "--url", help="Target URL."),
    poc: Optional[Path] = typer.Option(None, "--poc", help="Write a local PoC HTML file."),
    aggressive: AggressiveOpt = False,
    confirm: ConfirmOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Check X-Frame-Options and CSP frame-ancestors protections."""
    _scan_gate(confirm)
    _run(
        clickjacking.run(
            url,
            poc=poc,
            aggressive=aggressive,
            authorized=True,
        ),
        target=url,
        module="clickjack",
        options={"poc": str(poc) if poc else None, "aggressive": aggressive},
        json_output=json_output,
        output=output,
        title=f"Clickjacking check — {url}",
    )


@scan_app.command("csrf")
def scan_csrf(
    url: str = typer.Option(..., "-u", "--url", help="Page containing state-changing forms."),
    aggressive: AggressiveOpt = False,
    confirm: ConfirmOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Check POST forms for anti-CSRF tokens and SameSite cookies."""
    _scan_gate(confirm)
    _run(
        csrf.run(url, aggressive=aggressive, authorized=True),
        target=url,
        module="csrf",
        options={"aggressive": aggressive},
        json_output=json_output,
        output=output,
        title=f"CSRF check — {url}",
    )


@scan_app.command("cmdi")
def scan_cmdi(
    url: str = typer.Option(..., "-u", "--url", help="URL with an injectable query parameter."),
    params: ParamsOpt = None,
    time_based: bool = typer.Option(True, "--time-based/--no-time-based"),
    time_delay: float = typer.Option(3.0, "--time-delay", min=1.0, max=10.0),
    time_threshold: float = typer.Option(2.5, "--time-threshold", min=0.5, max=20.0),
    aggressive: AggressiveOpt = False,
    confirm: ConfirmOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Detect OS command injection with echo markers and sleep timing."""
    _scan_gate(confirm)
    _run(
        cmd_inject.run(
            url,
            params=params,
            time_based=time_based,
            time_delay=time_delay,
            time_threshold=time_threshold,
            aggressive=aggressive,
            authorized=True,
        ),
        target=url,
        module="cmdi",
        options={
            "params": params,
            "time_based": time_based,
            "time_delay": time_delay,
            "time_threshold": time_threshold,
        },
        json_output=json_output,
        output=output,
        title=f"Command injection scan — {url}",
    )


@scan_app.command("auto")
def scan_auto(
    domain: str = typer.Option(..., "-d", "--domain", help="Apex domain for the full assessment pipeline."),
    max_hosts: int = typer.Option(20, "--max-hosts", min=1, max=100),
    max_urls: int = typer.Option(40, "--max-urls", min=1, max=200),
    skip_portscan: bool = typer.Option(False, "--skip-portscan"),
    passive_only: bool = typer.Option(False, "--passive-only", help="Skip DNS brute-force."),
    time_based: bool = typer.Option(True, "--time-based/--no-time-based"),
    report: str = typer.Option("json", "--report", help="Output format: json or html."),
    aggressive: AggressiveOpt = False,
    confirm: ConfirmOpt = False,
    json_output: JsonOpt = False,
    output: OutputOpt = None,
) -> None:
    """Full pipeline: recon, ports, WAF, parameters, all detectors, and a report."""
    report = report.lower().strip()
    if report not in {"json", "html"}:
        raise typer.BadParameter("--report must be 'json' or 'html'.")
    _scan_gate(confirm)
    started_at, timer = started_now()
    findings = fetch_async(
        auto_scan.run(
            domain,
            authorized=True,
            max_hosts=max_hosts,
            max_urls=max_urls,
            skip_portscan=skip_portscan,
            passive_only=passive_only,
            aggressive=aggressive,
            time_based=time_based,
        )
    )
    finish(
        findings,
        target=domain,
        module="auto",
        started_at=started_at,
        timer=timer,
        options={
            "max_hosts": max_hosts,
            "max_urls": max_urls,
            "skip_portscan": skip_portscan,
            "passive_only": passive_only,
            "time_based": time_based,
            "aggressive": aggressive,
            "report": report,
        },
        json_output=json_output,
        output=output if report == "json" else None,
        title=f"Auto scan — {domain}",
    )
    if report == "html":
        summary = next(
            (finding for finding in findings if finding.type == "auto_scan_summary"), None
        )
        metadata = dict(summary.metadata) if summary else {}
        metadata["command"] = "nemesis scan auto"
        if output and str(output).lower().endswith(".html"):
            report_path = output
        elif output:
            report_path = Path(output)
        else:
            safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", domain)
            report_path = Path(f"auto_scan_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        try:
            write_html_report(
                findings,
                target=domain,
                output=report_path,
                metadata=metadata,
            )
        except OSError:
            raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Configuration commands
# ---------------------------------------------------------------------------


@config_app.command("show")
def config_show(
    json_output: JsonOpt = False,
) -> None:
    """Show effective settings with API keys and secrets redacted."""
    settings = get_settings()
    payload = settings.public_dict()
    paths = settings.resolved_paths()
    payload["paths"] = {key: str(value) for key, value in paths.items()}
    if json_output:
        print_json_stdout(payload)
        return
    from rich.table import Table

    table = Table(title="nemesis configuration", header_style="bold magenta", expand=True)
    table.add_column("Setting")
    table.add_column("Value")
    for key, value in payload.items():
        if key == "paths":
            continue
        table.add_row(key, str(value))
    console.print(table)
    console.print(
        f"Config file: [bold]{paths['config_path']}[/bold] "
        f"({'found' if paths['config_path'].exists() else 'not present'})"
    )
    console.print(f"Database: [bold]{paths['db_path']}[/bold]")
    console.print(f"Audit log: [bold]{paths['audit_log_path']}[/bold]")


def _configure_console_encoding() -> None:
    """Avoid crashes on legacy Windows code pages when results contain Unicode."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (LookupError, OSError, ValueError):
                pass


def main() -> None:
    _configure_console_encoding()
    app()


if __name__ == "__main__":
    main()
