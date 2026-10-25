"""Module registry that maps menu keys to real run() functions.

Both the interactive menu and the direct typer CLI must call exactly the same
underlying module functions — this registry is the single source of truth.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Awaitable

from ..core.models import Finding


@dataclass(slots=True, frozen=True)
class ModuleInfo:
    """Metadata for one registered module."""

    key: str
    slug: str
    label: str
    group: str  # "recon" or "scanner"
    description: str
    needs_auth: bool
    # The prompts that the interactive menu should ask for this module
    prompts: list[PromptSpec]


@dataclass(slots=True, frozen=True)
class PromptSpec:
    """Describes one piece of user input the interactive menu should collect."""

    name: str
    label: str
    required: bool = True
    default: str = ""
    example: str = ""
    input_type: str = "text"  # "text", "confirm", "choice"
    choices: list[str] | None = None


# ---------------------------------------------------------------------------
# Module table — order determines display in the multi-column menu
# ---------------------------------------------------------------------------

RECON_MODULES: list[ModuleInfo] = [
    ModuleInfo(
        key="1", slug="subdomain", label="Subdomain Enumeration",
        group="recon", description="Enumerate subdomains via crt.sh, APIs, DNS brute-force",
        needs_auth=False,
        prompts=[
            PromptSpec("domain", "Target apex domain", example="example.com"),
        ],
    ),
    ModuleInfo(
        key="2", slug="portscan", label="Port Scanner",
        group="recon", description="C++ port scanner (SYN/Connect/ACK/UDP, OS & service detection)",
        needs_auth=False,
        prompts=[
            PromptSpec("target", "Target host or IP address", example="192.168.1.1 or scanme.nmap.org"),
            PromptSpec("ports", "Port spec (optional, press Enter for top 100)", required=False, default="", example="22,80,443 or 1-1000"),
            PromptSpec("scan_type", "Scan type", required=False, default="connect", input_type="choice", choices=["connect", "syn", "ack", "udp", "null", "fin", "xmas"]),
            PromptSpec("timing", "Timing template (0-5)", required=False, default="3", example="3=normal, 4=aggressive"),
            PromptSpec("service_detect", "Detect service & version?", required=False, default="n", input_type="confirm"),
            PromptSpec("os_detect", "Detect OS?", required=False, default="n", input_type="confirm"),
        ],
    ),
    ModuleInfo(
        key="3", slug="mailscrape", label="Mail Scraper",
        group="recon", description="Crawl and search for published email addresses",
        needs_auth=False,
        prompts=[
            PromptSpec("domain", "Target domain", example="example.com"),
        ],
    ),
    ModuleInfo(
        key="4", slug="loginfind", label="Login Page Finder",
        group="recon", description="Probe common auth paths and detect password forms",
        needs_auth=False,
        prompts=[
            PromptSpec("domain", "Target domain or base URL", example="https://example.com or example.com"),
        ],
    ),
    ModuleInfo(
        key="5", slug="registerfind", label="Register Page Finder",
        group="recon", description="Probe common signup/registration endpoints",
        needs_auth=False,
        prompts=[
            PromptSpec("domain", "Target domain or base URL", example="https://example.com or example.com"),
        ],
    ),
    ModuleInfo(
        key="6", slug="paramfind", label="Parameter Finder",
        group="recon", description="Crawl pages and enumerate URL/form parameters",
        needs_auth=False,
        prompts=[
            PromptSpec("url", "Starting URL to crawl", example="https://example.com/search or https://example.com/products"),
        ],
    ),
    ModuleInfo(
        key="7", slug="dork", label="Google Dorking",
        group="recon", description="Run search dorks via SerpAPI/Google CSE",
        needs_auth=False,
        prompts=[
            PromptSpec("domain", "Target domain", example="example.com"),
        ],
    ),
    ModuleInfo(
        key="8", slug="osinthuman", label="OSINT — Human",
        group="recon", description="Aggregate public info about a person",
        needs_auth=False,
        prompts=[
            PromptSpec("name", "Full name (optional)", required=False, example="John Doe"),
            PromptSpec("username", "Username/handle (optional)", required=False, example="johndoe"),
            PromptSpec("email", "Email address (optional)", required=False, example="john.doe@example.com"),
        ],
    ),
    ModuleInfo(
        key="9", slug="osintsocial", label="OSINT — Social Media",
        group="recon", description="Check username across major platforms",
        needs_auth=False,
        prompts=[
            PromptSpec("username", "Public username/handle to check", example="torvalds"),
        ],
    ),
    ModuleInfo(
        key="10", slug="webmonitor", label="Web Monitor",
        group="recon", description="Snapshot and diff web assets on interval",
        needs_auth=False,
        prompts=[
            PromptSpec("url", "Target URL to monitor", example="https://example.com"),
        ],
    ),
    ModuleInfo(
        key="11", slug="waf", label="WAF Check",
        group="recon", description="Fingerprint WAF/CDN with benign probes",
        needs_auth=False,
        prompts=[
            PromptSpec("url", "Target URL or domain", example="https://example.com or cloudflare.com"),
        ],
    ),
    ModuleInfo(
        key="12", slug="iplocation", label="IP Location",
        group="recon", description="Geolocate an IP via GeoLite2 or ipinfo.io",
        needs_auth=False,
        prompts=[
            PromptSpec("target", "IP address or hostname", example="8.8.8.8 or google.com"),
        ],
    ),
    ModuleInfo(
        key="13", slug="track", label="Pro Tracker / Dashboard",
        group="recon", description="View consolidated scan history for a target",
        needs_auth=False,
        prompts=[
            PromptSpec("target", "Target filter (optional, press Enter for all)", required=False, example="example.com"),
        ],
    ),
]

SCANNER_MODULES: list[ModuleInfo] = [
    ModuleInfo(
        key="14", slug="xss", label="XSS Scanner",
        group="scanner", description="Detect reflected XSS indicators via marker injection",
        needs_auth=True,
        prompts=[
            PromptSpec("url", "Target URL with query parameter", example="https://example.com/search?q=test"),
        ],
    ),
    ModuleInfo(
        key="15", slug="traversal", label="Path Traversal",
        group="scanner", description="Detect LFI via known-file and error signatures",
        needs_auth=True,
        prompts=[
            PromptSpec("url", "Target URL with file/path parameter", example="https://example.com/page?file=test"),
        ],
    ),
    ModuleInfo(
        key="16", slug="autoscan", label="Auto Scan (All Vulns)",
        group="scanner", description="Full pipeline: subdomains → ports → params → all scanners",
        needs_auth=True,
        prompts=[
            PromptSpec("domain", "Apex domain for full assessment", example="example.com"),
        ],
    ),
    ModuleInfo(
        key="17", slug="sqli", label="SQLi Scanner",
        group="scanner", description="Check scoped request inputs for SQL/NoSQL error and boolean indicators",
        needs_auth=True,
        prompts=[
            PromptSpec("url", "Target URL with an input to inspect", example="https://example.com/item?id=1"),
        ],
    ),
    ModuleInfo(
        key="18", slug="clickjack", label="Clickjacking",
        group="scanner", description="Check X-Frame-Options and CSP frame-ancestors",
        needs_auth=True,
        prompts=[
            PromptSpec("url", "Target URL to test", example="https://example.com or https://example.com/login"),
        ],
    ),
    ModuleInfo(
        key="19", slug="csrf", label="CSRF Checker",
        group="scanner", description="Check forms for anti-CSRF tokens and SameSite cookies",
        needs_auth=True,
        prompts=[
            PromptSpec("url", "Page URL with state-changing forms", example="https://example.com/settings"),
        ],
    ),
    ModuleInfo(
        key="20", slug="cmdi", label="Command Injection",
        group="scanner", description="Detect OS command injection with echo/sleep markers",
        needs_auth=True,
        prompts=[
            PromptSpec("url", "Target URL with query parameter", example="https://example.com/ping?ip=127.0.0.1"),
        ],
    ),
]

ALL_MODULES: list[ModuleInfo] = RECON_MODULES + SCANNER_MODULES

MODULE_BY_KEY: dict[str, ModuleInfo] = {m.key: m for m in ALL_MODULES}
MODULE_BY_SLUG: dict[str, ModuleInfo] = {m.slug: m for m in ALL_MODULES}


def get_run_function(slug: str) -> Callable[..., Awaitable[list[Finding]]]:
    """Lazily import and return the async run() function for a module slug.

    This keeps startup fast — modules are only imported when actually selected.
    """
    match slug:
        # Recon
        case "subdomain":
            from ..recon import subdomain
            return subdomain.run
        case "portscan":
            from ..recon import nportscan
            return nportscan.run
        case "mailscrape":
            from ..recon import mail_scraper
            return mail_scraper.run
        case "loginfind":
            from ..recon import login_finder
            return login_finder.run
        case "registerfind":
            from ..recon import register_finder
            return register_finder.run
        case "paramfind":
            from ..recon import param_finder
            return param_finder.run
        case "dork":
            from ..recon import dorking
            return dorking.run
        case "osinthuman":
            from ..recon import osint_human
            return osint_human.run
        case "osintsocial":
            from ..recon import osint_social
            return osint_social.run
        case "webmonitor":
            from ..recon import web_monitor
            return web_monitor.run
        case "waf":
            from ..recon import waf_check
            return waf_check.run
        case "iplocation":
            from ..recon import ip_location
            return ip_location.run
        case "track":
            from ..recon import pro_tracker
            return pro_tracker.render_dashboard  # special: not async
        # Scanners
        case "xss":
            from ..scanner import xss
            return xss.run
        case "traversal":
            from ..scanner import path_traversal
            return path_traversal.run
        case "autoscan":
            from ..scanner import auto_scan
            return auto_scan.run
        case "sqli":
            from ..scanner import sql_injection
            return sql_injection.run
        case "clickjack":
            from ..scanner import clickjacking
            return clickjacking.run
        case "csrf":
            from ..scanner import csrf
            return csrf.run
        case "cmdi":
            from ..scanner import cmd_inject
            return cmd_inject.run
        case _:
            raise ValueError(f"Unknown module slug: {slug!r}")
