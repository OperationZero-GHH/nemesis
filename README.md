# Nemesis Toolkit

> **Version 1.0.0** · Python 3.11+ · MIT License · Author: Shayan Ahmed

Nemesis is a modular offensive-security reconnaissance and vulnerability-scanning toolkit.
It bundles 20 modules (13 recon, 7 scanners) behind one command-line interface, with an
interactive menu, direct Typer subcommands, a shorthand launcher, JSON/table output,
SQLite persistence, and an optional native C++ port-scanning engine.

---

## ⚠️ Legal and Ethical Notice

Nemesis is intended **only** for authorized security testing, CTFs, lab environments,
and systems you own or have explicit written permission to test.

- Every scanner command requires explicit authorization confirmation.
- Unauthorized scanning is illegal in most jurisdictions and violates most terms of service.
- You are solely responsible for how you use this software.
- The author accepts no liability for misuse or damage.

Read [`LICENSE`](LICENSE) before use.

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Quick Start](#quick-start)
6. [Running Nemesis](#running-nemesis)
7. [Command Reference](#command-reference)
   - [Root commands](#root-commands)
   - [recon](#recon)
   - [scan](#scan)
   - [config](#config)
8. [Module Catalog](#module-catalog)
9. [Output Formats and Exit Codes](#output-formats-and-exit-codes)
10. [Configuration](#configuration)
11. [Environment Variables](#environment-variables)
12. [API Keys and External Services](#api-keys-and-external-services)
13. [Database and Logging](#database-and-logging)
14. [Architecture](#architecture)
15. [Native C++ Engine](#native-c-engine)
16. [Testing](#testing)
17. [Troubleshooting](#troubleshooting)
18. [Known Limitations](#known-limitations)
19. [License](#license)

---

## Overview

Nemesis gives you a single entry point for the whole recon-to-scan workflow:

- **Recon** - subdomain enumeration, certificate transparency, DNS brute-force,
  permutation generation in the Python API, AXFR/NSEC checks, cloud-bucket and takeover
  detection, HTTP crawling, login/registration/parameter discovery, WAF detection,
  email/OSINT collection,
  IP geolocation, web-change monitoring, and local scan history.
- **Scanning** — auto-pipeline orchestration, port scanning, service/version detection,
  XSS, path traversal, SQL/NoSQL injection, clickjacking, CSRF, and command-injection
  indicator checks.
- **Persistence** — every run can be stored in SQLite, with append-only JSONL audit logs
  and a run log.
- **Automation-friendly** — stable JSON schema, deterministic exit codes, environment-variable
  configuration, and a non-interactive `--json` mode.

---

## Features

| Area | What you get |
|---|---|
| Interface | Interactive numbered menu, direct subcommands, shorthand launcher |
| Modules | 20 built-in modules: 13 recon + 7 scanners |
| Output | Human-readable tables or machine-readable JSON |
| Storage | SQLite (`targets`, `scan_runs`, `findings`, `snapshots`) |
| HTTP | Rate limiting, retries, User-Agent rotation, optional `robots.txt` enforcement |
| DNS | Resolver selection, brute-force wordlists, Python-API permutations, AXFR, NSEC walking |
| Port scanning | Native C++ engine (pybind11), `nemesis-scan` binary, or asyncio fallback |
| Reports | JSON and HTML (HTML via `scan auto --report html`) |
| Safety | Mandatory authorization gates, audit trail, input validation |
| Platform | Windows, Linux, macOS |

---

## Requirements

### Runtime

| Requirement | Version / Notes |
|---|---|
| Python | **3.11 or newer** |
| pip | Recent version recommended |
| OS | Windows 10+, Linux, macOS 11+ |
| Disk | ~50 MB plus database/log growth |
| Network | Outbound DNS and HTTP(S) for most modules |

### Python dependencies

Installed automatically by `pip install -e .`:

- `typer`
- `httpx[http2]`
- `rich`
- `pydantic`
- `pydantic-settings[yaml]`
- `PyYAML`
- `dnspython`
- `beautifulsoup4`
- `Jinja2`
- `geoip2`
- `questionary`

Development extras (`pip install -e ".[dev]"`):

- `pytest`
- `pytest-asyncio`
- `respx`
- `pytest-httpserver`

Optional native build dependencies:

- CMake 3.20+
- A C++20 compiler (MSVC Build Tools, GCC, or Clang)
- `pybind11` (required only for the Python extension)

---

## Installation

> If you obtained a ZIP, extract it and run the commands from the project root.
> All paths below are relative to that directory.

### 1. Create and activate a virtual environment

**Windows (PowerShell)**

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

**Windows (cmd.exe)**

```bat
py -3.11 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
```

**Linux / macOS**

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

> If an existing `.venv` was copied from another machine, delete it and recreate it.
> Virtual environments are not portable across machines or Python installations.

### 2. Install the package

```bash
# Editable install (recommended for development)
pip install -e .

# With development/test tooling
pip install -e ".[dev]"

# Regular install
pip install .
```

### 3. Verify

```bash
nemesis --version
nemesis --help
nemesis-toolkit --version   # equivalent alias
```

Expected version: `1.0.0`. Both `nemesis` and `nemesis-toolkit` are installed console
scripts and run the same CLI.

### 4. Optional: build the native engine

See [Native C++ Engine](#native-c-engine) for full build instructions. Nemesis works
without it by falling back to a pure-Python asyncio scanner.

---

## Quick Start

```bash
# 1. Activate the environment
.\.venv\Scripts\Activate.ps1        # Windows
source .venv/bin/activate            # Linux/macOS

# 2. Launch the interactive menu
nemesis

# 3. Or run a recon module directly
nemesis recon subdomain -d example.com --json

# 4. Run a port scan
nemesis recon portscan -t 127.0.0.1 -F

# 5. Run the automated assessment pipeline (authorized targets only)
nemesis scan auto -d example.com --confirm-authorized --report html

# 6. Inspect effective configuration
nemesis config show --json
```

---

## Running Nemesis

There are three ways to drive Nemesis.

### 1. Interactive mode

```bash
nemesis
```

The menu lists all 20 modules with keys `1`–`20`:

- Enter a **number**, an **exact slug** (e.g. `portscan`), or a **unique prefix**
  of a label/slug.
- Scanner modules (`14`–`20`) require typing `yes` or `y` at the authorization prompt.
- Enter `q`, `quit`, `exit`, or `0` to leave.
- After each module run, press Enter to return to the menu.

### 2. Direct subcommands

```bash
nemesis recon <module> [MODULE_OPTIONS]
nemesis scan  <module> [MODULE_OPTIONS]
nemesis config show [OPTIONS]
```

Targets are supplied through module-specific options (`-d/--domain`, `-u/--url`,
`-t/--target`), not as positional arguments. Use `--help` at any level for the
authoritative option list:

```bash
nemesis --help
nemesis recon --help
nemesis scan --help
nemesis recon subdomain --help
nemesis recon portscan --help
nemesis scan auto --help
```

### 3. Shorthand launcher

The repository ships `nemesis.py` plus Windows launchers. Shorthand maps a menu key or
slug directly to a module:

```bash
python nemesis.py <key_or_slug> [target] [ports]
```

Examples:

```bash
python nemesis.py 1 example.com
python nemesis.py subdomain example.com
python nemesis.py portscan 127.0.0.1 80,443
python nemesis.py 2 127.0.0.1 22,80,443
```

Windows helpers:

```bat
nemesis.bat 1 example.com
```

```powershell
.\nemesis.ps1 1 example.com
```

> Shorthand is provided by the launcher scripts, **not** by the installed `nemesis`
> console script. Use `nemesis recon ...` / `nemesis scan ...` for the packaged entry point.

---

## Command Reference

### Conventions used below

- **Required** options have no default and must be supplied.
- Every command and subcommand supports `-h`/`--help`.
- `PATH` values are expanded with `~`.
- `--json` prints a single JSON document to **stdout**.
- `-o/--output` writes the same JSON payload to a file (in addition to normal console output,
  except where noted).
- `--aggressive` disables `robots.txt` enforcement and per-host rate limiting for that run.
  Only use it on assets you are authorized to test.
- Scanner commands always print the authorization banner, then require either
  `--confirm-authorized` or `authorized_by_default: true` in configuration.
- Repeated `--url` and `--header` options can be supplied multiple times.

### Root commands

```text
nemesis [OPTIONS] COMMAND [ARGS]...
```

| Command / option | Description |
|---|---|
| `nemesis` | No subcommand: launch the interactive menu. |
| `nemesis --version` | Print `nemesis 1.0.0` and exit. |
| `nemesis --install-completion` | Install shell completion for the current shell (Typer). |
| `nemesis --show-completion` | Print the shell completion script to stdout (Typer). |
| `nemesis -h`, `nemesis --help` | Show root help. |
| `nemesis recon ...` | Reconnaissance modules (no authorization gate). |
| `nemesis scan ...` | Active scanners (authorization gate). |
| `nemesis config ...` | Inspect configuration and paths. |

The root help also prints the legal notice. `nemesis recon --help` and
`nemesis scan --help` list their subcommands. Completion options are available only at
the root level, while `-h`/`--help` works on every command. The installed
`nemesis-toolkit` console script is an exact alias for `nemesis`.

### Interactive menu

Running `nemesis` with no subcommand starts the banner and multi-column menu.

**Selecting a module**

| Input | Behavior |
|---|---|
| `1` … `20` | Select by menu key. |
| Exact slug, e.g. `portscan` | Select by slug. |
| Unique prefix of a label or slug, e.g. `port` | Select if exactly one module matches. |
| `q`, `quit`, `exit`, `0` | Leave the menu. |

**Prompts**

- Optional prompts show a default in brackets; press Enter to accept it.
- Module inputs are collected as text. For the port-scan prompt, enter `y`/`yes` to
  enable service or OS detection; anything else leaves it disabled.
- Scanner modules (`14`–`20`) first show the authorization banner and require `yes` or `y`.
- For XSS, traversal, SQLi, and command-injection modules, if the supplied URL has no
  query string, the menu appends `?q=test` (or `?file=test` for traversal).
- After a module completes, press Enter to return to the menu.

### recon

```text
nemesis recon [OPTIONS] COMMAND [ARGS]...
```

`nemesis recon` with no subcommand shows help. Recon modules do **not** require the
active-scan authorization gate.

#### `recon subdomain`

```text
nemesis recon subdomain -d DOMAIN [OPTIONS]
```

Enumerate subdomains from certificate transparency (crt.sh) and optional APIs, plus
DNS brute-force unless `--passive-only` is used. Permutations are implemented in the
module's programmatic API (`permutations=True`) but are not exposed by the CLI.
Programmatic callers can enable them with
`await subdomain.run(domain, permutations=True)`.

| Option | Type / default | Description |
|---|---|---|
| `-d, --domain` | text, **required** | Apex domain to enumerate. |
| `--wordlist PATH` | path, none | Custom DNS brute-force wordlist. |
| `--passive-only` | flag, off | Skip DNS brute-force; in programmatic use this also disables permutations. AXFR, NSEC, cloud-bucket, and takeover checks still run. |
| `--resolve / --no-resolve` | bool, resolve on | Resolve discovered hostnames. |
| `--concurrency INT` | 50, range 1–200 | Concurrent resolution workers. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Write JSON results to a file. |

#### `recon portscan`

```text
nemesis recon portscan -t TARGET [OPTIONS]
```

Port scanner using the native C++ engine when available, then the `nemesis-scan`
binary, then an asyncio TCP-connect fallback.

| Option | Type / default | Description |
|---|---|---|
| `-t, --target` | text, **required** | Host or IP to scan. |
| `-p, --ports TEXT` | text, none | Port spec such as `22,80,443` or `1-1024`. |
| `--top-1000` | flag, off | Scan the top 1000 TCP ports. |
| `-F, --fast` | flag, off | Fast mode: top 100 ports. |
| `--all-ports` | flag, off | Scan all 65535 ports. |
| `-s, --scan-type TEXT` | `connect` | `syn`, `connect`, `ack`, `window`, `maimon`, `null`, `fin`, `xmas`, or `udp`. |
| `-sV, --service-detect` | flag, off | Banner/version detection (slower). |
| `-O, --os-detect` | flag, off | Request OS detection. Accepted but not implemented by the native engine. |
| `-T, --timing INT` | 3, range 0–5 | Timing template. |
| `--concurrency INT` | 500, range 1–1000 | Concurrent connection workers. |
| `--timeout FLOAT` | 1.5, range 0.1–15.0 | Per-connection timeout in seconds. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Write JSON results to a file. |

**Port selection precedence:** `--all-ports` > `-F/--fast` > `--ports` > `--top-1000`.
With none of these, the **top 100** ports are scanned. (`--ports` wins over
`--top-1000` when both are supplied.)

**Engine-specific behavior**

- `--timing` is forwarded only to the `nemesis-scan` binary. The pybind11 bridge uses
  the native engine's default timing, and the asyncio fallback ignores it.
- `--timeout` applies only to the asyncio fallback. Both native paths use internal
  timeouts (the binary derives its timeouts from the timing preset).
- `--scan-type` is accepted, but every engine currently performs TCP connect. The
  pybind11 bridge does not set `scan_type`; the binary passes `-sT` for `connect` and
  `-sS` for every other value; the asyncio fallback always connects.

> Only TCP connect is implemented in the native engine. Other scan types are accepted
> but ultimately use TCP connect. See [Native C++ Engine](#native-c-engine).

#### `recon mail`

```text
nemesis recon mail -d DOMAIN [OPTIONS]
```

Crawl public pages and optional search APIs for published email addresses.

| Option | Type / default | Description |
|---|---|---|
| `-d, --domain` | text, **required** | Domain whose public emails to discover. |
| `--sources TEXT` | `web,search` | Comma-separated sources: `web`, `search`. |
| `--breaches / --no-breaches` | bool, off | Check discovered emails against Have I Been Pwned. Requires `NEMESIS_HIBP_API_KEY`. |
| `--max-pages INT` | 20, range 1–100 | Maximum pages to crawl. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Write JSON results to a file. |

#### `recon loginfind`

```text
nemesis recon loginfind -d DOMAIN [OPTIONS]
```

Probe common authentication paths and detect password forms.

| Option | Type / default | Description |
|---|---|---|
| `-d, --domain` | text, **required** | Base URL or domain. |
| `--paths PATH` | path, none | Additional path wordlist. |
| `--concurrency INT` | 10, range 1–50 | Concurrent probes. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Write JSON results to a file. |

#### `recon registerfind`

```text
nemesis recon registerfind -d DOMAIN [OPTIONS]
```

Probe common signup/registration paths and detect signup forms.

| Option | Type / default | Description |
|---|---|---|
| `-d, --domain` | text, **required** | Base URL or domain. |
| `--paths PATH` | path, none | Additional path wordlist. |
| `--concurrency INT` | 10, range 1–50 | Concurrent probes. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Write JSON results to a file. |

#### `recon paramfind`

```text
nemesis recon paramfind -u URL [OPTIONS]
```

Crawl same-host pages and enumerate URL and form parameters.

| Option | Type / default | Description |
|---|---|---|
| `-u, --url` | text, **required** | Starting URL. |
| `--depth INT` | 2, range 0–6 | Crawl depth. |
| `--max-pages INT` | 30, range 1–200 | Maximum pages to crawl. |
| `--no-forms` | flag, off | Do not extract form fields. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Write JSON results to a file. |

#### `recon dork`

```text
nemesis recon dork -d DOMAIN [OPTIONS]
```

Run public-search dorks through your own SerpAPI or Google Custom Search credentials.

| Option | Type / default | Description |
|---|---|---|
| `-d, --domain` | text, **required** | Domain to dork. |
| `--dork-file PATH` | path, none | Custom dork templates. Use `{domain}` as the placeholder. |
| `--max-results INT` | 8, range 1–20 | Results per dork. |
| `--max-dorks INT` | 8, range 1–50 | Maximum dorks to run. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Write JSON results to a file. |

#### `recon osinthuman`

```text
nemesis recon osinthuman [OPTIONS]
```

Aggregate already-public information about a person from explicit identifiers.
Supply at least one of `--name`, `--email`, or `--username`. With none, the command
prints `Provide at least one of --name, --email or --username.` and exits with code 2
(no finding is recorded).

| Option | Type / default | Description |
|---|---|---|
| `--name TEXT` | text, none | Full name for public search. |
| `--email TEXT` | text, none | Email for optional HIBP checks. |
| `--username TEXT` | text, none | Username across platforms. |
| `--concurrency INT` | 8, range 1–30 | Concurrent lookups. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Write JSON results to a file. |

#### `recon osintsocial`

```text
nemesis recon osintsocial -u USERNAME [OPTIONS]
```

Check public username availability/profiles across major platforms.

| Option | Type / default | Description |
|---|---|---|
| `-u, --username` | text, **required** | Public username/handle. |
| `--platforms TEXT` | long default list | Comma-separated platforms. Default: `github,gitlab,bitbucket,codeberg,reddit,medium,devto,keybase,hackernews,twitter,instagram,linkedin,tiktok`. |
| `--concurrency INT` | 8, range 1–30 | Concurrent checks. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Write JSON results to a file. |

#### `recon webmonitor`

```text
nemesis recon webmonitor -u URL [-u URL ...] [OPTIONS]
```

Snapshot assets and report changes. The first check is always one-pass.

| Option | Type / default | Description |
|---|---|---|
| `-u, --url` | text, **required, repeatable** | URL to monitor. Repeat for multiple URLs. |
| `--interval INT` | 300, min 5 | Seconds between checks. |
| `--diff-content / --no-diff-content` | bool, diff on | Include a unified content diff in change evidence. Hashing always detects changes. |
| `--webhook TEXT` | URL, none | POST JSON alerts to this webhook. |
| `--once` | flag, off | Perform one check and exit. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--json` | flag, off | Machine-readable JSON. **Requires `--once`.** |
| `-o, --output PATH` | path, none | Write JSON results to a file. |

Without `--once`, Nemesis loops until `Ctrl+C`; `--json` is rejected with exit code 2.
In streaming mode, output is written when changes are detected.

#### `recon waf`

```text
nemesis recon waf -u URL [OPTIONS]
```

Fingerprint a WAF/CDN using benign conventional probes.

| Option | Type / default | Description |
|---|---|---|
| `-u, --url` | text, **required** | Target URL. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Write JSON results to a file. |

#### `recon iplocation`

```text
nemesis recon iplocation -t TARGET [OPTIONS]
```

Geolocate an IP using a local MaxMind GeoLite2 database or ipinfo.io.

| Option | Type / default | Description |
|---|---|---|
| `-t, --target` | text, **required** | IP address or hostname. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Write JSON results to a file. |

#### `recon track`

```text
nemesis recon track [OPTIONS]
```

Show the SQLite-backed history/timeline for one target or all targets.

| Option | Type / default | Description |
|---|---|---|
| `--target TEXT` | text, none | Target whose history to show; omit for all targets. |
| `--limit INT` | 500, range 1–5000 | Maximum historical findings to include. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Write JSON history to a file. |

This command reads the database directly and does not perform network activity. Its
JSON payload contains `target`, `targets`, `runs`, `severity_counts`, `findings`,
`run_count`, and `finding_count`. Without `--json`, it renders the dashboard; `-o` can
be combined with either mode. `--limit` caps only the returned findings; the scan
timeline always shows at most the 100 most recent runs, and `severity_counts` covers
all findings in the selected scope, not just the returned subset.

---

### scan

```text
nemesis scan [OPTIONS] COMMAND [ARGS]...
```

`nemesis scan` with no subcommand shows help. Every scanner:

1. Prints the authorization banner to stderr.
2. Refuses to run unless `--confirm-authorized` is supplied or
   `authorized_by_default: true` is set in configuration.
3. Runs **detection only** — no exploitation or data extraction.

A refusal exits with code **2**.

#### `scan xss`

```text
nemesis scan xss -u URL [OPTIONS]
```

Detect reflected XSS indicators by injecting unique markers into selected parameters.

| Option | Type / default | Description |
|---|---|---|
| `-u, --url` | text, **required** | URL with an injectable query parameter. |
| `--params TEXT` | text, none | Comma-separated parameter names to test. |
| `--dom / --no-dom` | bool, off | Enable static DOM-XSS sink heuristics. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--confirm-authorized` | flag, off | Confirm ownership or written authorization. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Write JSON results to a file. |

#### `scan traversal`

```text
nemesis scan traversal -u URL [OPTIONS]
```

Detect local file inclusion/path traversal using known-file and error signatures.

| Option | Type / default | Description |
|---|---|---|
| `-u, --url` | text, **required** | URL with an injectable file/path parameter. |
| `--params TEXT` | text, none | Comma-separated parameter names to test. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--confirm-authorized` | flag, off | Confirm ownership or written authorization. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Write JSON results to a file. |

#### `scan sqli`

```text
nemesis scan sqli -u URL [OPTIONS]
```

Check scoped GET/POST inputs for SQL/NoSQL error and boolean indicators.

| Option | Type / default | Description |
|---|---|---|
| `-u, --url` | text, **required** | Target URL. Inputs can come from query, body, cookies, or headers. |
| `--params TEXT` | text, none | Comma-separated input names to test, matched across query, form, JSON/XML, cookie, and header candidates. Names not present are added as query parameters with a placeholder value. |
| `--method TEXT` | none (auto) | Request method: `GET` or `POST`. Defaults to POST when a body is supplied. |
| `--data TEXT` | text, none | Form values, e.g. `'id=1&name=book'`. |
| `--json-data TEXT` | JSON text, none | JSON request body to inspect. |
| `--xml-data TEXT` | XML text, none | XML/SOAP request body to inspect. |
| `--cookie TEXT` | text, none | Cookie values, e.g. `'session=abc; theme=dark'`. |
| `--header TEXT` | text, **repeatable** | Request header in `Name: value` form. |
| `--concurrency INT` | 2, range 1–3 | Maximum parameter workers. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--confirm-authorized` | flag, off | Confirm ownership or written authorization. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Write JSON results to a file. |

**Validation rules**

- Only one body format may be supplied: `--data`, `--json-data`, or `--xml-data`.
- A request body requires POST; omit `--method` to select POST automatically, or pass
  `--method POST` explicitly. `--method GET` with a body is rejected.
- Every `--header` must contain `:`, otherwise the command exits with an invalid-parameter error.
- `--method` must be `GET` or `POST`.

#### `scan clickjack`

```text
nemesis scan clickjack -u URL [OPTIONS]
```

Check `X-Frame-Options` and CSP `frame-ancestors` protections.

| Option | Type / default | Description |
|---|---|---|
| `-u, --url` | text, **required** | Target URL. |
| `--poc PATH` | path, none | Write a local proof-of-concept HTML file. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--confirm-authorized` | flag, off | Confirm ownership or written authorization. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Write JSON results to a file. |

#### `scan csrf`

```text
nemesis scan csrf -u URL [OPTIONS]
```

Check same-origin state-changing `POST`, `PUT`, `PATCH`, and `DELETE` forms for
anti-CSRF tokens and `SameSite` cookie protections.

| Option | Type / default | Description |
|---|---|---|
| `-u, --url` | text, **required** | Page containing state-changing forms. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--confirm-authorized` | flag, off | Confirm ownership or written authorization. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Write JSON results to a file. |

#### `scan cmdi`

```text
nemesis scan cmdi -u URL [OPTIONS]
```

Detect OS command injection with echo markers and optional sleep timing.

| Option | Type / default | Description |
|---|---|---|
| `-u, --url` | text, **required** | URL with an injectable query parameter. |
| `--params TEXT` | text, none | Comma-separated parameter names to test. |
| `--time-based / --no-time-based` | bool, timing on | Enable sleep-based timing checks. |
| `--time-delay FLOAT` | 3.0, range 1.0–10.0 | Delay injected into the payload, in seconds. |
| `--time-threshold FLOAT` | 2.5, range 0.5–20.0 | Response-time threshold for a timing hit, in seconds. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--confirm-authorized` | flag, off | Confirm ownership or written authorization. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Write JSON results to a file. |

#### `scan auto`

```text
nemesis scan auto -d DOMAIN [OPTIONS]
```

Run a bounded assessment pipeline: subdomain enumeration → optional scan of ten common
web ports → reachability probe → WAF check → parameter discovery → XSS/traversal/CMDi/
SQLi checks on GET endpoints → clickjacking/CSRF checks → summary/report. It does not run
the other recon modules (`mail`, `dork`, `loginfind`, `registerfind`, `osinthuman`,
`osintsocial`, `webmonitor`, or `track`).

| Option | Type / default | Description |
|---|---|---|
| `-d, --domain` | text, **required** | Apex domain for the assessment. |
| `--max-hosts INT` | 20, range 1–100 | Maximum hosts to include. |
| `--max-urls INT` | 40, range 1–200 | Maximum GET endpoints to test. |
| `--skip-portscan` | flag, off | Skip the port-scanning stage. |
| `--passive-only` | flag, off | Skip DNS brute-force in the subdomain stage. |
| `--time-based / --no-time-based` | bool, timing on | Enable time-based checks. |
| `--report TEXT` | `json` (default) or `html` | Report format. |
| `--aggressive` | flag, off | Disable robots/rate limiting for this run. |
| `--confirm-authorized` | flag, off | Confirm ownership or written authorization. |
| `--json` | flag, off | Machine-readable JSON to stdout. |
| `-o, --output PATH` | path, none | Output path. JSON file for `--report json`; HTML report for `--report html`. |

**HTML report behavior**

- With `--report html -o report.html`, the report is written to `report.html`.
- Without `-o`, the filename is `auto_scan_<safe_domain>_<YYYYMMDD_HHMMSS>.html` in the
  current directory.
- If the HTML report cannot be written, the command exits with code 1.

### config

```text
nemesis config [OPTIONS] COMMAND [ARGS]...
```

#### `config show`

```text
nemesis config show [OPTIONS]
```

Show effective settings with API keys and secrets redacted, plus resolved data paths.

| Option | Type / default | Description |
|---|---|---|
| `--json` | flag, off | Print the configuration as JSON. |

The table view prints the config file, database, and audit log paths after the settings.
`--json` includes a `paths` object with `data_dir`, `db_path`, `audit_log_path`,
`run_log_path`, and `config_path`.

---

## Module Catalog

The interactive menu, shorthand launcher, and direct CLI all map to the same 20 modules.
Command names differ from interactive slugs in two cases: `mail` ↔ `mailscrape` and
`auto` ↔ `autoscan`.

| Key | Interactive slug | Direct command | Group | Purpose |
|---|---|---|---|---|
| 1 | `subdomain` | `recon subdomain` | Recon | Certificate transparency, APIs, DNS brute-force. |
| 2 | `portscan` | `recon portscan` | Recon | Native/fallback TCP port scanning and service banners. |
| 3 | `mailscrape` | `recon mail` | Recon | Public email discovery and optional breach checks. |
| 4 | `loginfind` | `recon loginfind` | Recon | Login-page and password-form discovery. |
| 5 | `registerfind` | `recon registerfind` | Recon | Registration/signup endpoint discovery. |
| 6 | `paramfind` | `recon paramfind` | Recon | URL and form parameter enumeration. |
| 7 | `dork` | `recon dork` | Recon | SerpAPI/Google CSE dorking. |
| 8 | `osinthuman` | `recon osinthuman` | Recon | Public person OSINT from supplied identifiers. |
| 9 | `osintsocial` | `recon osintsocial` | Recon | Username/profile checks across platforms. |
| 10 | `webmonitor` | `recon webmonitor` | Recon | Snapshot, diff, and webhook alerts. |
| 11 | `waf` | `recon waf` | Recon | WAF/CDN fingerprinting. |
| 12 | `iplocation` | `recon iplocation` | Recon | IP geolocation. |
| 13 | `track` | `recon track` | Recon | SQLite history dashboard. |
| 14 | `xss` | `scan xss` | Scanner | Reflected XSS indicator detection. |
| 15 | `traversal` | `scan traversal` | Scanner | Path traversal/LFI indicator detection. |
| 16 | `autoscan` | `scan auto` | Scanner | Bounded automated assessment pipeline. |
| 17 | `sqli` | `scan sqli` | Scanner | SQL/NoSQL injection indicators. |
| 18 | `clickjack` | `scan clickjack` | Scanner | Clickjacking header checks. |
| 19 | `csrf` | `scan csrf` | Scanner | CSRF token/SameSite checks. |
| 20 | `cmdi` | `scan cmdi` | Scanner | OS command injection indicators. |

### What each module checks

| Module | Data sources / techniques | Typical findings |
|---|---|---|
| `subdomain` | crt.sh, optional SecurityTrails/VirusTotal/Shodan, DNS brute-force, Python-API permutations, AXFR, NSEC walking, cloud buckets, takeover fingerprints | Hostnames, resolved IPs, dangling CNAMEs, cloud assets |
| `portscan` | Native C++ engine, `nemesis-scan`, asyncio TCP connect, banner grab | Open ports, service banners, versions |
| `mail` | Website crawl, optional search API, optional HIBP | Published emails, breach exposure |
| `loginfind` | Common auth paths, form analysis | Login pages, password fields |
| `registerfind` | Common signup paths, form analysis | Registration pages, signup fields |
| `paramfind` | Same-host crawl, URL parsing, form extraction | Query parameters, form fields |
| `dork` | SerpAPI or Google Custom Search | Indexed pages, exposed documents |
| `osinthuman` | Public search, optional HIBP, username checks | Public profiles and mentions |
| `osintsocial` | Public profile URLs | Existing/absent accounts |
| `webmonitor` | HTTP snapshots, content diff, webhook | Content changes |
| `waf` | Header/body/status fingerprints | WAF/CDN vendor |
| `iplocation` | MaxMind GeoLite2 or ipinfo.io | Country, region, city, ASN, coordinates |
| `track` | Local SQLite only | Run history, findings timeline, severity counts |
| `xss` | Marker injection, reflection analysis, static DOM sinks | Reflected/DOM XSS indicators |
| `traversal` | Traversal payloads, known-file and error signatures | LFI/path traversal indicators |
| `autoscan` | Subdomain, web-port, WAF, parameter, and detector stages, summary | Aggregated findings and report |
| `sqli` | Error and boolean-response indicators across query/body/cookie/header inputs | SQL/NoSQL injection indicators |
| `clickjack` | `X-Frame-Options`, CSP `frame-ancestors` | Missing/framing protections |
| `csrf` | State-changing forms (`POST`/`PUT`/`PATCH`/`DELETE`), token fields, cookie `SameSite` | Missing anti-CSRF defenses |
| `cmdi` | Echo markers, sleep timing | Command injection indicators |

---

## Output Formats and Exit Codes

### Human-readable tables

Without `--json`, findings are rendered as a Rich table:

| Column | Content |
|---|---|
| Severity | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`, color-coded. |
| Type | Finding type identifier. |
| URL | Affected URL, if any. |
| Param | Affected parameter, if any. |
| Confidence | `high`, `medium`, or `low`. |
| Evidence | Supporting evidence, truncated to 420 characters in the table. |

Rows are sorted by severity (critical first), then module, then type. A summary line
reports total findings and per-severity counts. When there are no findings, Nemesis prints
a short “no findings” message instead of an empty table.

### JSON output

`--json` prints exactly one JSON document to stdout. Status and error messages go to
stderr, so stdout remains machine-parseable. The standard payload below applies to all
module runs except `recon track` and `config show`, which use their own documented
payloads.

```json
{
  "target": "example.com",
  "module": "subdomain",
  "generated_at": "2026-10-26T12:34:56+00:00",
  "count": 1,
  "severity_counts": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 1
  },
  "findings": [
    {
      "target": "example.com",
      "module": "subdomain",
      "type": "subdomain_found",
      "severity": "info",
      "confidence": "high",
      "url": "https://www.example.com",
      "param": null,
      "evidence": "Resolved 203.0.113.10",
      "metadata": {},
      "timestamp": "2026-10-26T12:34:56+00:00"
    }
  ]
}
```

Top-level fields:

| Field | Description |
|---|---|
| `target` | Target supplied to the run. |
| `module` | Module identifier (e.g. `portscan`, `auto`). |
| `generated_at` | UTC timestamp with second precision. |
| `count` | Number of findings. |
| `severity_counts` | Always contains all five severity keys, zero-filled. |
| `findings` | Array of finding objects. |

Finding fields: `target`, `module`, `type`, `severity`, `confidence`, `url`, `param`,
`evidence`, `metadata`, `timestamp`. `url` and `param` may be `null`.

### File output

- `-o/--output` writes the same payload as pretty-printed UTF-8 JSON, creating parent
  directories as needed.
- In normal modules, a file-write failure prints an error but does not change the exit code.
- `scan auto --report html` writes an HTML report instead of JSON. See
  [`scan auto`](#scan-auto).

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success, including no findings and a clean `Ctrl+C` exit from web monitor. |
| `1` | General runtime error: unexpected exception, network/configuration failure, or HTML report write failure. |
| `2` | Authorization refusal, invalid parameter, invalid report format, invalid SQLi body combination, or `--json` used with a long-running web monitor. |
| `3` | `robots.txt` denied a request (when robots enforcement is enabled). |
| `130` | `Ctrl+C` during a normal module run. |
| Click usage code (`2`) | Missing required option, unknown command, or bad option type. |

### Persistence

After a module completes, results are written to SQLite and an audit event is recorded.
Persistence failures produce a warning but do not fail the run.

---

## Configuration

### Precedence

Settings are loaded from highest to lowest priority:

1. Explicit constructor arguments (programmatic use).
2. `NEMESIS_*` environment variables.
3. A `.env` file in the current working directory.
4. YAML configuration file.
5. File secrets source.

The YAML file is `~/.toolconfig.yaml` by default. Set `NEMESIS_CONFIG_FILE` to use a
different path:

```powershell
$env:NEMESIS_CONFIG_FILE = "C:\secure\nemesis.yaml"
```

```bash
export NEMESIS_CONFIG_FILE="$HOME/.config/nemesis/config.yaml"
```

`NEMESIS_CONFIG_FILE` is read before settings are constructed, so it cannot be set
inside the YAML file itself.

> The bundled `toolconfig.example.yaml` contains legacy `REDTEAM_*` comments. The
> implementation uses the `NEMESIS_` prefix exclusively. Copy the keys, not the
> prefix comments, and prefer `NEMESIS_*` variables.

### YAML example

```yaml
# ~/.toolconfig.yaml
authorized_by_default: false
respect_robots: true
requests_per_second: 10
timeout: 15
max_retries: 3
concurrency: 40          # accepted, currently unused by modules

data_dir: ~/.local/share/nemesis
db_path: null
audit_log_path: null
run_log_path: null

crawl_max_pages: 30      # accepted, currently unused by modules
crawl_depth: 2           # accepted, currently unused by modules

# Optional credentials
securitytrails_api_key: null
virustotal_api_key: null
shodan_api_key: null
censys_api_id: null
censys_api_secret: null
hibp_api_key: null
serpapi_key: null
google_cse_api_key: null
google_cse_cx: null
ipinfo_token: null

geoip_db_path: null
geoip_asn_db_path: null
```

YAML keys are the setting names exactly as listed below. Environment variables use the
same names uppercased with the `NEMESIS_` prefix.

### Settings reference

| Setting | Env variable | Default | Notes |
|---|---|---|---|
| `authorized_by_default` | `NEMESIS_AUTHORIZED_BY_DEFAULT` | `false` | Skips the per-run confirmation prompt for scanners. Enable only in a config file you control. |
| `respect_robots` | `NEMESIS_RESPECT_ROBOTS` | `false` | Enforce `robots.txt` for GET/HEAD requests. `--aggressive` disables it per run. |
| `requests_per_second` | `NEMESIS_REQUESTS_PER_SECOND` | `20.0` | Per-host request rate. Must be > 0. |
| `timeout` | `NEMESIS_TIMEOUT` | `10.0` | HTTP timeout in seconds. Must be > 0. |
| `max_retries` | `NEMESIS_MAX_RETRIES` | `2` | Retries for 429/5xx and transport errors, range 0–8. |
| `concurrency` | `NEMESIS_CONCURRENCY` | `50` | Accepted and validated (range 1–500) but currently unused; module CLI options control worker counts. |
| `data_dir` | `NEMESIS_DATA_DIR` | Platform-specific | Base directory for database and logs. |
| `db_path` | `NEMESIS_DB_PATH` | `<data_dir>/nemesis.db` | SQLite database path. |
| `audit_log_path` | `NEMESIS_AUDIT_LOG_PATH` | `<data_dir>/audit.jsonl` | Append-only JSONL audit log. |
| `run_log_path` | `NEMESIS_RUN_LOG_PATH` | `<data_dir>/runs.log` | Operational log file. |
| `crawl_max_pages` | `NEMESIS_CRAWL_MAX_PAGES` | `30` | Accepted and validated (range 1–1000) but currently unused; `--max-pages` options set module limits. |
| `crawl_depth` | `NEMESIS_CRAWL_DEPTH` | `2` | Accepted and validated (range 0–10) but currently unused; `paramfind --depth` sets crawl depth. |
| `user_agents` | `NEMESIS_USER_AGENTS` | 3 browser UAs | List of User-Agent strings. |
| `securitytrails_api_key` | `NEMESIS_SECURITYTRAILS_API_KEY` | none | Subdomain enrichment. |
| `virustotal_api_key` | `NEMESIS_VIRUSTOTAL_API_KEY` | none | Subdomain enrichment. |
| `shodan_api_key` | `NEMESIS_SHODAN_API_KEY` | none | Subdomain/host enrichment. |
| `censys_api_id` | `NEMESIS_CENSYS_API_ID` | none | Reserved; no module currently uses Censys. |
| `censys_api_secret` | `NEMESIS_CENSYS_API_SECRET` | none | Reserved; no module currently uses Censys. |
| `hibp_api_key` | `NEMESIS_HIBP_API_KEY` | none | Breach checks in `mail` and `osinthuman`. |
| `serpapi_key` | `NEMESIS_SERPAPI_KEY` | none | `dork` via SerpAPI. |
| `google_cse_api_key` | `NEMESIS_GOOGLE_CSE_API_KEY` | none | `dork` via Google Custom Search. |
| `google_cse_cx` | `NEMESIS_GOOGLE_CSE_CX` | none | Google Custom Search engine ID. |
| `ipinfo_token` | `NEMESIS_IPINFO_TOKEN` | none | `iplocation` fallback provider. |
| `geoip_db_path` | `NEMESIS_GEOIP_DB_PATH` | none | Local MaxMind GeoLite2 City `.mmdb`. |
| `geoip_asn_db_path` | `NEMESIS_GEOIP_ASN_DB_PATH` | none | Local MaxMind GeoLite2 ASN `.mmdb`. |

### Default data paths

| Platform | Data directory |
|---|---|
| Windows | `%LOCALAPPDATA%\nemesis` |
| Linux | `$XDG_DATA_HOME/nemesis`, or `~/.local/share/nemesis` |
| macOS | `$XDG_DATA_HOME/nemesis`, or `~/.local/share/nemesis` |

Resolved defaults:

- Database: `<data_dir>/nemesis.db`
- Audit log: `<data_dir>/audit.jsonl`
- Run log: `<data_dir>/runs.log`
- Config file: `~/.toolconfig.yaml` (unless overridden)

Run `nemesis config show` to see the effective values for your machine.

### `.env` example

```dotenv
NEMESIS_RESPECT_ROBOTS=true
NEMESIS_REQUESTS_PER_SECOND=5
NEMESIS_TIMEOUT=20
NEMESIS_SERPAPI_KEY=your-key
NEMESIS_HIBP_API_KEY=your-key
```

---

## Environment Variables

### Nemesis-specific variables

All settings in the table above are available as `NEMESIS_*` variables.
`NEMESIS_CONFIG_FILE` is read before the settings model is constructed; the other
variables map directly to settings:

| Variable | Purpose |
|---|---|
| `NEMESIS_CONFIG_FILE` | Path to the YAML configuration file (read outside the model). |
| `NEMESIS_DATA_DIR` | Overrides the data directory (also a normal setting). |

### Standard variables used by the runtime

| Variable | Purpose |
|---|---|
| `LOCALAPPDATA` | Windows base for the default data directory. |
| `XDG_DATA_HOME` | Linux/macOS base for the default data directory. |
| `HOME` / `USERPROFILE` | Used to resolve `~` and the default config path. |

### Setting lists in environment variables

For list-valued settings such as `user_agents`, use JSON syntax:

```dotenv
NEMESIS_USER_AGENTS=["Mozilla/5.0 (compatible; Nemesis/1.0)","Mozilla/5.0"]
```

---

## API Keys and External Services

All credentials are optional. Modules that need a missing key return an informational
finding or a clear error instead of crashing.

| Credential | Used by | Purpose |
|---|---|---|
| `securitytrails_api_key` | `subdomain` | Passive subdomain intelligence. |
| `virustotal_api_key` | `subdomain` | Passive subdomain intelligence. |
| `shodan_api_key` | `subdomain` | Passive host/subdomain intelligence. |
| `censys_api_id` + `censys_api_secret` | — | Reserved settings; no module currently calls Censys. |
| `hibp_api_key` | `mail`, `osinthuman` | Have I Been Pwned breach checks. |
| `serpapi_key` | `dork`, `mail`, `osinthuman` | Search results via SerpAPI. |
| `google_cse_api_key` + `google_cse_cx` | `dork`, `mail`, `osinthuman` | Search results via Google Custom Search. |
| `ipinfo_token` | `iplocation` | ipinfo.io lookups when no local MaxMind DB is configured. |
| `geoip_db_path` | `iplocation` | Local MaxMind GeoLite2 City database. |
| `geoip_asn_db_path` | `iplocation` | Local MaxMind GeoLite2 ASN database. |

`dork`, the search source of `mail`, and name searches in `osinthuman` work with
**either** SerpAPI **or** Google CSE (key + CX). Without credentials they emit a
configuration finding.

### Example credential setup

```yaml
# ~/.toolconfig.yaml
serpapi_key: "your-serpapi-key"
hibp_api_key: "your-hibp-key"
ipinfo_token: "your-ipinfo-token"
geoip_db_path: "C:/GeoLite2/GeoLite2-City.mmdb"
geoip_asn_db_path: "C:/GeoLite2/GeoLite2-ASN.mmdb"
```

Or with environment variables:

```powershell
$env:NEMESIS_SERPAPI_KEY = "your-serpapi-key"
$env:NEMESIS_HIBP_API_KEY = "your-hibp-key"
```

`nemesis config show` replaces configured secrets with `***configured***` and shows
`None` for missing values.

---

## Database and Logging

### SQLite database

Default location: `<data_dir>/nemesis.db`. The database is created automatically on
first use. It uses WAL journal mode and foreign keys.

| Table | Purpose | Key columns |
|---|---|---|
| `targets` | Unique targets seen. | `name`, `created_at`, `updated_at` |
| `scan_runs` | One row per module run. | `target`, `module`, `started_at`, `finished_at`, `status`, `options_json`, `result_count`, `duration_seconds` |
| `findings` | One row per finding. | `run_id`, `target`, `module`, `type`, `severity`, `confidence`, `url`, `param`, `evidence`, `metadata_json`, `created_at` |
| `snapshots` | Web-monitor content history. | `url`, `content_hash`, `content`, `created_at` |

Notes:

- `scan_runs.status` defaults to `running`; completed CLI runs are stored as `completed`.
- `options_json` records the module options; SQLi secret values (form values, cookie
  values, header values, bodies) are **not** stored, only field/header/cookie names.
- `snapshots` stores page content (up to 2,000,000 characters per snapshot). Treat the
  database as sensitive.
- The database is not encrypted.
- `recon track` reads these tables and renders a dashboard or JSON history.

### Audit log

Default: `<data_dir>/audit.jsonl`. Append-only JSON Lines. Every record contains
`timestamp`, `event`, and `module`, plus event-specific fields.

Recorded events include:

- `http_request` — method, redacted URL, status, duration, attempt, error.
- `robots_denied` — module, target, method.
- `network` — port-scan start/complete and related network actions.
- `authorization_confirmed` — module, target, and whether confirmation came from a
  flag or configuration.
- `module_completed` — finding count and duration.
- `waf_pacing_adjusted` — auto-scan pacing changes.

URLs are redacted before audit logging where the shared client handles them. Audit
write failures are ignored so a full disk cannot abort a scan.

### Run log

Default: `<data_dir>/runs.log`. Append-mode Python logging output with timestamps,
level, logger name, and message. It records completed runs and non-fatal module
warnings, such as a failed native scan falling back to Python.

### Log rotation

There is no built-in rotation. Archive or delete `audit.jsonl` and `runs.log`
periodically, and back up `nemesis.db` if you need history.

---

## Architecture

### Project layout

```text
Nemesis V1.0/
├── nemesis.py                 # Shorthand launcher
├── nemesis.bat                # Windows cmd launcher
├── nemesis.ps1                # Windows PowerShell launcher
├── pyproject.toml             # Packaging, dependencies, pytest/ruff config
├── requirements.txt
├── requirements-dev.txt
├── toolconfig.example.yaml    # Example config (legacy REDTEAM_ comments)
├── LICENSE
├── README.md
├── nemesis_toolkit/
│   ├── main.py                # Typer CLI: all commands and options
│   ├── core/
│   │   ├── apis.py            # HIBP and external API helpers
│   │   ├── auth_gate.py       # Authorization banner and enforcement
│   │   ├── config.py          # Pydantic settings and paths
│   │   ├── db.py              # SQLite schema and persistence
│   │   ├── http_client.py     # Async HTTP, retries, robots, rate limiting
│   │   ├── logging.py         # Audit JSONL and run logger
│   │   ├── models.py          # Finding dataclass
│   │   ├── output.py          # Table/JSON rendering
│   │   ├── report.py          # HTML report writer
│   │   ├── runner.py          # Async execution, persistence, exit codes
│   │   ├── search.py          # SerpAPI / Google CSE client
│   │   └── utils.py           # URL, domain, severity helpers
│   ├── recon/
│   │   ├── subdomain.py       # Orchestrates subdomain stages
│   │   ├── _subdomain_passive.py
│   │   ├── _subdomain_dns.py
│   │   ├── _subdomain_intel.py
│   │   ├── _subdomain_takeover.py
│   │   ├── nportscan.py       # Port-scan orchestration and fallbacks
│   │   ├── mail_scraper.py
│   │   ├── login_finder.py
│   │   ├── register_finder.py
│   │   ├── _endpoint_finder.py
│   │   ├── param_finder.py
│   │   ├── dorking.py
│   │   ├── osint_human.py
│   │   ├── osint_social.py
│   │   ├── _social.py
│   │   ├── web_monitor.py
│   │   ├── waf_check.py
│   │   ├── ip_location.py
│   │   └── pro_tracker.py
│   ├── scanner/
│   │   ├── auto_scan.py       # Pipeline orchestrator
│   │   ├── xss.py
│   │   ├── path_traversal.py
│   │   ├── sql_injection.py
│   │   ├── clickjacking.py
│   │   ├── csrf.py
│   │   ├── cmd_inject.py
│   │   └── _common.py
│   ├── ui/
│   │   ├── banner.py
│   │   ├── menu.py            # Interactive loop and dispatch
│   │   ├── progress.py
│   │   └── registry.py        # Single source of truth for 20 modules
│   ├── native/
│   │   ├── CMakeLists.txt
│   │   └── src/
│   │       ├── core/          # Config, engine, ports, targets, timing
│   │       ├── scanning/      # TCP connect implementation + factory
│   │       ├── detection/     # Service/version detector
│   │       ├── output/        # JSON output
│   │       ├── bindings/      # cli_main.cpp, python_module.cpp
│   │       └── platform/      # Winsock/POSIX shims
│   ├── templates/report.html.j2
│   └── data/top_1000_ports.txt
└── tests/
    ├── conftest.py
    ├── test_auth_gate.py
    ├── test_auto_scan.py
    ├── test_cli.py
    ├── test_config.py
    ├── test_db.py
    ├── test_http_client.py
    ├── test_output.py
    ├── test_recon_endpoints.py
    ├── test_recon_network.py
    └── test_scanners.py
```

### Execution flow

1. **Entry** — `nemesis` calls the Typer app; `python nemesis.py` may intercept a
   shorthand command first.
2. **Collection** — Typer validates options, or the interactive menu collects prompts.
3. **Authorization** — scanner commands print the banner and check
   `--confirm-authorized` / `authorized_by_default`. The module’s `run()` function
   enforces the same check again.
4. **Execution** — `runner.fetch_async` calls `asyncio.run()` on the module coroutine.
5. **HTTP** — modules use `AsyncHTTPClient`, which applies User-Agent rotation,
   per-host rate limiting, retries with backoff, optional robots enforcement, and
   audit logging.
6. **Findings** — every module returns `list[Finding]`, regardless of whether it is
   recon or a scanner.
7. **Persistence** — `runner.finish` writes a `scan_runs` row, its findings, updates
   the target, and emits audit events.
8. **Rendering** — `emit_findings` prints a Rich table or JSON, and optionally writes
   a JSON file.

### Design principles

- **Detection only** — scanners report indicators; they do not exploit, extract data,
  or chain vulnerabilities.
- **Single module registry** — `ui/registry.py` defines keys, slugs, labels, prompts,
  and authorization requirements for both the menu and shorthand.
- **Shared finding model** — recon and scanners produce the same structure, so output
  and history are uniform.
- **Graceful degradation** — missing API keys, native engine, or database produce
  warnings/info findings, not crashes.
- **Auditability** — every run and every outbound HTTP request is recorded locally.

---

## Native C++ Engine

Nemesis includes an optional C++20 port-scanning engine with two interfaces:

1. A **pybind11 Python extension** (`nemesis_scan`) loaded automatically by
   `nemesis recon portscan`.
2. A **standalone CLI binary** (`nemesis-scan`) that can be run directly.

If neither is available or both fail, the Python scanner falls back to an asyncio
TCP-connect implementation. No build is required for normal use.

### Current implementation status

| Feature | Status |
|---|---|
| TCP connect scan | **Implemented** and used for every scan type. |
| SYN, ACK, window, Maimon, NULL, FIN, Xmas, UDP, SCTP, idle, FTP bounce | **Placeholders** — the factory falls back to TCP connect. |
| Host discovery | **Not implemented** — hosts are assumed up. `-Pn` is accepted. |
| List scan (`-sL`) | Implemented (lists targets, no port scan). |
| Ping scan (`-sn`) | Implemented as “host up, no port scan.” |
| Service/version detection (`-sV`) | Implemented via the native service detector. |
| OS detection (`-O`) | **Not implemented** — the flag is accepted but produces no OS result. |
| Port specifications, top ports, fast mode, all ports | Implemented. |
| JSON output and finding JSON | Implemented. |
| Raw-socket privilege | Checked; raw techniques fall back to connect if unavailable. |

### Build prerequisites

- CMake **3.20+**
- A **C++20** compiler:
  - Windows: Visual Studio 2022 Build Tools (MSVC)
  - Linux: GCC 11+ or Clang 14+
  - macOS: Apple Clang 14+
- Python development headers and `pybind11` only if you want the Python extension.

### Build the standalone binary

**Windows (PowerShell)**

```powershell
cd nemesis_toolkit\native
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

**Linux / macOS**

```bash
cd nemesis_toolkit/native
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

The binary is written to `nemesis_toolkit/native/bin/nemesis-scan.exe` (Windows) or
`nemesis_toolkit/native/bin/nemesis-scan` (Linux/macOS). The Python bridge also checks
your `PATH`.

### Build the Python extension

```bash
python -m pip install pybind11
cd nemesis_toolkit/native
cmake -S . -B build -Dpybind11_DIR="$(python -m pybind11 --cmakedir)"
cmake --build build --config Release
```

The extension is written into `nemesis_toolkit/native/` and imported as
`nemesis_toolkit.native.nemesis_scan`. Re-run the build after changing C++ sources.

Verify:

```bash
python -c "from nemesis_toolkit.native import nemesis_scan; print(nemesis_scan.NemesisScanEngine.version())"
```

### How the Python scanner selects an engine

`nemesis recon portscan` tries, in order:

1. Native pybind11 extension.
2. `nemesis-scan` binary (bundled path, then `PATH`).
3. asyncio TCP-connect fallback.

The chosen engine is recorded in the audit log as `scanner=native-c++`,
`scanner=nemesis-scan`, or `scanner=asyncio`. A failure in one layer is logged and the
next layer is tried.

### Standalone `nemesis-scan` CLI

```text
nemesis-scan [options] <target(s)>
```

Targets may be hostnames, IP addresses, or CIDR ranges.

| Option | Description |
|---|---|
| `<target> ...` | One or more targets. |
| `-iL FILE` | Read targets from a file. |
| `--exclude HOST` | Exclude one host or network. Repeat the flag for multiple. |
| `-sL` | List scan: list targets without scanning ports. |
| `-sn` | Ping scan: mark hosts up, skip port scanning. |
| `-Pn` | Treat all hosts as online; skip discovery. |
| `-sS`, `--syn` | TCP SYN scan (currently falls back to connect). |
| `-sT`, `--connect` | TCP connect scan. |
| `-sA`, `--ack` | TCP ACK scan (currently falls back to connect). |
| `-sU`, `--udp` | UDP scan (currently falls back to connect). |
| `-sN`, `--null` | TCP NULL scan (currently falls back to connect). |
| `-sF`, `--fin` | TCP FIN scan (currently falls back to connect). |
| `-sX`, `--xmas` | TCP Xmas scan (currently falls back to connect). |
| `-p SPEC` | Port spec, e.g. `-p 22,80,443` or `-p 1-1024`. Supports `T:`/`U:` prefixes. |
| `-pSPEC` | Attached form, e.g. `-p22,80`. |
| `-p-` | Scan all 65535 ports. |
| `-F` | Fast mode: top 100 ports. |
| `--top-ports N` | Scan the N most common ports. |
| `-r` | Do not randomize port order. |
| `-sV` | Service/version detection. |
| `--version-intensity LEVEL` | **Advertised in help but not parsed/wired.** |
| `-O` | Request OS detection. **Not implemented.** |
| `-T0` … `-T5` | Timing template (attached form only). |
| `--max-retries N` | **Advertised in help but not parsed/wired.** |
| `--concurrency N` | Maximum concurrent probes (default 500). |
| `-oJ FILE` | Write full scan JSON to a file. |
| `--findings` | Print a Nemesis finding JSON array to stdout. |
| `--json` | Print the full `ScanResult` JSON to stdout. |
| `-v` | Increase verbosity (progress output). |
| `-vv` | Increase verbosity by two. Implemented but not listed in help. |
| `-h`, `--help` | Show help and exit. |

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Scan completed or help shown. |
| `1` | No targets supplied. |
| `2` | Fatal scan error. |

Examples:

```bash
nemesis-scan -sT -p 22,80,443 -sV 192.0.2.10
nemesis-scan -F --findings example.com
nemesis-scan -p- --concurrency 1000 -oJ full.json 192.0.2.0/24
nemesis-scan -iL targets.txt --exclude 192.0.2.5
nemesis-scan -sL 192.0.2.0/24
```

> Despite the help text, the standalone parser does **not** implement
> `--version-intensity` or `--max-retries`. Use the Python API for `version_intensity`,
> and note that the current engine does not use retry counts.

### Programmatic port-scan options

`nemesis_toolkit.recon.nportscan.run()` accepts additional keyword arguments that are
not exposed by the Typer command:

`top_ports`, `randomize_ports`, `custom_flags`, `zombie_host`, `discovery`,
`version_intensity`, `scripts`, `script_args`, `max_retries`, `host_timeout`, `min_rate`,
`max_rate`, `fragment`, `decoys`, `source_ip`, `source_port`, `spoof_mac`, `mtu`,
`data_length`, `bad_checksum`, `randomize_hosts`, `output_format`, `show_reason`,
`traceroute`, `packet_trace`.

Only a subset is currently wired into the scanning path: `ports`, `top_ports`,
`fast_scan`, `all_ports`, `scan_type`, `service_detect`, `version_intensity`,
`os_detect`, `discovery`, `concurrency`, `timeout`, and `aggressive`. The rest are
accepted for API compatibility and future engine work but do not currently change scan
behavior. `scan_type` resolves to TCP connect on every engine, and `timeout` is honored
only by the asyncio fallback; see [`recon portscan`](#recon-portscan).

---

## Testing

### Install test dependencies

```bash
pip install -e ".[dev]"
```

### Run the suite

```bash
python -m pytest
```

Useful variants:

```bash
python -m pytest -v
python -m pytest tests/test_cli.py
python -m pytest tests/test_scanners.py -v
python -m pytest -k "xss or sqli"
```

### What the tests cover

The suite contains **75 test functions across 10 files**:

| File | Focus |
|---|---|
| `test_auth_gate.py` | Banner, authorization flag/config, module-level enforcement. |
| `test_auto_scan.py` | Pipeline aggregation and summary. |
| `test_cli.py` | Root/recon/scan/config commands and exit behavior. |
| `test_config.py` | Settings precedence, paths, redaction. |
| `test_db.py` | Schema, persistence, snapshots. |
| `test_http_client.py` | Retries, robots, rate limiting, audit. |
| `test_output.py` | JSON payload and rendering. |
| `test_recon_endpoints.py` | Login/register/parameter discovery. |
| `test_recon_network.py` | Subdomain, DNS, WAF, port scan, monitor. |
| `test_scanners.py` | XSS, traversal, SQLi, clickjacking, CSRF, command injection. |

Tests use a local `ThreadingHTTPServer` fixture and isolated temporary data
directories. They do not require live external targets, API keys, or a built native
engine. `pytest-asyncio` runs in `auto` mode, and `-ra` is enabled by default.

### Linting

Ruff is configured for Python 3.11 with a 110-character line length:

```bash
pip install ruff
ruff check .
```

Ruff is not included in the `dev` extra.

---

## Troubleshooting

### `Python 3.11 or newer is required`

Check the interpreter used inside the virtual environment:

```bash
python --version
```

If it reports 3.10 or older, create the environment with an explicit 3.11+ interpreter:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python --version
```

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python --version
```

### `nemesis` is not recognized

- Activate the virtual environment first.
- Or run the module directly:

```bash
python -m nemesis_toolkit.main --help
```

- Or run the launcher:

```bash
python nemesis.py --help
```

- On Windows, the console script lives at `.venv\Scripts\nemesis.exe`.
- The equivalent `nemesis-toolkit` command is installed alongside it; try
  `.venv\Scripts\nemesis-toolkit.exe` if `nemesis` is shadowed.

### PowerShell blocks `Activate.ps1`

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then reopen PowerShell and activate again.

### The existing `.venv` is broken

Virtual environments are machine-specific. Delete and recreate it:

```powershell
Remove-Item -Recurse -Force .venv
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

```bash
rm -rf .venv
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

### `ModuleNotFoundError: nemesis_toolkit`

Install the package in the active environment:

```bash
pip install -e .
```

If you are running `python nemesis.py` from another directory, use the absolute path to
the script or install the package.

### Garbled Unicode on Windows

Nemesis reconfigures stdout/stderr to UTF-8, but legacy consoles may still struggle.
Try:

```powershell
$env:PYTHONUTF8 = "1"
chcp 65001
```

### `pytest` is not installed

```bash
pip install -e ".[dev]"
```

### `robots.txt disallows ...` (exit code 3)

Robots enforcement is enabled (usually `respect_robots: true`). Either:

- Leave it enabled and target paths that are allowed, or
- Re-run with `--aggressive` **only if you are authorized** to ignore robots.

### A module reports a missing API key

Configure the key in `~/.toolconfig.yaml` or as a `NEMESIS_*` environment variable. See
[API Keys and External Services](#api-keys-and-external-services).

### Configuration changes are not picked up

- Check what is actually loaded:

```bash
nemesis config show --json
```

- Remember precedence: environment variables override `.env`, which overrides YAML.
- `NEMESIS_CONFIG_FILE` must point to the intended YAML file.
- Settings are cached for the life of a process; start a new command after editing.

### `--json` is rejected by web monitor

Long-running monitoring cannot emit a single JSON document. Add `--once`:

```bash
nemesis recon webmonitor -u https://example.com --once --json
```

### Port scan is slow or times out

- Reduce the port set: `-F` (top 100) or `--ports 22,80,443`.
- Raise `--concurrency` (maximum 1000). For scans above 5000 ports, values above 500
  are automatically reduced to 500.
- Lower `--timeout` for local networks (asyncio fallback only; native paths use their
  timing preset).
- Build the native engine for better throughput.
- Check firewall/egress rules; filtered ports wait for timeouts.

### Native build fails

The native engine is optional. Confirm:

- CMake is 3.20 or newer.
- The compiler supports C++20.
- On Windows, run the build from a Developer PowerShell for VS, or ensure MSVC is
  installed.
- For the Python extension, `pybind11_DIR` points to the correct CMake package.

If it still fails, skip it; the asyncio fallback works without a compiler.

### Database is locked

Nemesis uses WAL mode and a 20-second SQLite timeout. If a lock persists, close other
Nemesis processes or tools holding `nemesis.db`, then retry. Do not delete the database
while a scan is running.

### Scanners report nothing on a real target

Detection is heuristic and intentionally conservative:

- Confirm the URL actually has an injectable parameter, or pass `--params`.
- Try `--aggressive` only on authorized targets.
- Check WAF blocking and response filtering.
- Increase `NEMESIS_TIMEOUT` for slow targets.
- Review the JSON `evidence` and `confidence` fields rather than relying on severity alone.

### False positives

All scanner results are indicators, not proof. Manually verify any finding before
reporting or acting on it. Use the `confidence` and `evidence` fields to prioritize.

---

## Known Limitations

- **Detection only.** No exploitation, credential attacks, data extraction, or
  vulnerability chaining.
- **Native engine is TCP-connect only.** SYN/ACK/UDP/NULL/FIN/Xmas and other techniques
  are accepted but fall back to TCP connect.
- **No OS detection.** `-O` / `--os-detect` is accepted but not implemented.
- **No host discovery.** Hosts are assumed online; `-Pn` has no practical effect.
- **Standalone CLI gaps.** `--version-intensity` and `--max-retries` appear in help but
  are not wired; `-vv` works but is not listed.
- **Censys settings are unused.** `censys_api_id` and `censys_api_secret` are reserved.
- **Some global settings are unused.** `concurrency`, `crawl_max_pages`, and
  `crawl_depth` are accepted and validated but are not read by any current module.
  Module-specific options govern worker counts and crawl limits.
- **Auto-scan scope.** It runs subdomain enumeration, a ten-port web scan, WAF and
  parameter discovery, four parameter detectors, and clickjacking/CSRF checks. It only
  tests GET parameterized endpoints, does not run the other recon modules, and is not an
  exhaustive crawl or authenticated assessment.
- **Shorthand is limited.** `python nemesis.py` maps only the first prompt (plus
  port-scan ports); other options use module defaults. Full control requires the
  `nemesis recon` / `nemesis scan` commands.
- **No proxy or upstream-auth support** is exposed by the CLI.
- **No scheduling or distributed scanning.** Only `webmonitor` loops internally.
- **SQLite is unencrypted.** Snapshots may contain full page content; protect the data
  directory.
- **No log rotation.** Audit and run logs grow until you archive them.
- **Example config drift.** `toolconfig.example.yaml` uses legacy `REDTEAM_*` comments;
  the runtime prefix is `NEMESIS_`.
- **Tests are local-only.** They validate behavior against a controlled fixture, not
  every real-world WAF, framework, or network condition.
- **Native binaries are not bundled in this source checkout.** Build them if you want
  the native path.

---

## License

MIT License. See [`LICENSE`](LICENSE) for the full text.

Copyright © 2024–2026 Shayan Ahmed.

Project repository referenced by the launcher banner:
`https://github.com/OperationZero-GHH`

---

<p align="center">
  <strong>Nemesis Toolkit v1.0.0</strong><br>
  Authorized security testing only.
</p>
