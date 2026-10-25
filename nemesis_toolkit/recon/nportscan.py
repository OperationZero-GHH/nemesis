"""Nemesis Port Scanner — Python bridge to the high-performance C++ scanning engine.

Supports native C++ extension (_engine), standalone nemesis-scan binary subprocess,
and built-in async fallback for uninterrupted local development and testing.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import socket
import sys
import time
from pathlib import Path
from typing import Any

from ..core.logging import audit_network, get_logger
from ..core.models import Finding
from ..core.utils import normalize_host

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_TOP_1000_FILE = DATA_DIR / "top_1000_ports.txt"
_HOST_RE = re.compile(r"^[A-Za-z0-9_.:\[\]-]+$")

# Check for native C++ module
try:
    from ..native import nemesis_scan as _native_engine  # type: ignore
    _HAS_NATIVE = True
except (ImportError, ModuleNotFoundError):
    _native_engine = None
    _HAS_NATIVE = False

_BINARY_NAME = "nemesis-scan.exe" if sys.platform == "win32" else "nemesis-scan"
_BINARY_PATH = Path(__file__).resolve().parent.parent / "native" / "bin" / _BINARY_NAME


def _load_top_ports(limit: int = 1000) -> list[int]:
    try:
        values = [
            int(line.strip())
            for line in _TOP_1000_FILE.read_text(encoding="ascii").splitlines()
            if line.strip().isdigit()
        ]
    except OSError:
        values = []
    return values[:limit] or [
        80, 443, 22, 21, 25, 53, 110, 143, 445, 3306, 3389, 5432, 6379, 8080, 8443,
    ]


TOP_100 = _load_top_ports(100)
TOP_1000 = _load_top_ports(1000)

_SERVICE_HINTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}


def parse_ports(spec: str | None, *, top_1000: bool = False) -> list[int]:
    """Parse an nmap-style port specification into a sorted list of unique port numbers."""
    if not spec:
        return list(TOP_1000 if top_1000 else TOP_100)
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            try:
                start, end = int(start_text), int(end_text)
            except ValueError as exc:
                raise ValueError(f"Invalid port range: {chunk}") from exc
            if start > end:
                start, end = end, start
            if start < 1 or end > 65535:
                raise ValueError("Ports must be between 1 and 65535.")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(chunk)
            except ValueError as exc:
                raise ValueError(f"Invalid port: {chunk}") from exc
            if not 1 <= port <= 65535:
                raise ValueError("Ports must be between 1 and 65535.")
            ports.add(port)
    if not ports:
        raise ValueError("No valid ports were specified.")
    return sorted(ports)


def _compress_port_list(ports: list[int]) -> str:
    """Compress a list of ports into concise range string, e.g. [22, 80, 81, 82] -> '22,80-82'."""
    if not ports:
        return ""
    ranges: list[str] = []
    start = previous = ports[0]
    for port in ports[1:]:
        if port == previous + 1:
            previous = port
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = port
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(ranges)


def _service_name(port: int, banner: str = "") -> str:
    lower_banner = banner.lower()
    signatures = [
        ("ssh-", "ssh"),
        ("http/", "http"),
        ("smtp", "smtp"),
        ("ftp", "ftp"),
        ("mysql", "mysql"),
        ("postgres", "postgresql"),
        ("redis", "redis"),
        ("mongodb", "mongodb"),
        ("elasticsearch", "elasticsearch"),
    ]
    for signature, name in signatures:
        if signature in lower_banner:
            return name
    if port in _SERVICE_HINTS:
        return _SERVICE_HINTS[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


async def _async_probe(
    host: str,
    port: int,
    *,
    timeout: float,
    service_detect: bool,
    semaphore: asyncio.Semaphore,
) -> Finding | None:
    writer: asyncio.StreamWriter | None = None
    reader: asyncio.StreamReader | None = None
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            banner = ""
            if service_detect and reader is not None:
                try:
                    data = await asyncio.wait_for(reader.read(512), timeout=min(timeout, 0.8))
                    banner = data.decode("utf-8", errors="replace").strip()
                except (asyncio.TimeoutError, OSError):
                    banner = ""
            service = _service_name(port, banner)
            evidence = f"port {port}/tcp open — {service}"
            if banner:
                evidence += f" — banner: {banner[:180]!r}"
            return Finding(
                type="open_port",
                target=host,
                module="portscan",
                url=f"tcp://{host}:{port}",
                evidence=evidence,
                severity="info",
                confidence="high",
                metadata={
                    "host": host,
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "reason": "syn-ack",
                    "service": service,
                    "banner": banner[:1000],
                    "scanner": "asyncio",
                },
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass


async def _async_fallback_scan(
    host: str,
    port_list: list[int],
    *,
    timeout: float,
    service_detect: bool,
    concurrency: int,
) -> list[Finding]:
    semaphore = asyncio.Semaphore(max(1, min(concurrency, 1000)))
    results = await asyncio.gather(
        *(
            _async_probe(
                host,
                port,
                timeout=timeout,
                service_detect=service_detect,
                semaphore=semaphore,
            )
            for port in port_list
        )
    )
    findings = [f for f in results if f is not None]
    findings.sort(key=lambda x: int(x.metadata.get("port", 0)))
    return findings


def _find_binary() -> str | None:
    if _BINARY_PATH.is_file() and os.access(_BINARY_PATH, os.X_OK):
        return str(_BINARY_PATH)
    in_path = shutil.which(_BINARY_NAME)
    if in_path:
        return in_path
    return None


async def _run_binary_scan(
    host: str,
    port_list: list[int],
    binary_path: str,
    *,
    scan_type: str = "connect",
    service_detect: bool = False,
    os_detect: bool = False,
    timing: int = 3,
    concurrency: int = 500,
) -> list[Finding] | None:
    args = [
        binary_path,
        "-s" + ("T" if scan_type == "connect" else "S"),
        "-p", _compress_port_list(port_list),
        f"-T{timing}",
        "--concurrency", str(concurrency),
        "--findings",
        host,
    ]
    if service_detect:
        args.append("-sV")
    if os_detect:
        args.append("-O")

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0 or not stdout:
            get_logger().warning("nemesis-scan binary failed (exit %s): %s", proc.returncode, stderr.decode("utf-8", "replace"))
            return None

        data = json.loads(stdout.decode("utf-8", errors="replace"))
        findings: list[Finding] = []
        for item in data:
            findings.append(
                Finding(
                    type=item.get("type", "open_port"),
                    evidence=item.get("evidence", ""),
                    severity=item.get("severity", "info"),
                    confidence=item.get("confidence", "high"),
                    url=item.get("url"),
                    param=item.get("param"),
                    target=item.get("target", host),
                    module="portscan",
                    metadata=item.get("metadata", {}),
                    timestamp=item.get("timestamp"),
                )
            )
        return findings
    except Exception as exc:
        get_logger().warning("Error executing nemesis-scan: %s", exc)
        return None


async def run(
    target: str,
    *,
    ports: str | None = None,
    top_1000: bool = False,
    top_ports: int = 0,
    fast_scan: bool = False,
    all_ports: bool = False,
    randomize_ports: bool = False,
    scan_type: str = "connect",
    custom_flags: int = 0,
    zombie_host: str = "",
    discovery: str = "default",
    service_detect: bool = False,
    version_intensity: int = 7,
    os_detect: bool = False,
    scripts: str = "",
    script_args: str = "",
    timing: int = 3,
    max_retries: int = 10,
    host_timeout: int = 0,
    min_rate: float = 0,
    max_rate: float = 0,
    fragment: bool = False,
    decoys: str = "",
    source_ip: str = "",
    source_port: int = 0,
    spoof_mac: str = "",
    mtu: int = 0,
    data_length: int = 0,
    bad_checksum: bool = False,
    randomize_hosts: bool = False,
    output_format: str = "json",
    show_reason: bool = False,
    traceroute: bool = False,
    packet_trace: bool = False,
    concurrency: int = 500,
    timeout: float = 1.5,
    aggressive: bool = False,
) -> list[Finding]:
    """Execute high-performance port scan using Nemesis C++ engine with graceful fallbacks."""
    host = normalize_host(target)
    if not _HOST_RE.match(host) or host.startswith("-"):
        raise ValueError(f"Invalid host: {target!r}")

    if all_ports:
        port_list = list(range(1, 65536))
    elif fast_scan:
        port_list = list(TOP_100)
    elif top_ports > 0:
        port_list = _load_top_ports(top_ports)
    else:
        port_list = parse_ports(ports, top_1000=top_1000)

    if not port_list:
        raise ValueError("No ports selected.")

    if len(port_list) > 5000 and concurrency > 500:
        concurrency = 500

    audit_network(
        module="portscan",
        target=host,
        action="start",
        port_count=len(port_list),
        scan_type=scan_type,
        service_detect=service_detect,
    )

    findings: list[Finding] | None = None
    scanner = "asyncio"

    # 1. Native pybind11 module if available
    if _HAS_NATIVE and _native_engine is not None:
        try:
            cfg = _native_engine.ScanConfig()
            cfg.targets = [host]
            cfg.port_spec = _compress_port_list(port_list)
            cfg.service_detect = service_detect
            cfg.version_intensity = version_intensity
            cfg.os_detect = os_detect
            cfg.skip_discovery = (discovery in ("skip", "none"))
            cfg.concurrency = concurrency
            engine = _native_engine.NemesisScanEngine()
            result = engine.scan(cfg)
            raw_json = result.to_findings_json(False)
            parsed = json.loads(raw_json)
            findings = [
                Finding(
                    type=item.get("type", "open_port"),
                    evidence=item.get("evidence", ""),
                    severity=item.get("severity", "info"),
                    confidence=item.get("confidence", "high"),
                    url=item.get("url"),
                    param=item.get("param"),
                    target=item.get("target", host),
                    module="portscan",
                    metadata=item.get("metadata", {}),
                    timestamp=item.get("timestamp"),
                )
                for item in parsed
            ]
            scanner = "native-c++"
        except Exception as exc:
            get_logger().warning("Native C++ scan exception, falling back: %s", exc)
            findings = None

    # 2. Standalone binary if available
    if findings is None:
        binary = _find_binary()
        if binary:
            findings = await _run_binary_scan(
                host,
                port_list,
                binary,
                scan_type=scan_type,
                service_detect=service_detect,
                os_detect=os_detect,
                timing=timing,
                concurrency=concurrency,
            )
            if findings is not None:
                scanner = "nemesis-scan"

    # 3. Built-in async fallback
    if findings is None:
        scanner = "asyncio"
        findings = await _async_fallback_scan(
            host,
            port_list,
            timeout=timeout,
            service_detect=service_detect,
            concurrency=concurrency,
        )

    findings.sort(key=lambda finding: int(finding.metadata.get("port", 0)))

    audit_network(
        module="portscan",
        target=host,
        action="complete",
        scanner=scanner,
        open_ports=len(findings),
    )

    return findings
