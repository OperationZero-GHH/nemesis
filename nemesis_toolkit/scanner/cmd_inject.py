"""Benign OS command injection detection (echo markers and time delays)."""

from __future__ import annotations

import re
import time

from ..core.auth_gate import require_authorized
from ..core.http_client import AsyncHTTPClient, RobotsDenied
from ..core.models import Finding
from ..core.utils import ensure_url, probe_token
from ._common import extract_between, parameter_values, raw_replace_query, response_text

VERIFY_PATTERNS = (
    re.compile(r"uid=\d+\([^)]+\)"),
    re.compile(r"gid=\d+\([^)]+\)"),
)


async def run(
    target: str,
    *,
    params: list[str] | str | None = None,
    time_based: bool = True,
    time_delay: float = 3.0,
    time_threshold: float = 2.5,
    aggressive: bool = False,
    authorized: bool = False,
) -> list[Finding]:
    """Inject non-destructive command probes and detect execution indicators."""
    require_authorized(authorized, "cmdi", target)
    url = ensure_url(target)
    values = parameter_values(url, params)
    marker = probe_token("RTCMD")
    findings: list[Finding] = []
    reflect_payloads = [
        ("semicolon", f"; echo {marker}"),
        ("pipe", f"| echo {marker}"),
        ("and", f"&& echo {marker}"),
        ("subshell", f"$(echo {marker})"),
        ("backticks", f"`echo {marker}`"),
        ("newline", f"%0aecho {marker}"),
        ("windows-and", f"& echo {marker}"),
    ]
    time_payloads = [
        ("semicolon-sleep", f"; sleep {time_delay:g}"),
        ("pipe-sleep", f"| sleep {time_delay:g}"),
    ]
    async with AsyncHTTPClient(module="cmdi", aggressive=aggressive) as client:
        baseline_started = time.perf_counter()
        try:
            baseline = await client.get(url, module="cmdi", timeout=30.0)
        except RobotsDenied:
            raise
        baseline_elapsed_ms = int((time.perf_counter() - baseline_started) * 1000)
        baseline_body = response_text(baseline)

        for name, _value in values[:15]:
            reflected = False
            for label, payload in reflect_payloads:
                injected_url = raw_replace_query(url, name, payload)
                try:
                    response = await client.get(injected_url, module="cmdi", timeout=30.0)
                except RobotsDenied:
                    raise
                except Exception:
                    continue
                body = response_text(response)
                if marker in body and marker not in baseline_body:
                    findings.append(
                        Finding(
                            type="command_injection",
                            target=url,
                            module="cmdi",
                            url=str(response.url),
                            param=name,
                            evidence=(
                                f"Command marker was reflected after injecting the {label} payload. "
                                f"Context: …{extract_between(body, marker, radius=140)}…"
                            ),
                            severity="critical",
                            confidence="high",
                            metadata={
                                "payload": payload,
                                "variant": label,
                                "marker": marker,
                                "status": response.status_code,
                                "note": "Detection only; no data extraction was attempted.",
                            },
                        )
                    )
                    reflected = True
                    break
                # A command like 'echo' may be filtered while an OS identity
                # string still appears; keep this as a lower-confidence signal.
                if any(pattern.search(body) and not pattern.search(baseline_body) for pattern in VERIFY_PATTERNS):
                    findings.append(
                        Finding(
                            type="command_injection_indicator",
                            target=url,
                            module="cmdi",
                            url=str(response.url),
                            param=name,
                            evidence=f"OS identity output appeared after injecting the {label} payload.",
                            severity="medium",
                            confidence="low",
                            metadata={"payload": payload, "variant": label},
                        )
                    )
                    reflected = True
                    break
            if reflected:
                continue
            if time_based:
                for label, payload in time_payloads:
                    try:
                        injected_url = raw_replace_query(url, name, payload)
                        started = time.perf_counter()
                        response = await client.get(
                            injected_url, module="cmdi", timeout=time_delay + 15.0
                        )
                        elapsed_ms = int((time.perf_counter() - started) * 1000)
                    except RobotsDenied:
                        raise
                    except Exception:
                        continue
                    delta = elapsed_ms - baseline_elapsed_ms
                    if delta >= time_threshold * 1000:
                        findings.append(
                            Finding(
                                type="command_injection_time_blind",
                                target=url,
                                module="cmdi",
                                url=url,
                                param=name,
                                evidence=(
                                    f"Time-based indicator for '{name}': response took {elapsed_ms}ms "
                                    f"versus baseline {baseline_elapsed_ms}ms after the {label} sleep payload."
                                ),
                                severity="high",
                                confidence="medium",
                                metadata={
                                    "payload": payload,
                                    "elapsed_ms": elapsed_ms,
                                    "baseline_ms": baseline_elapsed_ms,
                                    "delta_ms": delta,
                                    "note": "Timing can be affected by network/server load.",
                                },
                            )
                        )
                        break
    return findings
