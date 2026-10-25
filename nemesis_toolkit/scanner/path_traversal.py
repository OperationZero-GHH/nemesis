"""Path traversal detection using benign known-file and error signatures."""

from __future__ import annotations

import html
from dataclasses import dataclass

from ..core.auth_gate import require_authorized
from ..core.http_client import AsyncHTTPClient, RobotsDenied
from ..core.models import Finding
from ..core.utils import ensure_url, truncate
from ._common import extract_between, parameter_values, raw_replace_query, response_text


@dataclass(slots=True)
class TraversalPayload:
    label: str
    value: str


PAYLOADS = [
    TraversalPayload("linux-relative", "../../../../../../etc/passwd"),
    TraversalPayload("linux-absolute", "/etc/passwd"),
    TraversalPayload("windows-relative", r"..\..\..\..\..\windows\win.ini"),
    TraversalPayload("windows-absolute", r"C:\Windows\win.ini"),
    TraversalPayload("url-encoded", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    TraversalPayload("double-encoded", "%252e%252e%252f%252e%252e%252fetc%252fpasswd"),
    TraversalPayload("obfuscated", "....//....//....//etc/passwd"),
    TraversalPayload("null-byte", "../../../../etc/passwd%00"),
]

FILE_SIGNATURES = [
    ("Linux /etc/passwd", ("root:x:0:0:", "root:*:0:0:", "daemon:x:1:1:")),
    ("Windows win.ini", ("[fonts]", "[extensions]", "for 16-bit app support")),
]

ERROR_MARKERS = (
    "open_basedir restriction",
    "failed to open stream",
    "no such file or directory",
    "the system cannot find the path specified",
    "warning: include(",
    "warning: require(",
    "root directory",
    "directory traversal",
    "path traversal",
    "cannot access parent directories",
)


def _file_match(body: str, baseline: str) -> tuple[str, str] | None:
    lower = body.lower()
    baseline_lower = baseline.lower()
    for name, markers in FILE_SIGNATURES:
        if any(marker.lower() in lower and marker.lower() not in baseline_lower for marker in markers):
            marker = next(marker for marker in markers if marker.lower() in lower)
            return name, marker
    return None


def _error_match(body: str, baseline: str) -> str | None:
    lower = body.lower()
    baseline_lower = baseline.lower()
    for marker in ERROR_MARKERS:
        if marker in lower and marker not in baseline_lower:
            return marker
    return None


async def run(
    target: str,
    *,
    params: list[str] | str | None = None,
    aggressive: bool = False,
    authorized: bool = False,
) -> list[Finding]:
    """Probe parameters for local file path traversal indicators."""
    require_authorized(authorized, "traversal", target)
    url = ensure_url(target)
    values = parameter_values(url, params)
    findings: list[Finding] = []
    async with AsyncHTTPClient(module="traversal", aggressive=aggressive) as client:
        try:
            baseline_response = await client.get(url, module="traversal", timeout=20.0)
            baseline_body = response_text(baseline_response)
        except RobotsDenied:
            raise
        except Exception:
            baseline_body = ""
        for name, _value in values[:20]:
            best_error: tuple[str, str, str] | None = None
            found = False
            for payload in PAYLOADS:
                injected_url = raw_replace_query(url, name, payload.value)
                try:
                    response = await client.get(injected_url, module="traversal", timeout=20.0)
                except RobotsDenied:
                    raise
                except Exception:
                    continue
                body = response_text(response)
                file_match = _file_match(body, baseline_body)
                if file_match:
                    file_name, marker = file_match
                    findings.append(
                        Finding(
                            type="path_traversal",
                            target=url,
                            module="traversal",
                            url=str(response.url),
                            param=name,
                            evidence=(
                                f"Known {file_name} signature detected after injecting "
                                f"{payload.label} payload. Context: …"
                                f"{extract_between(body, marker, radius=150)}…"
                            ),
                            severity="high",
                            confidence="high",
                            metadata={
                                "payload": payload.value,
                                "variant": payload.label,
                                "signature": marker,
                                "status": response.status_code,
                            },
                        )
                    )
                    found = True
                    break
                error = _error_match(body, baseline_body)
                if error and best_error is None:
                    best_error = (payload.value, payload.label, error)
            if not found and best_error is not None:
                payload_value, label, marker = best_error
                findings.append(
                    Finding(
                        type="path_traversal_error",
                        target=url,
                        module="traversal",
                        url=url,
                        param=name,
                        evidence=(
                            f"Injection of {label} payload produced a new path-related error marker "
                            f"({marker!r}). This is a weak indicator and may be a normal application error."
                        ),
                        severity="low",
                        confidence="low",
                        metadata={"payload": payload_value, "variant": label, "signature": marker},
                    )
                )
    return findings
