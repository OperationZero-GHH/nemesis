"""Scoped, non-destructive SQL/NoSQL injection indicator checks.

This module only reports error and boolean-response indicators. It never
enumerates databases, extracts rows, performs time-delay or out-of-band probes,
or attempts filesystem/OS access.
"""

from __future__ import annotations

import asyncio
import copy
import json
import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from xml.etree import ElementTree

from ..core.auth_gate import require_authorized
from ..core.http_client import AsyncHTTPClient, RobotsDenied
from ..core.models import Finding
from ..core.utils import ensure_url
from ._common import response_text


@dataclass(frozen=True, slots=True)
class ErrorSignature:
    engine: str
    pattern: re.Pattern[str]
    description: str


@dataclass(frozen=True, slots=True)
class Candidate:
    surface: str
    name: str
    original: str
    path: tuple[str | int, ...] = ()


@dataclass(slots=True)
class RequestTemplate:
    method: str
    url: str
    form: dict[str, Any]
    json_body: Any
    xml_body: str | None
    headers: dict[str, str]
    cookies: dict[str, str]


ERROR_SIGNATURES = (
    ErrorSignature("MySQL", re.compile(r"you have an error in your sql syntax", re.I), "MySQL syntax error"),
    ErrorSignature("MySQL", re.compile(r"warning\s*:\s*mysql_", re.I), "PHP MySQL warning"),
    ErrorSignature("MySQL", re.compile(r"mysql_fetch_(assoc|array|row)", re.I), "mysql_fetch error"),
    ErrorSignature("PostgreSQL", re.compile(r"postgresql.{0,80}error", re.I), "PostgreSQL error"),
    ErrorSignature("PostgreSQL", re.compile(r"pg_query\(\).{0,80}(failed|error)", re.I), "pg_query error"),
    ErrorSignature("PostgreSQL", re.compile(r"unterminated quoted string at or near", re.I), "PostgreSQL quote error"),
    ErrorSignature("MSSQL", re.compile(r"microsoft ole db provider for sql server", re.I), "MSSQL OLE DB error"),
    ErrorSignature("MSSQL", re.compile(r"unclosed quotation mark after the character string", re.I), "MSSQL quote error"),
    ErrorSignature("MSSQL", re.compile(r"incorrect syntax near", re.I), "MSSQL syntax error"),
    ErrorSignature("MSSQL", re.compile(r"system\.data\.sqlclient\.sqlexception", re.I), "MSSQL SqlException"),
    ErrorSignature("Oracle", re.compile(r"ORA-009(21|33|56|11|17)", re.I), "Oracle SQL error"),
    ErrorSignature("SQLite", re.compile(r"sqlite3?\.(operationalerror|databaseerror|exception)", re.I), "SQLite error"),
    ErrorSignature("SQLite", re.compile(r"sqliteexception", re.I), "SQLite exception"),
    ErrorSignature("SQLite", re.compile(r'near\s+".{0,80}":\s*syntax error', re.I), "SQLite syntax error"),
    ErrorSignature("Generic SQL", re.compile(r"sqlstate\[[0-9a-z]{5}\]", re.I), "SQLSTATE error"),
    ErrorSignature("Generic SQL", re.compile(r"syntax error at or near", re.I), "SQL syntax error"),
    ErrorSignature("Generic SQL", re.compile(r"unterminated quoted string", re.I), "SQL quote error"),
)

# Detection is deliberately limited to error messages surfaced by the app.
NOSQL_ERROR_SIGNATURES = (
    ErrorSignature("MongoDB", re.compile(r"Mongo(?:Server|DB).{0,60}(?:error|exception)", re.I), "MongoDB error"),
    ErrorSignature("MongoDB", re.compile(r"BSON(?:Type|Object|Error)", re.I), "BSON parsing error"),
    ErrorSignature("MongoDB", re.compile(r"Cast to (?:ObjectId|number) failed", re.I), "MongoDB cast error"),
    ErrorSignature("Couchbase", re.compile(r"N1QL.{0,80}(?:syntax|parsing) error", re.I), "N1QL syntax error"),
)

_BLOCK_STATUSES = {403, 406, 429}
_BLOCK_MARKERS = (
    "verify you are human",
    "checking your browser",
    "web application firewall",
    "request blocked by security",
    "cf-chl-",
    "captcha",
)
_PROTECTED_HEADERS = {
    "authorization",
    "connection",
    "content-length",
    "cookie",
    "host",
    "proxy-authorization",
    "transfer-encoding",
}
_MAX_CANDIDATES = 20


def _new_error(body: str, baseline: str) -> ErrorSignature | None:
    baseline_lower = baseline.lower()
    for signature in (*ERROR_SIGNATURES, *NOSQL_ERROR_SIGNATURES):
        match = signature.pattern.search(body)
        if match and match.group(0).lower() not in baseline_lower:
            return signature
    return None


def _similarity(left: str, right: str) -> float:
    left_norm = re.sub(r"\s+", " ", left[:250_000]).strip().lower()
    right_norm = re.sub(r"\s+", " ", right[:250_000]).strip().lower()
    if not left_norm and not right_norm:
        return 1.0
    return SequenceMatcher(None, left_norm, right_norm, autojunk=False).ratio()


def _scalar_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value)


def _flatten_json(value: Any, path: tuple[str | int, ...] = ()) -> list[Candidate]:
    candidates: list[Candidate] = []
    if isinstance(value, dict):
        for key, child in value.items():
            candidates.extend(_flatten_json(child, (*path, str(key))))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            candidates.extend(_flatten_json(child, (*path, index)))
    elif path:
        candidates.append(Candidate("json", str(path[-1]), _scalar_text(value), path))
    return candidates


def _flatten_xml(body: str | None) -> list[Candidate]:
    if not body:
        return []
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return []

    candidates: list[Candidate] = []

    def visit(element: ElementTree.Element, path: tuple[str | int, ...]) -> None:
        children = list(element)
        if not children:
            tag = element.tag.rsplit("}", 1)[-1]
            candidates.append(Candidate("xml", tag, element.text or "", path))
            return
        for index, child in enumerate(children):
            visit(child, (*path, index))

    visit(root, ())
    return candidates


def _candidates(template: RequestTemplate, params: list[str] | str | None) -> list[Candidate]:
    if isinstance(params, str):
        selected = {name.strip() for name in params.split(",") if name.strip()}
    else:
        selected = {str(name).strip() for name in (params or []) if str(name).strip()}

    parsed = urlsplit(template.url)
    candidates = [
        Candidate("query", key, value, (index,))
        for index, (key, value) in enumerate(parse_qsl(parsed.query, keep_blank_values=True))
    ]
    candidates.extend(Candidate("form", str(key), _scalar_text(value)) for key, value in template.form.items())
    candidates.extend(_flatten_json(template.json_body))
    candidates.extend(_flatten_xml(template.xml_body))
    candidates.extend(Candidate("cookie", key, value) for key, value in template.cookies.items())
    candidates.extend(
        Candidate("header", key, value)
        for key, value in template.headers.items()
        if key.lower() not in _PROTECTED_HEADERS
    )

    if selected:
        candidates = [candidate for candidate in candidates if candidate.name in selected]
        present = {candidate.name for candidate in candidates}
        for missing in sorted(selected - present):
            candidates.append(Candidate("query", missing, "test", ()))
    elif not candidates:
        raise ValueError(
            "No testable input was found. Add URL query parameters, a form/JSON/XML body, "
            "cookies, or selected headers; or provide --params."
        )
    return candidates[:_MAX_CANDIDATES]


def _set_nested(value: Any, path: tuple[str | int, ...], replacement: str) -> Any:
    if not path:
        return replacement
    current = value
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = replacement
    return value


def _mutate(template: RequestTemplate, candidate: Candidate, payload: str) -> RequestTemplate:
    request = copy.deepcopy(template)
    if candidate.surface == "query":
        parsed = urlsplit(request.url)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        index = candidate.path[0] if candidate.path else None
        if index is None:
            pairs.append((candidate.name, payload))
        else:
            key, _ = pairs[index]
            pairs[index] = (key, payload)
        request.url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs, doseq=True), parsed.fragment))
    elif candidate.surface == "form":
        request.form[candidate.name] = payload
    elif candidate.surface == "json":
        request.json_body = _set_nested(request.json_body, candidate.path, payload)
    elif candidate.surface == "xml":
        root = ElementTree.fromstring(request.xml_body or "")
        element = root
        for index in candidate.path:
            element = list(element)[int(index)]
        element.text = payload
        request.xml_body = ElementTree.tostring(root, encoding="unicode")
    elif candidate.surface == "cookie":
        request.cookies[candidate.name] = payload
    elif candidate.surface == "header":
        request.headers[candidate.name] = payload
    return request


async def _send(client: AsyncHTTPClient, template: RequestTemplate):
    kwargs: dict[str, Any] = {
        "module": "sqli",
        "headers": template.headers,
        "cookies": template.cookies,
        "timeout": 20.0,
    }
    if template.form:
        kwargs["data"] = template.form
    elif template.json_body is not None:
        kwargs["json"] = template.json_body
    elif template.xml_body is not None:
        kwargs["content"] = template.xml_body.encode("utf-8")
        kwargs["headers"] = {**template.headers, "Content-Type": "application/xml"}
    return await client.request(template.method, template.url, **kwargs)


def _blocked(response: Any, body: str) -> bool:
    if response.status_code in _BLOCK_STATUSES:
        return True
    headers = {str(key).lower(): str(value).lower() for key, value in response.headers.items()}
    if headers.get("cf-mitigated") == "challenge" or "x-sucuri-id" in headers:
        return True
    lower_body = body.lower()
    return any(marker in lower_body for marker in _BLOCK_MARKERS)


def _block_finding(target: str, url: str, status: int) -> Finding:
    return Finding(
        type="sqli_waf_skipped",
        target=target,
        module="sqli",
        url=url,
        evidence=f"A protection or request-block response (HTTP {status}) was detected; remaining probes were skipped.",
        severity="info",
        confidence="medium",
        metadata={"status": status, "action": "skipped; no bypass attempted"},
    )


def _error_finding(
    target: str,
    url: str,
    candidate: Candidate,
    signature: ErrorSignature,
    status: int,
) -> Finding:
    nosql = signature.engine in {"MongoDB", "Couchbase"}
    return Finding(
        type="nosqli_error_based" if nosql else "sqli_error_based",
        target=target,
        module="sqli",
        url=url,
        param=candidate.name,
        evidence=(
            f"A new {signature.engine} error signature ({signature.description}) appeared "
            f"while probing the {candidate.surface} input."
        ),
        severity="high",
        confidence="high",
        metadata={
            "surface": candidate.surface,
            "database": signature.engine,
            "signature": signature.description,
            "description": signature.description,
            "status": status,
            "mode": "error-based indicator",
            "note": "Detection only; no data was extracted.",
        },
    )


async def _probe(
    client: AsyncHTTPClient,
    target: str,
    baseline_url: str,
    baseline_body: str,
    baseline_status: int,
    template: RequestTemplate,
    candidate: Candidate,
    blocked_event: asyncio.Event,
) -> list[Finding]:
    findings: list[Finding] = []
    numeric = bool(re.fullmatch(r"-?\d+", candidate.original.strip()))
    if numeric:
        true_value = f"{candidate.original.strip()} AND 1=1"
        false_value = f"{candidate.original.strip()} AND 1=2"
    else:
        true_value = f"{candidate.original}' AND '1'='1"
        false_value = f"{candidate.original}' AND '1'='2"

    # A single quote probe is the inexpensive heuristic stage. Error text is
    # checked before response-difference probes so likely cases are surfaced early.
    quote_probe = _mutate(template, candidate, f"{candidate.original}'")
    if blocked_event.is_set():
        return findings
    try:
        response = await _send(client, quote_probe)
    except RobotsDenied:
        raise
    except Exception:
        return findings
    body = response_text(response)
    if _blocked(response, body):
        blocked_event.set()
        return [_block_finding(target, str(response.url), response.status_code)]
    match = _new_error(body, baseline_body)
    if match:
        findings.append(_error_finding(target, baseline_url, candidate, match, response.status_code))
        return findings

    true_probe = _mutate(template, candidate, true_value)
    false_probe = _mutate(template, candidate, false_value)
    try:
        true_response = await _send(client, true_probe)
        if _blocked(true_response, response_text(true_response)):
            blocked_event.set()
            return [_block_finding(target, str(true_response.url), true_response.status_code)]
        false_response = await _send(client, false_probe)
    except RobotsDenied:
        raise
    except Exception:
        return findings
    false_body = response_text(false_response)
    if _blocked(false_response, false_body):
        blocked_event.set()
        return [_block_finding(target, str(false_response.url), false_response.status_code)]

    true_body = response_text(true_response)
    similarity_true = _similarity(baseline_body, true_body)
    similarity_false = _similarity(baseline_body, false_body)
    boolean_match = (
        true_response.status_code == baseline_status
        and false_response.status_code == baseline_status
        and similarity_true >= 0.975
        and similarity_false <= 0.96
        and similarity_true - similarity_false >= 0.02
    )
    if boolean_match:
        findings.append(
            Finding(
                type="sqli_boolean_blind",
                target=target,
                module="sqli",
                url=baseline_url,
                param=candidate.name,
                evidence=(
                    f"True/false response divergence for the {candidate.surface} input: "
                    f"true-condition similarity {similarity_true:.3f}, "
                    f"false-condition similarity {similarity_false:.3f}."
                ),
                severity="high",
                confidence="medium",
                metadata={
                    "surface": candidate.surface,
                    "similarity_true": round(similarity_true, 4),
                    "similarity_false": round(similarity_false, 4),
                    "mode": "boolean response indicator",
                    "note": "Detection only; verify manually.",
                },
            )
        )
    return findings


async def run(
    target: str,
    *,
    params: list[str] | str | None = None,
    method: str | None = None,
    data: dict[str, Any] | None = None,
    json_body: Any = None,
    xml_body: str | None = None,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    concurrency: int = 2,
    aggressive: bool = False,
    authorized: bool = False,
) -> list[Finding]:
    """Check explicitly scoped inputs for SQL/NoSQL error or boolean indicators.

    Requests remain subject to the shared rate limiter and robots policy. Work
    across parameters is bounded to three concurrent request workers.
    """
    require_authorized(authorized, "sqli", target)
    url = ensure_url(target)
    form = dict(data or {})
    header_values = {str(key): str(value) for key, value in (headers or {}).items()}
    cookie_values = {str(key): str(value) for key, value in (cookies or {}).items()}
    body_supplied = bool(form) or json_body is not None or xml_body is not None
    request_method = (method or ("POST" if body_supplied else "GET")).upper()
    if request_method not in {"GET", "POST"}:
        raise ValueError("The SQL injection detector supports GET and POST only.")
    if request_method == "GET" and body_supplied:
        raise ValueError("Request bodies require method=POST.")
    if sum(bool(value) for value in (form, json_body is not None, xml_body is not None)) > 1:
        raise ValueError("Choose one request body format: form, JSON, or XML.")

    template = RequestTemplate(
        method=request_method,
        url=url,
        form=form,
        json_body=copy.deepcopy(json_body),
        xml_body=xml_body,
        headers=header_values,
        cookies=cookie_values,
    )
    candidates = _candidates(template, params)
    candidates = [candidate for candidate in candidates if candidate.surface != "header" or candidate.name.lower() not in _PROTECTED_HEADERS]
    findings: list[Finding] = []

    async with AsyncHTTPClient(module="sqli", aggressive=aggressive) as client:
        try:
            baseline_response = await _send(client, template)
        except RobotsDenied:
            raise
        baseline_body = response_text(baseline_response)
        baseline_status = baseline_response.status_code
        if _blocked(baseline_response, baseline_body):
            return [_block_finding(url, str(baseline_response.url), baseline_status)]

        blocked_event = asyncio.Event()
        semaphore = asyncio.Semaphore(max(1, min(int(concurrency), 3)))

        async def worker(candidate: Candidate) -> list[Finding]:
            async with semaphore:
                if blocked_event.is_set():
                    return []
                return await _probe(
                    client,
                    url,
                    str(baseline_response.url),
                    baseline_body,
                    baseline_status,
                    template,
                    candidate,
                    blocked_event,
                )

        results = await asyncio.gather(*(worker(candidate) for candidate in candidates), return_exceptions=True)
        for result in results:
            if isinstance(result, RobotsDenied):
                raise result
            if isinstance(result, Exception):
                continue
            findings.extend(result)
    return findings
