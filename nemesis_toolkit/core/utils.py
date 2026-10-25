"""Small URL, HTML and text helpers shared by modules."""

from __future__ import annotations

import html
import re
import secrets
from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_EMAIL_RE = re.compile(
    r"(?<![\w.+-])([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63})(?![\w.-])",
    re.IGNORECASE,
)


def normalize_host(value: str) -> str:
    """Extract a lower-case hostname from a domain, host:port or URL."""
    value = (value or "").strip()
    if not value:
        raise ValueError("A target is required.")
    parsed = urlparse(value if "://" in value else f"//{value}", scheme="https")
    host = parsed.hostname or ""
    if not host:
        raise ValueError(f"Could not determine a hostname from '{value}'.")
    return host.lower().rstrip(".")


def normalize_domain(value: str) -> str:
    """Return a clean domain or raise a clear validation error."""
    host = normalize_host(value)
    if " " in host or "/" in host:
        raise ValueError(f"Invalid domain: {value!r}")
    if host.startswith("www.") and host.count(".") >= 2:
        # Keep the host as supplied for scanning; callers can opt into this
        # normalization when enumerating a domain.
        return host
    return host


def ensure_url(target: str, scheme: str = "https") -> str:
    """Turn a host/URL into a URL and strip fragments."""
    target = (target or "").strip()
    if not target:
        raise ValueError("A target is required.")
    if not _URL_RE.match(target):
        target = f"{scheme}://{target}"
    parsed = urlparse(target)
    if not parsed.hostname:
        raise ValueError(f"Invalid URL: {target!r}")
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http and https URLs are supported.")
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))


def origin_of(url: str) -> str:
    parsed = urlparse(ensure_url(url))
    return f"{parsed.scheme}://{parsed.netloc}"


def host_of(url: str) -> str:
    return urlparse(ensure_url(url)).hostname or ""


def same_host(a: str, b: str) -> bool:
    try:
        return host_of(a).lower() == host_of(b).lower()
    except ValueError:
        return False


def same_origin(a: str, b: str) -> bool:
    try:
        pa, pb = urlparse(ensure_url(a)), urlparse(ensure_url(b))
        return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)
    except ValueError:
        return False


def url_join(base: str, href: str) -> str | None:
    href = (href or "").strip()
    if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
        return None
    joined = urljoin(base, href)
    parsed = urlparse(joined)
    if parsed.scheme not in ("http", "https"):
        return None
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))


def query_pairs(url: str) -> list[tuple[str, str]]:
    return parse_qsl(urlparse(url).query, keep_blank_values=True)


def query_param_names(url: str) -> list[str]:
    seen: set[str] = set()
    names: list[str] = []
    for name, _ in query_pairs(url):
        if name not in seen:
            seen.add(name)
            names.append(name)
    return names


def replace_query_param(url: str, name: str, value: str) -> str:
    """Replace all values of a query parameter while preserving order."""
    pairs = query_pairs(url)
    replaced = [(key, value if key == name else existing) for key, existing in pairs]
    parsed = urlparse(url)
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, urlencode(replaced), "")
    )


def append_query_param(url: str, name: str, value: str) -> str:
    pairs = query_pairs(url)
    if any(key == name for key, _ in pairs):
        return replace_query_param(url, name, value)
    pairs.append((name, value))
    parsed = urlparse(url)
    return urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, urlencode(pairs), "")
    )


def response_text(response: object) -> str:
    """Decode an httpx response as text, tolerating broken encodings."""
    try:
        return response.text  # type: ignore[attr-defined]
    except Exception:
        content = getattr(response, "content", b"")
        return content.decode("utf-8", errors="replace") if isinstance(content, bytes) else str(content)


def extract_title(body: str, limit: int = 160) -> str:
    if not body:
        return ""
    try:
        soup = BeautifulSoup(body, "html.parser")
        if soup.title and soup.title.string:
            return " ".join(soup.title.string.split())[:limit]
    except Exception:
        pass
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return " ".join(html.unescape(re.sub(r"<[^>]+>", "", match.group(1))).split())[:limit]


def extract_meta(html_text: str, name: str) -> str:
    try:
        soup = BeautifulSoup(html_text, "html.parser")
        tag = soup.find("meta", attrs={"name": re.compile(f"^{re.escape(name)}$", re.IGNORECASE)})
        if tag and tag.get("content"):
            return " ".join(str(tag["content"]).split())[:500]
    except Exception:
        pass
    return ""


def unique_strings(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        value = value.strip()
        key = value.lower()
        if value and key not in seen:
            seen.add(key)
            result.append(value)
    return result


def extract_emails(text: str, domain: str | None = None) -> list[str]:
    found = []
    for match in _EMAIL_RE.finditer(html.unescape(text or "")):
        email = match.group(1).strip().strip(".").lower()
        # Remove accidental URL/query suffix captured by broad matches.
        email = email.replace("%20", "")
        if domain and not email.endswith("@" + domain.lower().lstrip(".")):
            continue
        if re.search(r"\.(png|jpe?g|gif|svg|webp|css|js|woff2?)$", email, re.I):
            continue
        found.append(email)
    return unique_strings(found)


def probe_token(prefix: str = "RTPROBE") -> str:
    return f"{prefix}{secrets.token_hex(5)}"


def truncate(value: str, limit: int = 360) -> str:
    value = " ".join((value or "").split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def severity_rank(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get((severity or "info").lower(), 5)


def redact_url(url: str) -> str:
    """Remove credentials and common secret query values from a URL."""
    parsed = urlparse(url)
    netloc = parsed.netloc
    if parsed.username or parsed.password:
        host = parsed.hostname or ""
        if parsed.port:
            host += f":{parsed.port}"
        netloc = host
    sensitive = {
        "api_key",
        "apikey",
        "key",
        "token",
        "access_token",
        "secret",
        "client_secret",
        "auth",
        "password",
    }
    query = parsed.query
    if query:
        pairs = parse_qsl(query, keep_blank_values=True)
        query = urlencode(
            [
                (key, "***" if key.lower() in sensitive else value)
                for key, value in pairs
            ]
        )
    return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, query, ""))
