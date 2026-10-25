"""Shared async HTTP client with retries, user-agent rotation, rate limits,
robots.txt enforcement and complete audit logging.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

import httpx

from .config import Settings, get_settings
from .logging import audit_event, audit_http
from .utils import redact_url


class RobotsDenied(RuntimeError):
    """The target's robots.txt disallows this request."""


@dataclass(slots=True)
class RobotsPolicy:
    parser: RobotFileParser | None
    allow_all: bool
    crawl_delay: float | None = None

    def allowed(self, url: str, user_agent: str = "*") -> bool:
        if self.allow_all or self.parser is None:
            return True
        try:
            return self.parser.can_fetch(user_agent, url)
        except Exception:
            return True


class RateLimiter:
    """Reserve evenly spaced request slots per host."""

    def __init__(self, requests_per_second: float) -> None:
        self.interval = 1.0 / max(requests_per_second, 0.01)
        self._next: dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, host: str) -> None:
        loop = asyncio.get_running_loop()
        async with self._lock:
            now = loop.time()
            ready_at = max(now, self._next.get(host, now))
            self._next[host] = ready_at + self.interval
            delay = ready_at - now
        if delay > 0:
            await asyncio.sleep(delay)


class AsyncHTTPClient:
    """Async wrapper used by every network-facing module.

    Use as an async context manager. Every request (including robots.txt fetches
    and retries) emits one audit record.
    """

    RETRY_STATUS = {429, 500, 502, 503, 504}

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        module: str = "http",
        aggressive: bool = False,
        respect_robots: bool | None = None,
        base_headers: dict[str, str] | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.module = module
        self.aggressive = aggressive
        if respect_robots is None:
            respect_robots = self.settings.respect_robots and not aggressive
        self.respect_robots = respect_robots
        self.base_headers = dict(base_headers or {})
        self._client: httpx.AsyncClient | None = None
        rps = float("inf") if aggressive else self.settings.requests_per_second
        self._rate = RateLimiter(rps)
        self._robots: dict[str, RobotsPolicy] = {}
        self._robots_locks: dict[str, asyncio.Lock] = {}
        self._robots_lock = asyncio.Lock()

    async def __aenter__(self) -> "AsyncHTTPClient":
        self._client = httpx.AsyncClient(
            http2=True,
            follow_redirects=True,
            max_redirects=10,
            timeout=httpx.Timeout(self.settings.timeout),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.8",
                **self.base_headers,
            },
        )
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("AsyncHTTPClient must be used inside 'async with'.")
        return self._client

    def _user_agent(self) -> str:
        agents = self.settings.user_agents or ["nemesis/0.1"]
        return random.choice(agents)

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = dict(extra or {})
        if not any(key.lower() == "user-agent" for key in headers):
            headers["User-Agent"] = self._user_agent()
        return headers

    async def _robots_lock_for(self, origin: str) -> asyncio.Lock:
        async with self._robots_lock:
            lock = self._robots_locks.get(origin)
            if lock is None:
                lock = asyncio.Lock()
                self._robots_locks[origin] = lock
            return lock

    async def _get_robots_policy(self, url: str) -> RobotsPolicy:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        cached = self._robots.get(origin)
        if cached is not None:
            return cached
        lock = await self._robots_lock_for(origin)
        async with lock:
            if origin in self._robots:
                return self._robots[origin]
            robots_url = f"{origin}/robots.txt"
            policy = RobotsPolicy(parser=None, allow_all=True)
            await self._rate.acquire(parsed.hostname or parsed.netloc)
            started = time.perf_counter()
            status: int | None = None
            try:
                response = await self.client.get(
                    robots_url,
                    headers=self._headers(),
                    timeout=min(self.settings.timeout, 10.0),
                )
                status = response.status_code
                if response.status_code == 200 and response.text.strip():
                    parser = RobotFileParser()
                    parser.set_url(robots_url)
                    parser.parse(response.text.splitlines())
                    _prioritize_robots_rules(parser)
                    user_agent = self.settings.user_agents[0] if self.settings.user_agents else "*"
                    try:
                        delay = parser.crawl_delay(user_agent) or parser.crawl_delay("*")
                    except Exception:
                        delay = None
                    policy = RobotsPolicy(
                        parser=parser,
                        allow_all=False,
                        crawl_delay=float(delay) if delay else None,
                    )
                # 4xx/5xx robots.txt: standard courtesy behavior is to proceed,
                # because a missing policy is not an instruction not to crawl.
            except (httpx.HTTPError, ValueError):
                pass
            finally:
                audit_http(
                    module="robots",
                    method="GET",
                    url=robots_url,
                    status=status,
                    duration_ms=(time.perf_counter() - started) * 1000,
                )
            self._robots[origin] = policy
            return policy

    async def robots_allowed(self, url: str) -> bool:
        policy = await self._get_robots_policy(url)
        return policy.allowed(url, "nemesis")

    async def request(
        self,
        method: str,
        url: str,
        *,
        module: str | None = None,
        respect_robots: bool | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | httpx.Timeout | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        module = module or self.module
        method = method.upper()
        enforce_robots = self.respect_robots if respect_robots is None else respect_robots
        if enforce_robots and method in {"GET", "HEAD"}:
            try:
                allowed = await self.robots_allowed(url)
            except Exception:
                allowed = True
            if not allowed:
                audit_event(
                    "robots_denied",
                    module=module,
                    target=redact_url(url),
                    method=method,
                )
                raise RobotsDenied(
                    f"robots.txt disallows {method} {redact_url(url)}. "
                    "Rerun with --aggressive only if you are authorized to ignore it."
                )
            policy = self._robots.get(
                f"{urlparse(url).scheme}://{urlparse(url).netloc}",
            )
            if policy and policy.crawl_delay and not self.aggressive:
                await asyncio.sleep(min(policy.crawl_delay, 10.0))

        host = urlparse(url).hostname or url
        last_error: Exception | None = None
        attempts = self.settings.max_retries + 1
        request_timeout = timeout if timeout is not None else self.settings.timeout
        for attempt in range(1, attempts + 1):
            await self._rate.acquire(host)
            started = time.perf_counter()
            status: int | None = None
            try:
                response = await self.client.request(
                    method,
                    url,
                    headers=self._headers(headers),
                    timeout=request_timeout,
                    **kwargs,
                )
                status = response.status_code
                audit_http(
                    module=module,
                    method=method,
                    url=redact_url(str(response.request.url)),
                    status=status,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    attempt=attempt,
                )
                if response.status_code not in self.RETRY_STATUS or attempt >= attempts:
                    return response
                retry_after = _retry_after_seconds(response.headers.get("retry-after"))
                await asyncio.sleep(retry_after if retry_after is not None else min(2 ** attempt * 0.25, 4.0))
            except (httpx.TimeoutException, httpx.TransportError, httpx.ProxyError) as exc:
                last_error = exc
                audit_http(
                    module=module,
                    method=method,
                    url=redact_url(url),
                    status=status,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    error=type(exc).__name__,
                    attempt=attempt,
                )
                if attempt >= attempts:
                    raise
                await asyncio.sleep(min(2 ** attempt * 0.25, 4.0))
        if last_error is not None:
            raise last_error
        raise RuntimeError("HTTP request failed without a response.")

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("HEAD", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self.request("OPTIONS", url, **kwargs)


def _prioritize_robots_rules(parser: RobotFileParser) -> None:
    """Order rules by specificity so the first match honors longest-match.

    ``RobotFileParser.allowance`` returns the first matching rule. RFC 9309
    requires the longest matching rule to win (with ``Allow`` winning ties), so
    sort each agent group's rules before any fetch decisions are made.
    """
    entries = list(parser.entries)
    if parser.default_entry is not None:
        entries.append(parser.default_entry)
    for entry in entries:
        entry.rulelines.sort(key=lambda rule: (-len(rule.path), 0 if rule.allowance else 1))


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return min(max(float(value), 0.0), 15.0)
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
            delta = parsed.timestamp() - time.time()
            return min(max(delta, 0.0), 15.0)
        except (TypeError, ValueError, OverflowError):
            return None
