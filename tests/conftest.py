"""Test configuration and isolation for RedTeam CLI."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import pytest

from nemesis_toolkit.core.auth_gate import reset_banner
from nemesis_toolkit.core.config import get_settings
from nemesis_toolkit.core.logging import reset_logger

_MONITOR_COUNTERS: dict[str, int] = {}
_MONITOR_LOCK = threading.Lock()


class TestSiteHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "RedTeamTestSite/1.0"

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def _send(
        self,
        status: int,
        body: str,
        *,
        headers: dict[str, str] | None = None,
        content_type: str = "text/html; charset=utf-8",
    ) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query, keep_blank_values=True)

        if path == "/robots.txt":
            self._send(200, "User-agent: *\nAllow: /\nDisallow: /private\n", content_type="text/plain")
            return
        if path == "/private":
            self._send(200, "<html><body>private content</body></html>")
            return
        if path == "/":
            self._send(
                200,
                """
                <html><head><title>Test Site</title></head><body>
                <h1>Test home</h1>
                <a href="/xss?q=hello">Search</a>
                <a href="/xss-safe?q=hello">Safe search</a>
                <a href="/clickjacked">Framed page</a>
                <a href="/login">Login</a>
                <form method="post" action="/account/update">
                  <input name="email" value="user@example.test">
                  <input name="role" value="user">
                  <button type="submit">Update</button>
                </form>
                </body></html>
                """,
            )
            return
        if path == "/xss":
            value = query.get("q", [""])[0]
            self._send(200, f"<html><head><title>Search</title></head><body><p>{value}</p></body></html>")
            return
        if path == "/xss-safe":
            import html

            value = html.escape(query.get("q", [""])[0])
            self._send(
                200,
                f"<html><head><title>Safe search</title></head><body><p>{value}</p></body></html>",
            )
            return
        if path == "/dom":
            self._send(
                200,
                "<html><head><title>DOM sink</title></head><body><div id='out'></div>"
                "<script>const params = new URLSearchParams(location.search);"
                "document.getElementById('out').innerHTML = params.get('q');</script>"
                "</body></html>",
            )
            return
        if path == "/traversal":
            value = query.get("file", [""])[0].lower()
            if "passwd" in value:
                self._send(
                    200,
                    "<html><body><pre>root:x:0:0:root:/root:/bin/bash\n"
                    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin</pre></body></html>",
                )
                return
            if "win.ini" in value:
                self._send(
                    200,
                    "<html><body><pre>[fonts]\n[extensions]\nfor 16-bit app support</pre></body></html>",
                )
                return
            self._send(200, "<html><body>download ready</body></html>")
            return
        if path == "/sqli":
            value = query.get("id", [""])[0]
            if "'" in value or '"' in value:
                self._send(
                    200,
                    "<html><body>You have an error in your SQL syntax; "
                    "check the manual that corresponds to your MySQL server version</body></html>",
                )
                return
            self._send(200, "<html><body>Item 1: Widget</body></html>")
            return
        if path == "/sqli-safe":
            self._send(200, "<html><body>Item 1: Widget</body></html>")
            return
        if path == "/sqli-bool":
            value = query.get("id", [""])[0]
            if "AND 1=2" in value.upper():
                self._send(200, "<html><body>No items found. Nothing here.</body></html>")
            else:
                self._send(200, "<html><body>Item 1: Widget. In stock and ready to ship.</body></html>")
            return
        if path == "/cmdi":
            value = query.get("host", [""])[0]
            marker = ""
            if "echo " in value:
                marker = value.split("echo ", 1)[1].strip().strip("`$()")
            self._send(
                200,
                f"<html><body>Ping result for 127.0.0.1: {marker or 'ok'}</body></html>",
            )
            return
        if path == "/cmd-safe":
            self._send(200, "<html><body>Ping result for 127.0.0.1: ok</body></html>")
            return
        if path == "/clickjacked":
            self._send(200, "<html><body><h1>Framed page</h1></body></html>")
            return
        if path == "/clickjacked-safe":
            self._send(
                200,
                "<html><body><h1>Protected page</h1></body></html>",
                headers={
                    "X-Frame-Options": "DENY",
                    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                },
            )
            return
        if path == "/csrf":
            self._send(
                200,
                """
                <html><body><h1>Account</h1>
                <form method="post" action="/account/update">
                  <input name="email" value="user@example.test">
                  <input name="role" value="user">
                  <button type="submit">Update profile</button>
                </form></body></html>
                """,
                headers={"Set-Cookie": "session=abc123; Path=/; HttpOnly"},
            )
            return
        if path == "/csrf-safe":
            self._send(
                200,
                """
                <html><body><h1>Account</h1>
                <form method="post" action="/account/update">
                  <input type="hidden" name="csrf_token" value="abc">
                  <input name="email" value="user@example.test">
                  <button type="submit">Update profile</button>
                </form></body></html>
                """,
                headers={"Set-Cookie": "session=abc123; Path=/; HttpOnly; SameSite=Strict"},
            )
            return
        if path == "/login":
            self._send(
                200,
                "<html><head><title>Login</title></head><body><h1>Sign in</h1>"
                "<form method='post' action='/session'><input name='username'>"
                "<input type='password' name='password'><button>Sign in</button></form></body></html>",
            )
            return
        if path == "/register":
            self._send(
                200,
                "<html><head><title>Create account</title></head><body>"
                "<form method='post' action='/users'><input name='email'>"
                "<input type='password' name='password'><button>Sign up</button></form></body></html>",
            )
            return
        if path == "/monitor":
            key = parsed.query or "default"
            with _MONITOR_LOCK:
                _MONITOR_COUNTERS[key] = _MONITOR_COUNTERS.get(key, 0) + 1
                version = _MONITOR_COUNTERS[key]
            self._send(
                200,
                f"<html><head><title>Monitor</title></head><body>Version {version}</body></html>",
            )
            return
        if path == "/waf":
            value = query.get("id", [""])[0]
            suspicious = any(token in value for token in ("'", "<script", "../../", ";"))
            if suspicious:
                self._send(
                    403,
                    "<html><body>Attention Required! | Cloudflare. Request blocked.</body></html>",
                    headers={"Server": "cloudflare", "CF-Ray": "test-ray"},
                )
            else:
                self._send(200, "<html><body>Welcome</body></html>")
            return
        if path == "/param":
            self._send(
                200,
                """
                <html><body>
                <a href="/xss?q=test">query link</a>
                <form method="post" action="/search">
                  <input name="term"><input type="hidden" name="csrf_token" value="x">
                </form>
                </body></html>
                """,
            )
            return
        if path == "/redirect":
            self._redirect("/login")
            return
        self._send(404, "<html><head><title>Not Found</title></head><body>404</body></html>")


@pytest.fixture(scope="session")
def scanner_server() -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), TestSiteHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    yield f"http://{host}:{port}"
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    data = tmp_path / "data"
    monkeypatch.setenv("NEMESIS_CONFIG_FILE", str(tmp_path / "missing-toolconfig.yaml"))
    monkeypatch.setenv("NEMESIS_DATA_DIR", str(data))
    monkeypatch.setenv("NEMESIS_DB_PATH", str(data / "test.db"))
    monkeypatch.setenv("NEMESIS_AUDIT_LOG_PATH", str(data / "audit.jsonl"))
    monkeypatch.setenv("NEMESIS_RUN_LOG_PATH", str(data / "runs.log"))
    monkeypatch.setenv("NEMESIS_RESPECT_ROBOTS", "false")
    monkeypatch.setenv("NEMESIS_REQUESTS_PER_SECOND", "1000")
    monkeypatch.setenv("NEMESIS_MAX_RETRIES", "0")
    monkeypatch.setenv("NEMESIS_TIMEOUT", "10")
    monkeypatch.setenv("NEMESIS_AUTHORIZED_BY_DEFAULT", "false")
    for key in (
        "SECURITYTRAILS_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "SHODAN_API_KEY",
        "HIBP_API_KEY",
        "SERPAPI_KEY",
        "GOOGLE_CSE_API_KEY",
        "GOOGLE_CSE_CX",
        "IPINFO_TOKEN",
    ):
        monkeypatch.setenv(f"NEMESIS_{key}", "")
    get_settings.cache_clear()
    reset_logger()
    reset_banner()
    yield
    get_settings.cache_clear()
    reset_logger()
    reset_banner()
