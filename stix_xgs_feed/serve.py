"""Optional HTTPS server for the three feed files, with a refresh scheduler.

Off unless you run ``stix-xgs-feed serve``. It serves ips.txt, domains.txt and
urls.txt and nothing else: no directory listing, no redirects (Sophos Firewall
reports a 302 as a connection error), no other files. A refresh rebuilds the
files on a schedule and swaps each one in atomically, so a poll gets either
the old file or the new one, never half of one. It binds to localhost unless
told otherwise, and refuses to listen beyond localhost without TLS and
authentication.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import http.client
import http.server
import ipaddress
import logging
import os
import re
import shutil
import signal
import socket
import socketserver
import ssl
import sys
import threading
import time
import urllib.parse
from email.utils import formatdate
from http import HTTPStatus
from pathlib import Path

from .config import (SERVE_SECRET_MIN, XGS_FIELD_MAX, ConfigError, ServeAuth, ServeConfig, Settings,
                     resolve_secret)
from .fetch import FetchError, is_loopback_host
from .runner import FEED_FILES, RunError, build_clients, run_once

log = logging.getLogger("stix_xgs_feed.serve")

HEALTH_PATH = "/healthz"
HANDSHAKE_TIMEOUT = 10
REQUEST_TIMEOUT = 30
_PRINTABLE_RE = re.compile(r"^[\x21-\x7e]+$")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_QUERY_NAME_RE = re.compile(r"^[A-Za-z0-9._~-]+$")
_LOG_UNSAFE_RE = re.compile(r"[^\x21-\x7e]")


# --------------------------------------------------------------------------
# Scheduler
# --------------------------------------------------------------------------

class Scheduler:
    """Runs job() now and then every interval seconds, measured from the start of each run.

    After a failed run (job returns False or raises) it retries after retry
    seconds instead. Runs never overlap.
    """

    def __init__(self, job, interval: float, retry: float, name: str = "refresh"):
        self.job = job
        self.interval = interval
        self.retry = min(retry, interval)
        self.runs = 0
        self.failures = 0          # consecutive
        self.last_success: float | None = None
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name=name, daemon=True)

    def start(self):
        self._thread.start()

    def stop(self, timeout: float | None = None):
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout)

    def _loop(self):
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                ok = bool(self.job())
            except Exception:  # noqa: BLE001 - keep the schedule alive whatever the job does
                log.exception("refresh failed unexpectedly")
                ok = False
            self.runs += 1
            if ok:
                self.failures, self.last_success = 0, time.time()
            else:
                self.failures += 1
            delay = (self.interval if ok else self.retry) - (time.monotonic() - started)
            self._stop.wait(max(delay, 0))


# --------------------------------------------------------------------------
# Validation and authentication
# --------------------------------------------------------------------------

def _check_field(value: str, what: str, minimum: int = 1):
    if not _PRINTABLE_RE.match(value):
        raise ConfigError(f"{what} may only use printable ASCII characters, no spaces")
    if len(value) > XGS_FIELD_MAX:
        raise ConfigError(f"{what} is longer than {XGS_FIELD_MAX} characters, the most Sophos Firewall accepts")
    if len(value) < minimum:
        raise ConfigError(f"{what} must be at least {minimum} characters")


def check_serve(cfg: ServeConfig):
    """The refusal rules that need no secrets."""
    host = cfg.listen
    if not is_loopback_host(host):
        try:
            ipaddress.ip_address(host)
        except ValueError:
            raise ConfigError("serve.listen must be an IP address (0.0.0.0 for every IPv4 address) "
                              "or localhost") from None
        missing = []
        if not cfg.tls_cert:
            missing.append("TLS (serve.tls_cert and serve.tls_key)")
        if cfg.auth.type == "none":
            missing.append("authentication (serve.auth)")
        if missing:
            raise ConfigError(f"refusing to listen on {host} without " + " and ".join(missing)
                              + "; beyond localhost both are required")
    a = cfg.auth
    if a.type == "basic":
        _check_field(a.username or "", "serve.auth.username")
        if ":" in a.username:
            raise ConfigError("serve.auth.username must not contain a colon")
    elif a.type == "api_key":
        pattern = _HEADER_NAME_RE if a.add_to == "header" else _QUERY_NAME_RE
        if not a.key_name or not pattern.match(a.key_name) or len(a.key_name) > XGS_FIELD_MAX:
            raise ConfigError(f"serve.auth.key_name must be a valid {a.add_to} name of at most "
                              f"{XGS_FIELD_MAX} characters")


class AuthChecker:
    """Checks a request against the serve credentials in constant time."""

    def __init__(self, cfg: ServeAuth):
        self.type = cfg.type
        self.add_to = cfg.add_to
        self.key_name = cfg.key_name
        self._user = self._secret = b""
        if cfg.type == "basic":
            password = resolve_secret(cfg.password, "serve.auth.password")
            _check_field(password, "serve.auth.password", SERVE_SECRET_MIN)
            self._user, self._secret = cfg.username.encode(), password.encode()
        elif cfg.type == "api_key":
            key = resolve_secret(cfg.key_value, "serve.auth.key_value")
            _check_field(key, "serve.auth.key_value", SERVE_SECRET_MIN)
            self._secret = key.encode()

    def check(self, headers, query: str) -> bool:
        if self.type == "none":
            return True
        if self.type == "basic":
            scheme, _, token = (headers.get("Authorization") or "").strip().partition(" ")
            if scheme.lower() != "basic":
                return False
            try:
                raw = base64.b64decode(token.strip(), validate=True)
            except (binascii.Error, ValueError):
                return False
            user, sep, password = raw.partition(b":")
            user_ok = hmac.compare_digest(user, self._user)
            password_ok = hmac.compare_digest(password, self._secret)
            return bool(sep) and user_ok and password_ok
        if self.add_to == "header":
            supplied = headers.get(self.key_name)
        else:
            values = urllib.parse.parse_qs(query, keep_blank_values=True).get(self.key_name, [])
            supplied = values[0] if len(values) == 1 else None
        if supplied is None:
            return False
        return hmac.compare_digest(supplied.encode("utf-8", "surrogateescape"), self._secret)

    @property
    def challenge(self) -> str | None:
        return 'Basic realm="stix-xgs-feed", charset="UTF-8"' if self.type == "basic" else None


def server_tls_context(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.load_cert_chain(cert, key)
    except (OSError, ssl.SSLError) as exc:
        raise ConfigError(f"cannot load serve.tls_cert and serve.tls_key: {exc}") from None
    return ctx


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------

def _client_ip(address) -> ipaddress._BaseAddress:
    ip = ipaddress.ip_address(str(address[0]).split("%", 1)[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip


class FeedHandler(http.server.BaseHTTPRequestHandler):
    server_version = "stix-xgs-feed"
    sys_version = ""
    protocol_version = "HTTP/1.0"
    timeout = REQUEST_TIMEOUT

    def version_string(self):
        return self.server_version

    # The base class logs the raw request line, which can carry an API key in the
    # query string. Access logging happens in _access_log instead, path only.
    def log_message(self, format, *args):  # noqa: A002
        pass

    def log_error(self, format, *args):  # noqa: A002
        pass

    def send_error(self, code, message=None, explain=None):
        self._finish(code)

    def do_GET(self):  # noqa: N802
        self._handle()

    def do_HEAD(self):  # noqa: N802
        self._handle()

    def _not_allowed(self):
        self._finish(405, headers={"Allow": "GET, HEAD"})

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = _not_allowed

    def _handle(self):
        srv: FeedServer = self.server
        service = srv.service
        path, _, query = self.path.partition("?")
        ip = _client_ip(self.client_address)
        if path == HEALTH_PATH:
            ready = service.ready()
            return self._finish(200 if ready else 503, b"ok\n" if ready else b"unavailable\n")
        if not service.client_allowed(ip):
            return self._finish(403)
        if not service.auth.check(self.headers, query):
            log.warning("authentication failed from %s", ip)
            challenge = service.auth.challenge
            return self._finish(401, headers={"WWW-Authenticate": challenge} if challenge else None)
        name = service.routes.get(path)
        if name is None:
            return self._finish(404)
        try:
            f = open(service.feed_dir / name, "rb")  # noqa: SIM115 - the open handle pins this version of the file
        except FileNotFoundError:
            return self._finish(503)
        with f:
            st = os.fstat(f.fileno())
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=us-ascii")
            self.send_header("Content-Length", str(st.st_size))
            self.send_header("Last-Modified", formatdate(st.st_mtime, usegmt=True))
            self._common_headers()
            self.end_headers()
            if self.command != "HEAD":
                shutil.copyfileobj(f, self.wfile, 64 * 1024)
        self._access_log(200, st.st_size)

    def _common_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")

    def _finish(self, code: int, body: bytes | None = None, headers: dict | None = None):
        if body is None:
            body = f"{code} {HTTPStatus(code).phrase}\n".encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=us-ascii")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self._common_headers()
        self.end_headers()
        if getattr(self, "command", None) != "HEAD":
            self.wfile.write(body)
        self._access_log(code, len(body))

    def _access_log(self, code: int, size: int):
        # Path only: the query string can hold an API key.
        path = (getattr(self, "path", None) or "-").partition("?")[0]
        level = logging.DEBUG if path == HEALTH_PATH and code == 200 else logging.INFO
        path = _LOG_UNSAFE_RE.sub("?", path)[:200]
        method = _LOG_UNSAFE_RE.sub("?", getattr(self, "command", None) or "-")[:16]
        log.log(level, "%s %s %s %d %d", self.client_address[0], method, path, code, size)


class FeedServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, address, family, service: FeedService):
        self.address_family = family
        self.service = service
        self._slots = threading.BoundedSemaphore(service.cfg.max_connections)
        super().__init__(address, FeedHandler)

    def server_bind(self):
        # HTTPServer.server_bind does a reverse DNS lookup that can stall startup.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name, self.server_port = str(host), port

    def verify_request(self, request, client_address):
        ip = _client_ip(client_address)
        if self.service.allowed_clients and not ip.is_loopback and not self.service.client_allowed(ip):
            log.warning("connection from %s refused: not in serve.allowed_clients", ip)
            return False
        return True

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            log.warning("connection from %s dropped: %d connections already open", client_address[0],
                        self.service.cfg.max_connections)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def finish_request(self, request, client_address):
        conn = request
        if self.service.tls is not None:
            try:
                request.settimeout(HANDSHAKE_TIMEOUT)
                conn = self.service.tls.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError) as exc:
                log.info("TLS handshake with %s failed: %s", client_address[0], getattr(exc, "reason", None) or exc)
                return
        try:
            self.RequestHandlerClass(conn, client_address, self)
        finally:
            if conn is not request:
                try:
                    conn.close()
                except OSError:
                    pass

    def handle_error(self, request, client_address):
        log.info("connection with %s ended early: %s", client_address[0], sys.exc_info()[1])


# --------------------------------------------------------------------------
# Service
# --------------------------------------------------------------------------

class FeedService:
    """Serve mode: the HTTP(S) server plus the refresh scheduler."""

    def __init__(self, settings: Settings):
        if settings.serve is None:
            raise ConfigError("the config file has no serve section")
        self.settings = settings
        self.cfg = settings.serve
        check_serve(self.cfg)
        self.auth = AuthChecker(self.cfg.auth)
        self.tls = server_tls_context(self.cfg.tls_cert, self.cfg.tls_key) if self.cfg.tls_cert else None
        try:
            build_clients(settings)   # resolve source secrets and load certificates now, not at the first refresh
        except FetchError as exc:
            raise ConfigError(str(exc)) from None
        self.allowed_clients = list(self.cfg.allowed_clients)
        self.feed_dir = Path(settings.out)
        self.routes = {f"{self.cfg.path_prefix}/{name}": name for name in FEED_FILES}
        self.scheduler = Scheduler(self.refresh, self.cfg.refresh_minutes * 60, self.cfg.retry_minutes * 60)
        self.server: FeedServer | None = None
        self._thread: threading.Thread | None = None

    # ---- state ------------------------------------------------------------

    def ready(self) -> bool:
        return all((self.feed_dir / name).is_file() for name in FEED_FILES)

    def client_allowed(self, ip) -> bool:
        if not self.allowed_clients:
            return True
        return any(ip.version == net.version and ip in net for net in self.allowed_clients)

    @property
    def port(self) -> int:
        return self.server.server_address[1] if self.server else self.cfg.port

    # ---- work -------------------------------------------------------------

    def refresh(self) -> bool:
        try:
            report = run_once(self.settings)
        except RunError as exc:
            log.error("refresh failed; still serving the previous files: %s", exc)
            return False
        written = report["written"]
        log.info("refresh done: " + ", ".join(f"{name}={n}" for name, n in written.items()))
        for name, n in written.items():
            if n == 0:
                log.warning("%s is empty", name)
        return True

    def _remove_stale_temp_files(self):
        # write_atomic leaves .<name>.XXXX only if the process died mid-write.
        for path in self.feed_dir.glob(".*.txt.*"):
            if path.name.split(".txt.", 1)[0].lstrip(".") + ".txt" in FEED_FILES + ("ipv6.txt",):
                try:
                    path.unlink()
                except OSError:
                    pass

    def start(self, background: bool = True):
        self.feed_dir.mkdir(parents=True, exist_ok=True)
        self._remove_stale_temp_files()
        host = "127.0.0.1" if self.cfg.listen == "localhost" else self.cfg.listen
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.server = FeedServer((host, self.cfg.port), family, self)
        scheme = "https" if self.tls else "http"
        shown = f"[{host}]" if ":" in host else host
        log.info("serving %s://%s:%d%s/{%s} (auth %s, refresh every %g min)", scheme, shown, self.port,
                 self.cfg.path_prefix, ",".join(FEED_FILES), self.auth.type, self.cfg.refresh_minutes)
        if self.auth.type == "none":
            log.warning("serving without authentication; only do this behind a reverse proxy that adds it")
        self.scheduler.start()
        if background:
            self._thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.2},
                                            name="http", daemon=True)
            self._thread.start()

    def stop(self):
        self.scheduler.stop(timeout=10)
        if self.server is not None:
            if self._thread is not None:
                self.server.shutdown()
                self._thread.join(timeout=10)
            self.server.server_close()

    def run_forever(self) -> int:
        def _terminate(signum, frame):
            raise KeyboardInterrupt

        signal.signal(signal.SIGTERM, _terminate)
        self.start(background=False)
        try:
            self.server.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt:
            log.info("stopping")
        finally:
            self.scheduler.stop(timeout=10)
            self.server.server_close()
        return 0


def healthcheck(cfg: ServeConfig, timeout: float = 5.0) -> bool:
    """GET /healthz on the local listener. For container health checks; skips certificate checks on loopback."""
    host = {"0.0.0.0": "127.0.0.1", "::": "::1", "localhost": "127.0.0.1", "": "127.0.0.1"}.get(cfg.listen, cfg.listen)
    if cfg.tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, cfg.port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, cfg.port, timeout=timeout)
    try:
        conn.request("GET", HEALTH_PATH)
        return conn.getresponse().status == 200
    except (OSError, http.client.HTTPException):
        return False
    finally:
        conn.close()
