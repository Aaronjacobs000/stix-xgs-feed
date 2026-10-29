"""Shared test helpers: local HTTP(S) stubs, test certificates and small STIX bundles.

Every credential in the tests is an obviously fake value made up for the test.
"""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import ssl
import subprocess
import sys
import threading
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "tests" / "data"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import stix_xgs_feed as feed  # noqa: E402

NOW = "2026-10-29T00:00:00Z"
OPENSSL = shutil.which("openssl")
HAS_TOML = sys.version_info >= (3, 11)
needs_toml = unittest.skipUnless(HAS_TOML, "TOML config files need Python 3.11 or later")


def run_cli(*args) -> tuple:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        code = feed.main([str(a) for a in args])
    return code, buf.getvalue()


def read_lines(path: Path) -> list:
    return Path(path).read_text(encoding="ascii").splitlines()


def bundle(*domains: str) -> bytes:
    return json.dumps({"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000001",
                       "objects": indicators(*domains)}).encode()


def indicators(*domains: str) -> list:
    objs = []
    for d in domains:
        objs.append({"type": "indicator", "spec_version": "2.1",
                     "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, d)}",
                     "created": "2026-10-01T00:00:00Z", "modified": "2026-10-01T00:00:00Z",
                     "valid_from": "2026-10-01T00:00:00Z", "pattern_type": "stix",
                     "pattern": f"[domain-name:value = '{d}']"})
    return objs


def write_toml(path: Path, text: str) -> Path:
    if not HAS_TOML:
        raise unittest.SkipTest("TOML config files need Python 3.11 or later")
    path.write_text(text, encoding="utf-8")
    return path


# --------------------------------------------------------------------------
# Stub server
# --------------------------------------------------------------------------

def ok(body: bytes, ctype: str = "application/json"):
    return lambda h: (200, {"Content-Type": ctype}, body)


def redirect(location: str, code: int = 302):
    return lambda h: (code, {"Location": location}, b"")


def require_header(name: str, value: str, body: bytes):
    return lambda h: (200, {}, body) if h.headers.get(name) == value else (401, {}, b"no")


class _Recorder(BaseHTTPRequestHandler):
    routes: dict = {}
    seen: list = []

    def do_GET(self):  # noqa: N802
        url = urlparse(self.path)
        cert = None
        if isinstance(self.connection, ssl.SSLSocket):
            cert = self.connection.getpeercert()
        type(self).seen.append({
            "path": url.path, "query": parse_qs(url.query, keep_blank_values=True),
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "client_cert": cert or None,
        })
        route = self.routes.get(url.path)
        code, headers, body = route(self) if route else (404, {}, b"not found")
        self.send_response(code)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Stub:
    """A local HTTP or HTTPS server that records every request."""

    def __init__(self, routes: dict, tls: ssl.SSLContext | None = None):
        self.handler = type("Handler", (_Recorder,), {"routes": routes, "seen": []})
        self.server = HTTPServer(("127.0.0.1", 0), self.handler)
        if tls is not None:
            self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.scheme = "https" if tls else "http"
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    @property
    def seen(self) -> list:
        return self.handler.seen

    def url(self, path: str, host: str = "127.0.0.1") -> str:
        return f"{self.scheme}://{host}:{self.port}{path}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# --------------------------------------------------------------------------
# Certificates (made at test time with openssl; no key material in the repo)
# --------------------------------------------------------------------------

CLIENT_KEY_PASSWORD = "fake-client-key-password-0001"


def _openssl(*args, cwd: Path):
    subprocess.run([OPENSSL, *args], cwd=cwd, check=True, capture_output=True)


def make_certs(tmp: Path) -> dict:
    """CA, a server cert for localhost and 127.0.0.1 (via scripts/make-private-ca.sh), a client cert, and
    an encrypted copy of the client key."""
    if not OPENSSL:
        raise unittest.SkipTest("openssl not found")
    d = Path(tmp) / "pki"
    subprocess.run(["sh", str(ROOT / "scripts" / "make-private-ca.sh"), str(d), "localhost", "127.0.0.1"],
                   check=True, capture_output=True)
    (d / "client.cnf").write_text("[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = test-client\n")
    (d / "client.ext").write_text(
        "basicConstraints = critical,CA:FALSE\nkeyUsage = critical,digitalSignature\n"
        "extendedKeyUsage = clientAuth\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\n")
    _openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "client.key", "-out", "client.csr",
             "-config", "client.cnf", cwd=d)
    _openssl("x509", "-req", "-sha256", "-days", "2", "-in", "client.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
             "-set_serial", "0x1234", "-extfile", "client.ext", "-out", "client.pem", cwd=d)
    _openssl("pkey", "-in", "client.key", "-aes-256-cbc", "-passout", f"pass:{CLIENT_KEY_PASSWORD}",
             "-out", "client-encrypted.key", cwd=d)
    return {name: str(d / name) for name in ("ca.pem", "server.pem", "server.key", "client.pem", "client.key",
                                              "client-encrypted.key")}


def server_tls(certs: dict, client_auth: str | None = None) -> ssl.SSLContext:
    """client_auth: None, 'required' or 'optional'."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certs["server.pem"], certs["server.key"])
    if client_auth:
        ctx.verify_mode = ssl.CERT_REQUIRED if client_auth == "required" else ssl.CERT_OPTIONAL
        ctx.load_verify_locations(certs["ca.pem"])
    return ctx
