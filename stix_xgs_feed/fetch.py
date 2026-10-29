"""Fetching sources over HTTP(S): authentication, host pinning, redirects and TAXII 2.1 paging.

Credentials (auth headers, an API key query parameter and the client
certificate) are sent only to the scheme, host and port of the configured URL,
and never on a redirected request. A redirect from HTTPS to plain HTTP is
refused. Credentials are only sent over HTTPS, or plain HTTP to a loopback
address for local testing.
"""
from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import logging
import ssl
import urllib.error
import urllib.parse
import urllib.request

from . import __version__
from .config import ConfigError, Source, is_secret_ref, resolve_secret

log = logging.getLogger("stix_xgs_feed")

USER_AGENT = f"stix-xgs-feed/{__version__}"
TAXII_ACCEPT = "application/taxii+json;version=2.1"
REDIRECT_CODES = (301, 302, 303, 307, 308)
MAX_REDIRECTS = 5


class FetchError(Exception):
    """A source could not be fetched. Messages never include credentials or query strings."""


def is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    h = host.strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def redact_url(url: str) -> str:
    """scheme://host[:port]/path, without user info, query or fragment."""
    try:
        p = urllib.parse.urlsplit(url)
        host = p.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        port = f":{p.port}" if p.port else ""
    except ValueError:
        return "<invalid URL>"
    return f"{p.scheme}://{host}{port}{p.path}"


def origin(url: str) -> tuple:
    p = urllib.parse.urlsplit(url)
    scheme = p.scheme.lower()
    return scheme, (p.hostname or "").lower(), p.port or {"http": 80, "https": 443}.get(scheme)


def _client_context(ca_file: str | None, where: str) -> ssl.SSLContext:
    # With a ca_file only that CA is trusted (a private CA); otherwise the system store.
    try:
        return ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    except (OSError, ssl.SSLError) as exc:
        raise FetchError(f"{where}: cannot load CA file {ca_file}: {exc}") from None


def _with_params(url: str, params: dict) -> str:
    p = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(p.query, keep_blank_values=True)
    query += list(params.items())
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, urllib.parse.urlencode(query), p.fragment))


def _without_params(url: str, names) -> str:
    url = url.split("#", 1)[0]
    if not names:
        return url
    p = urllib.parse.urlsplit(url)
    query = [(k, v) for k, v in urllib.parse.parse_qsl(p.query, keep_blank_values=True) if k not in names]
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, urllib.parse.urlencode(query), ""))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Turn every redirect into an HTTPError so SourceClient decides what follows."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SourceClient:
    """Fetches URLs for one source with that source's credentials, pinned to its origin.

    Secrets are resolved when the client is built, so a rotated file: secret is
    picked up on the next run.
    """

    def __init__(self, source: Source):
        self.source = source
        self.name = source.name
        self.pinned = origin(source.location)
        auth = source.auth
        where = f"source {source.name}"
        headers, params = {}, {}
        try:
            if auth.type == "basic":
                password = resolve_secret(auth.password, f"{where} password")
                token = base64.b64encode(f"{auth.username}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {token}"
            elif auth.type == "api_key":
                value = resolve_secret(auth.key_value, f"{where} key_value")
                (headers if auth.add_to == "header" else params)[auth.key_name] = value
            elif auth.type == "bearer":
                headers["Authorization"] = "Bearer " + resolve_secret(auth.token, f"{where} token")
            for name, value in auth.headers.items():
                headers[name] = resolve_secret(value, f"{where} header {name}") if is_secret_ref(value) else value
            key_password = (resolve_secret(auth.client_key_password, f"{where} client_key_password")
                            if auth.client_key_password else None)
        except ConfigError as exc:
            raise FetchError(str(exc)) from None
        self._headers, self._params = headers, params

        scheme, host = self.pinned[0], self.pinned[1]
        if auth.has_secrets() and scheme == "http" and not is_loopback_host(host):
            raise FetchError(f"{where}: credentials are only sent over HTTPS; use an https:// URL")
        if auth.client_cert and scheme != "https":
            raise FetchError(f"{where}: a client certificate needs an https:// URL")

        self._ctx = _client_context(source.ca_file, where)
        self._ctx_creds = self._ctx
        if auth.client_cert:
            ctx = _client_context(source.ca_file, where)
            try:
                ctx.load_cert_chain(auth.client_cert, auth.client_key, password=key_password)
            except (OSError, ssl.SSLError) as exc:
                raise FetchError(f"{where}: cannot load the client certificate or key: {exc}") from None
            self._ctx_creds = ctx

    def get(self, url: str, accept: str | None = None) -> bytes:
        current = url
        with_creds = origin(url) == self.pinned
        for _ in range(MAX_REDIRECTS + 1):
            headers = {"User-Agent": USER_AGENT}
            if accept:
                headers["Accept"] = accept
            request_url, ctx = current, self._ctx
            if with_creds:
                headers.update(self._headers)
                if self._params:
                    request_url = _with_params(current, self._params)
                ctx = self._ctx_creds
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect)
            try:
                with opener.open(urllib.request.Request(request_url, headers=headers),
                                 timeout=self.source.timeout) as resp:
                    return resp.read()
            except urllib.error.HTTPError as exc:
                location = exc.headers.get("Location") if exc.code in REDIRECT_CODES else None
                exc.close()
                if not location:
                    raise FetchError(f"HTTP {exc.code} from {redact_url(current)}") from None
                target = urllib.parse.urljoin(current, location)
                target_scheme = urllib.parse.urlsplit(target).scheme.lower()
                if target_scheme not in ("http", "https"):
                    raise FetchError("redirect to an unsupported URL scheme") from None
                if urllib.parse.urlsplit(current).scheme.lower() == "https" and target_scheme != "https":
                    raise FetchError("refusing a redirect from HTTPS to plain HTTP "
                                     f"({redact_url(target)})") from None
                # A server that echoes our API key parameter into Location does not get to carry it on.
                current = _without_params(target, self._params)
                with_creds = False
                log.info("%s: redirected to %s; credentials are not sent on redirects", self.name,
                         redact_url(current))
            except urllib.error.URLError as exc:
                raise FetchError(f"cannot fetch {redact_url(current)}: {exc.reason}") from None
            except (OSError, http.client.HTTPException) as exc:
                raise FetchError(f"cannot fetch {redact_url(current)}: {exc}") from None
        raise FetchError(f"more than {MAX_REDIRECTS} redirects from {redact_url(url)}")


def taxii_objects(client: SourceClient, source: Source):
    """Yield every object in a TAXII 2.1 collection, following the next/more paging."""
    url = source.location
    base = url if url.rstrip("/").endswith("/objects") else url.rstrip("/") + "/objects"
    base = base.rstrip("/") + "/"
    params = {}
    if source.added_after:
        params["added_after"] = source.added_after
    if source.page_size:
        params["limit"] = str(source.page_size)
    nxt, pages = None, 0
    while True:
        q = dict(params)
        if nxt:
            q["next"] = nxt
        page_url = base + ("?" + urllib.parse.urlencode(q) if q else "")
        try:
            body = json.loads(client.get(page_url, TAXII_ACCEPT))
        except ValueError:
            raise FetchError("the TAXII server did not return JSON") from None
        if not isinstance(body, dict):
            raise FetchError("unexpected TAXII response")
        pages += 1
        yield from body.get("objects") or []
        if not body.get("more") or not body.get("next") or pages >= source.max_pages:
            break
        nxt = body["next"]
