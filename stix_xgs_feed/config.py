"""Settings from a config file (TOML or JSON) or command-line flags.

Secrets are never values in the config file or on the command line. Every
secret field holds a reference, ``env:NAME`` or ``file:/path``, resolved when
it is needed. Error messages name the reference, never the value.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

from .convert import TLP_RANK, model_limits

try:
    import tomllib
except ImportError:  # Python 3.9 and 3.10: JSON config only
    tomllib = None

SOURCE_TYPES = ("file", "url", "taxii")
SOURCE_AUTH_TYPES = ("none", "basic", "api_key", "bearer")
SERVE_AUTH_TYPES = ("none", "basic", "api_key")
OBSERVABLE_MODES = ("none", "linked", "all")

# Sophos Firewall third-party feed limits (XML API reference, SFOS 21.0):
# username, password, API key name and API key value are each at most 64 characters.
XGS_FIELD_MAX = 64
SERVE_SECRET_MIN = 16

_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_QUERY_NAME_RE = re.compile(r"^[A-Za-z0-9._~-]+$")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PRINTABLE_RE = re.compile(r"^[\x21-\x7e]+$")
_PREFIX_RE = re.compile(r"^(/[A-Za-z0-9._~-]+)*$")


class ConfigError(ValueError):
    """A configuration problem. Messages never include secret values."""


# --------------------------------------------------------------------------
# Secret references
# --------------------------------------------------------------------------

def is_secret_ref(value) -> bool:
    return isinstance(value, str) and value.startswith(("env:", "file:"))


def check_secret_ref(value, where: str, base: Path | None = None) -> str:
    """Validate a secret reference; make a relative file: path absolute against base."""
    if not is_secret_ref(value):
        raise ConfigError(f"{where} must be a secret reference, env:NAME or file:/path "
                          "(secret values are not accepted in the config file or on the command line)")
    kind, _, target = value.partition(":")
    if kind == "env":
        if not _ENV_NAME_RE.match(target):
            raise ConfigError(f"{where}: {target!r} is not a valid environment variable name")
        return value
    if not target:
        raise ConfigError(f"{where}: file: needs a path")
    path = Path(target).expanduser()
    if base is not None and not path.is_absolute():
        path = base / path
    return f"file:{path}"


def resolve_secret(ref: str, where: str) -> str:
    kind, _, target = ref.partition(":")
    if kind == "env":
        value = os.environ.get(target, "")
        if not value:
            raise ConfigError(f"{where}: environment variable {target} is not set")
    else:
        try:
            value = Path(target).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigError(f"{where}: cannot read secret file {target}: {exc.strerror}") from None
        if not value:
            raise ConfigError(f"{where}: secret file {target} is empty")
    if "\r" in value or "\n" in value:
        raise ConfigError(f"{where}: the secret contains a line break")
    return value


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class Auth:
    """Credentials for one source. Secret fields hold env:/file: references."""
    type: str = "none"                    # none | basic | api_key | bearer
    username: str | None = None
    password: str | None = None
    key_name: str | None = None
    key_value: str | None = None
    add_to: str = "header"                # header | query
    token: str | None = None
    client_cert: str | None = None        # mTLS, combines with any type
    client_key: str | None = None
    client_key_password: str | None = None
    headers: dict = field(default_factory=dict)   # name -> literal or secret reference

    def has_secrets(self) -> bool:
        return (self.type != "none" or bool(self.client_cert)
                or any(is_secret_ref(v) for v in self.headers.values()))


@dataclass
class Source:
    name: str
    type: str                             # file | url | taxii
    location: str                         # path or URL
    auth: Auth = field(default_factory=Auth)
    ca_file: str | None = None
    added_after: str | None = None
    page_size: int | None = None
    max_pages: int = 10_000
    timeout: float = 120.0


@dataclass
class ServeAuth:
    type: str = "none"                    # none | basic | api_key
    username: str | None = None
    password: str | None = None
    key_name: str | None = None
    key_value: str | None = None
    add_to: str = "header"                # header | query


@dataclass
class ServeConfig:
    listen: str = "127.0.0.1"
    port: int = 8443
    path_prefix: str = ""
    tls_cert: str | None = None
    tls_key: str | None = None
    auth: ServeAuth = field(default_factory=ServeAuth)
    refresh_minutes: float = 60.0
    retry_minutes: float = 5.0
    allowed_clients: list = field(default_factory=list)
    max_connections: int = 32


@dataclass
class Settings:
    """Everything one run needs. Attribute names match the command-line flags."""
    sources: list
    out: str
    report: str | None = None
    ipv6_file: bool = False
    observables: str = "linked"
    broaden: bool = False
    min_confidence: int = 0
    max_tlp: str = "amber"
    max_age_days: int | None = None
    allowlist: str | None = None
    keep_internal: bool = False
    expand_cidr: int | None = None
    model: str | None = None
    quota_share: float = 1.0
    max_ips: int | None = None
    max_domains: int | None = None
    max_urls: int | None = None
    serve: ServeConfig | None = None


# --------------------------------------------------------------------------
# Validation shared by the config file and the command line
# --------------------------------------------------------------------------

def check_url(url: str, where: str) -> str:
    try:
        parts = urllib.parse.urlsplit(url)
        parts.port  # noqa: B018 - raises on a bad port
    except ValueError:
        raise ConfigError(f"{where}: invalid URL") from None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ConfigError(f"{where}: URL must start with https:// or http:// and name a host")
    if parts.username is not None or parts.password is not None:
        raise ConfigError(f"{where}: put credentials in the auth settings, not in the URL")
    return url


def validate_settings(s: Settings) -> Settings:
    if not s.sources:
        raise ConfigError("give at least one source")
    if not s.out:
        raise ConfigError("give an output directory")
    if s.observables not in OBSERVABLE_MODES:
        raise ConfigError(f"observables must be one of: {', '.join(OBSERVABLE_MODES)}")
    if s.max_tlp not in TLP_RANK:
        raise ConfigError(f"max_tlp must be one of: {', '.join(TLP_RANK)}")
    if not 0 <= s.min_confidence <= 100:
        raise ConfigError("min_confidence must be between 0 and 100")
    if not 0 < s.quota_share <= 1:
        raise ConfigError("quota_share must be more than 0 and at most 1")
    if s.expand_cidr is not None and not 16 <= s.expand_cidr <= 32:
        raise ConfigError("expand_cidr must be between 16 and 32")
    if s.max_age_days is not None and s.max_age_days < 1:
        raise ConfigError("max_age_days must be at least 1")
    for name in ("max_ips", "max_domains", "max_urls"):
        if getattr(s, name) is not None and getattr(s, name) < 0:
            raise ConfigError(f"{name} must not be negative")
    if s.model:
        try:
            model_limits(s.model)
        except ValueError as exc:
            raise ConfigError(str(exc)) from None
    names = [src.name for src in s.sources]
    if len(names) != len(set(names)):
        raise ConfigError("source names must be unique")
    for src in s.sources:
        if src.page_size is not None and src.page_size < 1:
            raise ConfigError(f"source {src.name}: page_size must be at least 1")
        if src.max_pages < 1:
            raise ConfigError(f"source {src.name}: max_pages must be at least 1")
        if src.timeout <= 0:
            raise ConfigError(f"source {src.name}: timeout must be more than 0")
    return s


# --------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------

def settings_from_args(args) -> Settings:
    """Build settings from the flat command-line flags.

    Credential flags apply to --taxii sources only. --input URLs are fetched
    without credentials; authenticate them through a config file.
    """
    auth = Auth()
    if args.taxii_user:
        auth.type, auth.username = "basic", args.taxii_user
        auth.password = check_secret_ref(f"env:{args.taxii_password_env}", "--taxii-password-env")
    if args.bearer:
        if auth.type != "none":
            raise ConfigError("use either --taxii-user or --bearer, not both")
        auth.type, auth.token = "bearer", check_secret_ref(args.bearer, "--bearer")
    for h in args.header or []:
        name, sep, value = h.partition(":")
        name, value = name.strip(), value.strip()
        if not sep or not _HEADER_NAME_RE.match(name):
            raise ConfigError(f"--header {name!r}: use 'Name: value'")
        auth.headers[name] = check_secret_ref(value, f"--header {name}") if is_secret_ref(value) else value
    if bool(args.client_cert) != bool(args.client_key):
        raise ConfigError("give both --client-cert and --client-key")
    auth.client_cert, auth.client_key = args.client_cert, args.client_key
    if args.client_key_password:
        auth.client_key_password = check_secret_ref(args.client_key_password, "--client-key-password")

    sources = []
    for i, loc in enumerate(args.input, 1):
        is_url = bool(re.match(r"^https?://", loc, re.I))
        if is_url:
            check_url(loc, f"--input {i}")
        sources.append(Source(name=f"input{i}", type="url" if is_url else "file", location=loc,
                              ca_file=args.ca_file))
    for i, loc in enumerate(args.taxii, 1):
        check_url(loc, f"--taxii {i}")
        sources.append(Source(name=f"taxii{i}", type="taxii", location=loc, auth=auth, ca_file=args.ca_file,
                              added_after=args.added_after, page_size=args.page_size, max_pages=args.max_pages))
    s = Settings(sources=sources, out=args.out)
    for name in ("report", "ipv6_file", "observables", "broaden", "min_confidence", "max_tlp", "max_age_days",
                 "allowlist", "keep_internal", "expand_cidr", "model", "quota_share", "max_ips", "max_domains",
                 "max_urls"):
        setattr(s, name, getattr(args, name))
    return validate_settings(s)


# --------------------------------------------------------------------------
# Config file
# --------------------------------------------------------------------------

_TYPE_NAMES = {str: "a string", int: "an integer", float: "a number", bool: "true or false",
               list: "a list", dict: "a table"}


class _Table:
    """Typed access to one config table; unknown keys are errors, so typos surface."""

    def __init__(self, data, where: str):
        if not isinstance(data, dict):
            raise ConfigError(f"{where} must be a table")
        self.data, self.where, self.used = data, where, set()

    def has(self, key: str) -> bool:
        return key in self.data

    def get(self, key, kind, default=None, required=False, choices=None):
        self.used.add(key)
        if key not in self.data:
            if required:
                raise ConfigError(f"{self.where}.{key} is required")
            return default
        v = self.data[key]
        if kind is float and isinstance(v, int) and not isinstance(v, bool):
            v = float(v)
        if (kind in (int, float) and isinstance(v, bool)) or not isinstance(v, kind):
            raise ConfigError(f"{self.where}.{key} must be {_TYPE_NAMES[kind]}")
        if choices and v not in choices:
            raise ConfigError(f"{self.where}.{key} must be one of: {', '.join(choices)}")
        return v

    def sub(self, key) -> _Table | None:
        self.used.add(key)
        return _Table(self.data[key], f"{self.where}.{key}") if key in self.data else None

    def done(self):
        extra = sorted(set(self.data) - self.used)
        if extra:
            raise ConfigError(f"{self.where}.{extra[0]} is not a known setting here")


def _path(value: str | None, base: Path) -> str | None:
    if value is None:
        return None
    p = Path(value).expanduser()
    return str(p if p.is_absolute() else base / p)


def _parse_source_auth(t: _Table, base: Path) -> Auth:
    w = t.where
    a = Auth(type=t.get("type", str, "none", choices=SOURCE_AUTH_TYPES))
    if a.type == "basic":
        a.username = t.get("username", str, required=True)
        if not a.username or ":" in a.username:
            raise ConfigError(f"{w}.username must be non-empty and contain no colon")
        a.password = check_secret_ref(t.get("password", str, required=True), f"{w}.password", base)
    elif a.type == "api_key":
        a.add_to = t.get("add_to", str, "header", choices=("header", "query"))
        a.key_name = t.get("key_name", str, required=True)
        pattern = _HEADER_NAME_RE if a.add_to == "header" else _QUERY_NAME_RE
        if not pattern.match(a.key_name):
            raise ConfigError(f"{w}.key_name is not a valid {a.add_to} name")
        a.key_value = check_secret_ref(t.get("key_value", str, required=True), f"{w}.key_value", base)
    elif a.type == "bearer":
        a.token = check_secret_ref(t.get("token", str, required=True), f"{w}.token", base)
    a.client_cert = _path(t.get("client_cert", str), base)
    a.client_key = _path(t.get("client_key", str), base)
    if bool(a.client_cert) != bool(a.client_key):
        raise ConfigError(f"{w}: give both client_cert and client_key")
    if t.has("client_key_password"):
        a.client_key_password = check_secret_ref(t.get("client_key_password", str), f"{w}.client_key_password", base)
    headers = t.get("headers", dict, {})
    for name, value in headers.items():
        if not _HEADER_NAME_RE.match(name) or not isinstance(value, str):
            raise ConfigError(f"{w}.headers.{name}: use a valid header name and a string value")
        if "\r" in value or "\n" in value:
            raise ConfigError(f"{w}.headers.{name} contains a line break")
        a.headers[name] = check_secret_ref(value, f"{w}.headers.{name}", base) if is_secret_ref(value) else value
    t.done()
    return a


def _parse_source(t: _Table, index: int, base: Path) -> Source:
    kind = t.get("type", str, required=True, choices=SOURCE_TYPES)
    name = t.get("name", str, f"source{index + 1}")
    if not name:
        raise ConfigError(f"{t.where}.name must not be empty")
    if kind == "file":
        location = _path(t.get("path", str, required=True), base)
    else:
        location = check_url(t.get("url", str, required=True), f"{t.where}.url")
    src = Source(name=name, type=kind, location=location)
    if kind == "taxii":
        src.added_after = t.get("added_after", str)
        src.page_size = t.get("page_size", int)
        src.max_pages = t.get("max_pages", int, 10_000)
    else:
        for key in ("added_after", "page_size", "max_pages"):
            if t.has(key):
                raise ConfigError(f"{t.where}.{key} only applies to taxii sources")
    if kind == "file":
        for key in ("auth", "ca_file", "timeout"):
            if t.has(key):
                raise ConfigError(f"{t.where}.{key} does not apply to file sources")
    else:
        src.ca_file = _path(t.get("ca_file", str), base)
        src.timeout = t.get("timeout", float, 120.0)
        auth = t.sub("auth")
        if auth is not None:
            src.auth = _parse_source_auth(auth, base)
    t.done()
    return src


def _parse_serve(t: _Table, base: Path) -> ServeConfig:
    c = ServeConfig()
    c.listen = t.get("listen", str, c.listen)
    c.port = t.get("port", int, c.port)
    if not 0 <= c.port <= 65535:
        raise ConfigError("serve.port must be a port number, 1 to 65535")
    prefix = t.get("path_prefix", str, "").rstrip("/")
    if prefix and not prefix.startswith("/"):
        prefix = "/" + prefix
    if not _PREFIX_RE.match(prefix) or "/../" in prefix + "/" or "/./" in prefix + "/":
        raise ConfigError("serve.path_prefix may only hold letters, digits and . _ ~ - separated by /")
    c.path_prefix = prefix
    c.tls_cert = _path(t.get("tls_cert", str), base)
    c.tls_key = _path(t.get("tls_key", str), base)
    if bool(c.tls_cert) != bool(c.tls_key):
        raise ConfigError("serve: give both tls_cert and tls_key")
    c.refresh_minutes = t.get("refresh_minutes", float, c.refresh_minutes)
    c.retry_minutes = t.get("retry_minutes", float, c.retry_minutes)
    if not 1 <= c.refresh_minutes <= 43_200:
        raise ConfigError("serve.refresh_minutes must be between 1 and 43200 (30 days)")
    if c.retry_minutes < 1:
        raise ConfigError("serve.retry_minutes must be at least 1")
    c.max_connections = t.get("max_connections", int, c.max_connections)
    if not 1 <= c.max_connections <= 1024:
        raise ConfigError("serve.max_connections must be between 1 and 1024")
    clients = t.get("allowed_clients", list, [])
    for entry in clients:
        try:
            c.allowed_clients.append(ipaddress.ip_network(str(entry), strict=False))
        except ValueError:
            raise ConfigError(f"serve.allowed_clients: {entry!r} is not an IP address or network") from None
    at = t.sub("auth")
    if at is not None:
        a = ServeAuth(type=at.get("type", str, "none", choices=SERVE_AUTH_TYPES))
        if a.type == "basic":
            a.username = at.get("username", str, required=True)
            a.password = check_secret_ref(at.get("password", str, required=True), "serve.auth.password", base)
        elif a.type == "api_key":
            a.add_to = at.get("add_to", str, "header", choices=("header", "query"))
            a.key_name = at.get("key_name", str, required=True)
            a.key_value = check_secret_ref(at.get("key_value", str, required=True), "serve.auth.key_value", base)
        at.done()
        c.auth = a
    t.done()
    return c


def load_config(path) -> Settings:
    """Load a .toml or .json config. Relative paths resolve against the config file's folder."""
    p = Path(path)
    try:
        raw_bytes = p.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read config file {p}: {exc.strerror}") from None
    suffix = p.suffix.lower()
    try:
        if suffix == ".toml":
            if tomllib is None:
                raise ConfigError("TOML config files need Python 3.11 or later; use a .json config instead")
            raw = tomllib.loads(raw_bytes.decode("utf-8"))
        elif suffix == ".json":
            raw = json.loads(raw_bytes)
        else:
            raise ConfigError("config file must end in .toml or .json")
    except (ValueError, UnicodeDecodeError) as exc:
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError(f"cannot parse {p.name}: {exc}") from None
    base = p.resolve().parent
    root = _Table(raw, "config")

    sources_raw = root.get("sources", list, required=True)
    sources = [_parse_source(_Table(entry, f"sources[{i}]"), i, base) for i, entry in enumerate(sources_raw)]

    out_t = root.sub("output")
    if out_t is None:
        raise ConfigError("config.output is required")
    s = Settings(sources=sources, out=_path(out_t.get("dir", str, required=True), base))
    s.report = _path(out_t.get("report", str), base)
    s.ipv6_file = out_t.get("ipv6_file", bool, False)
    out_t.done()

    flt = root.sub("filter") or _Table({}, "filter")
    s.observables = flt.get("observables", str, s.observables, choices=OBSERVABLE_MODES)
    s.broaden = flt.get("broaden", bool, False)
    s.min_confidence = flt.get("min_confidence", int, 0)
    s.max_tlp = flt.get("max_tlp", str, s.max_tlp, choices=tuple(TLP_RANK))
    s.max_age_days = flt.get("max_age_days", int)
    s.allowlist = _path(flt.get("allowlist", str), base)
    s.keep_internal = flt.get("keep_internal", bool, False)
    s.expand_cidr = flt.get("expand_cidr", int)
    flt.done()

    lim = root.sub("limits") or _Table({}, "limits")
    s.model = lim.get("model", str)
    s.quota_share = lim.get("quota_share", float, 1.0)
    s.max_ips = lim.get("max_ips", int)
    s.max_domains = lim.get("max_domains", int)
    s.max_urls = lim.get("max_urls", int)
    lim.done()

    serve = root.sub("serve")
    if serve is not None:
        s.serve = _parse_serve(serve, base)
    root.done()
    return validate_settings(s)
