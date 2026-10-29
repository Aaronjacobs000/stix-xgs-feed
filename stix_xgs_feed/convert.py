"""Core conversion: STIX parsing, extraction, filtering, normalization and limits.

Reads STIX 2.x objects and STIX 1.x XML packages, extracts IPv4/IPv6 addresses,
domains and URLs from indicator patterns and cyber observables, filters and
normalizes them, and returns them ready for the three plain-text files that
Sophos Firewall third-party threat feeds poll (ips.txt, domains.txt, urls.txt).
"""
from __future__ import annotations

import ipaddress
import os
import re
import tempfile
import urllib.parse
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:  # Hardened XML parsing when available; stdlib expat otherwise.
    from defusedxml import ElementTree as ET  # type: ignore
except ImportError:  # pragma: no cover
    import xml.etree.ElementTree as ET  # noqa: N817

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

# Storage limits for third-party threat feeds, per Sophos KBA-000010056
# (checked 29/10/2026). Shared across all third-party feeds on the firewall
# and across the three indicator types. Domain and URL figures assume average
# lengths of 64 and 512 characters.
MODEL_LIMITS = [
    (("87", "88", "107", "116", "virtual", "cloud"), (180_000, 98_000, 18_000)),
    (("126", "118"), (270_000, 140_000, 28_000)),
    (("136", "128", "138", "2100", "2300"), (900_000, 490_000, 94_000)),
    (("3100", "3300", "4300", "4500"), (2_700_000, 1_480_000, 280_000)),
    (("5500", "6500"), (4_500_000, 2_470_000, 470_000)),
    (("7500", "8500"), (8_800_000, 10_100_000, 1_900_000)),
]

TLP_RANK = {"clear": 0, "white": 0, "green": 1, "amber": 2, "amber+strict": 3, "red": 4}
KNOWN_TLP = {
    # TLP 1.0, defined in the STIX 2.x specifications
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "white",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",
    # TLP 2.0, OASIS extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487": "clear",
    "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb": "green",
    "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421": "amber",
    "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003": "amber+strict",
    "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1": "red",
}
TLP2_EXTENSION = "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d"

SCO_TYPES = {"ipv4-addr", "ipv6-addr", "domain-name", "url"}
# Objects whose relationships make an SCO count as malicious in "linked" mode.
CONTEXT_TYPES = {"indicator", "malware", "infrastructure", "threat-actor", "intrusion-set", "campaign", "tool"}

# Address space that may be internal to a customer network or is not unicast.
# Blocking it could cut internal traffic, so it is dropped unless asked.
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4",
    "240.0.0.0/4", "::/128", "::1/128", "::ffff:0:0/96", "fc00::/7", "fe80::/10", "ff00::/8",
)]
INTERNAL_SUFFIXES = ("localhost", "local", "localdomain", "internal", "lan", "home", "corp",
                     "intranet", "home.arpa", "arpa")

# STIX 1.x High/Medium/Low mapped with the STIX 2.1 confidence scale (Appendix A).
STIX1_CONFIDENCE = {"high": 85, "medium": 50, "low": 15, "none": 0, "unknown": None}

XSI_TYPE = "{http://www.w3.org/2001/XMLSchema-instance}type"


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

_TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?)?\s*(Z|[+-]\d{2}:?\d{2})?$"
)


def parse_ts(value) -> datetime | None:
    """Parse a STIX/RFC 3339 timestamp into an aware UTC datetime."""
    if not isinstance(value, str):
        return None
    m = _TS_RE.match(value.strip())
    if not m:
        return None
    y, mo, d, h, mi, se, frac, tz = m.groups()
    micro = int((frac or "0")[:6].ljust(6, "0"))
    tzinfo = timezone.utc
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        tzinfo = timezone(sign * timedelta(hours=int(tz[1:3]), minutes=int(tz[-2:])))
    try:
        dt = datetime(int(y), int(mo), int(d), int(h or 0), int(mi or 0), int(se or 0), micro, tzinfo=tzinfo)
    except ValueError:
        return None
    return dt.astimezone(timezone.utc)


def refang(value: str) -> str:
    """Undo common defanging: hxxp, [.], (.), {.}, [dot], [:], [://], [@]."""
    v = value.strip().strip("\"'<>")
    v = re.sub(r"[\[\(\{](?:\.|dot)[\]\)\}]", ".", v, flags=re.I)
    for old, new in (("[://]", "://"), ("[:]", ":"), ("[/]", "/"), ("[@]", "@"), ("\\.", ".")):
        v = v.replace(old, new)
    v = re.sub(r"^h(?:xx|XX|xX|Xx)p(s?)(?=:|\[)", r"http\1", v)
    v = re.sub(r"^fxp(?=:)", "ftp", v, flags=re.I)
    return v


def is_internal_ip(ip) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return True
    return any(ip.version == n.version and ip in n for n in INTERNAL_NETS)


# --------------------------------------------------------------------------
# STIX patterning: tokenizer, parser and indicator extraction
# --------------------------------------------------------------------------

class PatternError(ValueError):
    pass


_TOKEN_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<ts>t'[^']*')
  | (?P<bin>b'[^']*')
  | (?P<hex>h'[^']*')
  | (?P<str>'(?:\\.|[^'\\])*')
  | (?P<path>[A-Za-z0-9_][A-Za-z0-9_-]*:(?:[A-Za-z0-9_-]+|'[^']*')(?:\.(?:[A-Za-z0-9_-]+|'[^']*')|\[(?:\*|\d+)\])*)
  | (?P<num>-?\d+(?:\.\d+)?)
  | (?P<op><=|>=|!=|<>|==|=|<|>)
  | (?P<punct>[\[\](),])
  | (?P<word>[A-Za-z_]+)
""", re.X)


def _tokenize(text: str):
    pos, out = 0, []
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m:
            raise PatternError(f"unexpected character at {pos}: {text[pos:pos + 12]!r}")
        pos = m.end()
        kind = m.lastgroup
        if kind != "ws":
            out.append((kind, m.group()))
    return out


class _Parser:
    """Recursive-descent parser for the STIX 2.x patterning grammar.

    Observation operators, lowest precedence first: FOLLOWEDBY, OR, AND.
    Comparison operators inside [ ]: OR, then AND.
    """

    def __init__(self, text: str):
        self.toks = _tokenize(text)
        self.i = 0

    def _peek(self, k: int = 0):
        j = self.i + k
        return self.toks[j] if j < len(self.toks) else (None, None)

    def _take(self):
        tok = self._peek()
        if tok[0] is None:
            raise PatternError("unexpected end of pattern")
        self.i += 1
        return tok

    def _is_word(self, word: str, k: int = 0) -> bool:
        kind, val = self._peek(k)
        return kind == "word" and val.upper() == word

    def _expect(self, kind: str, val: str | None = None):
        tok = self._take()
        if tok[0] != kind or (val is not None and tok[1] != val):
            raise PatternError(f"expected {val or kind}, got {tok[1]!r}")
        return tok

    def parse(self):
        node = self._obs_seq()
        if self._peek()[0] is not None:
            raise PatternError(f"trailing input: {self._peek()[1]!r}")
        return node

    def _obs_seq(self):
        items = [self._obs_or()]
        while self._is_word("FOLLOWEDBY"):
            self._take()
            items.append(self._obs_or())
        return items[0] if len(items) == 1 else ("seq", items)

    def _obs_or(self):
        items = [self._obs_and()]
        while self._is_word("OR"):
            self._take()
            items.append(self._obs_and())
        return items[0] if len(items) == 1 else ("oor", items)

    def _obs_and(self):
        items = [self._obs_qualified()]
        while self._is_word("AND"):
            self._take()
            items.append(self._obs_qualified())
        return items[0] if len(items) == 1 else ("oand", items)

    def _obs_qualified(self):
        kind, val = self._peek()
        if kind == "punct" and val == "[":
            self._take()
            comp = self._comp_or()
            self._expect("punct", "]")
            node = ("obs", comp)
        elif kind == "punct" and val == "(":
            self._take()
            node = self._obs_seq()
            self._expect("punct", ")")
        else:
            raise PatternError(f"expected '[' or '(', got {val!r}")
        quals = []
        while True:
            if self._is_word("START"):
                self._take()
                start = parse_ts(self._expect("ts")[1][2:-1])
                if not self._is_word("STOP"):
                    raise PatternError("START without STOP")
                self._take()
                stop = parse_ts(self._expect("ts")[1][2:-1])
                quals.append(("startstop", start, stop))
            elif self._is_word("WITHIN"):
                self._take()
                self._expect("num")
                if not self._is_word("SECONDS"):
                    raise PatternError("WITHIN without SECONDS")
                self._take()
                quals.append(("within",))
            elif self._is_word("REPEATS"):
                self._take()
                self._expect("num")
                if not self._is_word("TIMES"):
                    raise PatternError("REPEATS without TIMES")
                self._take()
                quals.append(("repeats",))
            else:
                break
        return ("qual", node, quals) if quals else node

    def _comp_or(self):
        items = [self._comp_and()]
        while self._is_word("OR"):
            self._take()
            items.append(self._comp_and())
        return items[0] if len(items) == 1 else ("or", items)

    def _comp_and(self):
        items = [self._comp_atom()]
        while self._is_word("AND"):
            self._take()
            items.append(self._comp_atom())
        return items[0] if len(items) == 1 else ("and", items)

    def _value(self):
        kind, val = self._take()
        if kind == "str":
            return val[1:-1].replace("\\'", "'").replace("\\\\", "\\")
        if kind == "num":
            return float(val) if "." in val else int(val)
        if kind in ("ts", "bin", "hex"):
            return val[2:-1]
        if kind == "word" and val.lower() in ("true", "false"):
            return val.lower() == "true"
        raise PatternError(f"expected a literal, got {val!r}")

    def _comp_atom(self):
        kind, val = self._peek()
        if kind == "punct" and val == "(":
            self._take()
            node = self._comp_or()
            self._expect("punct", ")")
            return node
        if self._is_word("EXISTS"):
            self._take()
            return ("exists", self._expect("path")[1])
        path = self._expect("path")[1]
        negated = False
        if self._is_word("NOT"):
            self._take()
            negated = True
        kind, val = self._take()
        if kind == "op":
            return ("cmp", path, "!=" if val == "<>" else ("=" if val == "==" else val), negated, self._value())
        if kind == "word" and val.upper() == "IN":
            self._expect("punct", "(")
            vals = [self._value()]
            while self._peek() == ("punct", ","):
                self._take()
                vals.append(self._value())
            self._expect("punct", ")")
            return ("cmp", path, "IN", negated, vals)
        if kind == "word" and val.upper() in ("LIKE", "MATCHES", "ISSUBSET", "ISSUPERSET"):
            return ("cmp", path, val.upper(), negated, self._value())
        raise PatternError(f"unknown operator {val!r}")


def parse_pattern(text: str):
    return _Parser(text).parse()


_IOC_PATHS = {"ipv4-addr:value": "ip", "ipv6-addr:value": "ip", "domain-name:value": "domain", "url:value": "url"}
_REF_VALUE_RE = re.compile(r"^[a-z0-9-]+:(?:[a-z_]+_ref|[a-z_]+_refs\[(?:\*|\d+)\])\.value$")
_REF_TYPE_RE = re.compile(r"^[a-z0-9-]+:(?:[a-z_]+_ref|[a-z_]+_refs\[(?:\*|\d+)\])\.type$")


def _classify_path(path: str) -> str:
    if path in _IOC_PATHS:
        return _IOC_PATHS[path]
    if _REF_VALUE_RE.match(path):
        return "auto"
    if _REF_TYPE_RE.match(path):
        return "neutral"
    return "other"


@dataclass
class Hit:
    hint: str          # ip | domain | url | auto
    value: str
    compound: bool     # true when the pattern only matches with other conditions


def _comp_extract(node, skipped: Counter):
    """Return (hits, status) where status is ioc, neutral or other."""
    kind = node[0]
    if kind == "cmp":
        _, path, op, negated, val = node
        cls = _classify_path(path)
        if cls == "neutral":
            return [], "neutral"
        if cls == "other":
            return [], "other"
        if negated or op == "!=":
            skipped["pattern_negated"] += 1
            return [], "other"
        if op in ("LIKE", "MATCHES"):
            skipped["pattern_wildcard_or_regex"] += 1
            return [], "other"
        if op in ("=", "ISSUBSET"):
            vals = [val]
        elif op == "IN":
            vals = list(val)
        else:
            skipped["pattern_unsupported_operator"] += 1
            return [], "other"
        return [Hit(cls, v, False) for v in vals if isinstance(v, str)], "ioc"
    if kind == "exists":
        return [], "other"
    results = [_comp_extract(child, skipped) for child in node[1]]
    hits = [h for hs, _ in results for h in hs]
    if kind == "and":
        n_ioc = sum(1 for _, s in results if s == "ioc")
        n_other = sum(1 for _, s in results if s == "other")
        if n_other or n_ioc > 1:
            for h in hits:
                h.compound = True
        return hits, ("ioc" if hits else ("other" if n_other else "neutral"))
    # or
    if hits:
        return hits, "ioc"
    return [], ("other" if any(s == "other" for _, s in results) else "neutral")


def _obs_extract(node, now: datetime, skipped: Counter) -> list:
    kind = node[0]
    if kind == "obs":
        hits, _ = _comp_extract(node[1], skipped)
        return hits
    if kind == "qual":
        _, inner, quals = node
        hits = _obs_extract(inner, now, skipped)
        for q in quals:
            if q[0] == "startstop":
                start, stop = q[1], q[2]
                if (stop and stop <= now) or (start and start > now):
                    skipped["pattern_time_window_closed"] += len(hits)
                    return []
        return hits
    children = [_obs_extract(child, now, skipped) for child in node[1]]
    hits = [h for hs in children for h in hs]
    if kind in ("oand", "seq"):
        for h in hits:
            h.compound = True
    return hits


def extract_from_pattern(pattern: str, now: datetime, skipped: Counter) -> list:
    return _obs_extract(parse_pattern(pattern), now, skipped)


# --------------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------------

@dataclass
class Options:
    keep_internal: bool = False
    expand_cidr: int | None = None


class Allowlist:
    """IPs/CIDRs apply to ips.txt, domains (and their subdomains) to domains.txt,
    URL prefixes to urls.txt. A domain entry does not exempt URLs on that host."""

    def __init__(self):
        self.nets, self.domains, self.url_prefixes = [], set(), []

    @classmethod
    def load(cls, path: str | None) -> Allowlist:
        al = cls()
        if not path:
            return al
        for raw in Path(path).read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip() if not raw.strip().startswith("http") else raw.strip()
            if not line:
                continue
            if "://" in line:
                norm = normalise_url(line, Options(keep_internal=True))
                al.url_prefixes.append(norm[1] if isinstance(norm, tuple) else line.lower())
                continue
            try:
                al.nets.append(ipaddress.ip_network(line, strict=False))
                continue
            except ValueError:
                pass
            al.domains.add(line.lower().lstrip("*.").rstrip("."))
        return al

    def blocks(self, kind: str, value: str) -> bool:
        if kind in ("ipv4", "ipv6"):
            ip = ipaddress.ip_address(value)
            return any(ip.version == n.version and ip in n for n in self.nets)
        if kind == "domain":
            labels = value.split(".")
            return any(".".join(labels[i:]) in self.domains for i in range(len(labels)))
        if kind == "url":
            return any(value.startswith(p) for p in self.url_prefixes)
        return False


_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


def normalise_domain(value: str):
    v = value.strip().lower().rstrip(".")
    if "*" in v:
        return "wildcard_domain"
    if not v or any(c in v for c in "/:@ \t?#"):
        return "invalid_domain"
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError:
        return "invalid_domain"
    labels = v.split(".")
    if len(v) > 253 or len(labels) < 2 or not all(_LABEL_RE.match(lbl) for lbl in labels):
        return "invalid_domain"
    if labels[-1].isdigit():
        return "invalid_domain"
    if any(v == s or v.endswith("." + s) for s in INTERNAL_SUFFIXES):
        return "internal_domain"
    return ("domain", v)


def normalise_ip(value: str, opts: Options):
    """Return ("ipv4"|"ipv6", value), a list of those for an expanded CIDR, or a drop reason."""
    v = value.strip()
    if "/" in v:
        try:
            net = ipaddress.ip_network(v, strict=False)
        except ValueError:
            return "invalid_ip"
        if net.num_addresses == 1:
            v = str(net.network_address)
        elif net.version == 4 and opts.expand_cidr is not None and net.prefixlen >= opts.expand_cidr:
            out = []
            for host in net:
                r = normalise_ip(str(host), opts)
                if isinstance(r, tuple):
                    out.append(r)
            return out or "internal_ip"
        else:
            return "cidr_range"
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return "invalid_ip"
    if not opts.keep_internal and is_internal_ip(ip):
        return "internal_ip"
    return ("ipv4" if ip.version == 4 else "ipv6", str(ip))


_URL_PATH_SAFE = "/%:@!$&'()*+,;=-._~"
_URL_QUERY_SAFE = "/%:@!$&'()*+,;=-._~?"


def normalise_url(value: str, opts: Options):
    v = value.strip()
    if "://" not in v:
        if re.match(r"^[a-z][a-z0-9+.-]*:", v, re.I) and not re.match(r"^[^/]+:\d", v):
            return "url_unsupported_scheme"
        v = "http://" + v.lstrip("/")
    try:
        parts = urllib.parse.urlsplit(v)
        port = parts.port
    except ValueError:
        return "invalid_url"
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return "url_unsupported_scheme"
    host = (parts.hostname or "").rstrip(".")
    if not host:
        return "invalid_url"
    try:
        ip = ipaddress.ip_address(host)
        if not opts.keep_internal and is_internal_ip(ip):
            return "internal_ip"
        host = f"[{ip}]" if ip.version == 6 else str(ip)
    except ValueError:
        d = normalise_domain(host)
        if not isinstance(d, tuple):
            return d if d == "internal_domain" else "invalid_url"
        host = d[1]
    if port and port != {"http": 80, "https": 443}[scheme]:
        host = f"{host}:{port}"
    path = urllib.parse.quote(parts.path or "/", safe=_URL_PATH_SAFE)
    url = f"{scheme}://{host}{path}"
    if parts.query:
        url += "?" + urllib.parse.quote(parts.query, safe=_URL_QUERY_SAFE)
    return ("url", url)


def normalise(hint: str, raw: str, opts: Options):
    """Map a raw STIX value to [(kind, value)] or a drop-reason string."""
    v = refang(raw)
    if not v:
        return "invalid_value"
    if hint == "url" or (hint == "auto" and "://" in v):
        r = normalise_url(v, opts)
        return [r] if isinstance(r, tuple) else r
    candidate = v.split("/", 1)[0] if "/" in v else v
    looks_ip = False
    try:
        ipaddress.ip_address(candidate.strip("[]"))
        looks_ip = True
    except ValueError:
        pass
    if hint == "ip" or looks_ip:
        r = normalise_ip(v.strip("[]"), opts)
        if isinstance(r, tuple):
            return [r]
        return r
    if hint in ("domain", "auto"):
        r = normalise_domain(v)
        return [r] if isinstance(r, tuple) else r
    return "invalid_value"


# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------

@dataclass
class Candidate:
    kind: str
    value: str
    confidence: int | None
    modified: datetime | None


class Collector:
    def __init__(self, args, now: datetime, allowlist: Allowlist):
        self.args = args
        self.now = now
        self.allowlist = allowlist
        self.opts = Options(keep_internal=args.keep_internal, expand_cidr=args.expand_cidr)
        self.stix2_objects: list = []
        self.objects_dropped: Counter = Counter()
        self.values_dropped: Counter = Counter()
        self.stats: Counter = Counter()
        self.parse_errors: list = []
        self.candidates: list = []

    # ---- shared filters -------------------------------------------------

    def _tlp_ok(self, level: str | None) -> bool:
        return level is None or TLP_RANK[level] <= TLP_RANK[self.args.max_tlp]

    def _confidence_ok(self, conf) -> bool:
        """Objects that carry no confidence value pass; many feeds never set one."""
        if self.args.min_confidence <= 0 or conf is None:
            return True
        return conf >= self.args.min_confidence

    def _add_hit(self, hint: str, raw: str, compound: bool, confidence, modified):
        self.stats["values_extracted"] += 1
        if compound and not self.args.broaden:
            self.values_dropped["pattern_compound"] += 1
            return
        result = normalise(hint, raw, self.opts)
        if isinstance(result, str):
            self.values_dropped[result] += 1
            return
        for kind, value in result:
            self.candidates.append(Candidate(kind, value, confidence, modified))

    # ---- STIX 2.x ---------------------------------------------------------

    def add_stix2(self, objects):
        for obj in objects:
            if isinstance(obj, dict) and isinstance(obj.get("type"), str):
                self.stix2_objects.append(obj)

    def _tlp_of(self, obj: dict, markings: dict) -> str | None:
        levels = [markings.get(ref) or KNOWN_TLP.get(ref) for ref in obj.get("object_marking_refs") or []]
        for label in obj.get("labels") or []:
            if isinstance(label, str) and label.lower().startswith("tlp:"):
                levels.append(label[4:].strip().lower())
        levels = [lv for lv in levels if lv in TLP_RANK]
        return max(levels, key=TLP_RANK.get) if levels else None

    def _time_reason(self, obj: dict) -> str | None:
        if obj.get("revoked") is True:
            return "revoked"
        until = parse_ts(obj.get("valid_until"))
        if until and until <= self.now:
            return "expired"
        start = parse_ts(obj.get("valid_from"))
        if start and start > self.now:
            return "not_yet_valid"
        if self.args.max_age_days and not until:
            ref = parse_ts(obj.get("modified")) or start or parse_ts(obj.get("created"))
            if ref and ref < self.now - timedelta(days=self.args.max_age_days):
                return "stale"
        return None

    def process_stix2(self):
        latest: dict = {}
        anonymous: list = []
        for obj in self.stix2_objects:
            oid = obj.get("id")
            if not isinstance(oid, str):
                anonymous.append(obj)
                continue
            prev = latest.get(oid)
            if prev is None:
                latest[oid] = obj
                continue
            self.stats["older_versions_ignored"] += 1
            if (obj.get("modified") or "") >= (prev.get("modified") or ""):
                latest[oid] = obj
        objs = list(latest.values()) + anonymous
        self.stats["stix2_objects"] = len(objs)

        markings = {}
        for o in objs:
            if o["type"] != "marking-definition":
                continue
            level = None
            if o.get("definition_type") == "tlp":
                level = str((o.get("definition") or {}).get("tlp", "")).lower()
            ext = (o.get("extensions") or {}).get(TLP2_EXTENSION) or {}
            level = ext.get("tlp_2_0", level)
            if level in TLP_RANK:
                markings[o["id"]] = level

        # id -> confidence of objects that give an SCO malicious context
        good_context: dict = {}
        for o in objs:
            t = o["type"]
            if t == "indicator":
                self.stats["indicators"] += 1
                if self._indicator(o, markings):
                    good_context[o["id"]] = o.get("confidence")
            elif t in CONTEXT_TYPES and o.get("revoked") is not True:
                good_context[o.get("id")] = o.get("confidence")

        mode = self.args.observables
        if mode == "none":
            return
        # SCO id -> best confidence among the context objects linked to it
        linked: dict = {}
        if mode == "linked":
            for o in objs:
                if o["type"] != "relationship" or o.get("revoked") is True:
                    continue
                src, dst = o.get("source_ref"), o.get("target_ref")
                for this, other in ((src, dst), (dst, src)):
                    if this in good_context:
                        conf = good_context[this]
                        prev = linked.get(other)
                        linked[other] = conf if prev is None or (conf is not None and conf > prev) else prev
        for o in objs:
            t = o["type"]
            if t in SCO_TYPES:
                self.stats["observables_seen"] += 1
                if mode == "linked" and o.get("id") not in linked:
                    self.objects_dropped["observable_not_linked"] += 1
                    continue
                self._observable(o, None, markings, linked.get(o.get("id")))
            elif t == "observed-data" and isinstance(o.get("objects"), dict):
                for sub in o["objects"].values():
                    if isinstance(sub, dict) and sub.get("type") in SCO_TYPES:
                        self.stats["observables_seen"] += 1
                        if mode == "linked":
                            self.objects_dropped["observable_not_linked"] += 1
                            continue
                        self._observable(sub, o, markings, o.get("confidence"))

    def _indicator(self, o: dict, markings: dict) -> bool:
        reason = self._time_reason(o)
        if not reason and not self._confidence_ok(o.get("confidence")):
            reason = "below_min_confidence"
        if not reason and not self._tlp_ok(self._tlp_of(o, markings)):
            reason = "tlp_above_max"
        if not reason and (o.get("pattern_type") or "stix") != "stix":
            reason = "non_stix_pattern"
        if reason:
            self.objects_dropped[reason] += 1
            return False
        pattern = o.get("pattern")
        if not isinstance(pattern, str):
            self.objects_dropped["pattern_missing"] += 1
            return False
        skipped: Counter = Counter()
        try:
            hits = extract_from_pattern(pattern, self.now, skipped)
        except PatternError as exc:
            self.objects_dropped["pattern_parse_error"] += 1
            if len(self.parse_errors) < 20:
                self.parse_errors.append({"id": o.get("id"), "error": str(exc)})
            return False
        self.values_dropped.update(skipped)
        if not hits and not skipped:
            self.objects_dropped["no_network_indicator"] += 1
            return True
        modified = parse_ts(o.get("modified")) or parse_ts(o.get("created"))
        for h in hits:
            self._add_hit(h.hint, h.value, h.compound, o.get("confidence"), modified)
        return True

    def _observable(self, sco: dict, parent: dict | None, markings: dict, confidence):
        """parent is the STIX 2.0 observed-data holding an embedded SCO, else None."""
        level = self._tlp_of(sco, markings) or (self._tlp_of(parent, markings) if parent else None)
        if not self._tlp_ok(level):
            self.objects_dropped["tlp_above_max"] += 1
            return
        if parent and parent.get("revoked") is True:
            self.objects_dropped["revoked"] += 1
            return
        value = sco.get("value")
        if not isinstance(value, str):
            self.objects_dropped["invalid_value"] += 1
            return
        if not self._confidence_ok(confidence):
            self.objects_dropped["below_min_confidence"] += 1
            return
        hint = {"ipv4-addr": "ip", "ipv6-addr": "ip", "domain-name": "domain", "url": "url"}[sco["type"]]
        modified = parse_ts(parent.get("modified")) if parent else None
        self._add_hit(hint, value, False, confidence, modified)

    # ---- STIX 1.x ---------------------------------------------------------

    def process_stix1(self, data: bytes):
        root = ET.fromstring(data)
        ids = {el.get("id"): el for el in root.iter() if el.get("id")}
        referenced: set = set()

        def local(el) -> str:
            return el.tag.rsplit("}", 1)[-1] if isinstance(el.tag, str) else ""

        def tlp_in(el) -> str | None:
            colours = [m.get("color", "").lower() for m in el.iter() if local(m) == "Marking_Structure" and m.get("color")]
            colours = [c for c in colours if c in TLP_RANK]
            return max(colours, key=TLP_RANK.get) if colours else None

        header = next((el for el in root if local(el) == "STIX_Header"), None)
        package_tlp = tlp_in(header) if header is not None else None

        def props_hits(props, compound: bool, skipped: Counter):
            xtype = props.get(XSI_TYPE, "").split(":")[-1]
            fields = []
            if xtype == "AddressObjectType":
                cat = props.get("category", "ipv4-addr")
                if cat in ("ipv4-addr", "ipv6-addr", "ipv4-net", "ipv6-net"):
                    fields = [(c, "ip") for c in props if local(c) == "Address_Value"]
            elif xtype == "DomainNameObjectType":
                fields = [(c, "domain") for c in props if local(c) == "Value"]
            elif xtype == "HostnameObjectType":
                fields = [(c, "domain") for c in props if local(c) == "Hostname_Value"]
            elif xtype == "URIObjectType":
                hint = {"URL": "url", "Domain Name": "domain"}.get(props.get("type", "URL"), "auto")
                fields = [(c, hint) for c in props if local(c) == "Value"]
            hits = []
            for el, hint in fields:
                cond = el.get("condition", "Equals")
                if cond in ("DoesNotEqual", "DoesNotContain"):
                    skipped["pattern_negated"] += 1
                    continue
                if cond != "Equals":
                    skipped["pattern_wildcard_or_regex"] += 1
                    continue
                values = [v for v in (el.text or "").split("##comma##") if v.strip()]
                multi_all = el.get("apply_condition", "ANY").upper() == "ALL" and len(values) > 1
                hits += [Hit(hint, v, compound or multi_all) for v in values]
            return hits

        def walk(el, compound: bool, skipped: Counter, depth: int = 0):
            if depth > 20:
                return []
            ref = el.get("idref")
            if ref and len(el) == 0:
                referenced.add(ref)
                target = ids.get(ref)
                return walk(target, compound, skipped, depth + 1) if target is not None else []
            if el.get("id"):
                referenced.add(el.get("id"))
            hits = []
            for child in el:
                name = local(child)
                if name == "Observable_Composition":
                    parts = [c for c in child if local(c) == "Observable"]
                    is_and = child.get("operator", "AND").upper() == "AND" and len(parts) > 1
                    for part in parts:
                        hits += walk(part, compound or is_and, skipped, depth + 1)
                elif name == "Object":
                    for props in child:
                        if local(props) == "Properties":
                            hits += props_hits(props, compound, skipped)
                elif name == "Observable":
                    hits += walk(child, compound, skipped, depth + 1)
            return hits

        for ind in (el for el in root.iter() if local(el) == "Indicator" and len(el) > 0):
            self.stats["indicators"] += 1
            reason = None
            if ind.get("negate", "false").lower() == "true":
                reason = "negated_indicator"
            start = end = None
            for vtp in (c for c in ind if local(c) == "Valid_Time_Position"):
                for vt in vtp:
                    if local(vt) == "Start_Time":
                        start = parse_ts(vt.text)
                    elif local(vt) == "End_Time":
                        end = parse_ts(vt.text)
            if not reason and end and end <= self.now:
                reason = "expired"
            if not reason and start and start > self.now:
                reason = "not_yet_valid"
            conf = None
            for c in ind:
                if local(c) == "Confidence":
                    for v in c:
                        if local(v) == "Value" and v.text:
                            conf = STIX1_CONFIDENCE.get(v.text.strip().lower())
            if not reason and not self._confidence_ok(conf):
                reason = "below_min_confidence"
            handling = next((c for c in ind if local(c) == "Handling"), None)
            level = (tlp_in(handling) if handling is not None else None) or package_tlp
            if not reason and not self._tlp_ok(level):
                reason = "tlp_above_max"
            skipped: Counter = Counter()
            hits = []
            for obs in (c for c in ind if local(c) == "Observable"):
                hits += walk(obs, False, skipped)
            if reason:
                self.objects_dropped[reason] += 1
                continue
            self.values_dropped.update(skipped)
            if not hits and not skipped:
                self.objects_dropped["no_network_indicator"] += 1
            for h in hits:
                self._add_hit(h.hint, h.value, h.compound, conf, None)

        # Package-level observables that no indicator referenced. In "linked"
        # mode they count when a TTP (e.g. C2 infrastructure), campaign, threat
        # actor or course of action points at them by idref.
        context_refs = {
            d.get("idref")
            for el in root.iter() if local(el) in ("TTP", "Campaign", "Threat_Actor", "Course_Of_Action")
            for d in el.iter() if d.get("idref")
        }
        for obs_list in (el for el in root if local(el) == "Observables"):
            for obs in (c for c in obs_list if local(c) == "Observable"):
                if obs.get("id") in referenced:
                    continue
                self.stats["observables_seen"] += 1
                mode = self.args.observables
                if mode == "none" or (mode == "linked" and obs.get("id") not in context_refs):
                    self.objects_dropped["observable_not_linked"] += 1
                    continue
                if not self._tlp_ok(package_tlp):
                    self.objects_dropped["tlp_above_max"] += 1
                    continue
                skipped = Counter()
                for h in walk(obs, False, skipped):
                    self._add_hit(h.hint, h.value, h.compound, None, None)
                self.values_dropped.update(skipped)

    # ---- finalise -------------------------------------------------------

    def results(self):
        best: dict = {}
        for c in self.candidates:
            if self.allowlist.blocks(c.kind, c.value):
                self.values_dropped["allowlisted"] += 1
                continue
            key = (c.kind, c.value)
            prev = best.get(key)
            if prev is None:
                best[key] = c
                continue
            self.stats["duplicates_merged"] += 1
            if _priority(c) > _priority(prev):
                best[key] = c
        out = {"ipv4": [], "ipv6": [], "domain": [], "url": []}
        for c in best.values():
            out[c.kind].append(c)
        return out


def _priority(c: Candidate):
    ts = c.modified.timestamp() if c.modified else 0.0
    return (c.confidence if c.confidence is not None else -1, ts)


# --------------------------------------------------------------------------
# Limits
# --------------------------------------------------------------------------

def model_limits(model: str):
    key = re.sub(r"(?i)^xgs\s*|w$|\s+", "", model.strip()).lower()
    for names, limits in MODEL_LIMITS:
        if key in names:
            return limits
    raise ValueError(f"unknown model {model!r}; known: " + ", ".join(n for names, _ in MODEL_LIMITS for n in names))


def quota_fraction(ips, domains, urls, limits) -> float:
    max_ip, max_dom, max_url = limits
    dom_chars = sum(len(c.value) for c in domains)
    url_chars = sum(len(c.value) for c in urls)
    return len(ips) / max_ip + dom_chars / (64 * max_dom) + url_chars / (512 * max_url)


def apply_caps(out: dict, args, dropped: Counter, report: dict):
    for kind in ("ipv4", "domain", "url"):
        out[kind].sort(key=_priority, reverse=True)
    caps = {"ipv4": args.max_ips, "domain": args.max_domains, "url": args.max_urls}
    for kind, cap in caps.items():
        if cap is not None and len(out[kind]) > cap:
            dropped["over_cap"] += len(out[kind]) - cap
            out[kind] = out[kind][:cap]
    if not args.model:
        return
    limits = model_limits(args.model)
    budget = args.quota_share
    used = quota_fraction(out["ipv4"], out["domain"], out["url"], limits)
    report["model"] = {"model": args.model, "limits_ipv4_domains_urls": limits, "quota_share": budget,
                       "estimated_use_before_trim": round(used, 8)}
    if used > budget:
        factor = budget / used
        for kind in ("ipv4", "domain", "url"):
            keep = int(len(out[kind]) * factor)
            dropped["over_model_quota"] += len(out[kind]) - keep
            out[kind] = out[kind][:keep]
        used = quota_fraction(out["ipv4"], out["domain"], out["url"], limits)
    report["model"]["estimated_use_after_trim"] = round(used, 8)


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def write_atomic(path: Path, lines: list):
    data = "".join(line + "\n" for line in lines).encode("ascii")
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _ip_sort(value: str):
    ip = ipaddress.ip_address(value)
    return (ip.version, int(ip))
