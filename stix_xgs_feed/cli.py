"""Command line: one-off runs from flags or a config file, serve mode and the container health check."""
from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone

from . import __version__
from .config import ConfigError, load_config, settings_from_args
from .convert import parse_ts
from .runner import RunError, run_once, summary_lines

# Flags that may sit next to --config: the config file holds everything else.
_CONFIG_COMPATIBLE = {"config", "now"}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="stix-xgs-feed",
        description="Convert STIX sources into Sophos Firewall third-party threat feed files "
                    "(ips.txt, domains.txt, urls.txt; one indicator per line). "
                    "Other commands: 'stix-xgs-feed serve --config FILE' serves the files over HTTPS "
                    "and refreshes them on a schedule; 'stix-xgs-feed healthcheck --config FILE' checks "
                    "a running server. Unofficial, not a Sophos product.",
    )
    p.add_argument("--config", "-c", metavar="FILE",
                   help="Run once from a .toml or .json config file (sources, per-source auth, filters, "
                        "limits, output). Cannot be combined with the flags below, except --now.")
    src = p.add_argument_group("sources (at least one, unless --config)")
    src.add_argument("--input", "-i", action="append", default=[], metavar="FILE_OR_URL",
                     help="STIX 2.x JSON bundle or STIX 1.x XML package, local path or http(s) URL. Repeatable. "
                          "Fetched without credentials; authenticate URLs through a config file.")
    src.add_argument("--taxii", action="append", default=[], metavar="COLLECTION_URL",
                     help="TAXII 2.1 collection URL (.../collections/<id>/). Repeatable.")
    src.add_argument("--added-after", metavar="TIMESTAMP", help="TAXII added_after filter, e.g. 2026-08-01T00:00:00Z.")
    src.add_argument("--page-size", type=int, default=None, help="TAXII page size (limit parameter).")
    src.add_argument("--max-pages", type=int, default=10_000, help="Stop after this many TAXII pages (default 10000).")

    auth = p.add_argument_group(
        "authentication and TLS (credentials go to --taxii sources only; secrets are read from "
        "env:NAME or file:/path, never typed on the command line)")
    auth.add_argument("--taxii-user", help="Basic auth user for TAXII sources.")
    auth.add_argument("--taxii-password-env", default="TAXII_PASSWORD",
                      help="Environment variable holding the basic auth password (default TAXII_PASSWORD).")
    auth.add_argument("--bearer", metavar="REF", help="Bearer token for TAXII sources, as env:NAME or file:/path.")
    auth.add_argument("--header", action="append", metavar="'Name: value'",
                      help="Extra HTTP header for TAXII sources, e.g. an API key. A value of env:NAME or "
                           "file:/path is read from there; use that for anything secret. Repeatable.")
    auth.add_argument("--client-cert", metavar="FILE", help="Client certificate (PEM) for mutual TLS to TAXII sources.")
    auth.add_argument("--client-key", metavar="FILE", help="Private key (PEM) for --client-cert.")
    auth.add_argument("--client-key-password", metavar="REF",
                      help="Password for an encrypted --client-key, as env:NAME or file:/path.")
    auth.add_argument("--ca-file", help="CA bundle for servers with a private certificate (all URL sources).")

    flt = p.add_argument_group("filtering")
    flt.add_argument("--observables", choices=("none", "linked", "all"), default="linked",
                     help="Bare observables (SCOs) to include: none; linked (default) = only those tied by a "
                          "relationship to a valid indicator, malware, infrastructure, threat actor, intrusion "
                          "set, campaign or tool; all.")
    flt.add_argument("--broaden", action="store_true",
                     help="Also emit values from compound patterns (AND, FOLLOWEDBY, port or protocol conditions). "
                          "Off by default because the bare value is broader than the indicator.")
    flt.add_argument("--min-confidence", type=int, default=0,
                     help="Drop indicators below this STIX confidence (0 to 100). Objects without a confidence pass.")
    flt.add_argument("--max-tlp", choices=("clear", "white", "green", "amber", "amber+strict", "red"), default="amber",
                     help="Highest TLP marking to publish (default amber; RED and AMBER+STRICT are dropped).")
    flt.add_argument("--max-age-days", type=int, default=None,
                     help="Drop indicators with no valid_until whose last modification is older than this.")
    flt.add_argument("--allowlist", help="File of IPs/CIDRs, domains (covers subdomains) and URL prefixes never to publish.")
    flt.add_argument("--keep-internal", action="store_true",
                     help="Keep RFC 1918, CGNAT, loopback, link-local, multicast, reserved and internal-suffix values.")
    flt.add_argument("--expand-cidr", type=int, metavar="PREFIX", default=None,
                     help="Expand IPv4 CIDRs of this prefix length or longer (16 to 32) into single addresses "
                          "(Sophos Firewall does not accept ranges). Default: drop CIDRs.")

    lim = p.add_argument_group("limits")
    lim.add_argument("--model", help="Firewall model for the KBA-000010056 storage check, e.g. 'XGS 2100', 'virtual'.")
    lim.add_argument("--quota-share", type=float, default=1.0,
                     help="Share of the model's third-party feed storage this feed may use (default 1.0). "
                          "Over budget, each file is trimmed to its highest-confidence, newest entries.")
    lim.add_argument("--max-ips", type=int)
    lim.add_argument("--max-domains", type=int)
    lim.add_argument("--max-urls", type=int)

    out = p.add_argument_group("output")
    out.add_argument("--out", "-o", help="Output directory for ips.txt, domains.txt and urls.txt (required unless --config).")
    out.add_argument("--ipv6-file", action="store_true",
                     help="Also write ipv6.txt. Sophos Firewall feeds do not accept IPv6, so it is for other uses.")
    out.add_argument("--report", help="Write a JSON run report here. Keep it outside the served directory.")
    out.add_argument("--now", help="Override the current time (testing), e.g. 2026-10-29T00:00:00Z.")
    out.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def build_serve_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="stix-xgs-feed serve",
        description="Serve ips.txt, domains.txt and urls.txt over HTTPS for Sophos Firewall to poll, and rebuild "
                    "them on a schedule. Settings come from the [serve] section of the config file.",
    )
    p.add_argument("--config", "-c", required=True, metavar="FILE", help="The .toml or .json config file.")
    p.add_argument("--check", action="store_true",
                   help="Validate the config, secrets and certificates, then exit without serving.")
    p.add_argument("--log-level", choices=("debug", "info", "warning", "error"), default="info")
    return p


def build_healthcheck_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="stix-xgs-feed healthcheck",
        description="Exit 0 if the local serve instance answers /healthz with 200, else 1. For container health checks.",
    )
    p.add_argument("--config", "-c", required=True, metavar="FILE", help="The config file the server uses.")
    p.add_argument("--timeout", type=float, default=5.0, help="Seconds to wait (default 5).")
    return p


def _err(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)


def serve_main(argv) -> int:
    from .serve import FeedService  # imported here so one-off runs never load the server code

    args = build_serve_parser().parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level.upper()),
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    try:
        service = FeedService(load_config(args.config))
    except ConfigError as exc:
        _err(str(exc))
        return 2
    if args.check:
        print("config OK")
        return 0
    try:
        return service.run_forever()
    except OSError as exc:
        _err(f"cannot listen on {service.cfg.listen}:{service.cfg.port}: {exc.strerror or exc}")
        return 1


def healthcheck_main(argv) -> int:
    from .serve import healthcheck

    args = build_healthcheck_parser().parse_args(argv)
    try:
        settings = load_config(args.config)
    except ConfigError as exc:
        _err(str(exc))
        return 1
    if settings.serve is None:
        _err("the config file has no serve section")
        return 1
    ok = healthcheck(settings.serve, args.timeout)
    if not ok:
        print("unhealthy", file=sys.stderr)
    return 0 if ok else 1


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "serve":
        return serve_main(argv[1:])
    if argv and argv[0] == "healthcheck":
        return healthcheck_main(argv[1:])

    parser = build_parser()
    args = parser.parse_args(argv)
    now = parse_ts(args.now) if args.now else datetime.now(timezone.utc)
    if now is None:
        _err("--now is not a valid timestamp")
        return 2
    try:
        if args.config:
            defaults = vars(parser.parse_args([]))
            extra = sorted(k for k, v in vars(args).items() if k not in _CONFIG_COMPATIBLE and v != defaults[k])
            if extra:
                flags = ", ".join("--" + k.replace("_", "-") for k in extra)
                raise ConfigError(f"--config cannot be combined with {flags}; put those settings in the config file")
            settings = load_config(args.config)
        else:
            if not args.input and not args.taxii:
                raise ConfigError("give at least one --input or --taxii source, or --config")
            if not args.out:
                raise ConfigError("give --out, or --config")
            settings = settings_from_args(args)
    except ConfigError as exc:
        _err(str(exc))
        return 2

    try:
        report = run_once(settings, now)
    except RunError as exc:
        _err(str(exc))
        return 1
    print("\n".join(summary_lines(report, settings.out)))
    return 0
