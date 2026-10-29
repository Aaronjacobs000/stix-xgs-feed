"""One conversion run: load every source, convert, write the files atomically.

Fail closed: if any source fails, nothing is written and the previous files
stay in place, so the firewall keeps polling the last good set.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import Settings
from .convert import Allowlist, Collector, _ip_sort, apply_caps, write_atomic
from .fetch import FetchError, SourceClient, taxii_objects

FEED_FILES = ("ips.txt", "domains.txt", "urls.txt")


class RunError(Exception):
    """The run failed and no files were written."""


def build_clients(settings: Settings) -> dict:
    """One client per URL or TAXII source. Resolves secrets and loads certificates, so it fails fast."""
    return {s.name: SourceClient(s) for s in settings.sources if s.type != "file"}


def load_sources(settings: Settings, collector: Collector):
    try:
        clients = build_clients(settings)
    except FetchError as exc:
        raise RunError(str(exc)) from None
    for src in settings.sources:
        try:
            if src.type == "taxii":
                collector.stats["taxii_collections"] += 1
                collector.add_stix2(taxii_objects(clients[src.name], src))
                continue
            data = Path(src.location).read_bytes() if src.type == "file" else clients[src.name].get(src.location)
            if data.lstrip()[:1] == b"<":
                collector.stats["stix1_packages"] += 1
                collector.process_stix1(data)
                continue
            doc = json.loads(data)
            objs = doc.get("objects", []) if isinstance(doc, dict) else doc
            if isinstance(doc, dict) and doc.get("type") not in (None, "bundle") and "objects" not in doc:
                objs = [doc]
            collector.stats["stix2_sources"] += 1
            collector.add_stix2(objs)
        except OSError as exc:
            raise RunError(f"source {src.name}: {exc.strerror or exc}") from None
        except Exception as exc:  # noqa: BLE001 - any parse or fetch failure aborts the run
            raise RunError(f"source {src.name}: {exc}") from None


def _write_json_atomic(path: Path, data: dict):
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(data, indent=2) + "\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def run_once(settings: Settings, now: datetime | None = None) -> dict:
    """Run one conversion and return the report. Raises RunError, writing nothing, on any failure."""
    now = now or datetime.now(timezone.utc)
    try:
        allowlist = Allowlist.load(settings.allowlist)
    except OSError as exc:
        raise RunError(f"cannot read the allowlist {settings.allowlist}: {exc.strerror}") from None
    collector = Collector(settings, now, allowlist)
    try:
        load_sources(settings, collector)
    except RunError as exc:
        raise RunError(f"failed to load sources, no files written: {exc}") from None

    collector.process_stix2()
    out = collector.results()
    if out["ipv6"] and not settings.ipv6_file:
        collector.values_dropped["ipv6_unsupported_by_sfos"] += len(out["ipv6"])

    report: dict = {}
    apply_caps(out, settings, collector.values_dropped, report)

    out_dir = Path(settings.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "ips.txt": sorted((c.value for c in out["ipv4"]), key=_ip_sort),
        "domains.txt": sorted(c.value for c in out["domain"]),
        "urls.txt": sorted(c.value for c in out["url"]),
    }
    if settings.ipv6_file:
        files["ipv6.txt"] = sorted((c.value for c in out["ipv6"]), key=_ip_sort)
    for name, lines in files.items():
        write_atomic(out_dir / name, lines)

    report.update({
        "generated": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version": __version__,
        "written": {name: len(lines) for name, lines in files.items()},
        "stats": dict(sorted(collector.stats.items())),
        "objects_dropped": dict(sorted(collector.objects_dropped.items())),
        "values_dropped": dict(sorted(collector.values_dropped.items())),
        "pattern_parse_errors": collector.parse_errors,
    })
    if settings.report:
        report_path = Path(settings.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        _write_json_atomic(report_path, report)
    return report


def summary_lines(report: dict, out_dir) -> list:
    lines = [f"stix-xgs-feed {report['version']}  {report['generated']}  -> {out_dir}"]
    for name, n in report["written"].items():
        lines.append(f"  {name:<12} {n:>8}")
    if "model" in report:
        m = report["model"]
        lines.append(f"  model {m['model']}: estimated storage use {m['estimated_use_after_trim']:.4%} "
                     f"of the third-party feed quota (this feed may use {m['quota_share']:.4%})")
    lines.append("  stats:          " + ", ".join(f"{k}={v}" for k, v in report["stats"].items()))
    if report["objects_dropped"]:
        lines.append("  objects dropped: " + ", ".join(f"{k}={v}" for k, v in report["objects_dropped"].items()))
    if report["values_dropped"]:
        lines.append("  values dropped:  " + ", ".join(f"{k}={v}" for k, v in report["values_dropped"].items()))
    for err in report["pattern_parse_errors"]:
        lines.append(f"  parse error {err['id']}: {err['error']}")
    for name, n in report["written"].items():
        if n == 0:
            lines.append(f"  warning: {name} is empty; check how the firewall treats an empty feed before relying on it")
    return lines
