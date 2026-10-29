"""Tests for stix_xgs_feed. Run: python3 -m unittest discover -s tests -v"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import sys
import tempfile
import threading
import unittest
import unittest.mock
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "tests" / "data"
sys.path.insert(0, str(ROOT))

import stix_xgs_feed as feed  # noqa: E402

NOW = "2026-10-29T00:00:00Z"
NOW_DT = datetime(2026, 10, 29, tzinfo=timezone.utc)


def run_cli(*args) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        code = feed.main([str(a) for a in args])
    return code, buf.getvalue()


def read_lines(path: Path) -> list:
    return path.read_text(encoding="ascii").splitlines()


class MixedBundleTests(unittest.TestCase):
    """The hand-made bundle in tests/data covers every filtering rule once."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def base_args(self):
        return ["-i", DATA / "mixed-bundle.json", "--allowlist", DATA / "allowlist.txt",
                "--min-confidence", "50", "--now", NOW, "-o", self.out]

    def test_default_output(self):
        code, _ = run_cli(*self.base_args())
        self.assertEqual(code, 0)
        self.assertEqual(read_lines(self.out / "ips.txt"), [
            "198.51.100.10", "198.51.100.20", "198.51.100.99", "198.51.100.123", "198.51.100.150",
            "203.0.113.5", "203.0.113.6", "203.0.113.44",
        ])
        self.assertEqual(read_lines(self.out / "domains.txt"), [
            "c2-panel.evil.test", "phish-login.evil.test", "v2-current.evil.test", "xn--bcher-login-thb.evil.test",
        ])
        self.assertEqual(read_lines(self.out / "urls.txt"), [
            "http://download.evil.test/update.exe",
            "http://payload.evil.test/Path/File.EXE",
            "http://payload.evil.test/drop/loader.exe",
            "https://drop.evil.test/a.ps1",
            "https://kit.evil.test/gate.php?id=1",
            "https://raw.githubusercontent.com/evil-user/repo/main/x.exe",
        ])
        self.assertFalse((self.out / "ipv6.txt").exists())

    def test_drop_reasons_reported(self):
        report = self.out / "report.json"
        run_cli(*self.base_args(), "--report", report)
        r = json.loads(report.read_text())
        self.assertEqual(r["objects_dropped"], {
            "below_min_confidence": 1, "expired": 1, "no_network_indicator": 1, "non_stix_pattern": 1,
            "not_yet_valid": 1, "observable_not_linked": 3, "pattern_parse_error": 1, "revoked": 1,
            "tlp_above_max": 2,
        })
        self.assertEqual(r["values_dropped"], {
            "allowlisted": 2, "cidr_range": 1, "internal_domain": 1, "internal_ip": 2,
            "ipv6_unsupported_by_sfos": 1, "pattern_compound": 3, "pattern_negated": 1,
            "pattern_time_window_closed": 1, "pattern_wildcard_or_regex": 2, "url_unsupported_scheme": 1,
            "wildcard_domain": 1,
        })
        self.assertEqual(r["stats"]["older_versions_ignored"], 2)
        self.assertEqual(r["stats"]["duplicates_merged"], 1)

    def test_opt_in_switches(self):
        code, _ = run_cli(*self.base_args(), "--broaden", "--expand-cidr", "30", "--observables", "all",
                          "--max-tlp", "amber+strict", "--ipv6-file")
        self.assertEqual(code, 0)
        ips = read_lines(self.out / "ips.txt")
        for ip in ("203.0.113.77", "203.0.113.128", "203.0.113.131", "198.51.100.160"):
            self.assertIn(ip, ips)
        domains = read_lines(self.out / "domains.txt")
        for d in ("stage1.evil.test", "strict.evil.test", "victim-corp.test", "observed-only.evil.test"):
            self.assertIn(d, domains)
        self.assertNotIn("red-only.evil.test", domains)
        self.assertIn("http://stage2.evil.test/payload.bin", read_lines(self.out / "urls.txt"))
        self.assertEqual(read_lines(self.out / "ipv6.txt"), ["2001:db8::bad"])

    def test_file_format(self):
        run_cli(*self.base_args())
        for name in ("ips.txt", "domains.txt", "urls.txt"):
            raw = (self.out / name).read_bytes()
            raw.decode("ascii")  # raises if not ASCII
            self.assertNotIn(b"\r", raw)
            self.assertTrue(raw.endswith(b"\n"))
            lines = raw.decode().split("\n")[:-1]
            self.assertTrue(all(line and line == line.strip() and not line.startswith("#") for line in lines))
            self.assertEqual(len(lines), len(set(lines)))

    def test_fail_closed(self):
        run_cli(*self.base_args())
        before = (self.out / "ips.txt").read_bytes()
        code, output = run_cli("-i", DATA / "does-not-exist.json", "-o", self.out)
        self.assertEqual(code, 1)
        self.assertIn("no files written", output)
        self.assertEqual((self.out / "ips.txt").read_bytes(), before)

    def test_model_trim(self):
        report = self.out / "report.json"
        run_cli(*self.base_args(), "--model", "XGS 107w", "--quota-share", "0.00002", "--report", report)
        r = json.loads(report.read_text())
        self.assertLessEqual(r["model"]["estimated_use_after_trim"], 0.00002)
        self.assertGreater(r["values_dropped"]["over_model_quota"], 0)


class PatternTests(unittest.TestCase):
    def hits(self, pattern):
        return [(h.hint, h.value, h.compound) for h in feed.extract_from_pattern(pattern, NOW_DT, Counter())]

    def test_or_across_types(self):
        self.assertEqual(self.hits("[ipv4-addr:value = '1.2.3.4' OR domain-name:value = 'a.test']"),
                         [("ip", "1.2.3.4", False), ("domain", "a.test", False)])

    def test_and_with_port_is_compound(self):
        self.assertEqual(self.hits("[network-traffic:dst_ref.value = '1.2.3.4' AND network-traffic:dst_port = 443]"),
                         [("auto", "1.2.3.4", True)])

    def test_ref_type_check_is_not_compound(self):
        self.assertEqual(
            self.hits("[network-traffic:dst_ref.type = 'ipv4-addr' AND network-traffic:dst_ref.value = '1.2.3.4']"),
            [("auto", "1.2.3.4", False)])

    def test_observation_and_and_followedby_are_compound(self):
        for op in ("AND", "FOLLOWEDBY"):
            self.assertTrue(all(c for _, _, c in self.hits(f"[url:value = 'http://a.test/'] {op} [domain-name:value = 'b.test']")))

    def test_observation_or_is_not_compound(self):
        self.assertFalse(any(c for _, _, c in self.hits("[url:value = 'http://a.test/'] OR [domain-name:value = 'b.test']")))

    def test_in_set_and_escapes(self):
        self.assertEqual(self.hits("[domain-name:value IN ('a.test', 'b\\'c.test')]"),
                         [("domain", "a.test", False), ("domain", "b'c.test", False)])

    def test_negation_and_regex_skipped(self):
        skipped = Counter()
        hits = feed.extract_from_pattern(
            "[domain-name:value NOT = 'a.test' OR domain-name:value MATCHES '^x' OR domain-name:value LIKE '%.y']",
            NOW_DT, skipped)
        self.assertEqual(hits, [])
        self.assertEqual(skipped, Counter(pattern_negated=1, pattern_wildcard_or_regex=2))

    def test_closed_start_stop_window(self):
        skipped = Counter()
        hits = feed.extract_from_pattern(
            "[ipv4-addr:value = '1.2.3.4'] START t'2020-01-01T00:00:00Z' STOP t'2020-02-01T00:00:00Z'", NOW_DT, skipped)
        self.assertEqual(hits, [])
        self.assertEqual(skipped["pattern_time_window_closed"], 1)

    def test_qualifiers_and_hash_paths_parse(self):
        self.assertEqual(self.hits("[file:hashes.'SHA-256' = 'ab'] REPEATS 5 TIMES WITHIN 10 SECONDS"), [])

    def test_invalid_pattern_raises(self):
        for bad in ("[ipv4-addr:value = '1.2.3.4'", "ipv4-addr:value = '1.2.3.4'", "[ipv4-addr:value ~ 'x']"):
            with self.assertRaises(feed.PatternError):
                feed.parse_pattern(bad)


class NormaliseTests(unittest.TestCase):
    def test_refang(self):
        self.assertEqual(feed.refang("hxxps[:]//evil[.]test[/]x"), "https://evil.test/x")
        self.assertEqual(feed.refang("1.2.3(.)4"), "1.2.3.4")
        self.assertEqual(feed.refang("evil[dot]test"), "evil.test")

    def test_ip_rules(self):
        o = feed.Options()
        self.assertEqual(feed.normalise("ip", "8.8.8.8", o), [("ipv4", "8.8.8.8")])
        self.assertEqual(feed.normalise("ip", "10.1.2.3", o), "internal_ip")
        self.assertEqual(feed.normalise("ip", "8.8.8.0/24", o), "cidr_range")
        self.assertEqual(feed.normalise("ip", "8.8.8.8/32", o), [("ipv4", "8.8.8.8")])
        self.assertEqual(len(feed.normalise("ip", "8.8.8.0/30", feed.Options(expand_cidr=30))), 4)
        self.assertEqual(feed.normalise("domain", "8.8.4.4", o), [("ipv4", "8.8.4.4")])

    def test_domain_rules(self):
        o = feed.Options()
        self.assertEqual(feed.normalise("domain", "Evil.TEST.", o), [("domain", "evil.test")])
        self.assertEqual(feed.normalise("domain", "*.evil.test", o), "wildcard_domain")
        self.assertEqual(feed.normalise("domain", "dc01.corp", o), "internal_domain")
        self.assertEqual(feed.normalise("domain", "domain bad.test", o), "invalid_domain")

    def test_url_rules(self):
        o = feed.Options()
        self.assertEqual(feed.normalise("url", "HTTPS://Evil.test:443/a b?q=1#frag", o),
                         [("url", "https://evil.test/a%20b?q=1")])
        self.assertEqual(feed.normalise("url", "evil.test/x", o), [("url", "http://evil.test/x")])
        self.assertEqual(feed.normalise("url", "ftp://evil.test/x", o), "url_unsupported_scheme")
        self.assertEqual(feed.normalise("url", "http://192.168.1.1/x", o), "internal_ip")

    def test_allowlist(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("github.com\n203.0.113.0/24\nhttps://cdn.test/safe/\n")
        al = feed.Allowlist.load(f.name)
        Path(f.name).unlink()
        self.assertTrue(al.blocks("domain", "codeload.github.com"))
        self.assertFalse(al.blocks("domain", "notgithub.com"))
        self.assertFalse(al.blocks("url", "https://github.com/evil/x.exe"))
        self.assertTrue(al.blocks("url", "https://cdn.test/safe/lib.js"))
        self.assertTrue(al.blocks("ipv4", "203.0.113.9"))

    def test_model_names(self):
        self.assertEqual(feed.model_limits("XGS 2100"), (900_000, 490_000, 94_000))
        self.assertEqual(feed.model_limits("xgs87w"), (180_000, 98_000, 18_000))
        self.assertEqual(feed.model_limits("Virtual"), (180_000, 98_000, 18_000))


STIX1 = b"""<?xml version="1.0" encoding="UTF-8"?>
<stix:STIX_Package xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:stix="http://stix.mitre.org/stix-1" xmlns:indicator="http://stix.mitre.org/Indicator-2"
  xmlns:stixCommon="http://stix.mitre.org/common-1" xmlns:cybox="http://cybox.mitre.org/cybox-2"
  xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2"
  xmlns:DomainNameObj="http://cybox.mitre.org/objects#DomainNameObject-1"
  xmlns:URIObj="http://cybox.mitre.org/objects#URIObject-2"
  xmlns:marking="http://data-marking.mitre.org/Marking-1"
  xmlns:tlpMarking="http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1" id="ex:pkg-1" version="1.2">
 <stix:Indicators>
  <stix:Indicator id="ex:ind-or" xsi:type="indicator:IndicatorType">
   <indicator:Observable id="ex:obs-or"><cybox:Observable_Composition operator="OR">
     <cybox:Observable id="ex:o1"><cybox:Object><cybox:Properties xsi:type="AddressObj:AddressObjectType" category="ipv4-addr">
       <AddressObj:Address_Value condition="Equals" apply_condition="ANY">8.8.8.1##comma##8.8.8.2</AddressObj:Address_Value>
     </cybox:Properties></cybox:Object></cybox:Observable>
     <cybox:Observable id="ex:o2"><cybox:Object><cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType">
       <DomainNameObj:Value condition="Equals">bad[.]test</DomainNameObj:Value>
     </cybox:Properties></cybox:Object></cybox:Observable>
   </cybox:Observable_Composition></indicator:Observable>
   <indicator:Confidence><stixCommon:Value>High</stixCommon:Value></indicator:Confidence>
  </stix:Indicator>
  <stix:Indicator id="ex:ind-and" xsi:type="indicator:IndicatorType">
   <indicator:Observable><cybox:Observable_Composition operator="AND">
     <cybox:Observable idref="ex:shared"/>
     <cybox:Observable><cybox:Object><cybox:Properties xsi:type="URIObj:URIObjectType" type="URL">
       <URIObj:Value condition="Contains">/gate.php</URIObj:Value></cybox:Properties></cybox:Object></cybox:Observable>
   </cybox:Observable_Composition></indicator:Observable>
  </stix:Indicator>
  <stix:Indicator id="ex:ind-expired" xsi:type="indicator:IndicatorType">
   <indicator:Valid_Time_Position><indicator:End_Time>2020-01-01T00:00:00Z</indicator:End_Time></indicator:Valid_Time_Position>
   <indicator:Observable><cybox:Object><cybox:Properties xsi:type="URIObj:URIObjectType" type="URL">
     <URIObj:Value condition="Equals">http://old.test/x</URIObj:Value></cybox:Properties></cybox:Object></indicator:Observable>
  </stix:Indicator>
  <stix:Indicator id="ex:ind-red" xsi:type="indicator:IndicatorType">
   <indicator:Observable><cybox:Object><cybox:Properties xsi:type="URIObj:URIObjectType" type="URL">
     <URIObj:Value>http://secret.test/x</URIObj:Value></cybox:Properties></cybox:Object></indicator:Observable>
   <indicator:Handling><marking:Marking><marking:Marking_Structure xsi:type="tlpMarking:TLPMarkingStructureType" color="RED"/></marking:Marking></indicator:Handling>
  </stix:Indicator>
 </stix:Indicators>
 <stix:Observables cybox_major_version="2" cybox_minor_version="1">
  <cybox:Observable id="ex:shared"><cybox:Object><cybox:Properties xsi:type="AddressObj:AddressObjectType" category="ipv4-addr">
    <AddressObj:Address_Value>8.8.8.3</AddressObj:Address_Value></cybox:Properties></cybox:Object></cybox:Observable>
  <cybox:Observable id="ex:loose"><cybox:Object><cybox:Properties xsi:type="AddressObj:AddressObjectType" category="ipv4-addr">
    <AddressObj:Address_Value>8.8.8.4</AddressObj:Address_Value></cybox:Properties></cybox:Object></cybox:Observable>
 </stix:Observables>
</stix:STIX_Package>
"""


class Stix1Tests(unittest.TestCase):
    def test_stix1_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "pkg.xml"
            src.write_bytes(STIX1)
            out = Path(tmp) / "out"
            report = Path(tmp) / "r.json"
            code, _ = run_cli("-i", src, "-o", out, "--now", NOW, "--report", report)
            self.assertEqual(code, 0)
            self.assertEqual(read_lines(out / "ips.txt"), ["8.8.8.1", "8.8.8.2"])
            self.assertEqual(read_lines(out / "domains.txt"), ["bad.test"])
            self.assertEqual(read_lines(out / "urls.txt"), [])
            r = json.loads(report.read_text())
            self.assertEqual(r["objects_dropped"], {"expired": 1, "observable_not_linked": 1, "tlp_above_max": 1})
            self.assertEqual(r["values_dropped"], {"pattern_compound": 1, "pattern_wildcard_or_regex": 1})


class _TaxiiHandler(BaseHTTPRequestHandler):
    pages: list = []
    expected_auth = "Basic " + base64.b64encode(b"u:p").decode()
    seen: list = []

    def do_GET(self):  # noqa: N802
        if self.headers.get("Authorization") != self.expected_auth:
            self.send_response(401)
            self.end_headers()
            return
        q = parse_qs(urlparse(self.path).query)
        type(self).seen.append(q)
        idx = int(q.get("next", ["0"])[0])
        body = {"objects": self.pages[idx]}
        if idx + 1 < len(self.pages):
            body.update(more=True, next=str(idx + 1))
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/taxii+json;version=2.1")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class TaxiiTests(unittest.TestCase):
    def test_pagination_and_auth(self):
        def ind(n, value):
            return {"type": "indicator", "spec_version": "2.1", "id": f"indicator--00000000-0000-4000-8000-00000000000{n}",
                    "created": "2026-10-01T00:00:00Z", "modified": "2026-10-01T00:00:00Z",
                    "valid_from": "2026-10-01T00:00:00Z", "pattern_type": "stix",
                    "pattern": f"[domain-name:value = '{value}']"}
        _TaxiiHandler.pages = [[ind(1, "one.test")], [ind(2, "two.test")], [ind(3, "three.test")]]
        _TaxiiHandler.seen = []
        server = HTTPServer(("127.0.0.1", 0), _TaxiiHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}/api1/collections/abc/"
            with tempfile.TemporaryDirectory() as tmp, unittest.mock.patch.dict("os.environ", {"TAXII_PASSWORD": "p"}):
                code, _ = run_cli("--taxii", url, "--taxii-user", "u", "--page-size", "1",
                                  "--added-after", "2026-09-01T00:00:00Z", "-o", tmp, "--now", NOW)
                self.assertEqual(code, 0)
                self.assertEqual(read_lines(Path(tmp) / "domains.txt"), ["one.test", "three.test", "two.test"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertEqual(len(_TaxiiHandler.seen), 3)
        self.assertTrue(all(q["added_after"] == ["2026-09-01T00:00:00Z"] and q["limit"] == ["1"]
                            for q in _TaxiiHandler.seen))


class _RecordingHandler(BaseHTTPRequestHandler):
    """Serves a bundle and a cross-host redirect; records the Authorization header per path."""
    seen: list = []
    port = 0

    def do_GET(self):  # noqa: N802
        path = urlparse(self.path).path
        type(self).seen.append((path, self.headers.get("Authorization")))
        if path == "/redir/objects/":
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{self.port}/open/objects/")
            self.end_headers()
            return
        bundle = {"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000001", "objects": [
            {"type": "indicator", "spec_version": "2.1", "id": "indicator--00000000-0000-4000-8000-000000000009",
             "created": "2026-10-01T00:00:00Z", "modified": "2026-10-01T00:00:00Z",
             "valid_from": "2026-10-01T00:00:00Z", "pattern_type": "stix", "pattern": "[domain-name:value = 'x.test']"}]}
        data = json.dumps(bundle).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class CredentialScopeTests(unittest.TestCase):
    def setUp(self):
        _RecordingHandler.seen = []
        self.server = HTTPServer(("127.0.0.1", 0), _RecordingHandler)
        _RecordingHandler.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.tmp.cleanup()

    def test_input_url_gets_no_credentials(self):
        with unittest.mock.patch.dict("os.environ", {"TAXII_PASSWORD": "p", "KEY": "k"}):
            code, _ = run_cli("-i", f"http://127.0.0.1:{_RecordingHandler.port}/bundle.json", "--taxii-user", "u",
                              "--header", "X-Api-Key: env:KEY", "-o", self.tmp.name, "--now", NOW)
        self.assertEqual(code, 0)
        self.assertEqual(_RecordingHandler.seen, [("/bundle.json", None)])

    def test_cross_host_redirect_drops_credentials(self):
        with unittest.mock.patch.dict("os.environ", {"TAXII_PASSWORD": "p"}):
            code, _ = run_cli("--taxii", f"http://127.0.0.1:{_RecordingHandler.port}/redir/", "--taxii-user", "u",
                              "-o", self.tmp.name, "--now", NOW)
        self.assertEqual(code, 0)
        self.assertEqual(_RecordingHandler.seen[0], ("/redir/objects/", "Basic " + base64.b64encode(b"u:p").decode()))
        self.assertEqual(_RecordingHandler.seen[1], ("/open/objects/", None))
        self.assertEqual(read_lines(Path(self.tmp.name) / "domains.txt"), ["x.test"])


if __name__ == "__main__":
    unittest.main()
