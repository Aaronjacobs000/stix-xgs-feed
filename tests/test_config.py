"""Config file loading and validation. Run: python3 -m unittest discover -s tests -v"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from support import DATA, NOW, ROOT, needs_toml, read_lines, run_cli, write_toml  # noqa: E402

import stix_xgs_feed as feed  # noqa: E402
from stix_xgs_feed.config import ConfigError, load_config  # noqa: E402

MINIMAL = '''
[[sources]]
type = "file"
path = "{bundle}"

[output]
dir = "out"
'''


class ConfigTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def toml(self, text: str, name: str = "feed.toml") -> Path:
        return write_toml(self.dir / name, text)

    def assertConfigError(self, text: str, fragment: str):
        with self.assertRaises(ConfigError) as cm:
            load_config(self.toml(text))
        self.assertIn(fragment, str(cm.exception))


class LoadTests(ConfigTestCase):
    @needs_toml
    def test_example_config_loads(self):
        s = load_config(ROOT / "config.example.toml")
        self.assertEqual([(x.name, x.type) for x in s.sources],
                         [("isac", "taxii"), ("vendor", "url"), ("partner", "url"), ("local-export", "file")])
        isac, vendor, partner, local = s.sources
        self.assertEqual((isac.auth.type, isac.auth.username, isac.auth.password), ("basic", "feeduser", "env:ISAC_PASSWORD"))
        self.assertEqual(isac.page_size, 1000)
        self.assertEqual((vendor.auth.type, vendor.auth.token), ("bearer", "file:/run/secrets/vendor_token"))
        self.assertEqual((partner.auth.type, partner.auth.key_name, partner.auth.add_to), ("api_key", "X-Api-Key", "header"))
        self.assertEqual(partner.auth.client_cert, str(ROOT / "certs" / "partner-client.pem"))
        self.assertEqual(local.location, str(ROOT / "exports" / "isac-export.xml"))
        self.assertEqual(s.out, str(ROOT / "feeds"))
        self.assertEqual((s.min_confidence, s.max_age_days, s.model, s.quota_share), (50, 90, "XGS 2100", 0.5))
        self.assertEqual(s.serve.path_prefix, "/acme")
        self.assertEqual(s.serve.auth.type, "basic")
        self.assertEqual((s.serve.listen, s.serve.allowed_clients), ("127.0.0.1", []))

    def test_config_run_matches_cli_run(self):
        cli_out = self.dir / "cli"
        code, _ = run_cli("-i", DATA / "mixed-bundle.json", "--allowlist", DATA / "allowlist.txt",
                          "--min-confidence", "50", "--now", NOW, "-o", cli_out)
        self.assertEqual(code, 0)
        cfg = self.toml(f'''
[[sources]]
type = "file"
path = "{DATA / 'mixed-bundle.json'}"
[output]
dir = "out"
report = "report.json"
[filter]
allowlist = "{DATA / 'allowlist.txt'}"
min_confidence = 50
''')
        code, out = run_cli("--config", cfg, "--now", NOW)
        self.assertEqual(code, 0, out)
        for name in feed.FEED_FILES:
            self.assertEqual(read_lines(self.dir / "out" / name), read_lines(cli_out / name), name)
        self.assertTrue((self.dir / "report.json").is_file())

    def test_json_config(self):
        cfg = self.dir / "feed.json"
        cfg.write_text(json.dumps({
            "sources": [{"type": "file", "path": str(DATA / "mixed-bundle.json")}],
            "output": {"dir": "out"},
            "filter": {"min_confidence": 50, "allowlist": str(DATA / "allowlist.txt")},
        }))
        code, out = run_cli("--config", cfg, "--now", NOW)
        self.assertEqual(code, 0, out)
        self.assertIn("c2-panel.evil.test", read_lines(self.dir / "out" / "domains.txt"))

    def test_relative_paths_resolve_against_config_folder(self):
        sub = self.dir / "conf"
        sub.mkdir()
        s = load_config(write_toml(sub / "feed.toml", '''
[[sources]]
type = "url"
url = "https://intel.example.com/feed.json"
ca_file = "ca.pem"
[sources.auth]
type = "bearer"
token = "file:secrets/token"
[output]
dir = "../feeds"
'''))
        sub = sub.resolve()
        self.assertEqual(s.sources[0].ca_file, str(sub / "ca.pem"))
        self.assertEqual(s.sources[0].auth.token, f"file:{sub / 'secrets' / 'token'}")
        self.assertEqual(Path(s.out).resolve(), (self.dir / "feeds").resolve())


class ValidationTests(ConfigTestCase):
    def test_typo_is_an_error(self):
        self.assertConfigError('''
[[sources]]
type = "url"
url = "https://intel.example.com/feed.json"
[sources.auth]
type = "basic"
username = "u"
pasword = "env:X"
[output]
dir = "out"
''', "sources[0].auth.password is required")
        self.assertConfigError(MINIMAL.format(bundle="x.json") + "[filter]\nmin_confidense = 5\n",
                               "filter.min_confidense is not a known setting")

    def test_literal_secret_refused(self):
        self.assertConfigError('''
[[sources]]
type = "url"
url = "https://intel.example.com/feed.json"
[sources.auth]
type = "bearer"
token = "fake-token-typed-in-the-file"
[output]
dir = "out"
''', "must be a secret reference")

    def test_url_with_credentials_refused(self):
        self.assertConfigError('''
[[sources]]
type = "url"
url = "https://user:fake-password@intel.example.com/feed.json"
[output]
dir = "out"
''', "not in the URL")

    def test_taxii_settings_only_on_taxii(self):
        self.assertConfigError('''
[[sources]]
type = "url"
url = "https://intel.example.com/feed.json"
page_size = 10
[output]
dir = "out"
''', "only applies to taxii sources")

    def test_value_checks(self):
        base = MINIMAL.format(bundle="x.json")
        for extra, fragment in (
            ('[filter]\nmax_tlp = "purple"\n', "max_tlp must be one of"),
            ("[filter]\nexpand_cidr = 8\n", "expand_cidr must be between 16 and 32"),
            ("[limits]\nquota_share = 0\n", "quota_share must be more than 0"),
            ('[limits]\nmodel = "XGS 9999"\n', "unknown model"),
            ("[filter]\nmin_confidence = true\n", "must be an integer"),
            ('[serve]\nport = 70000\n', "port number"),
            ('[serve]\nrefresh_minutes = 0\n', "refresh_minutes must be between"),
            ('[serve]\nallowed_clients = ["not-an-ip"]\n', "not an IP address"),
            ('[serve]\npath_prefix = "/a/../b"\n', "path_prefix"),
            ('[serve]\ntls_cert = "a.pem"\n', "give both tls_cert and tls_key"),
        ):
            with self.subTest(extra=extra):
                self.assertConfigError(base + extra, fragment)

    def test_config_cannot_mix_with_flags(self):
        cfg = self.toml(MINIMAL.format(bundle=DATA / "mixed-bundle.json"))
        code, out = run_cli("--config", cfg, "--min-confidence", "50")
        self.assertEqual(code, 2)
        self.assertIn("--config cannot be combined with --min-confidence", out)

    def test_bad_syntax_and_missing_file(self):
        with self.assertRaises(ConfigError):
            load_config(self.toml("[[sources]\n"))
        with self.assertRaises(ConfigError):
            load_config(self.dir / "missing.toml")
        with self.assertRaises(ConfigError):
            load_config(write_toml(self.dir / "feed.yaml", "sources: []"))


if __name__ == "__main__":
    unittest.main()
