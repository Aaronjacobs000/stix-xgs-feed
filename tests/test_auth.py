"""Source authentication: basic, API key, bearer, extra headers, mTLS, secret references,
host pinning and redirect handling. Run: python3 -m unittest discover -s tests -v"""
from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from support import (  # noqa: E402
    CLIENT_KEY_PASSWORD, NOW, Stub, bundle, indicators, make_certs, ok, read_lines, redirect, require_header, run_cli,
    server_tls, write_toml,
)

FAKE_PASSWORD = "fake-password-not-real-0001"
FAKE_KEY = "fake-api-key-not-real-0002"
FAKE_TOKEN = "fake-bearer-token-not-real-0003"
BODY = bundle("one.test", "two.test")


def basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class AuthTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.env = unittest.mock.patch.dict("os.environ", {
            "T_PASSWORD": FAKE_PASSWORD, "T_KEY": FAKE_KEY, "T_TOKEN": FAKE_TOKEN,
            "T_KEY_PASSWORD": CLIENT_KEY_PASSWORD})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def run_config(self, sources: str):
        path = write_toml(self.dir / "feed.toml", sources + '\n[output]\ndir = "out"\n')
        return run_cli("--config", path, "--now", NOW)

    def domains(self) -> list:
        return read_lines(self.dir / "out" / "domains.txt")


class HeaderAuthTests(AuthTestCase):
    def test_basic_auth_on_plain_url(self):
        with Stub({"/feed.json": require_header("Authorization", basic("feeduser", FAKE_PASSWORD), BODY)}) as s:
            code, out = self.run_config(f'''
[[sources]]
type = "url"
url = "{s.url('/feed.json')}"
[sources.auth]
type = "basic"
username = "feeduser"
password = "env:T_PASSWORD"
''')
        self.assertEqual(code, 0, out)
        self.assertEqual(self.domains(), ["one.test", "two.test"])

    def test_api_key_in_header(self):
        with Stub({"/feed.json": require_header("X-Api-Key", FAKE_KEY, BODY)}) as s:
            code, out = self.run_config(f'''
[[sources]]
type = "url"
url = "{s.url('/feed.json')}"
[sources.auth]
type = "api_key"
key_name = "X-Api-Key"
key_value = "env:T_KEY"
''')
        self.assertEqual(code, 0, out)

    def test_api_key_in_query(self):
        with Stub({"/feed.json": ok(BODY)}) as s:
            code, out = self.run_config(f'''
[[sources]]
type = "url"
url = "{s.url('/feed.json?format=stix')}"
[sources.auth]
type = "api_key"
key_name = "apikey"
key_value = "env:T_KEY"
add_to = "query"
''')
            self.assertEqual(code, 0, out)
            self.assertEqual(s.seen[0]["query"], {"format": ["stix"], "apikey": [FAKE_KEY]})
            self.assertNotIn("x-api-key", s.seen[0]["headers"])

    def test_bearer_token_from_file(self):
        secret = self.dir / "token.txt"
        secret.write_text(FAKE_TOKEN + "\n")
        with Stub({"/feed.json": require_header("Authorization", f"Bearer {FAKE_TOKEN}", BODY)}) as s:
            code, out = self.run_config(f'''
[[sources]]
type = "url"
url = "{s.url('/feed.json')}"
[sources.auth]
type = "bearer"
token = "file:token.txt"
''')
        self.assertEqual(code, 0, out)

    def test_extra_headers_literal_and_secret(self):
        with Stub({"/feed.json": ok(BODY)}) as s:
            code, out = self.run_config(f'''
[[sources]]
type = "url"
url = "{s.url('/feed.json')}"
[sources.auth.headers]
X-Tenant = "acme"
X-Feed-Token = "env:T_TOKEN"
''')
            self.assertEqual(code, 0, out)
            self.assertEqual(s.seen[0]["headers"]["x-tenant"], "acme")
            self.assertEqual(s.seen[0]["headers"]["x-feed-token"], FAKE_TOKEN)

    def test_taxii_bearer_on_every_page(self):
        def page(h):
            idx = int(h.path.split("next=")[1]) if "next=" in h.path else 0
            body = {"objects": indicators(f"p{idx}.test")}
            if idx < 2:
                body.update(more=True, next=str(idx + 1))
            return 200, {"Content-Type": "application/taxii+json;version=2.1"}, json.dumps(body).encode()

        with Stub({"/api1/collections/abc/objects/": page}) as s:
            code, out = self.run_config(f'''
[[sources]]
type = "taxii"
url = "{s.url('/api1/collections/abc/')}"
page_size = 1
[sources.auth]
type = "bearer"
token = "env:T_TOKEN"
''')
            self.assertEqual(code, 0, out)
            self.assertEqual(len(s.seen), 3)
            self.assertTrue(all(r["headers"]["authorization"] == f"Bearer {FAKE_TOKEN}" for r in s.seen))
            self.assertTrue(all(r["headers"]["accept"] == "application/taxii+json;version=2.1" for r in s.seen))
        self.assertEqual(self.domains(), ["p0.test", "p1.test", "p2.test"])

    def test_cli_bearer_and_header_refs(self):
        secret = self.dir / "key.txt"
        secret.write_text(FAKE_KEY)
        with Stub({"/api1/collections/abc/objects/": ok(BODY)}) as s:
            code, out = run_cli("--taxii", s.url("/api1/collections/abc/"), "--bearer", "env:T_TOKEN",
                                "--header", f"X-Api-Key: file:{secret}", "-o", self.dir / "out", "--now", NOW)
            self.assertEqual(code, 0, out)
            self.assertEqual(s.seen[0]["headers"]["authorization"], f"Bearer {FAKE_TOKEN}")
            self.assertEqual(s.seen[0]["headers"]["x-api-key"], FAKE_KEY)


class SecretHandlingTests(AuthTestCase):
    def test_literal_secret_on_command_line_refused(self):
        code, out = run_cli("--taxii", "https://taxii.example.org/api1/collections/abc/", "--bearer", FAKE_TOKEN,
                            "-o", self.dir / "out")
        self.assertEqual(code, 2)
        self.assertIn("secret reference", out)
        self.assertNotIn(FAKE_TOKEN, out)

    def test_missing_env_fails_closed(self):
        out_dir = self.dir / "out"
        out_dir.mkdir()
        (out_dir / "domains.txt").write_text("previous.test\n")
        with Stub({"/feed.json": ok(BODY)}) as s:
            code, out = self.run_config(f'''
[[sources]]
type = "url"
url = "{s.url('/feed.json')}"
[sources.auth]
type = "bearer"
token = "env:T_NOT_SET"
''')
            self.assertEqual(s.seen, [])
        self.assertEqual(code, 1)
        self.assertIn("T_NOT_SET is not set", out)
        self.assertEqual(self.domains(), ["previous.test"])

    def test_rejected_credentials_do_not_leak(self):
        with Stub({"/feed.json": lambda h: (401, {}, b"denied")}) as s:
            code, out = self.run_config(f'''
[[sources]]
type = "url"
url = "{s.url('/feed.json')}"
[sources.auth]
type = "api_key"
key_name = "key"
key_value = "env:T_KEY"
add_to = "query"
''')
        self.assertEqual(code, 1)
        self.assertIn("HTTP 401", out)
        self.assertNotIn(FAKE_KEY, out)
        self.assertNotIn("key=", out)

    def test_credentials_need_https(self):
        code, out = self.run_config('''
[[sources]]
type = "url"
url = "http://192.0.2.1/feed.json"
[sources.auth]
type = "basic"
username = "u"
password = "env:T_PASSWORD"
''')
        self.assertEqual(code, 1)
        self.assertIn("only sent over HTTPS", out)

    def test_cli_taxii_password_env_must_be_set(self):
        code, out = run_cli("--taxii", "http://127.0.0.1:9/api1/collections/abc/", "--taxii-user", "u",
                            "--taxii-password-env", "T_NOT_SET", "-o", self.dir / "out")
        self.assertEqual(code, 1)
        self.assertIn("T_NOT_SET is not set", out)


class RedirectTests(AuthTestCase):
    def test_same_host_redirect_drops_credentials(self):
        with Stub({"/old.json": redirect("/new.json"), "/new.json": ok(BODY)}) as s:
            code, out = self.run_config(f'''
[[sources]]
type = "url"
url = "{s.url('/old.json')}"
[sources.auth]
type = "basic"
username = "u"
password = "env:T_PASSWORD"
[sources.auth.headers]
X-Tenant = "acme"
''')
            self.assertEqual(code, 0, out)
            self.assertEqual([r["path"] for r in s.seen], ["/old.json", "/new.json"])
            self.assertEqual(s.seen[0]["headers"]["authorization"], basic("u", FAKE_PASSWORD))
            self.assertNotIn("authorization", s.seen[1]["headers"])
            self.assertNotIn("x-tenant", s.seen[1]["headers"])

    def test_cross_host_redirect_drops_query_key_even_if_echoed(self):
        with Stub({"/feed.json": ok(BODY)}) as target:
            echo = target.url(f"/feed.json?apikey={FAKE_KEY}&v=2", host="localhost")
            with Stub({"/start.json": redirect(echo, 307)}) as s:
                code, out = self.run_config(f'''
[[sources]]
type = "url"
url = "{s.url('/start.json')}"
[sources.auth]
type = "api_key"
key_name = "apikey"
key_value = "env:T_KEY"
add_to = "query"
''')
                self.assertEqual(code, 0, out)
                self.assertEqual(s.seen[0]["query"]["apikey"], [FAKE_KEY])
            self.assertEqual(target.seen[0]["query"], {"v": ["2"]})
        self.assertNotIn(FAKE_KEY, out)

    def test_redirect_loop_stops(self):
        with Stub({"/a": redirect("/b"), "/b": redirect("/a")}) as s:
            code, out = self.run_config(f'''
[[sources]]
type = "url"
url = "{s.url('/a')}"
''')
            self.assertEqual(code, 1)
            self.assertIn("more than 5 redirects", out)
            self.assertEqual(len(s.seen), 6)


class TlsSourceTests(AuthTestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki_tmp = tempfile.TemporaryDirectory()
        cls.certs = make_certs(Path(cls.pki_tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls.pki_tmp.cleanup()

    def mtls_source(self, url: str, key: str = "client.key", extra: str = "") -> str:
        c = self.certs
        return f'''
[[sources]]
type = "url"
url = "{url}"
ca_file = "{c['ca.pem']}"
[sources.auth]
client_cert = "{c['client.pem']}"
client_key = "{c[key]}"
{extra}
'''

    def test_client_certificate_accepted(self):
        with Stub({"/feed.json": ok(BODY)}, tls=server_tls(self.certs, "required")) as s:
            code, out = self.run_config(self.mtls_source(s.url("/feed.json")))
            self.assertEqual(code, 0, out)
            subject = dict(x[0] for x in s.seen[0]["client_cert"]["subject"])
            self.assertEqual(subject["commonName"], "test-client")
        self.assertEqual(self.domains(), ["one.test", "two.test"])

    def test_encrypted_client_key(self):
        with Stub({"/feed.json": ok(BODY)}, tls=server_tls(self.certs, "required")) as s:
            code, out = self.run_config(self.mtls_source(
                s.url("/feed.json"), "client-encrypted.key", 'client_key_password = "env:T_KEY_PASSWORD"'))
        self.assertEqual(code, 0, out)
        self.assertNotIn(CLIENT_KEY_PASSWORD, out)

    def test_server_requiring_a_client_cert_rejects_none(self):
        with Stub({"/feed.json": ok(BODY)}, tls=server_tls(self.certs, "required")) as s:
            code, out = self.run_config(f'''
[[sources]]
type = "url"
url = "{s.url('/feed.json')}"
ca_file = "{self.certs['ca.pem']}"
''')
        self.assertEqual(code, 1)
        self.assertIn("no files written", out)

    def test_private_ca_needs_ca_file(self):
        with Stub({"/feed.json": ok(BODY)}, tls=server_tls(self.certs)) as s:
            code, out = self.run_config(f'''
[[sources]]
type = "url"
url = "{s.url('/feed.json')}"
''')
        self.assertEqual(code, 1)
        self.assertIn("CERTIFICATE_VERIFY_FAILED", out)

    def test_client_cert_not_presented_after_redirect(self):
        tls_optional = server_tls(self.certs, "optional")
        with Stub({"/feed.json": ok(BODY)}, tls=tls_optional) as target:
            with Stub({"/start.json": redirect(target.url("/feed.json", host="localhost"))},
                      tls=server_tls(self.certs, "required")) as s:
                code, out = self.run_config(self.mtls_source(s.url("/start.json")))
                self.assertEqual(code, 0, out)
                self.assertIsNotNone(s.seen[0]["client_cert"])
            self.assertIsNone(target.seen[0]["client_cert"])

    def test_https_to_http_redirect_refused(self):
        with Stub({"/feed.json": ok(BODY)}) as plain:
            with Stub({"/start.json": redirect(plain.url("/feed.json"))}, tls=server_tls(self.certs)) as s:
                code, out = self.run_config(f'''
[[sources]]
type = "url"
url = "{s.url('/start.json')}"
ca_file = "{self.certs['ca.pem']}"
''')
            self.assertEqual(plain.seen, [])
        self.assertEqual(code, 1)
        self.assertIn("refusing a redirect from HTTPS to plain HTTP", out)

    def test_client_cert_needs_https(self):
        code, out = self.run_config(self.mtls_source("http://127.0.0.1:9/feed.json"))
        self.assertEqual(code, 1)
        self.assertIn("needs an https:// URL", out)


if __name__ == "__main__":
    unittest.main()
