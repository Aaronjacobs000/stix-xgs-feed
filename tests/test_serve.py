"""Serve mode: refusals, authentication, routing, TLS, atomic swap and the scheduler.
Run: python3 -m unittest discover -s tests -v"""
from __future__ import annotations

import base64
import dataclasses
import http.client
import logging
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from support import DATA, bundle, make_certs, needs_toml, run_cli, write_toml  # noqa: E402

from stix_xgs_feed.config import ConfigError, ServeAuth, ServeConfig, Settings, Source  # noqa: E402
from stix_xgs_feed.convert import write_atomic  # noqa: E402
from stix_xgs_feed.serve import FeedService, Scheduler, check_serve, healthcheck  # noqa: E402

logging.getLogger("stix_xgs_feed").addHandler(logging.NullHandler())

FAKE_SERVE_PASSWORD = "fake-serve-password-0001"
FAKE_SERVE_KEY = "fake-serve-api-key-0002"


def basic(user: str, password: str) -> dict:
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}


def wait_for(predicate, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


class ServeTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        env = unittest.mock.patch.dict("os.environ", {"S_PASSWORD": FAKE_SERVE_PASSWORD, "S_KEY": FAKE_SERVE_KEY})
        env.start()
        self.addCleanup(env.stop)
        self.addCleanup(self.tmp.cleanup)

    def settings(self, cfg: ServeConfig, source: Path | None = None) -> Settings:
        src = Source(name="local", type="file", location=str(source or DATA / "mixed-bundle.json"))
        return Settings(sources=[src], out=str(self.dir / "feeds"), serve=cfg,
                        allowlist=str(DATA / "allowlist.txt"), min_confidence=50)

    def service(self, source: Path | None = None, wait: bool = True, **kw) -> FeedService:
        kw.setdefault("listen", "127.0.0.1")
        kw.setdefault("port", 0)
        svc = FeedService(self.settings(ServeConfig(**kw), source))
        svc.start()
        self.addCleanup(svc.stop)
        if wait:
            self.assertTrue(wait_for(lambda: svc.scheduler.runs >= 1), "first refresh did not finish")
        return svc

    def get(self, svc: FeedService, path: str, headers: dict | None = None, method: str = "GET",
            ctx: ssl.SSLContext | None = None, host: str = "127.0.0.1"):
        if ctx is not None:
            conn = http.client.HTTPSConnection(host, svc.port, timeout=10, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, svc.port, timeout=10)
        try:
            conn.request(method, path, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, resp.headers, resp.read()
        finally:
            conn.close()

    def feed_bytes(self, name: str) -> bytes:
        return (self.dir / "feeds" / name).read_bytes()


class RefusalTests(ServeTestCase):
    def refuse(self, fragment: str, **kw):
        with self.assertRaises(ConfigError) as cm:
            FeedService(self.settings(ServeConfig(**kw)))
        self.assertIn(fragment, str(cm.exception))
        self.assertNotIn(FAKE_SERVE_PASSWORD, str(cm.exception))

    def test_beyond_localhost_needs_tls_and_auth(self):
        self.refuse("refusing to listen on 0.0.0.0 without TLS (serve.tls_cert and serve.tls_key) and "
                    "authentication (serve.auth)", listen="0.0.0.0")
        self.refuse("without TLS", listen="0.0.0.0",
                    auth=ServeAuth(type="basic", username="xgs", password="env:S_PASSWORD"))
        self.refuse("without authentication", listen="192.0.2.10", tls_cert="a.pem", tls_key="a.key")
        self.refuse("without TLS", listen="::",
                    auth=ServeAuth(type="api_key", key_name="X-Key", key_value="env:S_KEY"))
        self.refuse("must be an IP address", listen="feeds.example.lan")

    def test_beyond_localhost_with_tls_and_auth_passes_the_rules(self):
        check_serve(ServeConfig(listen="0.0.0.0", tls_cert="a.pem", tls_key="a.key",
                                auth=ServeAuth(type="basic", username="xgs", password="env:S_PASSWORD")))

    def test_firewall_length_limits(self):
        cases = (("a" * 65, "longer than 64"), ("short-fake-pw", "at least 16"), ("fake password with spaces",
                                                                                   "printable ASCII"))
        for value, fragment in cases:
            with self.subTest(value=value), unittest.mock.patch.dict("os.environ", {"S_LONG": value}):
                self.refuse(fragment, auth=ServeAuth(type="basic", username="xgs", password="env:S_LONG"))
                self.refuse(fragment, auth=ServeAuth(type="api_key", key_name="X-Key", key_value="env:S_LONG"))
        with unittest.mock.patch.dict("os.environ", {"S_64": "b" * 64}):
            FeedService(self.settings(ServeConfig(auth=ServeAuth(type="basic", username="xgs", password="env:S_64"))))
        self.refuse("longer than 64", auth=ServeAuth(type="basic", username="u" * 65, password="env:S_PASSWORD"))
        self.refuse("must not contain a colon", auth=ServeAuth(type="basic", username="a:b", password="env:S_PASSWORD"))
        self.refuse("key_name must be a valid header name",
                    auth=ServeAuth(type="api_key", key_name="X Key", key_value="env:S_KEY"))
        self.refuse("key_name must be a valid query name",
                    auth=ServeAuth(type="api_key", key_name="k=v", key_value="env:S_KEY", add_to="query"))

    def test_missing_serve_secret(self):
        self.refuse("S_MISSING is not set", auth=ServeAuth(type="basic", username="xgs", password="env:S_MISSING"))

    def test_bad_tls_files(self):
        self.refuse("cannot load serve.tls_cert", tls_cert=str(self.dir / "none.pem"), tls_key=str(self.dir / "none.key"))

    def test_cli_check(self):
        cfg = write_toml(self.dir / "feed.toml", f'''
[[sources]]
type = "file"
path = "{DATA / 'mixed-bundle.json'}"
[output]
dir = "feeds"
[serve]
listen = "0.0.0.0"
''')
        with unittest.mock.patch("logging.basicConfig"):
            code, out = run_cli("serve", "--config", cfg, "--check")
            self.assertEqual(code, 2)
            self.assertIn("refusing to listen on 0.0.0.0", out)
            cfg.write_text(cfg.read_text().replace('"0.0.0.0"', '"127.0.0.1"'))
            code, out = run_cli("serve", "--config", cfg, "--check")
        self.assertEqual((code, out.strip()), (0, "config OK"))


class BasicAuthServeTests(ServeTestCase):
    def setUp(self):
        super().setUp()
        self.svc = self.service(auth=ServeAuth(type="basic", username="xgs", password="env:S_PASSWORD"))
        self.auth = basic("xgs", FAKE_SERVE_PASSWORD)

    def test_serves_the_three_files(self):
        for name in ("ips.txt", "domains.txt", "urls.txt"):
            status, headers, body = self.get(self.svc, f"/{name}", self.auth)
            self.assertEqual(status, 200)
            self.assertEqual(body, self.feed_bytes(name))
            self.assertEqual(headers["Content-Type"], "text/plain; charset=us-ascii")
            self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn(b"198.51.100.10\n", self.feed_bytes("ips.txt"))

    def test_head(self):
        status, headers, body = self.get(self.svc, "/ips.txt", self.auth, method="HEAD")
        self.assertEqual((status, body), (200, b""))
        self.assertEqual(int(headers["Content-Length"]), len(self.feed_bytes("ips.txt")))

    def test_wrong_or_missing_credentials(self):
        for headers in ({}, basic("xgs", "wrong-password-0000"), basic("other", FAKE_SERVE_PASSWORD),
                        {"Authorization": "Basic !!notbase64"}, {"Authorization": f"Bearer {FAKE_SERVE_PASSWORD}"}):
            with self.subTest(headers=headers):
                status, resp_headers, body = self.get(self.svc, "/ips.txt", headers)
                self.assertEqual(status, 401)
                self.assertIn("Basic", resp_headers["WWW-Authenticate"])
                self.assertNotIn(b"198.51.100", body)

    def test_only_the_feed_paths_exist(self):
        for path in ("/", "/ips.txt/", "/IPS.TXT", "/ips.txt.bak", "/ipv6.txt", "/report.json", "/../ips.txt",
                     "/%2e%2e/ips.txt", "/feeds/ips.txt", "/.ips.txt.tmp", "http://x/ips.txt"):
            with self.subTest(path=path):
                status, headers, _ = self.get(self.svc, path, self.auth)
                self.assertEqual(status, 404)
                self.assertNotIn("Location", headers)
        status, _, _ = self.get(self.svc, "/report.json")
        self.assertEqual(status, 401)   # unauthenticated callers learn nothing about paths

    def test_other_methods(self):
        for method in ("POST", "PUT", "DELETE", "OPTIONS"):
            status, headers, _ = self.get(self.svc, "/ips.txt", self.auth, method=method)
            self.assertEqual(status, 405)
            self.assertEqual(headers["Allow"], "GET, HEAD")

    def test_health_endpoint_leaks_nothing(self):
        status, headers, body = self.get(self.svc, "/healthz")
        self.assertEqual((status, body), (200, b"ok\n"))
        self.assertEqual(headers["Server"], "stix-xgs-feed")
        self.assertNotIn("Last-Modified", headers)
        self.assertNotIn("Python", str(headers))

    def test_logs_hold_no_secrets(self):
        with self.assertLogs("stix_xgs_feed", level="DEBUG") as logs:
            self.get(self.svc, "/ips.txt", self.auth)
            self.get(self.svc, "/ips.txt", basic("xgs", FAKE_SERVE_PASSWORD + "x"))
            self.get(self.svc, "/ips.txt?password=" + FAKE_SERVE_PASSWORD)
            self.assertTrue(wait_for(lambda: sum("GET /ips.txt" in line for line in logs.output) >= 3))
        text = "\n".join(logs.output)
        self.assertIn("authentication failed from 127.0.0.1", text)
        self.assertNotIn(FAKE_SERVE_PASSWORD, text)


class ApiKeyServeTests(ServeTestCase):
    def test_header_key(self):
        svc = self.service(auth=ServeAuth(type="api_key", key_name="X-Feed-Key", key_value="env:S_KEY"))
        self.assertEqual(self.get(svc, "/urls.txt", {"X-Feed-Key": FAKE_SERVE_KEY})[0], 200)
        self.assertEqual(self.get(svc, "/urls.txt", {"x-feed-key": FAKE_SERVE_KEY})[0], 200)
        self.assertEqual(self.get(svc, "/urls.txt", {"X-Feed-Key": FAKE_SERVE_KEY[:-1]})[0], 401)
        self.assertEqual(self.get(svc, f"/urls.txt?X-Feed-Key={FAKE_SERVE_KEY}")[0], 401)
        _, headers, _ = self.get(svc, "/urls.txt")
        self.assertNotIn("WWW-Authenticate", headers)

    def test_query_key_and_logs(self):
        svc = self.service(auth=ServeAuth(type="api_key", key_name="key", key_value="env:S_KEY", add_to="query"))
        with self.assertLogs("stix_xgs_feed", level="DEBUG") as logs:
            status, _, body = self.get(svc, f"/domains.txt?key={FAKE_SERVE_KEY}")
            self.assertEqual(status, 200)
            self.assertEqual(body, self.feed_bytes("domains.txt"))
            self.assertEqual(self.get(svc, f"/domains.txt?key={FAKE_SERVE_KEY}&key=other")[0], 401)
            self.assertEqual(self.get(svc, "/domains.txt?key=")[0], 401)
            self.assertEqual(self.get(svc, "/domains.txt", {"key": FAKE_SERVE_KEY})[0], 401)
            self.assertTrue(wait_for(lambda: sum("GET /domains.txt" in line for line in logs.output) >= 4))
        self.assertNotIn(FAKE_SERVE_KEY, "\n".join(logs.output))


class RoutingAndAccessTests(ServeTestCase):
    def test_path_prefix(self):
        svc = self.service(path_prefix="/acme")
        self.assertEqual(self.get(svc, "/acme/ips.txt")[0], 200)
        for path in ("/ips.txt", "/acme", "/acme/", "/acme/acme/ips.txt"):
            status, headers, _ = self.get(svc, path)
            self.assertEqual(status, 404, path)
            self.assertNotIn("Location", headers)

    def test_allowed_clients(self):
        import ipaddress
        svc = self.service(allowed_clients=[ipaddress.ip_network("192.0.2.1/32")])
        self.assertEqual(self.get(svc, "/ips.txt")[0], 403)     # loopback is not on the list
        self.assertEqual(self.get(svc, "/healthz")[0], 200)     # but may run the health check
        svc2 = self.service(allowed_clients=[ipaddress.ip_network("127.0.0.0/8")])
        self.assertEqual(self.get(svc2, "/ips.txt")[0], 200)

    def test_connection_cap(self):
        svc = self.service(max_connections=1)
        hold = socket.create_connection(("127.0.0.1", svc.port))
        try:
            self.assertTrue(wait_for(lambda: svc.server._slots._value == 0))
            extra = socket.create_connection(("127.0.0.1", svc.port))
            extra.settimeout(5)
            try:
                extra.sendall(b"GET /healthz HTTP/1.0\r\n\r\n")
                data = extra.recv(100)
            except ConnectionResetError:
                data = b""
            finally:
                extra.close()
            self.assertEqual(data, b"")
        finally:
            hold.close()
        self.assertTrue(wait_for(lambda: svc.server._slots._value == 1))
        self.assertEqual(self.get(svc, "/healthz")[0], 200)

    def test_not_ready_until_the_first_good_refresh(self):
        svc = self.service(source=self.dir / "missing.json")
        status, _, body = self.get(svc, "/healthz")
        self.assertEqual((status, body), (503, b"unavailable\n"))
        self.assertEqual(self.get(svc, "/ips.txt")[0], 503)
        self.assertEqual(svc.scheduler.failures, 1)


class TlsServeTests(ServeTestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki_tmp = tempfile.TemporaryDirectory()
        cls.certs = make_certs(Path(cls.pki_tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls.pki_tmp.cleanup()

    def test_https_with_private_ca(self):
        svc = self.service(tls_cert=self.certs["server.pem"], tls_key=self.certs["server.key"],
                           auth=ServeAuth(type="basic", username="xgs", password="env:S_PASSWORD"))
        ctx = ssl.create_default_context(cafile=self.certs["ca.pem"])
        status, _, body = self.get(svc, "/ips.txt", basic("xgs", FAKE_SERVE_PASSWORD), ctx=ctx, host="localhost")
        self.assertEqual((status, body), (200, self.feed_bytes("ips.txt")))
        with self.assertRaises(ssl.SSLError):     # the system store does not trust the private CA
            self.get(svc, "/healthz", ctx=ssl.create_default_context(), host="localhost")
        old = ssl.create_default_context(cafile=self.certs["ca.pem"])
        old.maximum_version = ssl.TLSVersion.TLSv1_1
        old.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        with self.assertRaises((ssl.SSLError, OSError)):
            self.get(svc, "/healthz", ctx=old, host="localhost")
        with self.assertRaises((http.client.HTTPException, OSError)):
            self.get(svc, "/healthz")                  # plain HTTP to the TLS port
        self.assertTrue(healthcheck(dataclasses.replace(svc.cfg, port=svc.port)))

    def test_healthcheck_command_fails_when_nothing_listens(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self.assertFalse(healthcheck(ServeConfig(port=port, tls_cert="x", tls_key="y"), timeout=2))


class SwapAndRefreshTests(ServeTestCase):
    def test_atomic_swap_under_load(self):
        svc = self.service()
        path = self.dir / "feeds" / "ips.txt"
        versions = [[f"198.51.{i // 256}.{i % 256}" for i in range(20_000)],
                    [f"203.0.{i // 256}.{i % 256}" for i in range(15_000)]]
        bodies = [("".join(line + "\n" for line in v)).encode() for v in versions]
        stop = threading.Event()
        bad, seen = [], set()

        def writer():
            i = 0
            while not stop.is_set():
                write_atomic(path, versions[i % 2])
                i += 1

        def reader():
            for _ in range(40):
                status, _, body = self.get(svc, "/ips.txt")
                if status != 200 or body not in bodies:
                    bad.append((status, len(body)))
                else:
                    seen.add(bodies.index(body))

        write_atomic(path, versions[1])
        w = threading.Thread(target=writer)
        w.start()
        readers = [threading.Thread(target=reader) for _ in range(4)]
        for r in readers:
            r.start()
        for r in readers:
            r.join()
        stop.set()
        w.join()
        self.assertEqual(bad, [])
        self.assertEqual(seen, {0, 1})                         # both versions were served while swapping
        self.assertEqual(list(path.parent.glob(".ips.txt.*")), [])   # no temp files left behind

    def test_failed_refresh_keeps_serving_the_last_good_files(self):
        source = self.dir / "source.json"
        source.write_bytes(bundle("first.test"))
        svc = self.service(source=source)
        self.assertEqual(self.get(svc, "/domains.txt")[2], b"first.test\n")
        source.write_text("{not json")
        with self.assertLogs("stix_xgs_feed", level="ERROR") as logs:
            self.assertFalse(svc.refresh())
        self.assertIn("still serving the previous files", logs.output[0])
        self.assertEqual(self.get(svc, "/domains.txt")[2], b"first.test\n")
        source.write_bytes(bundle("second.test", "third.test"))
        self.assertTrue(svc.refresh())
        self.assertEqual(self.get(svc, "/domains.txt")[2], b"second.test\nthird.test\n")

    def test_stale_temp_files_removed_at_start(self):
        feeds = self.dir / "feeds"
        feeds.mkdir()
        (feeds / ".ips.txt.abc123").write_text("half")
        (feeds / ".keep.me").write_text("other")
        self.service()
        self.assertFalse((feeds / ".ips.txt.abc123").exists())
        self.assertTrue((feeds / ".keep.me").exists())


class SchedulerTests(unittest.TestCase):
    def test_runs_now_then_every_interval(self):
        calls = []
        sched = Scheduler(lambda: calls.append(time.monotonic()) or True, interval=0.05, retry=0.05)
        sched.start()
        self.assertTrue(wait_for(lambda: len(calls) >= 4, 5))
        sched.stop(2)
        gaps = [b - a for a, b in zip(calls, calls[1:])]
        self.assertTrue(all(g >= 0.04 for g in gaps), gaps)
        self.assertEqual(sched.failures, 0)
        self.assertIsNotNone(sched.last_success)

    def test_retries_sooner_after_a_failure(self):
        results = iter([False, False, True])
        calls = []

        def job():
            calls.append(time.monotonic())
            return next(results, True)

        sched = Scheduler(job, interval=30, retry=0.05)
        sched.start()
        self.assertTrue(wait_for(lambda: len(calls) >= 3, 5))
        time.sleep(0.3)
        sched.stop(2)
        self.assertEqual(len(calls), 3)          # after the success it waits the full interval
        self.assertEqual(sched.failures, 0)

    def test_a_crashing_job_does_not_stop_the_schedule(self):
        calls = []

        def job():
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("boom")
            return True

        with self.assertLogs("stix_xgs_feed", level="ERROR"):
            sched = Scheduler(job, interval=0.05, retry=0.05)
            sched.start()
            self.assertTrue(wait_for(lambda: len(calls) >= 2, 5))
            sched.stop(2)

    def test_stop_is_prompt_and_retry_never_exceeds_interval(self):
        sched = Scheduler(lambda: True, interval=3600, retry=7200)
        self.assertEqual(sched.retry, 3600)
        sched.start()
        self.assertTrue(wait_for(lambda: sched.runs == 1, 5))
        started = time.monotonic()
        sched.stop(5)
        self.assertLess(time.monotonic() - started, 1)
        self.assertFalse(sched._thread.is_alive())

    def test_runs_never_overlap(self):
        active, overlaps = [0], []

        def job():
            active[0] += 1
            if active[0] > 1:
                overlaps.append(1)
            time.sleep(0.05)
            active[0] -= 1
            return True

        sched = Scheduler(job, interval=0.01, retry=0.01)
        sched.start()
        self.assertTrue(wait_for(lambda: sched.runs >= 4, 5))
        sched.stop(2)
        self.assertEqual(overlaps, [])


class DockerExampleTests(unittest.TestCase):
    @needs_toml
    def test_compose_example_config_passes_the_serve_rules(self):
        from stix_xgs_feed.config import load_config
        s = load_config(Path(__file__).resolve().parent.parent / "examples" / "docker" / "feed.toml")
        self.assertEqual((s.serve.listen, s.serve.port, s.out), ("0.0.0.0", 8443, "/data/feeds"))
        check_serve(s.serve)


if __name__ == "__main__":
    unittest.main()
