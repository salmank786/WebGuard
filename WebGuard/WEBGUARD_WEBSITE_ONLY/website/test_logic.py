"""Offline unit tests (no browser, no network) for WebGuard website-only helpers."""
import time, unittest
import server

class FakeResp:
    def __init__(self, rows): self.rows = rows
    def raise_for_status(self): pass
    def json(self): return [["timestamp", "original"]] + self.rows

class TestHelpers(unittest.TestCase):
    def test_clean_url(self):
        self.assertEqual(server.clean_url("https://a.com/x#frag"), "https://a.com/x")
        for bad in ("ftp://a.com", "https://user:pw@a.com/", "javascript:alert(1)", ""):
            with self.assertRaises(ValueError): server.clean_url(bad)

    def test_private_hosts_blocked(self):
        for url in ("http://127.0.0.1/", "http://localhost/", "http://10.0.0.5/", "http://192.168.1.1/", "http://169.254.169.254/"):
            with self.assertRaises(ValueError): server.public_host(url)

    def test_same_origin_default_ports(self):
        self.assertTrue(server.same_origin("https://a.com/x", "https://a.com:443/"))
        self.assertFalse(server.same_origin("http://a.com/", "https://a.com/"))
        self.assertFalse(server.same_origin("https://b.com/", "https://a.com/"))

class TestArchiveCandidates(unittest.TestCase):
    def setUp(self):
        self._get = server.requests.get

    def tearDown(self):
        server.requests.get = self._get

    def run_cdx(self, rows, excluded=(), limit=20):
        server.requests.get = lambda *a, **k: FakeResp(rows)
        return server.archive_candidates("https://a.com", set(excluded), limit)

    def test_filters(self):
        y = time.gmtime().tm_year
        rows = [["20120101000000", "https://a.com/old.html"], ["20120101000000", "https://a.com/logo.png"],
                ["20120101000000", "https://b.com/other.html"], ["20120101000000", "https://a.com/linked.html"],
                ["20120101000000", "https://a.com/active.html"], [f"{y}0101000000", "https://a.com/active.html"],
                ["20120101000000", "https://a.com/clip.mpg"], ["20120101000000", "https://a.com/pack.zip"],
                ["20120101000000", "https://a.com/font.woff2"], ["20120101000000", "https://a.com/scan.tiff"]]
        c, note = self.run_cdx(rows, excluded={"https://a.com/linked.html"})
        self.assertEqual([u for u, _ in c], ["https://a.com/old.html"])
        self.assertIsNone(note)

    def test_resource_extension_list_is_the_papers(self):
        self.assertEqual(len(server.RESOURCE_EXTENSIONS), 70)     # 68 from the paper + .zip + .woff2

    def test_limit_and_zero_budget(self):
        rows = [[f"2012{i:02d}01000000", f"https://a.com/p{i}.html"] for i in range(1, 10)]
        self.assertEqual(len(self.run_cdx(rows, limit=3)[0]), 3)
        c, note = self.run_cdx(rows, limit=0)
        self.assertEqual(c, []); self.assertIn("No attempt budget", note)

    def test_archive_failure_is_reported(self):
        def boom(*a, **k): raise RuntimeError("offline")
        server.requests.get = boom
        c, note = server.archive_candidates("https://a.com", set(), 5)
        self.assertEqual(c, []); self.assertIn("unavailable", note)

if __name__ == "__main__":
    unittest.main(verbosity=2)
