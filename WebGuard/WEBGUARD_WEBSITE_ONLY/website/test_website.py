"""End-to-end tests for WebGuard website-only: real Chromium, a local test site, simulated Internet Archive.

The private-address block is switched off for these tests only, so the tool can reach 127.0.0.1.
Nothing here touches a real website."""
import json, sys, threading, time, types, unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0, ".")
import server

HITS, SITE, ARCHIVED, CDX = [], {}, {}, []     # requests seen, live pages, archived copies, CDX rows

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        HITS.append(self.path)
        if self.path == "/redir":
            self.send_response(302); self.send_header("Location", "http://example.org/"); self.end_headers(); return
        status, html = SITE.get(self.path, (404, "<h1>404 Not Found</h1>"))
        self.send_response(status); self.send_header("Content-Type", "text/html"); self.end_headers()
        self.wfile.write(html.encode())
    do_HEAD = do_GET

def page(title, links=(), extra="", pad=0):
    return (f"<html><head><title>{title}</title></head><body><p>{title} words words words</p>" +
            "".join(f'<a href="{l}">{l}</a>' for l in links) + extra + ("<p>" + "filler " * pad + "</p>" if pad else "") +
            "</body></html>")

def orphan(path, html, archived=None):
    """A live page that nothing links to, present in the (simulated) Internet Archive."""
    SITE[path] = (200, html); ARCHIVED[BASE + path] = html if archived is None else archived
    CDX.append(["20120101000000", BASE + path])

srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
threading.Thread(target=srv.serve_forever, daemon=True).start()

SLEEPS = []
server.time = types.SimpleNamespace(sleep=lambda s: SLEEPS.append(s), gmtime=time.gmtime, strftime=time.strftime)
REAL_PUBLIC = server.public_host

class FakeCdx:
    status_code = 200
    def raise_for_status(self): pass
    def json(self): return [["timestamp", "original"]] + CDX

class FakeSnapshot:
    encoding = "utf-8"
    def __init__(self, html): self.html = html; self.status_code = 200 if html is not None else 404
    def iter_content(self, n): yield (self.html or "").encode()

_real_get = server.requests.get
def fake_get(url, *a, **k):
    if "web.archive.org/cdx" in url: return FakeCdx()
    if "web.archive.org/web/" in url: return FakeSnapshot(ARCHIVED.get(url.split("id_/", 1)[1]))
    return _real_get(url, *a, **k)
server.requests.get = fake_get
client = server.app.test_client()

def run(max_pages=100, authorized=True, url=BASE + "/"):
    HITS.clear(); SLEEPS.clear()
    r = client.post("/api/crawl", json={"url": url, "authorized": authorized, "max_pages": max_pages, "delay": 1.5})
    return r.status_code, r.get_json()

class T(unittest.TestCase):
    def setUp(self):
        server.public_host = lambda u: None
        SITE.clear(); ARCHIVED.clear(); CDX.clear()

    def test_01_guards(self):
        server.public_host = REAL_PUBLIC
        self.assertEqual(run(authorized=False)[0], 400)
        code, body = run(); self.assertEqual(code, 400); self.assertIn("Private", body["error"])
        server.public_host = lambda u: None
        self.assertEqual(run(url="ftp://x.example/")[0], 400)
        self.assertEqual(run(url="http://user:pw@127.0.0.1/")[0], 400)

    def test_02_small_site(self):
        SITE.update({"/": (200, page("Home", ["/a", "/b", "/missing", "/redir"], '<button onclick="x()">go</button>')),
                     "/a": (200, page("A", ["/"])), "/b": (200, page("B", ["/a"])), "/gone.html": (404, "nope")})
        orphan("/old-promo.html", page("Old promo", [], "Copyright 2009", pad=30))
        CDX.extend([["20120101000000", BASE + "/gone.html"], ["20120101000000", BASE + "/a"], ["20100101000000", BASE + "/logo.png"]])
        code, d = run(); self.assertEqual(code, 200)
        self.assertEqual({p["url"] for p in d["pages"]}, {BASE + "/", BASE + "/a", BASE + "/b"})   # 404 is not a crawled page
        self.assertTrue(any("/missing" in e["url"] and "HTTP 404" in e["error"] for e in d["errors"]))
        self.assertTrue(any("/redir" in e["url"] for e in d["errors"]))                              # off-origin redirect not followed
        self.assertTrue(d["crawl_complete"])
        o = d["orphan_candidates"]
        self.assertEqual([x["url"] for x in o], [BASE + "/old-promo.html"])
        self.assertTrue(o[0]["classification"].startswith("Potential orphan"))
        self.assertEqual((o[0]["page_type"], o[0]["paper_label"], o[0]["similarity"]), ("Old copyright", "Likely orphaned", 1.0))
        self.assertGreaterEqual(o[0]["orphan_score"], 0.9)
        self.assertEqual({p["url"]: p["inbound_links"] for p in d["pages"]}[BASE + "/a"], 2)
        self.assertEqual(d["attempt_summary"]["successful_crawl_pages"], 3)
        self.assertTrue(all(s >= 1.0 for s in SLEEPS))
        self.assertIn("not confirmed SQL injection or XSS", d["limitations"])
        print("\nSMALL SITE:", json.dumps(d["attempt_summary"]), "| risk:", d["risk"]["overall"])

    def test_03_cap_counts_failures(self):
        SITE["/"] = (200, page("Home", [f"/dead{i}" for i in range(150)]))
        code, d = run(max_pages=100)
        attempts = d["attempt_summary"]["unique_page_urls_attempted"]
        print("\nCAP (150 dead links): attempted", attempts, "| requests received by site:", len(HITS))
        self.assertLessEqual(attempts, 100); self.assertLessEqual(len(HITS), 100)

    def test_04_no_false_orphans_when_cap_hit(self):
        SITE["/"] = (200, page("Home", [f"/p{i:03d}" for i in range(120)]))
        for i in range(120): SITE[f"/p{i:03d}"] = (200, page(f"P{i}", ["/"]))
        CDX.extend([["20150101000000", BASE + f"/p{i:03d}"] for i in range(100, 120)])
        code, d = run(max_pages=100)
        self.assertEqual(d["orphan_candidates"], [])
        print("\nBIG SITE: crawled", d["summary"]["pages"], "| linked pages wrongly reported as orphans: 0")

    def test_05_unused_attempts_roll_over(self):
        SITE.update({"/": (200, page("Home", ["/a"])), "/a": (200, page("A"))})
        for i in range(40): orphan(f"/o{i}.html", page(f"O{i}", pad=i * 10 + 1))     # distinct sizes
        code, d = run(max_pages=100)
        print("\nBUDGET: 40 true orphans, reported:", len(d["orphan_candidates"]), "| attempts used:", d["attempt_summary"]["unique_page_urls_attempted"], "/ 100")
        self.assertEqual(len(d["orphan_candidates"]), 40)

    def test_06_incomplete_crawl_labels_leads(self):
        SITE["/"] = (200, page("Home", [f"/p{i:03d}" for i in range(120)]))
        for i in range(120): SITE[f"/p{i:03d}"] = (200, page(f"P{i}", ["/"]))
        orphan("/old-promo.html", page("Old promo", pad=5))
        code, d = run(max_pages=100)
        self.assertFalse(d["crawl_complete"])
        self.assertEqual([o["url"] for o in d["orphan_candidates"]], [BASE + "/old-promo.html"])
        self.assertTrue(d["orphan_candidates"][0]["classification"].startswith("Archive lead"))
        self.assertIn("leads, not orphans", d["archive_discovery"]["note"])

    def test_07_archive_last_snapshot_rule(self):
        SITE.update({"/": (200, page("Home", ["/a"])), "/a": (200, page("A")), "/active.html": (200, page("Active"))})
        CDX.extend([["20120101000000", BASE + "/active.html"], [f"{time.gmtime().tm_year}0101000000", BASE + "/active.html"]])
        orphan("/stale.html", page("Stale", pad=7))
        code, d = run()
        self.assertEqual([o["url"] for o in d["orphan_candidates"]], [BASE + "/stale.html"])

    def test_08_paper_filters(self):
        year = time.gmtime().tm_year
        SITE.update({"/": (200, page("Home", ["/a"])), "/a": (200, page("A"))})
        orphan("/keep-old.html", page("Keep old", [], "Copyright 2010", pad=60))               # kept: old copyright
        orphan("/changed.html", page("Changed page now about something else entirely and quite different", pad=20),
               archived="<html><body><p>Completely unrelated archived text that shares nothing with the new page "
                        "whatsoever, written long ago about gardening, boats, music, bread and tax returns.</p></body></html>")
        for n in (1, 2): orphan(f"/fake{n}.html", "<html><body><h1>Page Not Found</h1></body></html>")   # same size -> size filter
        orphan("/recent.html", page("Recent", [], f"Copyright {year}", pad=2))                 # recent copyright -> not orphaned
        orphan("/empty.html", "<html><body></body></html>")                                     # boilerplate
        for n in range(1, 5): orphan(f"/articles/2001/January/story-{n}.html", page(f"Story {n}", pad=n * 9))   # generated URLs
        CDX.append(["20100101000000", BASE + "/logo.png"])                                      # resource file
        code, d = run()
        got = {o["url"].rsplit("/", 1)[1]: (o["page_type"], o["paper_label"]) for o in d["orphan_candidates"]}
        self.assertEqual(got, {"keep-old.html": ("Old copyright", "Likely orphaned"), "empty.html": ("Boilerplate", "Likely orphaned")})
        f = d["pipeline_funnel"]
        self.assertEqual((f["archive_leads"], f["after_dynamic_url_detection"], f["live_html_200"], f["after_size_filter"]), (10, 6, 6, 4))
        self.assertEqual((f["below_orphan_score_cutoff"], f["recent_copyright_excluded"], f["reported"]), (1, 1, 2))
        self.assertFalse([h for h in HITS if h.startswith("/articles") or h.endswith(".png")])     # never requested
        print("\nPIPELINE FUNNEL:", json.dumps(f))

if __name__ == "__main__":
    unittest.main(argv=["x"], verbosity=2)
