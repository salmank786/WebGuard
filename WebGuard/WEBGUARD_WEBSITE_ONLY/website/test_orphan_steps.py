import unittest
from orphan_steps import (parse_cdx, split_archive, filter_resources, dynamic_url_detection, size_filter,
                            simhash, similarity, orphan_score, classify_page, classify_with_follow,
                            copyright_info, fnv1a_64)

D = "example.com"
LISTING_1 = [
    "https://example.com/articles/1997/January/article1.html",
    "https://example.com/articles/1997/February/article1.html",
    "https://example.com/articles/2002/May/article1.html",
    "https://example.com/articles/2002/May/article2.html",
    "https://example.com/contact.html",
    "https://example.com/login.html",
]
TEXT = "The quick brown fox jumps over the lazy dog while the city sleeps quietly tonight again"


class TestSteps(unittest.TestCase):
    def test_split_archive_uses_last_seen_year(self):
        rows = parse_cdx([["timestamp", "original"], ["20100101000000", "https://a.com/x"],
                          ["20190505000000", "https://a.com/x"], ["20200301000000", "https://a.com/y"],
                          ["20080101000000", "https://a.com/z"]])
        cand = split_archive(rows, 2020)
        self.assertEqual(set(cand), {"https://a.com/x", "https://a.com/z"})
        self.assertEqual(cand["https://a.com/x"][0], 2019)

    def test_resource_filter(self):
        urls = ["https://a.com/a.png", "https://a.com/s.CSS", "https://a.com/page.html", "https://a.com/f.pdf"]
        self.assertEqual(filter_resources(urls), ["https://a.com/page.html"])

    def test_dude_matches_paper_listing(self):
        kept, removed = dynamic_url_detection(LISTING_1, D)
        self.assertEqual(sorted(kept), ["https://example.com/contact.html", "https://example.com/login.html"])
        self.assertEqual(len(removed), 4)

    def test_dude_keeps_short_urls(self):
        urls = ["https://example.com/a.html", "https://example.com/b.html"]
        kept, removed = dynamic_url_detection(urls, D)
        self.assertEqual(kept, urls)
        self.assertEqual(removed, [])

    def test_size_filter_same_domain_only(self):
        sizes = {"https://a.com/1": 1000, "https://a.com/2": 1003, "https://a.com/3": 5000, "https://b.com/1": 1001}
        kept, removed = size_filter(sizes)
        self.assertEqual(sorted(removed), ["https://a.com/1", "https://a.com/2"])
        self.assertIn("https://b.com/1", kept)

    def test_fnv_known_value(self):
        self.assertEqual(fnv1a_64(b""), 0xCBF29CE484222325)
        self.assertEqual(fnv1a_64(b"a"), 0xAF63DC4C8601EC8C)

    def test_simhash_identical_and_different(self):
        a = f"<html><body><p>{TEXT}</p></body></html>"
        b = "<html><body><p>Completely different words appear here instead of the other text, nothing shared at all today</p></body></html>"
        self.assertEqual(similarity(simhash(a), simhash(a)), 1.0)
        self.assertLess(similarity(simhash(a), simhash(b)), 1.0)

    def test_simhash_ignores_tags_and_scripts(self):
        a = f"<p>{TEXT}</p>"
        b = f"<div><script>var x=1;</script><span>{TEXT}</span></div>"
        self.assertEqual(simhash(a), simhash(b))

    def test_orphan_score_formula(self):
        self.assertAlmostEqual(orphan_score(1.0, 0), 0.9)
        self.assertAlmostEqual(orphan_score(1.0, 23), 1.0)
        self.assertAlmostEqual(orphan_score(0.5, 0), 0.45)
        self.assertAlmostEqual(orphan_score(1.0, 99), 1.0)   # age is clamped


class TestClassify(unittest.TestCase):
    def test_copyright(self):
        self.assertEqual(copyright_info("Welcome. Copyright 2009 Acme Ltd")[1], 2009)
        self.assertEqual(copyright_info("\u00a9 Acme Ltd all rights reserved"), (True, None))
        self.assertEqual(copyright_info("nothing here"), (False, None))

    def test_labels(self):
        old = classify_page("<p>Welcome to our shop and sales page. Copyright 2009 Acme</p>")
        self.assertEqual((old["type"], old["status"]), ("Old copyright", "Likely orphaned"))
        new = classify_page("<p>Welcome to our shop and sales page. Copyright 2021 Acme</p>", recent_year=2020)
        self.assertEqual(new["status"], "Not orphaned")
        nodate = classify_page("<p>Welcome to our shop and sales page. \u00a9 Acme</p>")
        self.assertEqual(nodate["status"], "Uncertain")
        self.assertEqual(classify_page("<html><body><script>x()</script></body></html>")["type"], "Boilerplate")
        self.assertEqual(classify_page("<h1>404 Not Found</h1><p>Sorry</p>")["status"], "Discard")
        self.assertEqual(classify_page("<p>This is a normal long enough page with words but no dates</p>")["type"], "Undefined")

    def test_redirect_and_frame_targets(self):
        meta = '<meta http-equiv="refresh" content="0; url=/new.html">'
        self.assertEqual(classify_page(meta, "https://a.com/old")["target"], "https://a.com/new.html")
        frame = '<frameset><frame src="/inner.html"></frameset>'
        self.assertEqual(classify_page(frame, "https://a.com/")["type"], "Frame")

    def test_follow_resolves_and_detects_loop(self):
        pages = {"https://a.com/new": (200, "<p>Some real page with several words. Copyright 2005 Acme</p>")}
        meta = '<meta http-equiv="refresh" content="0; url=/new">'
        res = classify_with_follow("https://a.com/old", meta, lambda u: pages.get(u, (404, "")))
        self.assertEqual(res["type"], "Old copyright")
        loop = {"https://a.com/b": (200, '<meta http-equiv="refresh" content="0; url=/a">'),
                "https://a.com/a": (200, '<meta http-equiv="refresh" content="0; url=/b">')}
        res = classify_with_follow("https://a.com/a", loop["https://a.com/a"][1], lambda u: loop[u])
        self.assertEqual(res["type"], "Redirect overflow")

    def test_follow_blocks_offsite(self):
        meta = '<meta http-equiv="refresh" content="0; url=https://evil.example/x">'
        res = classify_with_follow("https://a.com/a", meta, lambda u: (200, ""), base_ok=lambda u: u.startswith("https://a.com"))
        self.assertEqual(res["status"], "Uncertain")


if __name__ == "__main__":
    unittest.main()
