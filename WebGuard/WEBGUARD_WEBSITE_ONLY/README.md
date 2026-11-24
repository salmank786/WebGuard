# WebGuard — Website Only

A bounded, read-only website crawler and passive security-risk review dashboard, with Internet Archive-assisted orphan-page candidate discovery.

## Features
- Website URL input and same-origin page crawling.
- Hard maximum of **100 unique target page URLs attempted per scan**. Failed URLs (including HTTP 404/500 pages) and archive candidate probes count toward the same limit.
- Page/link relationship graph, HTTP status, inbound-link counts and security-header observations.
- Orphan-page pipeline after Pletinckx, Borgolte and Fiebig (ACM CCS 2021): Internet Archive discovery, resource and dynamic-URL filters, live HTTP 200 check, page-size filter, simhash similarity and orphan score, and page labels (copyright, boilerplate, redirects, frames).
- Passive XSS indicators and security-header observations.
- Overall risk classification with a visible alert for Moderate or High Risk.
- JSON and CSV evidence exports.

## Windows setup
1. Install Python 3.10 or newer.
2. Double-click `START_WEBGUARD.bat`.
3. Wait for Chromium setup, then open `http://127.0.0.1:8787` if it does not open automatically.
4. Enter a website URL and confirm that you own it or have explicit permission to assess it.
5. Choose a page-attempt limit up to 100 and start the scan.

## How the 100 limit works
The server counts each unique target page URL before attempting to request it. A failed URL still consumes one attempt and cannot be retried in the same scan. Up to 20 attempts are reserved for the orphan pipeline, and any crawl attempts left unused roll over to it. Redirect and frame targets followed by the page labels also count. The count covers target HTML page URLs, not browser subresources such as images, scripts, stylesheets or fonts. A page that returns HTTP 400 or higher is recorded as a failed attempt, not as a crawled page, and is not checked for XSS indicators.

## Orphan pipeline (CCS 2021 method)
The internal-link crawl alone cannot identify orphan pages, because it only reaches pages that are linked. WebGuard therefore follows the paper's steps (functions in `website/orphan_steps.py`, requests in `server.py`):

1. **Archive leads:** Internet Archive CDX URLs on the same site whose **last** snapshot is before the current year, minus every URL that any crawled page links to (even if the page limit stopped the crawl before visiting it).
2. **Resource filter:** the paper's 68 file extensions (images, CSS, scripts, PDF, media, fonts) plus .zip and .woff2.
3. **Dynamic URL Detection (DUDe):** removes clusters of generated URLs (paper values: 5%, 15, 20, 0).
4. **Live check:** one same-origin GET per lead, redirects not followed; only HTTP 200 HTML pages continue.
5. **Size filter:** pages within 5 bytes of another page on the site are dropped as fake "not found" pages.
6. **Simhash and orphan score:** the live page is compared with its last archived copy (FNV-1a 64-bit simhash over word 8-grams). O = (S x 30 x 0.9 + age x 0.1) / 30, where 30 is the Internet Archive's age scale (the paper used 23). Pages with O below 0.9 are dropped. If the archived copy cannot be fetched, the page is kept and shown with score "n/a".
7. **Page labels:** copyright year (a year at or above last year counts as recent and the page is excluded as "Not orphaned"), boilerplate (under 5 words), error pages (discarded), and redirects or frames (followed up to 20 hops, same origin only).

If the crawl stopped at the page limit (`crawl_complete` is false), results are labelled "Archive lead" instead of "Potential orphan candidate", because they may be linked from pages that were not crawled. The results page shows how many URLs survive each step. All of this is a discovery heuristic, not proof of orphan status. The Archive request returns at most 5,000 snapshot rows, so coverage on large sites is partial. The paper's active Wapiti XSS and SQLi scan is **not** part of WebGuard; its passive checks are used instead.

## Safety and security limitations
Only assess websites you own or are explicitly authorised to test. The crawler does not submit forms, inject exploit payloads, or perform active SQL injection testing. It validates public IP addresses before browser requests, checks navigation redirects, and blocks off-origin navigations. Browser subresources are not included in the 100-page count. Indicators and header gaps are not confirmed SQL injection or XSS vulnerabilities. Findings are triage indicators and require manual verification; this is not a full penetration test and cannot guarantee detection of every vulnerability.

## Tests
Run from the `website` folder (Python 3.10+, packages from `requirements.txt`):
```bash
python -m unittest test_logic test_orphan_steps -v   # 21 offline tests, no browser or network
python test_website.py                               # 8 end-to-end tests, about 2-3 minutes
```
`test_website.py` needs Chromium (`python -m playwright install chromium`). It starts a small local test site and simulates the Internet Archive; the tool's private-address block is switched off for these tests only. It never touches a real website.
