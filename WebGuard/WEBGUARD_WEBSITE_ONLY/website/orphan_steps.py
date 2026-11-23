"""Step functions of the Web Orphanic pipeline (used by server.py), after Pletinckx, Borgolte and Fiebig,
"Out of Sight, Out of Mind: Detecting Orphaned Web Pages at Internet-Scale" (ACM CCS 2021).

Steps (paper section in brackets):
  1. archive snapshots -> candidates last seen before the reference year           [3.1.1]
  2. drop resource files by extension                                              [3.1.2, App. B]
  3. Dynamic URL Detection (DUDe)                                                  [3.1.3, Alg. 1]
  4. liveness probe: HTTP HEAD, keep status 200                                    [3.1.4]
  5. size-based filter for custom "not found" pages (within 5 bytes)               [3.2.4]
  6. simhash similarity to the last archived version + orphan score, cutoff 0.9    [4.3, 4.4]
  7. page-type classification: copyright, boilerplate, errors, redirects, frames   [4.5]

Pure functions only: no network access here. server.py does the requests, with the same-origin,
public-host, delay and 100-attempt limits. Results are candidates and labels, not proof.
"""
from __future__ import annotations

import math
import re
import time
from collections import Counter
from statistics import mean
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

RESOURCE_EXTENSIONS = (
    ".3g2 .3gp .3gp2 .3gpp .3gpp2 .ai .avi .bmp .css .dib .eot .eps .f4a .f4b .f4v .flv .gif .heic "
    ".heif .ico .ind .indd .indt .j2k .jfi .jfif .jif .jp2 .jpe .jpeg .jpf .jpg .jpm .jpx .js .m4a "
    ".m4b .m4p .m4r .m4v .mj2 .mov .mp2 .mp3 .mp4 .mpe .mpeg .mpg .mpv .oga .ogg .ogv .ogx .pdf .png "
    ".psd .qt .svg .svgz .swf .tif .tiff .ttf .webm .webp .wma .wmv .woff"
).split()

ERROR_PHRASES = ("404 not found", "404 error", "page not found")
REDIRECT_MARKERS = ("window.location", "top.location", 'http-equiv="refresh"', "http-equiv='refresh'",
                    "redirect(", "object moved to")
FRAME_MARKERS = ("<iframe", "<frameset", "<frame")


# ---------------------------------------------------------------- step 1: archive candidates
def parse_cdx(rows):
    """Wayback CDX JSON rows [[timestamp, original], ...] (header row optional) -> [(ts, url)]."""
    out = []
    for row in rows:
        if len(row) >= 2 and str(row[0]).isdigit():
            out.append((str(row[0]), str(row[1])))
    return out


def split_archive(snapshots, reference_year):
    """Candidates = URLs whose last archived snapshot is before reference_year.
    Returns {url: (last_seen_year, last_timestamp)}."""
    last = {}
    for ts, url in snapshots:
        if url not in last or ts > last[url]:
            last[url] = ts
    return {u: (int(ts[:4]), ts) for u, ts in last.items() if int(ts[:4]) < reference_year}


# ---------------------------------------------------------------- step 2: resource files
def has_resource_extension(url):
    path = urlsplit(url).path.lower()
    return any(path.endswith(ext) for ext in RESOURCE_EXTENSIONS)


def filter_resources(urls):
    return [u for u in urls if not has_resource_extension(u)]


# ---------------------------------------------------------------- step 3: DUDe (Algorithm 1)
def dynamic_url_detection(urls, domain, pc=0.05, st=15, lt=20, lc=0):
    """Remove clusters of generated URLs that share a long prefix.

    pc: popularity cutoff, st: short-link threshold, lt: long-link threshold, lc: long-link cutoff.
    Defaults are the values the paper chose (5%, 15, 20, 0). Returns (kept, removed)."""
    remaining = list(dict.fromkeys(urls))
    removed = []
    min_prefix = len(domain) + 8 + st                 # 8 = len("https://")
    while remaining:
        large = [u for u in remaining if len(u) > lt + len(domain) + 8]
        if not large or len(large) <= lc:
            break
        max_len = max(len(u) for u in large)
        avg_len = int(mean(len(u) for u in remaining))
        generated = "".join(
            Counter(u[i] for u in large if len(u) > i).most_common(1)[0][0] for i in range(max_len))
        prefix = generated[:avg_len]
        need = max(1, math.ceil(pc * len(remaining)))
        matched = []
        while len(prefix) >= min_prefix:
            matched = [u for u in remaining if prefix in u]
            if len(matched) >= need:
                break
            prefix = prefix[:-1]
        else:
            break                                      # no usable prefix left
        removed.extend(matched)
        gone = set(matched)
        remaining = [u for u in remaining if u not in gone]
    return remaining, removed


# ---------------------------------------------------------------- step 5: size filter
def size_filter(sizes, tolerance=5):
    """sizes: {url: bytes}. Drop pages whose size is within `tolerance` bytes of another page of the
    same domain (likely a custom error page that returns 200). Returns (kept, removed)."""
    by_host = {}
    for url, size in sizes.items():
        by_host.setdefault(urlsplit(url).hostname, []).append((size, url))
    kept, removed = [], []
    for items in by_host.values():
        items.sort()
        flagged = set()
        for i in range(len(items) - 1):
            if items[i + 1][0] - items[i][0] <= tolerance:
                flagged.update((items[i][1], items[i + 1][1]))
        for _, url in items:
            (removed if url in flagged else kept).append(url)
    return kept, removed


# ---------------------------------------------------------------- step 6: simhash + orphan score
FNV_OFFSET, FNV_PRIME, MASK64 = 0xCBF29CE484222325, 0x100000001B3, (1 << 64) - 1


def fnv1a_64(data: bytes) -> int:
    h = FNV_OFFSET
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & MASK64
    return h


def visible_text(html: str) -> str:
    soup = BeautifulSoup(html or "", "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    return soup.get_text(" ", strip=True)


def ngrams(text, n=8):
    """Word n-grams (n=8 as in the paper). Fewer than n words -> one gram. Word level is our
    reading of the paper, which does not say whether n-grams are words or characters."""
    words = text.split()
    if not words:
        return []
    if len(words) < n:
        return [" ".join(words)]
    return [" ".join(words[i:i + n]) for i in range(len(words) - n + 1)]


def simhash(html: str, n=8) -> int:
    counts = [0] * 64
    for gram in ngrams(visible_text(html), n):
        h = fnv1a_64(gram.encode("utf-8", "ignore"))
        for i in range(64):
            counts[i] += 1 if (h >> i) & 1 else -1
    return sum(1 << i for i, c in enumerate(counts) if c > 0)


def similarity(a: int, b: int) -> float:
    return 1.0 - bin(a ^ b).count("1") / 64.0


def orphan_score(sim, age, ws=0.9, wa=0.1, max_age=23):
    """O = (max_age * S * ws + A * wa) / max_age, in [0, 1]. Paper: ws=0.9, wa=0.1, max_age=23."""
    age = min(max(age, 0), max_age)
    return (max_age * sim * ws + age * wa) / max_age


# ---------------------------------------------------------------- step 7: page types
_COPY = re.compile(r"copyright|\u00a9", re.I)
_YEAR = re.compile(r"(?<!\d)(19[89]\d|20[0-4]\d)(?!\d)")
_META = re.compile(r"http-equiv=[\"']refresh[\"'][^>]*content=[\"']\s*\d+\s*;\s*url=([^\"'>\s]+)", re.I)
_JS = re.compile(r"(?:window|top|document)\.location(?:\.href)?\s*=\s*[\"']([^\"']+)[\"']", re.I)
_FRAME_SRC = re.compile(r"<i?frame[^>]+src=[\"']([^\"']+)[\"']", re.I)


def copyright_info(text):
    """(present, latest_year) from the 50 characters around each copyright mark."""
    present, years = False, []
    for m in _COPY.finditer(text):
        present = True
        years += [int(y) for y in _YEAR.findall(text[max(0, m.start() - 50):m.end() + 50])]
    return present, (max(years) if years else None)


def find_target(html, page_url):
    for rx in (_META, _JS, _FRAME_SRC):
        m = rx.search(html or "")
        if m:
            return urljoin(page_url, m.group(1).strip())
    return None


def classify_page(html, page_url="", recent_year=2020):
    """Label one page. Returns {'type', 'status', 'target'}; status is Likely orphaned / Uncertain /
    Not orphaned / Discard / Follow. Heuristics only, not proof."""
    raw = (html or "").lower()
    text = visible_text(html)
    low = text.lower()
    if any(p in low for p in ERROR_PHRASES):
        return {"type": "Error page", "status": "Discard", "target": None}
    if any(m in raw for m in REDIRECT_MARKERS):
        return {"type": "Redirect", "status": "Follow", "target": find_target(html, page_url)}
    if any(m in raw for m in FRAME_MARKERS):
        return {"type": "Frame", "status": "Follow", "target": find_target(html, page_url)}
    present, year = copyright_info(text)
    if present and year is None:
        return {"type": "Copyright without date", "status": "Uncertain", "target": None}
    if present:
        if year >= recent_year:
            return {"type": "Recent copyright", "status": "Not orphaned", "target": None}
        return {"type": "Old copyright", "status": "Likely orphaned", "target": None}
    if len(text.split()) < 5:
        return {"type": "Boilerplate", "status": "Likely orphaned", "target": None}
    return {"type": "Undefined", "status": "Uncertain", "target": None}


def classify_with_follow(url, html, get_page, base_ok=lambda u: True, recent_year=2020, max_hops=20):
    """Follow in-page redirects and frames (max 20 hops, same origin only, loops detected)."""
    seen, hops = {url}, 0
    result = classify_page(html, url, recent_year)
    while result["status"] == "Follow":
        target = result["target"]
        if not target or not base_ok(target):
            return {"type": result["type"] + " (target not followed)", "status": "Uncertain", "target": target}
        hops += 1
        if hops > max_hops or target in seen:
            return {"type": "Redirect overflow", "status": "Uncertain", "target": target}
        seen.add(target)
        status, body = get_page(target)
        if status != 200:
            return {"type": "Redirect to unavailable page", "status": "Uncertain", "target": target}
        result = classify_page(body, target, recent_year)
    return result
