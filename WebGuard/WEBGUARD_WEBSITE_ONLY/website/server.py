"""WebGuard: authorised, bounded, read-only website review."""
from flask import Flask, request, jsonify, send_from_directory
from urllib.parse import urlsplit, urldefrag
import ipaddress, socket, time
from collections import deque
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
import requests
from xss import inspect_html
from risk import classify_findings, overall_risk, risk_counts
from orphan_steps import (dynamic_url_detection, size_filter, simhash, similarity, orphan_score,
                          classify_with_follow, RESOURCE_EXTENSIONS as PAPER_EXTENSIONS)

app = Flask(__name__, static_folder='static')
MAX_BODY = 300_000
IA_START_YEAR = 1996      # the Internet Archive's first crawls; fixes the age scale of the orphan score
ORPHAN_CUTOFF = 0.9       # paper: keep pages with orphan score >= 0.9
# The paper's 68 resource extensions (Appendix B) plus .zip and .woff2.
RESOURCE_EXTENSIONS = tuple(sorted(set(PAPER_EXTENSIONS) | {'.zip', '.woff2'}))

def clean_url(url):
    url = urldefrag(str(url).strip())[0]
    p = urlsplit(url)
    if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password:
        raise ValueError('Use a valid HTTP(S) URL without embedded credentials.')
    return url

def public_host(url):
    host = urlsplit(clean_url(url)).hostname
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f'Host could not be resolved: {host}') from exc
    if not infos:
        raise ValueError('Host did not resolve to an IP address.')
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise ValueError('Private, loopback and reserved network targets are blocked.')

def same_origin(url, base):
    a, b = urlsplit(url), urlsplit(base)
    def port(p): return p.port or (443 if p.scheme == 'https' else 80)
    return (a.scheme, a.hostname, port(a)) == (b.scheme, b.hostname, port(b))

def archive_candidates(base, excluded, limit):
    """Return archived URLs whose last CDX snapshot predates this year.

    These are discovery leads only. A URL is labelled a potential orphan only
    after a bounded, same-origin live GET succeeds and the crawler did not find it.
    """
    if limit <= 0:
        return [], 'No attempt budget remained for archive discovery.'
    host = urlsplit(base).hostname
    try:
        response = requests.get(
            'https://web.archive.org/cdx/search/cdx',
            params={'url': host + '/*', 'output': 'json', 'filter': 'statuscode:200',
                    'fl': 'timestamp,original', 'limit': '5000'},
            timeout=15, headers={'User-Agent': 'WebGuard/1.0 (authorised passive research)'}
        )
        response.raise_for_status()
        rows = response.json()
        latest = {}
        for row in rows:
            if len(row) >= 2 and str(row[0]).isdigit():
                ts, original = str(row[0]), str(row[1])
                if original not in latest or ts > latest[original]:
                    latest[original] = ts
        year = time.gmtime().tm_year
        candidates = []
        for url, ts in latest.items():
            try:
                u = clean_url(url)
                if not same_origin(u, base) or u in excluded:
                    continue
                if urlsplit(u).path.lower().endswith(RESOURCE_EXTENSIONS):
                    continue
                if int(ts[:4]) < year:
                    candidates.append((u, ts))
            except (ValueError, TypeError):
                continue
        candidates.sort(key=lambda item: item[1])
        return candidates[:limit], None
    except Exception as exc:
        return [], f'Internet Archive discovery unavailable: {str(exc)[:180]}'

def fetch_snapshot(url, timestamp):
    """Last archived HTML of a URL (raw, via the id_ flag). Returns '' if unavailable."""
    try:
        r = requests.get(f'https://web.archive.org/web/{timestamp}id_/{url}', timeout=15, stream=True,
                         headers={'User-Agent': 'WebGuard/1.0 (authorised passive research)'})
        if r.status_code != 200:
            return ''
        body = b''
        for chunk in r.iter_content(8192):
            body += chunk
            if len(body) >= MAX_BODY:
                break
        return body.decode(r.encoding or 'utf-8', errors='replace')
    except Exception:
        return ''
    finally:
        time.sleep(1.0)


@app.get('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.post('/api/crawl')
def crawl():
    body = request.get_json(force=True) or {}
    if body.get('authorized') is not True:
        return jsonify(error='Confirm you own the site or have explicit permission before crawling.'), 400
    try:
        base = clean_url(body.get('url', ''))
        public_host(base)
        max_pages = max(1, min(int(body.get('max_pages', 100)), 100))
        delay = max(1.0, min(float(body.get('delay', 1.5)), 5.0))
    except Exception as exc:
        return jsonify(error=str(exc)), 400

    # Reserve up to 20% of the unique-URL attempt budget for archived URL leads.
    archive_budget = min(20, max_pages // 4) if max_pages >= 4 else 0
    crawl_budget = max_pages - archive_budget
    queue = deque([base])
    attempted = set()  # every unique target page URL counts, including failures
    seen, edges, errors = {}, [], []
    archive_note = None

    def guard_route(route):
        url = route.request.url
        try:
            # Check every navigation (including redirect destinations) and every
            # resource host before Chromium is allowed to request it.
            public_host(url)
            if route.request.is_navigation_request() and not same_origin(url, base):
                route.abort()
                return
            route.continue_()
        except Exception:
            route.abort()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=False, java_script_enabled=True)
            page = context.new_page()
            page.route('**/*', guard_route)
            while queue and len(attempted) < crawl_budget:
                url = queue.popleft()
                if url in attempted:
                    continue
                if not same_origin(url, base):
                    continue
                attempted.add(url)  # count before request, including failed attempts
                try:
                    public_host(url)
                    resp = page.goto(url, wait_until='domcontentloaded', timeout=15000)
                    try:
                        page.wait_for_load_state('networkidle', timeout=1800)
                    except Exception:
                        pass
                    final = clean_url(page.url)
                    if not same_origin(final, base):
                        errors.append({'url': url, 'error': 'Navigation ended off-origin; page not followed'})
                        time.sleep(delay)
                        continue
                    # Re-resolve final URL after redirects as a second check.
                    public_host(final)
                    title = page.title()[:250]
                    html = page.content()[:MAX_BODY]
                    status = resp.status if resp else None
                    if status is not None and status >= 400:
                        errors.append({'url': url, 'error': f'HTTP {status}: page not available'})
                        time.sleep(delay)
                        continue
                    hdr = resp.all_headers() if resp else {}
                    links = []
                    for href in page.locator('a[href]').evaluate_all("els => els.map(a => a.href)"):
                        try:
                            u = clean_url(href)
                            if same_origin(u, base):
                                links.append(u)
                        except Exception:
                            pass
                    links = sorted(set(links))
                    seen[url] = {'url': url, 'final_url': final, 'title': title, 'status': status,
                                 'headers': hdr, 'links': links,
                                 'xss_indicators': inspect_html(url, html, hdr)}
                    for link in links:
                        edges.append({'source': url, 'target': link})
                        if link not in attempted and link not in queue:
                            queue.append(link)
                except Exception as exc:
                    errors.append({'url': url, 'error': str(exc)[:240]})
                time.sleep(delay)
            browser.close()
    except Exception as exc:
        return jsonify(error=f'Browser crawler failed: {exc}. Install Chromium using the setup instructions.'), 500

    crawl_attempts = len(attempted)
    # A crawl is complete only if every discovered same-origin link was attempted.
    pending = [u for u in queue if u not in attempted]
    crawl_complete = not pending
    # Any URL that some crawled page links to is NOT an orphan, even if the budget stopped us from visiting it.
    linked_targets = {e['target'] for e in edges}
    excluded = set(seen) | attempted | linked_targets | set(pending)
    # Archive-assisted pipeline (Pletinckx, Borgolte and Fiebig, CCS 2021). Every request to the target
    # site counts toward the same attempt budget; unused crawl attempts roll over to these steps.
    year = time.gmtime().tm_year
    recent_year = year - 1                       # copyright year at or above this counts as "recent"
    max_age = max(1, year - IA_START_YEAR)
    budget = max_pages - len(attempted)
    archive_rows, archive_note = archive_candidates(base, excluded, 10**6 if budget > 0 else 0)
    if not crawl_complete and not archive_note:
        archive_note = 'Crawl stopped at the page limit, so archive leads may be linked from pages that were not crawled. Treat them as leads, not orphans.'
    funnel = {'archive_leads': len(archive_rows)}
    last_ts = dict(archive_rows)
    leads, dynamic_removed = dynamic_url_detection([u for u, _ in archive_rows], urlsplit(base).hostname)
    funnel['after_dynamic_url_detection'] = len(leads)

    session = requests.Session()
    session.trust_env = False
    session.headers.update({'User-Agent': 'WebGuard/1.0 (authorised passive research)'})

    def get_page(target):
        """One same-origin GET, no redirects followed, body capped. Counts toward the attempt budget."""
        if len(attempted) >= max_pages or not same_origin(target, base):
            return None, ''
        attempted.add(target)
        try:
            public_host(target)
            with session.get(target, timeout=8, allow_redirects=False, stream=True) as response:
                body = b''
                for chunk in response.iter_content(8192):
                    body += chunk
                    if len(body) >= MAX_BODY:
                        break
                ctype = response.headers.get('Content-Type', '').lower()
                text = body.decode(response.encoding or 'utf-8', errors='replace')
                if response.status_code == 200 and ctype and 'html' not in ctype:
                    return 0, ''                  # not an HTML page
                return response.status_code, text
        except Exception as exc:
            errors.append({'url': target, 'error': f'Archive candidate probe: {str(exc)[:180]}'})
            return None, ''
        finally:
            time.sleep(delay)

    live = {}
    for candidate in leads:
        if len(attempted) >= max_pages:
            break
        if candidate in attempted:
            continue
        status, text = get_page(candidate)
        if status == 200:
            live[candidate] = text
    funnel['live_html_200'] = len(live)
    kept, size_removed = size_filter({u: len(t.encode('utf-8', 'ignore')) for u, t in live.items()})
    funnel['after_size_filter'] = len(kept)

    orphan_candidates, below_cutoff, discarded, recent_excluded = [], 0, 0, 0
    for candidate in kept:
        ts = last_ts[candidate]
        similarity_value, score, age = None, None, max(0, year - int(ts[:4]))
        snapshot = fetch_snapshot(candidate, ts)
        if snapshot:
            similarity_value = similarity(simhash(live[candidate]), simhash(snapshot))
            score = orphan_score(similarity_value, age, max_age=max_age)
            if score < ORPHAN_CUTOFF:
                below_cutoff += 1
                continue
        label = classify_with_follow(candidate, live[candidate], get_page,
                                     base_ok=lambda t: same_origin(t, base), recent_year=recent_year)
        if label['status'] == 'Discard':
            discarded += 1
            continue
        if label['status'] == 'Not orphaned':
            recent_excluded += 1
            continue
        evidence = ('URL appears in Internet Archive CDX history (last snapshot before this year), returned HTTP 200 and '
                    'no crawled page links to it.')
        if score is None:
            evidence += ' The archived snapshot could not be fetched, so the similarity score was not computed.'
        orphan_candidates.append({
            'url': candidate, 'last_archived': ts, 'live_status': 200,
            'age_years': age, 'similarity': None if similarity_value is None else round(similarity_value, 3),
            'orphan_score': None if score is None else round(score, 3),
            'page_type': label['type'], 'paper_label': label['status'],
            'evidence': evidence,
            'classification': ('Potential orphan candidate — manual verification required' if crawl_complete
                               else 'Archive lead — crawl incomplete, may be linked from pages not crawled; verify manually')})
    funnel['below_orphan_score_cutoff'] = below_cutoff
    funnel['error_pages_discarded'] = discarded
    funnel['recent_copyright_excluded'] = recent_excluded
    funnel['reported'] = len(orphan_candidates)
    orphan_candidates.sort(key=lambda o: (o['orphan_score'] is None, -(o['orphan_score'] or 0)))

    inbound = {u: 0 for u in seen}
    for edge in edges:
        if edge['target'] in inbound:
            inbound[edge['target']] += 1
    headers_report = []
    for url, item in seen.items():
        item['inbound_links'] = inbound[url]
        # A crawl graph alone cannot establish orphan status.
        item['orphan_candidate'] = False
        h = {k.lower(): v for k, v in item['headers'].items()}
        item['security_headers'] = {name: bool(h.get(name)) for name in
            ['content-security-policy', 'strict-transport-security', 'x-content-type-options',
             'referrer-policy', 'permissions-policy']}
        headers_report.append({'url': url, 'status': item['status'], 'security_headers': item['security_headers']})

    findings = []
    for item in seen.values():
        for finding in item['xss_indicators']:
            # Deduplicate identical finding records from overlapping passive checks.
            findings.append({**finding, 'status': 'Potential indicator — manual verification required'})
        missing = [key for key, value in item['security_headers'].items() if not value]
        if missing:
            findings.append({'url': item['url'], 'type': 'Missing security-header hardening',
                'severity': 'Hardening', 'evidence': ', '.join(missing),
                'confidence': 'Configuration observation', 'status': 'Not a confirmed vulnerability'})
    unique_findings, finding_keys = [], set()
    for finding in findings:
        key = (finding.get('url'), finding.get('type'), finding.get('evidence'))
        if key not in finding_keys:
            finding_keys.add(key)
            unique_findings.append(finding)
    findings = classify_findings(unique_findings)
    risk = overall_risk(findings)
    return jsonify(
        base_url=base, started_utc=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        pages=list(seen.values()), edges=edges, errors=errors, findings=findings,
        orphan_candidates=orphan_candidates,
        attempt_summary={'unique_page_urls_attempted': len(attempted), 'maximum': max_pages,
                         'successful_crawl_pages': len(seen),
                         'failed_or_unavailable_attempts': len([e for e in errors if e.get('url') in attempted]),
                         'archive_candidate_probes': len(attempted) - crawl_attempts},
        crawl_complete=crawl_complete, pipeline_funnel=funnel,
        archive_discovery={'source': 'Internet Archive CDX', 'note': archive_note,
                           'candidate_count': len(orphan_candidates)},
        risk={'overall': risk, 'counts': risk_counts(findings), 'alert': risk in ('High Risk', 'Moderate Risk')},
        summary={'pages': len(seen), 'edges': len(edges), 'orphan_candidates': len(orphan_candidates), 'crawl_complete': crawl_complete,
                 'findings_for_review': len(findings)},
        limitations=('Indicators and header gaps are not confirmed SQL injection or XSS vulnerabilities. Orphan results are candidates only: Internet Archive coverage is incomplete and a live HTTP 200 page may still be intentionally hidden. '
                     'The 100 limit counts unique target page URLs attempted, including failures and archive probes; browser subresources are not counted as pages. '
                     'This is a passive review, not a full penetration test. Login-only routes and dynamic interactions may be missed.')
    )

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8787, debug=False)
