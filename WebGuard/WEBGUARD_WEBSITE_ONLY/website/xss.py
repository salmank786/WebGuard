"""Passive XSS triage for WebGuard. Does not send exploit payloads or submit forms.

Findings are indicators for manual verification, not proof of exploitability.
Only same-origin, authorised targets are fetched; redirects are not followed.
"""
from __future__ import annotations
import ipaddress
import re
import socket
import time
from urllib.parse import urlsplit, urlunsplit, urldefrag, parse_qsl

import requests
from bs4 import BeautifulSoup

USER_AGENT = "WebGuardAIPro/4.1 (authorised-passive-xss-review)"
MAX_BODY = 262144


def _normalise(url: str) -> str:
    url = urldefrag(str(url).strip())[0]
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise ValueError("Use an http(s) URL without embedded credentials.")
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, ""))


def _same_origin(url: str, base: str) -> bool:
    a, b = urlsplit(_normalise(url)), urlsplit(_normalise(base))
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)


def _public_host(url: str, allow_local: bool = False) -> None:
    host = urlsplit(_normalise(url)).hostname
    if allow_local and host in ("localhost", "127.0.0.1", "::1"):
        return
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"Could not resolve host: {host}") from exc
    if not infos:
        raise ValueError(f"Could not resolve host: {host}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise ValueError("Private, loopback and reserved targets are blocked.")


def inspect_html(url: str, html: str, headers: dict | None = None) -> list[dict]:
    """Return conservative passive indicators from an already-fetched HTML response."""
    findings: list[dict] = []
    soup = BeautifulSoup(html or "", "html.parser")
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}

    for tag in soup.find_all(True):
        for attr, value in tag.attrs.items():
            if attr.lower().startswith("on"):
                findings.append({"url": url, "type": "Inline event handler", "severity": "Review", "evidence": f"<{tag.name} {attr}=…>", "confidence": "Indicator"})
            if attr.lower() in ("href", "src", "action", "formaction") and isinstance(value, str) and value.strip().lower().startswith(("javascript:", "vbscript:")):
                findings.append({"url": url, "type": "Script-capable URL attribute", "severity": "High review priority", "evidence": f"<{tag.name} {attr}=script-capable URL>", "confidence": "Indicator"})

    script_text = "\n".join(s.get_text("\n", strip=False) for s in soup.find_all("script"))
    # Sink presence is a review signal, not a vulnerability by itself.
    sink_patterns = [
        (r"\b(?:innerHTML|outerHTML)\s*=", "HTML injection sink assignment"),
        (r"\bdocument\.write(?:ln)?\s*\(", "document.write sink"),
        (r"\beval\s*\(", "eval usage"),
        (r"\bnew\s+Function\s*\(", "Dynamic Function constructor"),
        (r"\b(?:setTimeout|setInterval)\s*\(\s*['\"]", "String-based timer execution"),
    ]
    for pattern, label in sink_patterns:
        if re.search(pattern, script_text, re.I):
            findings.append({"url": url, "type": label, "severity": "Review", "evidence": "Potential client-side execution sink found in inline script", "confidence": "Context required"})

    # Only inspect values already present in the URL; never inject test strings.
    for key, value in parse_qsl(urlsplit(url).query, keep_blank_values=False)[:30]:
        if len(value) < 3 or not re.search(r"[<>\"'`()]", value):
            continue
        if value in (html or ""):
            findings.append({"url": url, "type": "Existing query value reflected in raw HTML", "severity": "Review", "evidence": f"Parameter {key!r} value appears unescaped in response source; verify exact browser context", "confidence": "Potential reflection only"})

    csp = headers.get("content-security-policy", "")
    if not csp:
        findings.append({"url": url, "type": "Content-Security-Policy header absent", "severity": "Hardening", "evidence": "Response has no Content-Security-Policy header", "confidence": "Configuration observation"})
    return findings


def scan_xss_passive(base_url: str, urls, max_pages: int = 25, delay: float = 0.2, allow_local: bool = False) -> dict:
    """Fetch up to max_pages same-origin URLs and passively inspect HTML.

    GET requests only. Does not submit forms, mutate data, follow redirects, or inject payloads.
    """
    base = _normalise(base_url)
    _public_host(base, allow_local=allow_local)
    targets = []
    for candidate in urls:
        try:
            candidate = _normalise(candidate)
            if _same_origin(candidate, base) and candidate not in targets:
                targets.append(candidate)
        except ValueError:
            continue
        if len(targets) >= max(1, min(int(max_pages), 50)):
            break
    session = requests.Session()
    session.trust_env = False
    rows, errors = [], []
    for url in targets:
        try:
            _public_host(url, allow_local=allow_local)
            response = session.get(url, timeout=7, allow_redirects=False, stream=True,
                                   headers={"User-Agent": USER_AGENT, "Accept": "text/html"})
            try:
                status = response.status_code
                ctype = response.headers.get("Content-Type", "")
                if status in (301, 302, 303, 307, 308):
                    rows.append({"url": url, "type": "Redirect not followed", "severity": "Informational", "evidence": "Redirect response inspected only; destination not requested", "confidence": "Observation", "http_status": status})
                    continue
                if "html" not in ctype.lower():
                    continue
                body = bytearray()
                for chunk in response.iter_content(8192):
                    body.extend(chunk)
                    if len(body) >= MAX_BODY:
                        break
                html = bytes(body).decode(response.encoding or "utf-8", errors="replace")
                for item in inspect_html(url, html, dict(response.headers)):
                    item["http_status"] = status
                    rows.append(item)
            finally:
                response.close()
        except (requests.RequestException, ValueError, OSError) as exc:
            errors.append({"url": url, "error": str(exc)[:240]})
        if delay:
            time.sleep(max(0, min(float(delay), 2)))
    return {
        "base_url": base,
        "urls_checked": len(targets),
        "findings_count": len(rows),
        "findings": rows,
        "errors": errors,
        "method": "Passive HTML/JavaScript inspection; no injected payloads or form submissions",
        "limitations": "Indicators are not proof of exploitable XSS. Stored XSS requires application-specific testing; external scripts and runtime DOM behavior may not be visible in static HTML. Verify findings manually or with an authorised dynamic scanner.",
    }
