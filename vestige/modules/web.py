"""Optional, lightweight HTTP/TLS inspection of an explicitly authorised target.

Safety properties (all enforced here and covered by tests):
* Runs only when Scope.http_allowed (both --http-checks and --confirm-authorized).
* Every URL (start URL and every redirect hop) must be in scope: the authorised domain or a
  subdomain of it. Out-of-scope redirects are recorded but NOT followed.
* Every destination hostname is resolved first and refused if any address is non-public.
* At most MAX_REDIRECTS hops; response bodies are size-capped; only GET requests are sent;
  no payloads, no authentication, no brute forcing.
"""
from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from vestige.core.context import Batch, Context
from vestige.core.http_client import HttpResult, ProviderError
from vestige.core.models import Confidence, Observation, utcnow
from vestige.core.scope import Scope, ScopeError, resolve_public

MAX_REDIRECTS = 5
BODY_CAP = 256 * 1024

SECURITY_HEADERS = [
    "strict-transport-security", "content-security-policy", "x-content-type-options",
    "referrer-policy", "permissions-policy", "x-frame-options",
]
TECH_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator", "via", "x-served-by"]


def _safe_get(ctx: Context, url: str, *, ok=(200, 301, 302, 303, 307, 308, 404), max_bytes=BODY_CAP) -> HttpResult:
    """One scoped, SSRF-checked GET (redirects are never followed automatically)."""
    scope: Scope = ctx.scope  # type: ignore[assignment]
    host = scope.check_url(url)
    (ctx.resolve_public_fn or resolve_public)(host)
    return ctx.http.get(url, source="target-http", ok=ok, allow_redirects=False, retry=False, max_bytes=max_bytes)


def follow_chain(ctx: Context, start_url: str) -> tuple[list[dict], HttpResult | None, str]:
    """Follow redirects manually, enforcing scope at every hop. Returns (chain, final_response, stop_reason)."""
    chain: list[dict] = []
    url, res, reason = start_url, None, ""
    for _ in range(MAX_REDIRECTS + 1):
        try:
            res = _safe_get(ctx, url)
        except ScopeError as exc:
            reason = f"stopped: {exc}"
            break
        chain.append({"url": url, "status": res.status})
        if res.status in (301, 302, 303, 307, 308) and res.headers.get("location"):
            nxt = urljoin(url, res.headers["location"])
            try:
                ctx.scope.check_url(nxt)  # type: ignore[union-attr]
            except ScopeError as exc:
                chain[-1]["redirect_to"] = nxt
                reason = f"redirect not followed: {exc}"
                break
            url = nxt
            continue
        break
    else:
        reason = f"stopped after {MAX_REDIRECTS} redirects"
    return chain, res, reason


def evaluate_headers(headers: dict[str, str], is_https: bool) -> dict:
    """Record presence/absence of security headers with parsed details. A missing header is an
    observation, not a vulnerability."""
    out: dict = {}
    for h in SECURITY_HEADERS:
        out[h] = headers.get(h)
    hsts = headers.get("strict-transport-security")
    if hsts:
        m = re.search(r"max-age=(\d+)", hsts, re.I)
        out["hsts_max_age"] = int(m.group(1)) if m else None
        out["hsts_include_subdomains"] = "includesubdomains" in hsts.lower()
        out["hsts_preload"] = "preload" in hsts.lower()
    csp = headers.get("content-security-policy")
    if csp:
        low = csp.lower()
        out["csp_unsafe_inline"] = "'unsafe-inline'" in low
        out["csp_unsafe_eval"] = "'unsafe-eval'" in low
        out["csp_has_default_or_script_src"] = "default-src" in low or "script-src" in low
    out["_is_https"] = is_https
    return out


def parse_security_txt(text: str, now: datetime | None = None) -> dict:
    """Parse RFC 9116 fields. Contact and Expires are REQUIRED by the standard."""
    now = now or datetime.now(timezone.utc)
    fields: dict[str, list[str]] = {}
    signed = "-----BEGIN PGP SIGNED MESSAGE-----" in text
    for line in text.splitlines():
        if line.startswith("#") or ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        if k in ("contact", "expires", "encryption", "acknowledgments", "preferred-languages", "canonical", "policy", "hiring", "csrf"):
            fields.setdefault(k, []).append(v.strip())
    problems, expires_dt = [], None
    if "contact" not in fields:
        problems.append("missing required 'Contact' field")
    if "expires" not in fields:
        problems.append("missing required 'Expires' field")
    elif len(fields["expires"]) > 1:
        problems.append("'Expires' must appear only once")
    else:
        try:
            expires_dt = datetime.fromisoformat(fields["expires"][0].replace("Z", "+00:00"))
            if expires_dt.tzinfo is None:
                expires_dt = expires_dt.replace(tzinfo=timezone.utc)
            if expires_dt < now:
                problems.append("'Expires' date is in the past (file is stale)")
        except ValueError:
            problems.append("'Expires' is not a valid ISO 8601 date")
    for c in fields.get("contact", []):
        if not re.match(r"^(mailto:|https://|tel:)", c, re.I):
            problems.append(f"Contact '{c[:40]}' should be a mailto:, https: or tel: URI")
    return {"fields": fields, "pgp_signed": signed, "expires": expires_dt.isoformat() if expires_dt else None,
            "problems": problems}


def parse_robots(text: str) -> dict:
    disallow = allow = 0
    sitemaps = []
    agents = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        k, v = (x.strip() for x in line.split(":", 1))
        k = k.lower()
        if k == "disallow" and v:
            disallow += 1
        elif k == "allow" and v:
            allow += 1
        elif k == "sitemap" and v:
            sitemaps.append(v)
        elif k == "user-agent":
            agents.add(v)
    return {"disallow_rules": disallow, "allow_rules": allow, "sitemaps": sitemaps[:10], "user_agent_groups": len(agents)}


def parse_sitemap(text: str) -> dict:
    """Regex-based on purpose: stdlib XML parsers are unsafe on untrusted input."""
    locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text, re.I)
    lastmods = sorted(re.findall(r"<lastmod>\s*([^<\s]+)\s*</lastmod>", text, re.I))
    return {"url_count": len(locs), "is_index": "<sitemapindex" in text.lower(),
            "lastmod_min": lastmods[0] if lastmods else None, "lastmod_max": lastmods[-1] if lastmods else None}


def fetch_tls(host: str, port: int = 443, timeout: float = 8.0, ip: str | None = None) -> dict:
    """TLS handshake with full verification (chain + hostname). Never disables verification."""
    ctx_ssl = ssl.create_default_context()
    info: dict = {"host": host, "verified": False}
    try:
        with socket.create_connection((ip or host, port), timeout=timeout) as sock:
            with ctx_ssl.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                info.update(verified=True, hostname_valid=True, protocol=tls.version(),
                            cipher=tls.cipher()[0] if tls.cipher() else None)
    except ssl.SSLCertVerificationError as exc:
        info.update(error=f"certificate verification failed: {exc.verify_message}",
                    hostname_valid=("hostname" not in (exc.verify_message or "").lower()))
        return info
    except (OSError, ssl.SSLError) as exc:
        info["error"] = f"TLS connection failed: {type(exc).__name__}"
        return info
    issuer = dict(x[0] for x in cert.get("issuer", ()))
    subject = dict(x[0] for x in cert.get("subject", ()))
    nb = ssl.cert_time_to_seconds(cert["notBefore"])
    na = ssl.cert_time_to_seconds(cert["notAfter"])
    now = datetime.now(timezone.utc).timestamp()
    info.update(
        issuer_org=issuer.get("organizationName"), issuer_cn=issuer.get("commonName"),
        subject_cn=subject.get("commonName"),
        san=sorted(v for k, v in cert.get("subjectAltName", ()) if k == "DNS")[:50],
        not_before=datetime.fromtimestamp(nb, timezone.utc).isoformat(),
        not_after=datetime.fromtimestamp(na, timezone.utc).isoformat(),
        days_until_expiry=int((na - now) // 86400),
    )
    return info


def web_checks(ctx: Context, domain: str, host: str | None = None) -> None:
    """Run all HTTP/TLS checks; every sub-check records its own SourceResult."""
    host = host or domain
    if not ctx.scope or not ctx.scope.http_allowed:
        reason = ("passive mode: direct HTTP/TLS checks not enabled "
                  "(use --http-checks --confirm-authorized for targets you are authorised to test)")
        for s in ("http-response", "tls-certificate", "security.txt", "robots.txt/sitemap"):
            ctx.run_source("web", s, lambda: Batch(), skip_reason=reason)
        ctx.inv.limitations.append("No direct HTTP/TLS requests were sent to the target (passive mode).")
        return
    now = utcnow()
    state: dict = {}

    def http_response() -> Batch:
        chain, res, stop = follow_chain(ctx, f"https://{host}/")
        if res is None:
            raise ProviderError("network", stop or "no response")
        final_url = chain[-1]["url"]
        is_https = final_url.startswith("https://")
        state["https_final"] = is_https
        h = res.headers
        data = {"host": host, "final_url": final_url, "status": res.status, "redirect_chain": chain,
                "redirect_note": stop, "technology_headers": {k: h[k] for k in TECH_HEADERS if k in h},
                "headers": evaluate_headers(h, is_https)}
        return Batch([Observation("http_response", host, "direct-http", Confidence.HIGH, now, data)],
                     http_status=res.status, detail=stop)

    def tls_check() -> Batch:
        addrs = (ctx.resolve_public_fn or resolve_public)(host, 443)
        info = (ctx.tls_fn or fetch_tls)(host, 443, ctx.http.timeout, addrs[0])
        return Batch([Observation("tls_certificate", host, "direct-tls", Confidence.HIGH, now, info)],
                     detail=info.get("error", ""))

    def security_txt() -> Batch:
        for path in ("/.well-known/security.txt", "/security.txt"):
            r = _safe_get(ctx, f"https://{host}{path}", ok=(200, 301, 302, 307, 308, 404, 403), max_bytes=64 * 1024)
            if r.status == 200 and "html" not in r.content_type.lower():
                p = parse_security_txt(r.text)
                p.update(location=path, content_type=r.content_type,
                         canonical_location=path == "/.well-known/security.txt")
                return Batch([Observation("security_txt", f"https://{host}{path}", "direct-http", Confidence.HIGH, now, p)])
        return Batch([Observation("security_txt", "absent", "direct-http", Confidence.MEDIUM, now,
                                  {"present": False, "checked": ["/.well-known/security.txt", "/security.txt"]})])

    def robots_sitemap() -> Batch:
        obs = []
        r = _safe_get(ctx, f"https://{host}/robots.txt", max_bytes=128 * 1024)
        sitemaps = []
        if r.status == 200 and "html" not in r.content_type.lower():
            info = parse_robots(r.text)
            sitemaps = info["sitemaps"]
            obs.append(Observation("robots_txt", host, "direct-http", Confidence.HIGH, now, {"present": True, **info}))
        else:
            obs.append(Observation("robots_txt", host, "direct-http", Confidence.MEDIUM, now,
                                   {"present": False, "status": r.status}))
        sm_url = sitemaps[0] if sitemaps else f"https://{host}/sitemap.xml"
        try:
            s = _safe_get(ctx, sm_url, max_bytes=1024 * 1024)
            if s.status == 200 and "xml" in s.content_type.lower():
                obs.append(Observation("sitemap", sm_url, "direct-http", Confidence.HIGH, now,
                                       {"present": True, **parse_sitemap(s.text)}))
        except ScopeError as exc:
            obs.append(Observation("sitemap", sm_url, "direct-http", Confidence.MEDIUM, now,
                                   {"present": False, "note": f"not fetched: {exc}"}))
        return Batch(obs)

    ctx.run_source("web", "http-response", http_response)
    ctx.run_source("web", "tls-certificate", tls_check)
    ctx.run_source("web", "security.txt", security_txt)
    ctx.run_source("web", "robots.txt/sitemap", robots_sitemap)
    ctx.inv.limitations.append(
        "Direct checks inspected only the root host over HTTPS. Missing headers are configuration observations, not exploitable vulnerabilities. "
        "A DNS-rebinding race between the public-address check and the request is possible in principle (see docs/SECURITY.md).")
