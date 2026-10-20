"""Historical / archived intelligence: Wayback Machine CDX index and urlscan.io read-only search.

* Read-only. VESTIGE never submits URLs to any scanning service.
* URLs are normalised, de-duplicated and have sensitive query values redacted before they are
  stored. Archived observations describe the past; they are not claims about the current state.
"""
from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from vestige.core.context import Batch, Context
from vestige.core.http_client import ProviderError
from vestige.core.models import Confidence, Observation, Relationship, utcnow
from vestige.core.redact import REDACTED, SENSITIVE_PARAMS
from vestige.core.scope import in_scope, normalize_hostname

CDX = "https://web.archive.org/cdx/search/cdx"
URLSCAN = "https://urlscan.io/api/v1/search/"


def normalize_url(url: str) -> str | None:
    """Canonical, redacted form of an http(s) URL; None if unusable."""
    try:
        p = urlsplit(url.strip())
        host = (p.hostname or "").lower().rstrip(".")
        port = p.port
    except ValueError:
        return None
    if p.scheme.lower() not in ("http", "https") or not host:
        return None
    netloc = host if port in (None, 80, 443) else f"{host}:{port}"
    q = sorted((k, REDACTED if k.lower() in SENSITIVE_PARAMS else v) for k, v in parse_qsl(p.query, keep_blank_values=True))
    path = p.path or "/"
    return urlunsplit((p.scheme.lower(), netloc, path, urlencode(q, safe="[]"), ""))


def _ts(wayback_ts: str) -> str | None:
    t = wayback_ts or ""
    if len(t) >= 8 and t[:8].isdigit():
        return f"{t[0:4]}-{t[4:6]}-{t[6:8]}"
    return None


def parse_cdx(rows, domain: str) -> dict[str, dict]:
    """rows = CDX JSON output (first row is the header). Returns {normalized_url: info}."""
    if not isinstance(rows, list):
        raise ProviderError("malformed", "CDX response is not a JSON list")
    if not rows:
        return {}
    header, body = rows[0], rows[1:]
    if not isinstance(header, list):
        raise ProviderError("malformed", "CDX response has no header row")
    idx = {name: i for i, name in enumerate(header)}
    out: dict[str, dict] = {}
    for r in body:
        try:
            raw = r[idx["original"]]
            ts = _ts(r[idx["timestamp"]])
        except (IndexError, KeyError, TypeError):
            continue
        n = normalize_url(raw)
        if not n:
            continue
        host = urlsplit(n).hostname or ""
        if not in_scope(host, domain):
            continue
        e = out.setdefault(n, {"first_seen": ts, "last_seen": ts, "status": None, "mimetype": None, "host": host})
        if ts:
            if not e["first_seen"] or ts < e["first_seen"]:
                e["first_seen"] = ts
            if not e["last_seen"] or ts > e["last_seen"]:
                e["last_seen"] = ts
        e["status"] = r[idx["statuscode"]] if "statuscode" in idx and idx["statuscode"] < len(r) else e["status"]
        e["mimetype"] = r[idx["mimetype"]] if "mimetype" in idx and idx["mimetype"] < len(r) else e["mimetype"]
    return out


def wayback(ctx: Context, domain: str) -> Batch:
    cap = min(max(ctx.limit * 2, 100), 2000)
    res = ctx.http.get(CDX, params={"url": domain, "matchType": "domain", "output": "json",
                                    "fl": "timestamp,original,statuscode,mimetype", "collapse": "urlkey",
                                    "limit": cap},
                       source="wayback", cacheable=True, ttl=12 * 3600, timeout=max(ctx.http.timeout, 20.0))
    text = res.text.strip()
    if not text:
        return Batch([], detail="no archived captures", http_status=res.status)
    urls = parse_cdx(res.json(), domain)
    now = utcnow()
    obs, rels, hosts = [], [], {}
    for u, e in sorted(urls.items()):
        obs.append(Observation("historical_url", u, "wayback", Confidence.MEDIUM, now, {
            "first_seen": e["first_seen"], "last_seen": e["last_seen"], "archived_status": e["status"],
            "mimetype": e["mimetype"],
            "note": "earliest capture per URL (collapse=urlkey); describes the past, not the current state"}))
        hosts.setdefault(e["host"], e)
    for h, e in sorted(hosts.items()):
        if h != domain:
            obs.append(Observation("subdomain", h, "wayback", Confidence.LOW, now, {
                "first_seen": e["first_seen"], "last_seen": e["last_seen"], "archive_only_reference": True}))
            rels.append(Relationship(domain, "has_subdomain", h, "wayback", Confidence.LOW, now,
                                     "hostname appears in archived URLs; may no longer exist"))
    partial = f"capped at {cap} URL keys" if len(urls) >= cap else ""
    return Batch(obs[: ctx.limit * 2], rels, partial=partial, http_status=res.status)


def parse_urlscan(doc: dict, domain: str) -> list[dict]:
    if not isinstance(doc, dict) or not isinstance(doc.get("results", []), list):
        raise ProviderError("malformed", "urlscan response missing 'results'")
    out = []
    for r in doc["results"]:
        if not isinstance(r, dict):
            continue
        page, task = r.get("page") or {}, r.get("task") or {}
        host = normalize_hostname(str(page.get("domain", "")), domain)
        url = normalize_url(str(page.get("url") or task.get("url") or ""))
        if host:
            out.append({"host": host, "url": url, "time": task.get("time"), "ip": page.get("ip"),
                        "asn": page.get("asn"), "server": page.get("server"), "result_id": r.get("_id")})
    return out


def urlscan(ctx: Context, domain: str) -> Batch:
    headers = {"API-Key": ctx.creds["URLSCAN_KEY"]} if "URLSCAN_KEY" in ctx.creds else None
    res = ctx.http.get(URLSCAN, params={"q": f"domain:{domain}", "size": min(100, ctx.limit)},
                       headers=headers, source="urlscan", cacheable=True, ttl=6 * 3600)
    now = utcnow()
    obs, rels, seen_hosts = [], [], {}
    for r in parse_urlscan(res.json(), domain):
        seen_hosts.setdefault(r["host"], []).append(r)
        if r["url"]:
            obs.append(Observation("historical_url", r["url"], "urlscan", Confidence.MEDIUM, now, {
                "first_seen": (r["time"] or "")[:10] or None, "last_seen": (r["time"] or "")[:10] or None,
                "observed_ip": r["ip"], "urlscan_result_id": r["result_id"],
                "note": "existing public scan record (read-only search); no new scan was submitted"}))
    for h, recs in sorted(seen_hosts.items()):
        times = sorted(x["time"] for x in recs if x["time"])
        if h != domain:
            obs.append(Observation("subdomain", h, "urlscan", Confidence.MEDIUM, now, {
                "first_seen": times[0][:10] if times else None, "last_seen": times[-1][:10] if times else None,
                "historical_ips": sorted({x["ip"] for x in recs if x["ip"]})}))
            rels.append(Relationship(domain, "has_subdomain", h, "urlscan", Confidence.MEDIUM, now,
                                     "host appears in a public scan record"))
    return Batch(obs, rels, http_status=res.status,
                 detail="" if "URLSCAN_KEY" in ctx.creds else "anonymous (low rate limits)")


def archived_vs_current(inv) -> list[dict]:
    """Compare archive-only subdomain references with their present DNS state."""
    out = []
    for o in inv.obs("subdomain"):
        srcs = set(o.data.get("sources", []))
        if srcs and srcs <= {"wayback", "urlscan"}:
            out.append({"host": o.value, "dns_state": o.data.get("dns_state", "unverified"),
                        "first_seen": o.data.get("first_seen"), "last_seen": o.data.get("last_seen")})
    return sorted(out, key=lambda x: x["host"])
