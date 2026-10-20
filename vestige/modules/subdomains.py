"""Passive subdomain discovery (several sources) and DNS verification.

No brute-forcing. A discovered name is only called "resolved" after a DNS lookup returned
addresses for it; otherwise it stays "unverified" or "no_dns_answer".
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from vestige.core.context import Batch, Context
from vestige.core.http_client import ProviderError
from vestige.core.models import Confidence, Observation, Relationship, utcnow
from vestige.core.scope import normalize_hostname
from vestige.modules.dns import DnsError, Resolver


def _subdomain(name: str, domain: str, source: str, conf: Confidence, now: str, **data) -> tuple[Observation, Relationship]:
    return (Observation("subdomain", name, source, conf, now, data),
            Relationship(domain, "has_subdomain", name, source, conf, now, "reported by passive source; liveness not tested"))


def parse_hackertarget(text: str, domain: str) -> list[tuple[str, str | None]]:
    low = text.strip().lower()
    if low.startswith("error") or "api count exceeded" in low:
        raise ProviderError("ratelimit", "HackerTarget daily free quota exceeded or request rejected")
    if low.startswith("no records"):
        return []
    out = []
    for line in text.splitlines():
        host, _, ip = line.partition(",")
        h = normalize_hostname(host, domain)
        if h and h != domain:
            out.append((h, ip.strip() or None))
    return out


def hackertarget(ctx: Context, domain: str) -> Batch:
    res = ctx.http.get("https://api.hackertarget.com/hostsearch/", params={"q": domain},
                       source="hackertarget", cacheable=True, ttl=6 * 3600)
    now = utcnow()
    obs, rels = [], []
    for name, ip in parse_hackertarget(res.text, domain):
        o, r = _subdomain(name, domain, "hackertarget", Confidence.MEDIUM, now, reported_ip=ip)
        obs.append(o)
        rels.append(r)
    return Batch(obs[: ctx.limit], rels[: ctx.limit], http_status=res.status)


def parse_otx(doc: dict, domain: str) -> list[dict]:
    if not isinstance(doc, dict) or not isinstance(doc.get("passive_dns", []), list):
        raise ProviderError("malformed", "OTX response missing 'passive_dns' list")
    seen: dict[str, dict] = {}
    for rec in doc.get("passive_dns", []):
        if not isinstance(rec, dict):
            continue
        h = normalize_hostname(str(rec.get("hostname", "")), domain)
        if not h or h == domain:
            continue
        e = seen.setdefault(h, {"first": rec.get("first"), "last": rec.get("last"), "ips": set()})
        if rec.get("first") and (not e["first"] or rec["first"] < e["first"]):
            e["first"] = rec["first"]
        if rec.get("last") and (not e["last"] or rec["last"] > e["last"]):
            e["last"] = rec["last"]
        if rec.get("record_type") in ("A", "AAAA") and rec.get("address"):
            e["ips"].add(str(rec["address"]))
    return [{"name": k, **{"first": v["first"], "last": v["last"], "ips": sorted(v["ips"])}} for k, v in sorted(seen.items())]


def otx(ctx: Context, domain: str) -> Batch:
    res = ctx.http.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                       headers={"X-OTX-API-KEY": ctx.creds["OTX_API_KEY"]}, source="otx", cacheable=False)
    now = utcnow()
    obs, rels = [], []
    for e in parse_otx(res.json(), domain):
        o, r = _subdomain(e["name"], domain, "alienvault-otx", Confidence.MEDIUM, now,
                          first_seen=e["first"], last_seen=e["last"], historical_ips=e["ips"])
        obs.append(o)
        rels.append(r)
    return Batch(obs[: ctx.limit], rels[: ctx.limit], http_status=res.status)


def parse_vt_subdomains(doc: dict, domain: str) -> list[str]:
    if not isinstance(doc, dict) or not isinstance(doc.get("data", []), list):
        raise ProviderError("malformed", "VirusTotal response missing 'data' list")
    names = []
    for item in doc["data"]:
        h = normalize_hostname(str(item.get("id", "")) if isinstance(item, dict) else "", domain)
        if h and h != domain:
            names.append(h)
    return sorted(set(names))


def virustotal_subdomains(ctx: Context, domain: str) -> Batch:
    res = ctx.http.get(f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
                       params={"limit": min(40, ctx.limit)},
                       headers={"x-apikey": ctx.creds["VIRUSTOTAL_KEY"]}, source="virustotal")
    now = utcnow()
    obs, rels = [], []
    for name in parse_vt_subdomains(res.json(), domain):
        o, r = _subdomain(name, domain, "virustotal", Confidence.MEDIUM, now)
        obs.append(o)
        rels.append(r)
    return Batch(obs, rels, http_status=res.status, partial="first page only (40 results)" if len(obs) >= 40 else "")


def discover_passive(ctx: Context, domain: str, sources: set[str] | None = None) -> None:
    """Run all keyless/keyed passive subdomain sources. Each records its own SourceResult."""
    want = lambda s: sources is None or s in sources  # noqa: E731
    if want("hackertarget"):
        ctx.run_source("subdomains", "hackertarget", lambda: hackertarget(ctx, domain))
    if want("otx"):
        ctx.run_source("subdomains", "alienvault-otx", lambda: otx(ctx, domain), requires="OTX_API_KEY")
    if want("virustotal"):
        ctx.run_source("subdomains", "virustotal", lambda: virustotal_subdomains(ctx, domain), requires="VIRUSTOTAL_KEY")


# --- DNS verification -------------------------------------------------------------------

def _resolve_one(res: Resolver, name: str) -> tuple[str, str, list[str]]:
    ips: list[str] = []
    errors = 0
    nx = 0
    for t in ("A", "AAAA"):
        try:
            ips += res.query(name, t)
        except DnsError as exc:
            if exc.kind == "nxdomain":
                nx += 1
            else:
                errors += 1
    if ips:
        return name, "resolved", sorted(set(ips))
    if errors:
        return name, "unverified", []
    return name, "no_dns_answer", []


def resolve_subdomains(ctx: Context, domain: str, *, wildcard_ips: set[str] | None = None) -> None:
    """Test discovered subdomains with DNS and annotate each observation's data.

    States: resolved | wildcard_only | no_dns_answer | unverified (error or beyond --limit).
    """
    subs = [o for o in ctx.inv.observations if o.kind == "subdomain"]
    subs.sort(key=lambda o: o.value)
    todo, skipped = subs[: ctx.limit], subs[ctx.limit:]
    wc = wildcard_ips or set()
    now = utcnow()
    for o in skipped:
        o.data.update(dns_state="unverified", dns_note=f"not tested (beyond --limit {ctx.limit})")
    if not todo:
        return
    with ThreadPoolExecutor(max_workers=max(1, ctx.max_workers)) as pool:
        results = list(pool.map(lambda o: _resolve_one(ctx.resolver, o.value), todo))  # type: ignore[arg-type]
    by_name = {o.value: o for o in todo}
    for name, state, ips in results:
        o = by_name[name]
        if state == "resolved" and wc and set(ips) <= wc:
            state = "wildcard_only"
        o.data.update(dns_state=state, resolved_ips=ips, dns_tested_at=now)
        if state in ("resolved", "wildcard_only"):
            conf = Confidence.HIGH if state == "resolved" else Confidence.LOW
            for ip in ips:
                ctx.inv.relationships.append(Relationship(
                    name, "resolves_to", ip, "dns", conf, now,
                    "wildcard answer; may not be a distinct host" if state == "wildcard_only" else ""))
