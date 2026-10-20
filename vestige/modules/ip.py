"""IP intelligence: classification, reverse DNS, ASN (Team Cymru DNS), geolocation (ipapi.co),
Shodan InternetDB (passive), AbuseIPDB reputation (optional key).

Non-public addresses are classified locally and are never sent to third parties.
"""
from __future__ import annotations

import ipaddress

from vestige.core.context import Batch, Context
from vestige.core.http_client import ProviderError
from vestige.core.models import Confidence, Observation, Relationship, SourceResult, Status, utcnow
from vestige.core.scope import classify_ip
from vestige.modules.dns import DnsError, Resolver
from vestige.modules.reputation import abuseipdb


def cymru_name(ip: str) -> str:
    a = ipaddress.ip_address(ip)
    if a.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    nibbles = a.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def parse_cymru_origin(txt: str) -> dict:
    parts = [p.strip() for p in txt.strip('"').split("|")]
    if len(parts) < 3 or not parts[0].split()[0].isdigit():
        raise ProviderError("malformed", f"unexpected Team Cymru record: {txt[:60]!r}")
    return {"asn": int(parts[0].split()[0]), "prefix": parts[1], "country": parts[2],
            "registry": parts[3] if len(parts) > 3 else None, "allocated": parts[4] if len(parts) > 4 else None}


def parse_cymru_asn(txt: str) -> dict:
    parts = [p.strip() for p in txt.strip('"').split("|")]
    return {"as_name": parts[4] if len(parts) > 4 else None}


def asn_lookup(ctx: Context, ip: str) -> Batch:
    res: Resolver = ctx.resolver  # type: ignore[assignment]
    try:
        recs = res.query(cymru_name(ip), "TXT")
    except DnsError as exc:
        if exc.kind == "nxdomain":
            return Batch([], detail="no BGP origin found for this address")
        raise ProviderError("network", f"Team Cymru DNS lookup failed ({exc.kind})") from exc
    if not recs:
        return Batch([])
    info = parse_cymru_origin(recs[0])
    try:
        asn_txt = res.query(f"AS{info['asn']}.asn.cymru.com", "TXT")
        if asn_txt:
            info.update(parse_cymru_asn(asn_txt[0]))
    except DnsError:
        pass
    now = utcnow()
    asn = f"AS{info['asn']}"
    return Batch([Observation("asn", asn, "team-cymru-dns", Confidence.HIGH, now, {"ip": ip, **info})],
                 [Relationship(ip, "announced_by", asn, "team-cymru-dns", Confidence.HIGH, now,
                               f"BGP origin for {info['prefix']}")])


def reverse_dns(ctx: Context, ip: str) -> Batch:
    res: Resolver = ctx.resolver  # type: ignore[assignment]
    try:
        ptrs = res.query(ipaddress.ip_address(ip).reverse_pointer, "PTR")
    except DnsError as exc:
        if exc.kind == "nxdomain":
            return Batch([], detail="no PTR record")
        raise ProviderError("network", f"PTR lookup failed ({exc.kind})") from exc
    now = utcnow()
    return Batch([Observation("reverse_dns", f"{ip} {p.rstrip('.').lower()}", "dns", Confidence.MEDIUM, now,
                              {"ip": ip, "ptr": p.rstrip(".").lower(),
                               "note": "PTR is set by the address owner and is not verified to match forward DNS"})
                  for p in ptrs])


def parse_ipapi(doc: dict) -> dict:
    if not isinstance(doc, dict):
        raise ProviderError("malformed", "ipapi.co response is not an object")
    if doc.get("error"):
        reason = str(doc.get("reason", "error"))
        kind = "ratelimit" if "rate" in reason.lower() else "http"
        raise ProviderError(kind, f"ipapi.co: {reason}")
    return {"country": doc.get("country_name"), "country_code": doc.get("country_code") or doc.get("country"),
            "region": doc.get("region"), "city": doc.get("city"), "timezone": doc.get("timezone"),
            "org": doc.get("org"), "asn": doc.get("asn"), "latitude": doc.get("latitude"),
            "longitude": doc.get("longitude"),
            "accuracy_note": "IP geolocation is approximate (often city/region level or ISP hub); it does not locate a person"}


def geolocation(ctx: Context, ip: str) -> Batch:
    res = ctx.http.get(f"https://ipapi.co/{ip}/json/", source="ipapi", cacheable=True, ttl=24 * 3600, ok=(200,))
    return Batch([Observation("geolocation", ip, "ipapi.co", Confidence.LOW, utcnow(),
                              {"ip": ip, **parse_ipapi(res.json())})], http_status=res.status)


def parse_internetdb(doc: dict) -> dict:
    if not isinstance(doc, dict) or "ip" not in doc:
        raise ProviderError("malformed", "InternetDB response malformed")
    return {"ports": sorted(int(p) for p in doc.get("ports", []) if str(p).isdigit()),
            "hostnames": sorted(doc.get("hostnames", []) or []), "tags": sorted(doc.get("tags", []) or []),
            "cpes": sorted(doc.get("cpes", []) or []), "vulns": sorted(doc.get("vulns", []) or []),
            "note": "passive Shodan crawler data; may be stale; vulnerability IDs are inferred from banners and unverified"}


def internetdb(ctx: Context, ip: str) -> Batch:
    res = ctx.http.get(f"https://internetdb.shodan.io/{ip}", source="shodan-internetdb",
                       ok=(200, 404), cacheable=True, ttl=6 * 3600)
    if res.status == 404:
        return Batch([], detail="no data held for this address", http_status=404)
    return Batch([Observation("exposure_metadata", ip, "shodan-internetdb", Confidence.MEDIUM, utcnow(),
                              {"ip": ip, **parse_internetdb(res.json())})], http_status=res.status)


def analyze_ip(ctx: Context, ip: str, *, reputation: bool = True) -> dict:
    """Run all IP sources. Returns the classification dict."""
    info = classify_ip(ip)
    addr = info["address"]
    now = utcnow()
    ctx.inv.observations.append(Observation("ip_classification", addr, "local", Confidence.HIGH, now, info))
    ctx.record(SourceResult("ip", "classification", Status.OK, info["classification"], items=1))
    public = info["is_global"]
    why = None if public else f"{info['classification']} address: not sent to third-party services"
    ctx.run_source("ip", "reverse-dns", lambda: reverse_dns(ctx, addr), skip_reason=None if public else why)
    ctx.run_source("ip", "asn (team-cymru)", lambda: asn_lookup(ctx, addr), skip_reason=why)
    ctx.run_source("ip", "geolocation (ipapi.co)", lambda: geolocation(ctx, addr), skip_reason=why)
    ctx.run_source("ip", "exposure (shodan-internetdb)", lambda: internetdb(ctx, addr), skip_reason=why)
    if reputation:
        ctx.run_source("ip", "reputation (abuseipdb)", lambda: abuseipdb(ctx, addr),
                       requires="ABUSEIPDB_KEY" if public else None, skip_reason=why)
    ctx.inv.limitations.append("Geolocation is approximate and reflects network registration/infrastructure, not a person.")
    return info
