"""Third-party reputation records (AbuseIPDB for IPs, VirusTotal for domains).

These are *other people's observations*: a score is never presented as proof of malice.
"""
from __future__ import annotations

from vestige.core.context import Batch, Context
from vestige.core.http_client import ProviderError
from vestige.core.models import Confidence, Observation, Relationship, utcnow


def parse_abuseipdb(doc: dict) -> dict:
    d = doc.get("data") if isinstance(doc, dict) else None
    if not isinstance(d, dict) or "abuseConfidenceScore" not in d:
        errs = doc.get("errors") if isinstance(doc, dict) else None
        detail = (errs[0].get("detail") if errs and isinstance(errs[0], dict) else None) or "unexpected response shape"
        raise ProviderError("malformed", f"AbuseIPDB: {detail}")
    return {
        "abuse_confidence_score": d.get("abuseConfidenceScore"),
        "total_reports": d.get("totalReports"),
        "distinct_reporters": d.get("numDistinctUsers"),
        "last_reported_at": d.get("lastReportedAt"),
        "is_whitelisted": d.get("isWhitelisted"),
        "usage_type": d.get("usageType"),
        "isp": d.get("isp"),
        "country_code": d.get("countryCode"),
        "window_days": 90,
    }


def abuseipdb(ctx: Context, ip: str) -> Batch:
    res = ctx.http.get("https://api.abuseipdb.com/api/v2/check",
                       params={"ipAddress": ip, "maxAgeInDays": 90},
                       headers={"Key": ctx.creds["ABUSEIPDB_KEY"], "Accept": "application/json"},
                       source="abuseipdb", ok=(200,))
    info = parse_abuseipdb(res.json())
    now = utcnow()
    info["note"] = "community-reported abuse confidence; not proof of malicious activity"
    return Batch([Observation("reputation", f"abuseipdb:{ip}", "abuseipdb", Confidence.MEDIUM, now,
                              {"subject": ip, **info})],
                 [Relationship(ip, "has_reputation_observation", "abuseipdb", "abuseipdb", Confidence.MEDIUM, now,
                               "third-party report count/score")], http_status=res.status)


def parse_virustotal_domain(doc: dict) -> dict:
    attrs = (doc.get("data") or {}).get("attributes") if isinstance(doc, dict) else None
    if not isinstance(attrs, dict):
        raise ProviderError("malformed", "VirusTotal response has no data.attributes")
    stats = attrs.get("last_analysis_stats") or {}
    return {
        "malicious": int(stats.get("malicious", 0)), "suspicious": int(stats.get("suspicious", 0)),
        "harmless": int(stats.get("harmless", 0)), "undetected": int(stats.get("undetected", 0)),
        "community_reputation": attrs.get("reputation"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "categories": sorted(set((attrs.get("categories") or {}).values())),
    }


def virustotal_domain(ctx: Context, domain: str) -> Batch:
    res = ctx.http.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                       headers={"x-apikey": ctx.creds["VIRUSTOTAL_KEY"]}, source="virustotal", ok=(200,))
    info = parse_virustotal_domain(res.json())
    now = utcnow()
    info["note"] = "engine verdicts are third-party opinions and include false positives"
    return Batch([Observation("reputation", f"virustotal:{domain}", "virustotal", Confidence.MEDIUM, now,
                              {"subject": domain, **info})],
                 [Relationship(domain, "has_reputation_observation", "virustotal", "virustotal", Confidence.MEDIUM, now)],
                 http_status=res.status)
