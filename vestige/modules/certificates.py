"""Certificate Transparency analysis via crt.sh.

CT shows which certificates were *issued* for names. It does not show that a host is live,
who operates it, or that a service is exposed.
"""
from __future__ import annotations

from typing import Any

from vestige.core.context import Batch, Context
from vestige.core.http_client import ProviderError
from vestige.core.models import Confidence, Observation, Relationship, utcnow
from vestige.core.scope import in_scope, normalize_hostname

CRTSH = "https://crt.sh/"
CRTSH_MAX_BYTES = 30 * 1024 * 1024


def split_names(name_value: str) -> list[str]:
    """crt.sh joins all SANs of a certificate with newlines in `name_value`."""
    return [n for n in (name_value or "").replace("\r", "").split("\n") if n.strip()]


def parse_crtsh(entries: Any, domain: str, limit: int = 500) -> tuple[list[Observation], list[Relationship], dict]:
    if not isinstance(entries, list):
        raise ProviderError("malformed", "crt.sh returned JSON that is not a list")
    now = utcnow()
    certs: dict[int, dict] = {}
    names: dict[str, dict] = {}
    for e in entries:
        if not isinstance(e, dict) or "id" not in e:
            continue
        try:
            cid = int(e["id"])
        except (TypeError, ValueError):
            continue
        raw = split_names(str(e.get("name_value", ""))) or ([str(e["common_name"])] if e.get("common_name") else [])
        cert_names = []
        for raw_name in raw:
            wildcard = raw_name.strip().startswith("*.")
            host = normalize_hostname(raw_name, domain)
            if not host:
                continue
            cert_names.append(host)
            rec = names.setdefault(host, {"first": None, "last": None, "wildcard_only": True, "certs": set()})
            nb = str(e.get("not_before") or e.get("entry_timestamp") or "")[:19]
            na = str(e.get("not_after") or "")[:19]
            if nb and (rec["first"] is None or nb < rec["first"]):
                rec["first"] = nb
            if na and (rec["last"] is None or na > rec["last"]):
                rec["last"] = na
            if not wildcard:
                rec["wildcard_only"] = False
            rec["certs"].add(cid)
        if cert_names:
            certs[cid] = {"id": cid, "issuer": e.get("issuer_name"), "not_before": e.get("not_before"),
                          "not_after": e.get("not_after"), "serial": e.get("serial_number"),
                          "names": sorted(set(cert_names)), "logged_at": e.get("entry_timestamp")}

    obs: list[Observation] = []
    rels: list[Relationship] = []
    for host in sorted(names):
        rec = names[host]
        if host == domain:
            continue  # the apex itself is the target, not a "discovered subdomain"
        conf = Confidence.LOW if rec["wildcard_only"] else Confidence.MEDIUM
        obs.append(Observation("subdomain", host, "crt.sh", conf, now, {
            "first_seen": rec["first"], "last_seen": rec["last"], "cert_count": len(rec["certs"]),
            "from_wildcard_cert_only": rec["wildcard_only"],
        }))
        rels.append(Relationship(domain, "has_subdomain", host, "crt.sh", conf, now,
                                 "name appears in a CT-logged certificate; liveness not tested"))
    newest = sorted(certs.values(), key=lambda c: (str(c["not_before"]), c["id"]), reverse=True)[:limit]
    for c in newest:
        obs.append(Observation("certificate", f"crt.sh:{c['id']}", "crt.sh", Confidence.HIGH, now, c))
        for n in c["names"][:25]:
            rels.append(Relationship(n, "covered_by_certificate", f"crt.sh:{c['id']}", "crt.sh", Confidence.HIGH, now,
                                     "SAN listed in the certificate; says nothing about operator"))
    stats = {"entries": len(entries), "certificates": len(certs), "names": len(names)}
    return obs, rels, stats


def crtsh_lookup(ctx: Context, domain: str) -> Batch:
    res = ctx.http.get(CRTSH, params={"q": f"%.{domain}", "output": "json"}, source="crt.sh",
                       cacheable=True, ttl=6 * 3600, max_bytes=CRTSH_MAX_BYTES, timeout=max(ctx.http.timeout, 25.0))
    if res.truncated:
        raise ProviderError("malformed", "crt.sh response exceeded the size cap; result not used (try a narrower target)")
    text = res.text.strip()
    if not text or text == "null":
        return Batch([], detail="no certificates logged")
    obs, rels, stats = parse_crtsh(res.json(), domain, limit=ctx.limit)
    return Batch(obs, rels, detail=f"{stats['certificates']} certs, {stats['names']} names", http_status=res.status)


def in_scope_names(obs: list[Observation], domain: str) -> list[str]:
    return sorted({o.value for o in obs if o.kind == "subdomain" and in_scope(o.value, domain)})
