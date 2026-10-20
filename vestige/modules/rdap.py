"""Domain registration data via RDAP (RFC 7480-7484, bootstrap RFC 9224), WHOIS fallback.

Only registrar, lifecycle dates, status, nameservers and DNSSEC flag are extracted. Registrant /
contact entities are intentionally NOT collected (privacy; most are redacted anyway).
"""
from __future__ import annotations

import re
import socket
from typing import Callable

from vestige.core.context import Batch, Context
from vestige.core.http_client import ProviderError
from vestige.core.models import Confidence, Observation, Relationship, utcnow

IANA_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"


class NoRdapService(ProviderError):
    def __init__(self, message: str):
        super().__init__("unsupported", message)


def find_rdap_base(bootstrap: dict, tld: str) -> str | None:
    """Pick the RDAP base URL for a TLD from an IANA bootstrap document (prefers https)."""
    services = bootstrap.get("services") if isinstance(bootstrap, dict) else None
    if not isinstance(services, list):
        raise ProviderError("malformed", "RDAP bootstrap document has no 'services' list")
    for entry in services:
        try:
            tlds, urls = entry[0], entry[1]
        except (IndexError, TypeError):
            continue
        if tld.lower() in [t.lower() for t in tlds] and urls:
            https = [u for u in urls if u.startswith("https://")]
            return (https or urls)[0].rstrip("/")
    return None


def _vcard_fn(entity: dict) -> str | None:
    try:
        for item in entity["vcardArray"][1]:
            if item[0] == "fn":
                return str(item[3])
    except (KeyError, IndexError, TypeError):
        pass
    return None


def parse_rdap_domain(doc: dict) -> dict:
    """Extract the minimum registration facts from an RDAP domain object."""
    if not isinstance(doc, dict) or doc.get("objectClassName") not in (None, "domain"):
        raise ProviderError("malformed", "RDAP response is not a domain object")
    events = {}
    for ev in doc.get("events", []) or []:
        action, date = ev.get("eventAction"), ev.get("eventDate")
        if action and date and action != "last update of RDAP database":
            events[action] = date
    registrar = registrar_id = None
    for ent in doc.get("entities", []) or []:
        if "registrar" in (ent.get("roles") or []):
            registrar = _vcard_fn(ent)
            for pid in ent.get("publicIds", []) or []:
                if "registrar id" in str(pid.get("type", "")).lower():
                    registrar_id = pid.get("identifier")
    ns = sorted({(n.get("ldhName") or "").lower().rstrip(".") for n in doc.get("nameservers", []) or []} - {""})
    return {
        "domain": (doc.get("ldhName") or "").lower(),
        "registrar": registrar,
        "registrar_iana_id": registrar_id,
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "status": sorted(doc.get("status", []) or []),
        "nameservers": ns,
        "dnssec_delegation_signed": (doc.get("secureDNS") or {}).get("delegationSigned"),
    }


def candidates(domain: str) -> list[str]:
    """domain, then its parents down to two labels (no public-suffix list is bundled)."""
    labels = domain.split(".")
    return [".".join(labels[i:]) for i in range(0, max(1, len(labels) - 1))]


def rdap_lookup(ctx: Context, domain: str) -> Batch:
    boot = ctx.http.get(IANA_BOOTSTRAP, source="iana-rdap-bootstrap", cacheable=True, ttl=86400).json()
    tld = domain.rsplit(".", 1)[-1]
    base = find_rdap_base(boot, tld)
    if not base:
        raise NoRdapService(f"no RDAP service registered for .{tld}")
    last_404 = False
    for cand in candidates(domain):
        res = ctx.http.get(f"{base}/domain/{cand}", source="rdap", ok=(200, 404), cacheable=True, ttl=3600,
                           headers={"Accept": "application/rdap+json, application/json"})
        if res.status == 404:
            last_404 = True
            continue
        info = parse_rdap_domain(res.json())
        info.update(via="rdap", rdap_server=base, registered_domain=cand)
        now = utcnow()
        obs = [Observation("registration", cand, f"rdap ({base.split('//')[-1]})", Confidence.HIGH, now, info)]
        rels = [Relationship(cand, "has_nameserver", n, "rdap", Confidence.HIGH, now) for n in info["nameservers"]]
        detail = "" if cand == domain else f"registered domain is {cand}"
        return Batch(obs, rels, detail=detail, http_status=200)
    if last_404:
        return Batch([], [], detail="RDAP server has no record (domain not registered or not served)", http_status=404)
    return Batch([])


# --- WHOIS fallback ---------------------------------------------------------------------

def _whois_raw(server: str, query: str, timeout: float) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall((query + "\r\n").encode("ascii"))
        chunks = []
        while len(b"".join(chunks)) < 200_000:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", "replace")


_KV = re.compile(r"^\s*([A-Za-z][A-Za-z /-]+?):\s*(.+?)\s*$")


def parse_whois(text: str) -> dict:
    """Parse the common key: value WHOIS layout. Registrant/contact fields are ignored."""
    want = {
        "registrar": "registrar", "creation date": "registered", "created": "registered",
        "registry expiry date": "expires", "registrar registration expiration date": "expires",
        "expiry date": "expires", "updated date": "last_changed", "last updated": "last_changed",
        "domain status": "status", "name server": "nameservers", "nserver": "nameservers",
    }
    out: dict = {"status": [], "nameservers": []}
    for line in text.splitlines():
        m = _KV.match(line)
        if not m:
            continue
        key, val = m.group(1).lower(), m.group(2)
        field = want.get(key)
        if field in ("status",):
            out["status"].append(val.split()[0])
        elif field == "nameservers":
            out["nameservers"].append(val.split()[0].lower().rstrip("."))
        elif field and field not in out:
            out[field] = val
    out["status"] = sorted(set(out["status"]))
    out["nameservers"] = sorted(set(out["nameservers"]))
    return out


def whois_lookup(ctx: Context, domain: str, *, timeout: float = 8.0,
                 raw_fn: Callable[[str, str, float], str] = _whois_raw) -> Batch:
    if ctx.http.offline:
        raise ProviderError("offline", "WHOIS needs network access")
    tld = domain.rsplit(".", 1)[-1]
    try:
        iana = raw_fn("whois.iana.org", tld, timeout)
        m = re.search(r"^\s*(?:refer|whois):\s*(\S+)", iana, re.I | re.M)
        if not m:
            raise ProviderError("http", f"IANA lists no WHOIS server for .{tld}")
        text = raw_fn(m.group(1), domain, timeout)
    except OSError as exc:
        raise ProviderError("network", f"WHOIS connection failed: {type(exc).__name__}") from exc
    info = parse_whois(text)
    if not (info.get("registrar") or info.get("registered") or info["nameservers"]):
        return Batch([], detail="WHOIS returned no parseable registration data")
    info.update(domain=domain, via="whois", whois_server=m.group(1))
    now = utcnow()
    return Batch([Observation("registration", domain, f"whois ({m.group(1)})", Confidence.MEDIUM, now, info)],
                 [Relationship(domain, "has_nameserver", n, "whois", Confidence.MEDIUM, now) for n in info["nameservers"]])
