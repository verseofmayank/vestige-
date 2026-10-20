"""DNS investigation: record lookups, wildcard detection, DNSSEC observations, reverse DNS,
DNS-provider inference.

All lookups go through a `Resolver` object so tests and the offline demo can inject answers.
"""
from __future__ import annotations

import ipaddress
import json
import secrets
from functools import lru_cache
from importlib import resources
from typing import Protocol

from vestige.core.context import Batch, Context
from vestige.core.models import Confidence, Observation, Relationship, utcnow

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]


class DnsError(Exception):
    """kind: nxdomain | timeout | servfail | error"""

    def __init__(self, kind: str, message: str = ""):
        super().__init__(message or kind)
        self.kind = kind


def to_provider_error(exc: "DnsError"):
    """Map a resolver failure to a ProviderError so run_source reports an honest FAILED/SKIPPED."""
    from vestige.core.http_client import ProviderError
    if exc.kind == "offline":
        return ProviderError("offline", "offline mode: DNS disabled")
    return ProviderError("network", f"DNS {exc.kind}: {exc}")


class Resolver(Protocol):
    def query(self, name: str, rtype: str) -> list[str]:
        """Return rdata as text. [] for NOERROR/NODATA. Raise DnsError otherwise."""


class DnspythonResolver:
    def __init__(self, timeout: float = 5.0, nameservers: list[str] | None = None):
        import dns.resolver
        self._r = dns.resolver.Resolver(configure=True)
        self._r.lifetime = timeout
        self._r.timeout = min(timeout, 3.0)
        if nameservers:
            self._r.nameservers = nameservers

    def query(self, name: str, rtype: str) -> list[str]:
        import dns.exception
        import dns.resolver
        try:
            ans = self._r.resolve(name, rtype, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN as exc:
            raise DnsError("nxdomain", name) from exc
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NoNameservers as exc:
            raise DnsError("servfail", f"{name} {rtype}: all nameservers failed") from exc
        except dns.exception.Timeout as exc:
            raise DnsError("timeout", f"{name} {rtype}: timed out") from exc
        except dns.exception.DNSException as exc:
            raise DnsError("error", f"{name} {rtype}: {type(exc).__name__}") from exc
        if ans.rrset is None:
            return []
        out = []
        for r in ans:
            if rtype == "TXT":
                out.append(b"".join(r.strings).decode("utf-8", "replace"))
            else:
                out.append(r.to_text())
        return sorted(out)


class OfflineResolver:
    """Used with --offline: refuses every lookup so no DNS traffic leaves the machine."""

    def query(self, name: str, rtype: str) -> list[str]:
        raise DnsError("offline", "offline mode: DNS disabled")


class FakeResolver:
    """Deterministic resolver for tests / offline demo.

    records: {(name, TYPE): [rdata, ...]}; names in `nxdomain` raise NXDOMAIN;
    `wildcard` maps a zone to answers returned for any otherwise-unknown label (A/AAAA).
    """

    def __init__(self, records=None, nxdomain=(), errors=None, wildcard=None):
        self.records = {(k[0].lower(), k[1].upper()): v for k, v in (records or {}).items()}
        self.nxdomain = {n.lower() for n in nxdomain}
        self.errors = {(k[0].lower(), k[1].upper()): v for k, v in (errors or {}).items()}
        self.wildcard = {k.lower(): v for k, v in (wildcard or {}).items()}
        self.calls: list[tuple[str, str]] = []

    def query(self, name: str, rtype: str) -> list[str]:
        name, rtype = name.lower().rstrip("."), rtype.upper()
        self.calls.append((name, rtype))
        if (name, rtype) in self.errors:
            raise DnsError(self.errors[(name, rtype)], name)
        if (name, rtype) in self.records:
            return list(self.records[(name, rtype)])
        if name in self.nxdomain:
            raise DnsError("nxdomain", name)
        known = any(n == name for (n, _t) in self.records)
        if not known:
            for zone, answers in self.wildcard.items():
                if name.endswith("." + zone):
                    return list(answers.get(rtype, []))
            raise DnsError("nxdomain", name)
        return []


@lru_cache(maxsize=1)
def _providers() -> dict[str, str]:
    with resources.files("vestige.data").joinpath("dns_providers.json").open("r", encoding="utf-8") as f:
        return json.load(f)


def infer_dns_provider(nameservers: list[str]) -> str | None:
    """Best-effort DNS provider from NS hostnames. Heuristic, labelled low/medium confidence."""
    found = set()
    for ns in nameservers:
        host = ns.lower().rstrip(".")
        for suffix, provider in _providers().items():
            if host == suffix or host.endswith("." + suffix) or suffix in host:
                found.add(provider)
    return ", ".join(sorted(found)) if found else None


def _clean_target(text: str) -> str:
    return text.strip().rstrip(".").lower()


def parse_mx(rdata: str) -> tuple[int, str] | None:
    parts = rdata.split()
    if len(parts) != 2 or not parts[0].isdigit():
        return None
    return int(parts[0]), _clean_target(parts[1])


def parse_soa(rdata: str) -> dict | None:
    p = rdata.split()
    if len(p) != 7:
        return None
    try:
        return {"mname": _clean_target(p[0]), "rname": _clean_target(p[1]), "serial": int(p[2]),
                "refresh": int(p[3]), "retry": int(p[4]), "expire": int(p[5]), "minimum": int(p[6])}
    except ValueError:
        return None


def detect_wildcard(resolver: Resolver, domain: str) -> dict:
    """Query a random, non-existent label. Answers mean the zone has a wildcard record."""
    label = "vestige-" + secrets.token_hex(6)
    ips: set[str] = set()
    for t in ("A", "AAAA"):
        try:
            ips.update(resolver.query(f"{label}.{domain}", t))
        except DnsError:
            pass
    return {"wildcard": bool(ips), "ips": sorted(ips), "probe": f"{label}.{domain}"}


def lookup_dns(ctx: Context, domain: str) -> Batch:
    """Apex records, wildcard check, DNSSEC presence, reverse DNS of resolved addresses."""
    res: Resolver = ctx.resolver  # type: ignore[assignment]
    obs: list[Observation] = []
    rels: list[Relationship] = []
    notes: list[str] = []
    now = utcnow()
    src = "dns"
    ips: set[str] = set()
    ns_hosts: list[str] = []
    all_failed = True

    for rtype in RECORD_TYPES:
        try:
            answers = res.query(domain, rtype)
            all_failed = False
        except DnsError as exc:
            if exc.kind == "offline":
                from vestige.core.http_client import ProviderError
                raise ProviderError("offline", "offline mode: DNS disabled") from exc
            if exc.kind == "nxdomain":
                notes.append(f"{domain} does not exist (NXDOMAIN)")
                obs.append(Observation("dns_status", "NXDOMAIN", src, Confidence.HIGH, now))
                all_failed = False
                break
            notes.append(f"{rtype}: {exc.kind}")
            continue
        for a in answers:
            data = {"name": domain, "type": rtype, "value": a}
            if rtype == "MX":
                mx = parse_mx(a)
                if not mx:
                    continue
                data.update(priority=mx[0], host=mx[1])
                rels.append(Relationship(domain, "uses_mail_exchanger", mx[1], src, Confidence.HIGH, now))
            elif rtype == "NS":
                host = _clean_target(a)
                ns_hosts.append(host)
                data["host"] = host
                rels.append(Relationship(domain, "has_nameserver", host, src, Confidence.HIGH, now))
            elif rtype in ("A", "AAAA"):
                try:
                    ips.add(str(ipaddress.ip_address(a)))
                except ValueError:
                    continue
                rels.append(Relationship(domain, "resolves_to", a, src, Confidence.HIGH, now))
            elif rtype == "SOA":
                soa = parse_soa(a)
                if soa:
                    data.update(soa)
            obs.append(Observation("dns_record", f"{domain} {rtype} {a}", src, Confidence.HIGH, now, data))

    if all_failed:  # every query failed: make no claims about wildcard/DNSSEC, report the failure
        from vestige.core.http_client import ProviderError
        raise ProviderError("network", "no DNS record type could be retrieved: " + "; ".join(notes))

    if ns_hosts:
        prov = infer_dns_provider(ns_hosts)
        if prov:
            obs.append(Observation("dns_provider", prov, "dns (inferred from NS names)",
                                   Confidence.LOW, now, {"nameservers": sorted(set(ns_hosts))}))

    if not any(o.kind == "dns_status" for o in obs):
        wc = detect_wildcard(res, domain)
        obs.append(Observation("wildcard_dns", "present" if wc["wildcard"] else "absent", src,
                               Confidence.MEDIUM, now, wc))
        # DNSSEC: DNSKEY in the zone + DS in the parent. Presence only: no signature validation.
        try:
            dnskey = res.query(domain, "DNSKEY")
        except DnsError:
            dnskey = []
        try:
            ds = res.query(domain, "DS")
        except DnsError:
            ds = []
        if dnskey and ds:
            state = "signed"
        elif dnskey and not ds:
            state = "dnskey-without-ds"
        elif ds and not dnskey:
            state = "ds-without-dnskey"
        else:
            state = "unsigned"
        obs.append(Observation("dnssec", state, src, Confidence.MEDIUM, now,
                               {"dnskey_count": len(dnskey), "ds_count": len(ds),
                                "validated": False,
                                "note": "presence of DNSKEY/DS only; signatures were not validated"}))

        for ip in sorted(ips):
            try:
                rev = ipaddress.ip_address(ip).reverse_pointer
                for ptr in res.query(rev, "PTR"):
                    obs.append(Observation("reverse_dns", f"{ip} {_clean_target(ptr)}", src,
                                           Confidence.MEDIUM, now, {"ip": ip, "ptr": _clean_target(ptr)}))
            except DnsError:
                continue

    return Batch(obs, rels, detail="; ".join(notes))
