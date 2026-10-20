"""Email address validation and mail-infrastructure security intelligence.

Public metadata only: MX, SPF, DMARC, MTA-STS, TLS-RPT, DKIM (explicit selector), disposable
domain lists. No mailbox probing, no breach/credential lookups.
"""
from __future__ import annotations

import ipaddress
import re
from importlib import resources

from vestige.core.context import Batch, Context
from vestige.core.models import Confidence, Observation, Relationship, utcnow
from vestige.core.scope import ValidationError, normalize_domain
from vestige.modules.dns import DnsError, Resolver, parse_mx, to_provider_error

_LOCAL_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*$")
DISPOSABLE_URL = ("https://raw.githubusercontent.com/disposable-email-domains/"
                  "disposable-email-domains/main/disposable_email_blocklist.conf")


def validate_email(addr: str) -> tuple[str, str]:
    """Return (local, ascii_domain). Quoted local parts and internationalised local parts
    are rejected on purpose (rare; and unsafe to pass around). Raises ValidationError."""
    if not addr or not addr.strip():
        raise ValidationError("email address is empty")
    a = addr.strip()
    if a.count("@") != 1:
        raise ValidationError("email address must contain exactly one '@'")
    local, domain = a.split("@")
    if not local or len(local) > 64:
        raise ValidationError("local part must be 1-64 characters")
    if not _LOCAL_RE.match(local):
        raise ValidationError("local part has invalid characters or dot placement (quoted/internationalised local parts are not supported)")
    return local, normalize_domain(domain)


def mask_email(local: str, domain: str) -> str:
    """Privacy: reports keep only the first character of the local part."""
    return f"{local[0]}{'*' * min(max(len(local) - 1, 2), 6)}@{domain}"


# --- SPF --------------------------------------------------------------------------------

_LOOKUP_MECHS = {"include", "a", "mx", "ptr", "exists"}


def parse_spf(record: str) -> dict:
    """Parse an SPF record (RFC 7208) into mechanisms and a conservative interpretation."""
    terms = record.strip().split()
    if not terms or terms[0].lower() != "v=spf1":
        raise ValueError("not an SPF record")
    mechs, includes, ip_ranges = [], [], []
    redirect = all_q = None
    lookups = 0
    flags: list[str] = []
    for t in terms[1:]:
        low = t.lower()
        if low.startswith("redirect="):
            redirect = low.split("=", 1)[1]
            lookups += 1
            continue
        if low.startswith("exp="):
            continue
        q = "+"
        if low[0] in "+-~?":
            q, low = low[0], low[1:]
        name, _, arg = low.partition(":")
        name = name.split("/")[0]
        mechs.append(f"{q}{low}")
        if name == "all":
            all_q = q
        elif name in _LOOKUP_MECHS:
            lookups += 1
            if name == "include":
                includes.append(arg)
            if name == "ptr":
                flags.append("uses deprecated 'ptr' mechanism")
        elif name in ("ip4", "ip6"):
            ip_ranges.append(arg)
            try:
                net = ipaddress.ip_network(arg, strict=False)
                if net.prefixlen == 0:
                    flags.append(f"authorises the entire address space ({arg})")
                elif net.num_addresses >= 2 ** 16 and net.version == 4:
                    flags.append(f"very large authorised range ({arg})")
            except ValueError:
                flags.append(f"malformed range '{arg}'")
    if all_q == "+":
        flags.append("'+all' allows any sender")
    if lookups > 10:
        flags.append(f"{lookups} DNS-lookup mechanisms at top level (limit is 10 including nested includes)")
    policy = {"-": "hard fail (reject unauthorised senders)", "~": "soft fail (unauthorised senders are marked)",
              "?": "neutral (no assertion)", "+": "pass all (no protection)", None: "no 'all' mechanism"}[all_q]
    if redirect and all_q is None:
        policy = f"delegated by redirect to {redirect}"
    return {"mechanisms": mechs, "includes": includes, "ip_ranges": ip_ranges, "redirect": redirect,
            "all": all_q, "policy": policy, "dns_lookup_terms": lookups, "flags": flags}


# --- DMARC ------------------------------------------------------------------------------

def parse_dmarc(record: str) -> dict:
    parts = [p.strip() for p in record.strip().split(";") if p.strip()]
    tags = {}
    for i, p in enumerate(parts):
        k, _, v = p.partition("=")
        tags[k.strip().lower()] = v.strip()
        if i == 0 and (k.strip().lower() != "v" or v.strip().upper() != "DMARC1"):
            raise ValueError("DMARC record must start with v=DMARC1")
    if "p" not in tags:
        raise ValueError("DMARC record has no p= tag")
    p = tags["p"].lower()
    pct = int(tags["pct"]) if tags.get("pct", "").isdigit() else 100
    interp = {"none": "monitoring only: no enforcement", "quarantine": "unauthenticated mail should be quarantined",
              "reject": "unauthenticated mail should be rejected"}.get(p, f"unknown policy '{p}'")
    return {"policy": p, "subdomain_policy": tags.get("sp", "").lower() or None, "pct": pct,
            "rua": [x.strip() for x in tags.get("rua", "").split(",") if x.strip()],
            "ruf": [x.strip() for x in tags.get("ruf", "").split(",") if x.strip()],
            "adkim": tags.get("adkim", "r"), "aspf": tags.get("aspf", "r"), "interpretation": interp,
            "tags": tags}


def parse_kv_record(record: str) -> dict:
    out = {}
    for p in record.split(";"):
        k, _, v = p.strip().partition("=")
        if k:
            out[k.strip().lower()] = v.strip()
    return out


MAIL_PROVIDERS = {
    "google.com": "Google Workspace / Gmail", "googlemail.com": "Google Workspace / Gmail",
    "outlook.com": "Microsoft 365 / Exchange Online", "protection.outlook.com": "Microsoft 365 / Exchange Online",
    "pphosted.com": "Proofpoint", "mimecast.com": "Mimecast", "zoho.com": "Zoho Mail", "zoho.in": "Zoho Mail",
    "protonmail.ch": "Proton Mail", "mailgun.org": "Mailgun", "secureserver.net": "GoDaddy",
    "messagelabs.com": "Broadcom/Symantec Email Security", "yahoodns.net": "Yahoo", "icloud.com": "Apple iCloud Mail",
    "fastmail.com": "Fastmail", "messagingengine.com": "Fastmail", "barracudanetworks.com": "Barracuda",
}


def infer_mail_provider(mx_hosts: list[str]) -> str | None:
    found = {p for h in mx_hosts for s, p in MAIL_PROVIDERS.items() if h == s or h.endswith("." + s)}
    return ", ".join(sorted(found)) or None


def _txt(res: Resolver, name: str) -> list[str]:
    try:
        return res.query(name, "TXT")
    except DnsError as exc:
        if exc.kind == "nxdomain":
            return []
        raise to_provider_error(exc) from exc


def load_disposable(ctx: Context) -> tuple[set[str], str]:
    """Return (domains, provenance). Prefers the maintained public list; falls back to the
    small bundled seed list when the network or provider is unavailable."""
    seed = resources.files("vestige.data").joinpath("disposable_seed.txt").read_text(encoding="utf-8")
    seed_set = {l.strip().lower() for l in seed.splitlines() if l.strip() and not l.startswith("#")}
    try:
        res = ctx.http.get(DISPOSABLE_URL, source="disposable-list", cacheable=True, ttl=7 * 86400,
                           max_bytes=3 * 1024 * 1024)
        live = {l.strip().lower() for l in res.text.splitlines() if l.strip() and not l.startswith("#")}
        if len(live) > 100:
            return live | seed_set, "disposable-email-domains (GitHub, maintained list)"
    except Exception:  # noqa: BLE001 - fallback is reported in provenance
        pass
    return seed_set, "bundled seed list (small; maintained list unreachable)"


def analyze_mail(ctx: Context, domain: str, *, dkim_selectors: list[str] | None = None,
                 check_disposable: bool = True) -> None:
    """Run all mail-security checks for a domain. Each check is its own SourceResult."""
    res: Resolver = ctx.resolver  # type: ignore[assignment]
    now = utcnow()

    def mx_check() -> Batch:
        try:
            raw = res.query(domain, "MX")
        except DnsError as exc:
            if exc.kind == "nxdomain":
                return Batch([], detail=f"{domain} does not exist")
            raise to_provider_error(exc) from exc
        obs, rels, hosts = [], [], []
        null_mx = False
        for r in raw:
            mx = parse_mx(r)
            if not mx:
                continue
            prio, host = mx
            if host == "":
                null_mx = True
                continue
            hosts.append(host)
            obs.append(Observation("mx", host, "dns", Confidence.HIGH, now, {"priority": prio, "domain": domain}))
            rels.append(Relationship(domain, "uses_mail_exchanger", host, "dns", Confidence.HIGH, now))
            for t in ("A", "AAAA"):
                try:
                    for ip in res.query(host, t):
                        rels.append(Relationship(host, "resolves_to", ip, "dns", Confidence.HIGH, now))
                except DnsError:
                    continue
        if null_mx:
            obs.append(Observation("mx_null", domain, "dns", Confidence.HIGH, now,
                                   {"note": "RFC 7505 null MX: domain declares it accepts no mail"}))
        prov = infer_mail_provider(hosts)
        if prov:
            obs.append(Observation("mail_provider", prov, "dns (inferred from MX names)", Confidence.LOW, now,
                                   {"mx": sorted(hosts)}))
        if not raw:
            # RFC 5321 s5.1: with no MX, an A/AAAA record is used as an implicit MX
            obs.append(Observation("mx_absent", domain, "dns", Confidence.HIGH, now, {}))
        return Batch(obs, rels, detail=("no MX records" if not raw else ""))

    def spf_check() -> Batch:
        txts = [t for t in _txt(res, domain) if t.lower().startswith("v=spf1")]
        if not txts:
            return Batch([Observation("spf", "missing", "dns", Confidence.HIGH, now, {"present": False})])
        if len(txts) > 1:
            return Batch([Observation("spf", "multiple-records", "dns", Confidence.HIGH, now,
                                      {"present": True, "records": txts, "valid": False,
                                       "flags": ["multiple SPF records: receivers return permerror (RFC 7208 s4.5)"]})])
        try:
            p = parse_spf(txts[0])
        except ValueError as exc:
            return Batch([Observation("spf", "unparseable", "dns", Confidence.MEDIUM, now,
                                      {"present": True, "record": txts[0], "valid": False, "error": str(exc)})])
        return Batch([Observation("spf", txts[0], "dns", Confidence.HIGH, now, {"present": True, "valid": True, **p})])

    def dmarc_check() -> Batch:
        labels = domain.split(".")
        for i in range(0, max(1, len(labels) - 1)):
            cand = ".".join(labels[i:])
            recs = [t for t in _txt(res, f"_dmarc.{cand}") if t.lower().replace(" ", "").startswith("v=dmarc1")]
            if recs:
                try:
                    p = parse_dmarc(recs[0])
                except ValueError as exc:
                    return Batch([Observation("dmarc", "unparseable", "dns", Confidence.MEDIUM, now,
                                              {"present": True, "record": recs[0], "valid": False, "error": str(exc)})])
                return Batch([Observation("dmarc", recs[0], "dns", Confidence.HIGH, now,
                                          {"present": True, "valid": True, "found_at": f"_dmarc.{cand}",
                                           "inherited": cand != domain, **p})])
        return Batch([Observation("dmarc", "missing", "dns", Confidence.HIGH, now, {"present": False})])

    def mtasts_check() -> Batch:
        recs = [t for t in _txt(res, f"_mta-sts.{domain}") if t.lower().startswith("v=stsv1")]
        if not recs:
            return Batch([Observation("mta_sts", "missing", "dns", Confidence.HIGH, now, {"present": False})])
        data = {"present": True, "record": recs[0], **parse_kv_record(recs[0]),
                "policy_fetched": False,
                "note": "policy file not fetched (passive mode)"}
        if ctx.scope and ctx.scope.http_allowed:
            url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
            try:
                ctx.scope.check_url(url)
                r = ctx.http.get(url, source="mta-sts-policy", ok=(200, 404), allow_redirects=False,
                                 max_bytes=64 * 1024)
                data["policy_fetched"] = r.status == 200
                data["note"] = "policy fetched" if r.status == 200 else f"policy URL returned HTTP {r.status}"
                if r.status == 200:
                    data["policy"] = dict(l.split(":", 1) for l in r.text.splitlines() if ":" in l)
                    data["policy"] = {k.strip(): v.strip() for k, v in data["policy"].items()}
            except Exception as exc:  # noqa: BLE001
                data["note"] = f"policy fetch failed: {type(exc).__name__}"
        return Batch([Observation("mta_sts", recs[0], "dns", Confidence.HIGH, now, data)])

    def tlsrpt_check() -> Batch:
        recs = [t for t in _txt(res, f"_smtp._tls.{domain}") if t.lower().startswith("v=tlsrptv1")]
        if not recs:
            return Batch([Observation("tls_rpt", "missing", "dns", Confidence.HIGH, now, {"present": False})])
        return Batch([Observation("tls_rpt", recs[0], "dns", Confidence.HIGH, now,
                                  {"present": True, **parse_kv_record(recs[0])})])

    ctx.run_source("email", "mx", mx_check)
    ctx.run_source("email", "spf", spf_check)
    ctx.run_source("email", "dmarc", dmarc_check)
    ctx.run_source("email", "mta-sts", mtasts_check)
    ctx.run_source("email", "tls-rpt", tlsrpt_check)

    if dkim_selectors:
        for sel in dkim_selectors:
            def dkim_check(sel=sel) -> Batch:
                if not re.match(r"^[A-Za-z0-9_-]{1,63}(\.[A-Za-z0-9_-]{1,63})*$", sel):
                    raise ValidationError(f"invalid DKIM selector '{sel}'")
                recs = [t for t in _txt(res, f"{sel}._domainkey.{domain}") if "p=" in t.lower() or "v=dkim1" in t.lower()]
                if not recs:
                    return Batch([Observation("dkim", f"{sel}: not found", "dns", Confidence.MEDIUM, now,
                                              {"selector": sel, "present": False,
                                               "note": "selector not found; this does not prove DKIM is unused (other selectors may exist)"})])
                kv = parse_kv_record(recs[0])
                revoked = kv.get("p", "x") == ""
                return Batch([Observation("dkim", f"{sel}: {'revoked' if revoked else 'published'}", "dns",
                                          Confidence.HIGH, now,
                                          {"selector": sel, "present": True, "revoked": revoked,
                                           "key_type": kv.get("k", "rsa"), "testing": "y" in kv.get("t", "")})])
            ctx.run_source("email", f"dkim:{sel}", dkim_check)
    else:
        ctx.inv.limitations.append("DKIM not checked: there is no universal DKIM lookup; supply selectors with --dkim-selector.")

    if check_disposable:
        def disposable_check() -> Batch:
            domains, prov = load_disposable(ctx)
            hit = domain in domains
            return Batch([Observation("disposable_domain", "yes" if hit else "no", "disposable-list", Confidence.MEDIUM, now,
                                      {"disposable": hit, "list_size": len(domains), "list_provenance": prov})],
                         detail=prov)
        ctx.run_source("email", "disposable-list", disposable_check)
