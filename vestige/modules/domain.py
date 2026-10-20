"""Domain investigation orchestrator used by both `domain` and `recon`.

Each module runs as an independent source: one failing provider never aborts the run.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from vestige.core import rules
from vestige.core.context import Batch, Context
from vestige.core.correlator import correlate
from vestige.core.models import utcnow
from vestige.core.scope import Scope, is_public_ip
from vestige.modules import archive, certificates, ip as ipmod, reputation, subdomains, web
from vestige.modules.dns import lookup_dns
from vestige.modules.email import analyze_mail
from vestige.modules.rdap import rdap_lookup, whois_lookup

ALL_MODULES = ["dns", "rdap", "certs", "subdomains", "email", "ips", "archive", "reputation", "web"]
DOMAIN_COMMAND_MODULES = ["dns", "rdap", "certs", "subdomains", "ips", "web"]
MAX_ENRICH_IPS = 25
MAX_DEEP_IPS = 5


def _per_ip(ips: list[str], fn) -> Batch:
    """Run an IP lookup for each address; aggregate into one Batch (partial on per-IP failure)."""
    from vestige.core.http_client import ProviderError
    out = Batch()
    failures = []
    for ip in ips:
        try:
            b = fn(ip)
        except ProviderError as exc:
            failures.append(f"{ip}: {exc.kind}")
            if exc.kind in ("ratelimit", "quota", "auth", "offline"):
                if not out.observations:
                    raise
                break
            continue
        out.observations += b.observations
        out.relationships += b.relationships
    if failures:
        out.partial = "; ".join(failures[:5])
    return out


def investigate_domain(ctx: Context, domain: str, *, modules: list[str] | None = None,
                       dkim_selectors: list[str] | None = None, resolve: bool = True,
                       now: datetime | None = None) -> None:
    mods = set(modules or ALL_MODULES)
    inv = ctx.inv
    inv.scope = (ctx.scope or Scope(domain)).to_dict()
    pool = ThreadPoolExecutor(max_workers=max(2, min(ctx.max_workers, 6)))
    futures = []

    def submit(*a, **kw):
        futures.append(pool.submit(ctx.run_source, *a, **kw))

    # -- DNS first (needed by later steps) --------------------------------------------------
    if "dns" in mods:
        ctx.run_source("dns", "dns-records", lambda: lookup_dns(ctx, domain))

    # -- independent passive sources, in parallel ------------------------------------------
    if "rdap" in mods:
        def reg():
            b = ctx.run_source("registration", "rdap", lambda: rdap_lookup(ctx, domain))
            if b is None:
                ctx.run_source("registration", "whois (fallback)", lambda: whois_lookup(ctx, domain))
        futures.append(pool.submit(reg))
    if "certs" in mods:
        submit("certificates", "crt.sh", lambda: certificates.crtsh_lookup(ctx, domain))
    if "subdomains" in mods:
        futures.append(pool.submit(subdomains.discover_passive, ctx, domain))
    if "archive" in mods:
        submit("archive", "wayback", lambda: archive.wayback(ctx, domain))
        submit("archive", "urlscan (read-only search)", lambda: archive.urlscan(ctx, domain))
    if "reputation" in mods:
        submit("reputation", "virustotal (domain)", lambda: reputation.virustotal_domain(ctx, domain), requires="VIRUSTOTAL_KEY")
    if "email" in mods:
        futures.append(pool.submit(analyze_mail, ctx, domain, dkim_selectors=dkim_selectors))
    for f in futures:
        f.result()
    pool.shutdown()

    # -- correlate, then test discovered names with DNS -------------------------------------
    correlate(inv)
    if "subdomains" in mods or "certs" in mods or "archive" in mods:
        wc = next((set(o.data.get("ips", [])) for o in inv.obs("wildcard_dns") if o.value == "present"), set())
        if resolve and ctx.resolver is not None and inv.obs("subdomain"):
            def _resolve():
                subdomains.resolve_subdomains(ctx, domain, wildcard_ips=wc)
                tested = [o for o in inv.obs("subdomain") if o.data.get("dns_state") in ("resolved", "wildcard_only", "no_dns_answer")]
                return Batch(count=len(tested), detail=f"{len(tested)} of {len(inv.obs('subdomain'))} discovered names tested")
            ctx.run_source("subdomains", "dns-verification", _resolve)
        else:
            for o in inv.obs("subdomain"):
                o.data.setdefault("dns_state", "unverified")
                o.data.setdefault("dns_note", "DNS verification disabled")
        correlate(inv)

    # -- public infrastructure metadata ------------------------------------------------------
    if "ips" in mods:
        all_ips = sorted({r.object for r in inv.relationships if r.predicate == "resolves_to" and is_public_ip(r.object)})
        apex_ips = sorted({r.object for r in inv.relationships
                           if r.predicate == "resolves_to" and r.subject == domain and is_public_ip(r.object)})[:MAX_DEEP_IPS]
        if all_ips:
            ctx.run_source("ips", "asn (team-cymru)", lambda: _per_ip(all_ips[:MAX_ENRICH_IPS], lambda i: ipmod.asn_lookup(ctx, i)))
            ctx.run_source("ips", "geolocation (ipapi.co)", lambda: _per_ip(apex_ips, lambda i: ipmod.geolocation(ctx, i)))
            ctx.run_source("ips", "exposure (shodan-internetdb)", lambda: _per_ip(apex_ips, lambda i: ipmod.internetdb(ctx, i)))
            if "reputation" in mods:
                ctx.run_source("reputation", "abuseipdb (apex IPs)", lambda: _per_ip(apex_ips, lambda i: reputation.abuseipdb(ctx, i)),
                               requires="ABUSEIPDB_KEY")
            if len(all_ips) > MAX_ENRICH_IPS:
                inv.limitations.append(f"ASN enrichment limited to the first {MAX_ENRICH_IPS} of {len(all_ips)} public IPs.")
        else:
            ctx.run_source("ips", "asn (team-cymru)", lambda: Batch(), skip_reason="no public IP addresses observed for the domain")

    # -- active HTTP checks only when authorised ----------------------------------------------
    if "web" in mods:
        web.web_checks(ctx, domain)

    correlate(inv)
    inv.findings = rules.evaluate(inv, domain, now or datetime.now(timezone.utc))
    inv.limitations.extend([
        "Passive subdomain sources are incomplete by nature; absence of a name is not evidence it does not exist.",
        "Subdomain states: 'resolved' = DNS returned an address at test time; 'no_dns_answer' = no A/AAAA answer; "
        "'wildcard_only' = answer matches a wildcard record; 'unverified' = not tested or lookup error.",
        "Third-party reputation and exposure data are other parties' observations, not VESTIGE verdicts.",
    ])
    inv.limitations = list(dict.fromkeys(inv.limitations))
    inv.sources.sort(key=lambda s: (s.module, s.source))
    inv.finished_at = utcnow()

