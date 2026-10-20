"""Rule-based, explainable security observations.

Each rule inspects structured observations (never raw network data) and emits Finding records
with evidence, source, confidence, explanation, recommendation and the relevant standard.
Severities are deliberately conservative; nothing here is a confirmed vulnerability and no
"risk score" is computed.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from vestige.core.models import Confidence, Finding, Investigation, Observation, Severity

H, M, L = Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _f(id_, title, sev, target, evidence, source, conf, why, rec, std="", at=None) -> Finding:
    kw = {"observed_at": at} if at else {}
    return Finding(id_, title, sev, target, evidence, source, conf, why, rec, std, **kw)


def _first(inv: Investigation, kind: str) -> Observation | None:
    o = inv.obs(kind)
    return o[0] if o else None


def _has_mail(inv: Investigation) -> bool:
    return bool(inv.obs("mx")) and not inv.obs("mx_null")


# ---- mail ------------------------------------------------------------------------------------

def rule_dmarc(inv, domain, now):
    o = _first(inv, "dmarc")
    if not o:
        return []
    d = o.data
    if not d.get("present"):
        sev = Severity.MEDIUM if _has_mail(inv) else Severity.LOW
        return [_f("VST-MAIL-001", "No DMARC policy published", sev, domain,
                   f"No TXT record starting with v=DMARC1 found at _dmarc.{domain} (or parent domains).",
                   "dns", H,
                   "Without DMARC, receivers have no domain-owner policy for mail that fails SPF/DKIM alignment, which makes "
                   "spoofing of the domain easier. This is a mail-authentication gap, not proof of abuse.",
                   "Publish a DMARC record, start with p=none and rua= reporting, then move to quarantine/reject once legitimate senders are aligned.",
                   "RFC 7489", o.observed_at)]
    out = []
    if not d.get("valid"):
        out.append(_f("VST-MAIL-004", "DMARC record could not be parsed", Severity.LOW, domain,
                      f"Record: {d.get('record', '')[:200]}; error: {d.get('error')}", "dns", M,
                      "A malformed DMARC record is ignored by receivers, so it provides no protection.",
                      "Correct the record syntax (v=DMARC1; p=...).", "RFC 7489 s6.3", o.observed_at))
        return out
    if d["policy"] == "none":
        out.append(_f("VST-MAIL-002", "DMARC policy is monitoring-only (p=none)", Severity.INFO, domain,
                      f"{d.get('found_at')}: p=none" + (f"; reports to {', '.join(d['rua'])}" if d["rua"] else "; no rua reporting address"),
                      "dns", H,
                      "p=none asks receivers not to act on failing mail. It is a normal first step of a DMARC rollout but offers no enforcement.",
                      "If reports show legitimate mail is aligned, move to p=quarantine and then p=reject.", "RFC 7489 s6.3", o.observed_at))
    elif d["pct"] < 100:
        out.append(_f("VST-MAIL-003", f"DMARC enforcement applies to only {d['pct']}% of mail", Severity.INFO, domain,
                      f"p={d['policy']}; pct={d['pct']}", "dns", H,
                      "pct< 100 applies the policy to a sample of failing messages, typically during rollout.",
                      "Raise pct to 100 when rollout is complete.", "RFC 7489 s6.3", o.observed_at))
    return out


def rule_spf(inv, domain, now):
    o = _first(inv, "spf")
    if not o:
        return []
    d = o.data
    out = []
    if not d.get("present"):
        if _has_mail(inv):
            out.append(_f("VST-MAIL-010", "No SPF record published for a domain that receives mail", Severity.LOW, domain,
                          f"No TXT record starting with v=spf1 at {domain}; MX hosts exist.", "dns", H,
                          "Without SPF, receivers cannot check whether a sending server is authorised by the domain.",
                          "Publish an SPF record listing legitimate senders and ending in ~all or -all.", "RFC 7208", o.observed_at))
        return out
    if o.value == "multiple-records":
        out.append(_f("VST-MAIL-013", "Multiple SPF records published", Severity.MEDIUM, domain,
                      f"{len(d.get('records', []))} TXT records start with v=spf1", "dns", H,
                      "RFC 7208 requires exactly one SPF record; multiple records cause a permanent error (permerror), so SPF fails for all mail.",
                      "Merge the records into a single v=spf1 record.", "RFC 7208 s4.5", o.observed_at))
        return out
    if not d.get("valid"):
        return out
    q = d.get("all")
    if q == "+":
        out.append(_f("VST-MAIL-011", "SPF record allows any sender (+all)", Severity.MEDIUM, domain,
                      " ".join(d["mechanisms"])[:200], "dns", H,
                      "'+all' authorises every IP address, which defeats the purpose of SPF.",
                      "Replace with ~all or -all after listing legitimate senders.", "RFC 7208 s5.1", o.observed_at))
    elif q == "?" or (q is None and not d.get("redirect")):
        out.append(_f("VST-MAIL-011", "SPF record has no enforcing 'all' qualifier", Severity.LOW, domain,
                      f"policy: {d['policy']}", "dns", H,
                      "A neutral or missing 'all' term means receivers draw no conclusion about unlisted senders.",
                      "End the record with ~all (soft fail) or -all (hard fail).", "RFC 7208 s5.1", o.observed_at))
    if d.get("flags"):
        for flag in d["flags"]:
            if flag.startswith("authorises the entire"):
                out.append(_f("VST-MAIL-014", "SPF authorises an entire address range", Severity.MEDIUM, domain, flag, "dns", H,
                              "A /0 range permits all addresses of that IP version.", "Restrict to the sending infrastructure's actual ranges.",
                              "RFC 7208", o.observed_at))
    if d.get("dns_lookup_terms", 0) > 10:
        out.append(_f("VST-MAIL-012", "SPF record exceeds the 10 DNS-lookup limit", Severity.LOW, domain,
                      f"{d['dns_lookup_terms']} lookup-causing terms at top level (nested includes not counted)", "dns", M,
                      "More than 10 DNS-querying terms cause SPF evaluation to fail with permerror at many receivers.",
                      "Flatten or consolidate includes.", "RFC 7208 s4.6.4", o.observed_at))
    return out


def rule_mail_transport(inv, domain, now):
    if not _has_mail(inv):
        return []
    out = []
    ms = _first(inv, "mta_sts")
    if ms and not ms.data.get("present"):
        out.append(_f("VST-MAIL-020", "No MTA-STS policy published", Severity.INFO, domain,
                      f"No TXT record at _mta-sts.{domain}", "dns", H,
                      "MTA-STS lets a domain require TLS for inbound SMTP and protects against downgrade attacks. Adoption is optional.",
                      "Consider publishing MTA-STS (start in testing mode) and TLS-RPT.", "RFC 8461", ms.observed_at))
    tr = _first(inv, "tls_rpt")
    if tr and not tr.data.get("present") and ms and ms.data.get("present"):
        out.append(_f("VST-MAIL-021", "MTA-STS present without TLS-RPT reporting", Severity.INFO, domain,
                      f"No TXT record at _smtp._tls.{domain}", "dns", H,
                      "TLS-RPT delivers failure reports that make MTA-STS operable.", "Publish a TLS-RPT record with an rua= address.", "RFC 8460", tr.observed_at))
    for dk in inv.obs("dkim"):
        if dk.data.get("revoked"):
            out.append(_f("VST-MAIL-030", f"DKIM key for selector '{dk.data['selector']}' is revoked (empty p=)", Severity.INFO, domain,
                          dk.value, "dns", H, "An empty p= tag revokes the key; mail signed with this selector will fail DKIM.",
                          "Confirm the selector is intentionally retired.", "RFC 6376 s3.6.1", dk.observed_at))
    dd = _first(inv, "disposable_domain")
    if dd and dd.data.get("disposable"):
        out.append(_f("VST-MAIL-040", "Domain appears on a disposable-email list", Severity.INFO, domain,
                      f"listed in: {dd.data.get('list_provenance')}", "disposable-list", M,
                      "Disposable-mail providers issue short-lived addresses, often used for sign-up abuse; legitimate uses exist too.",
                      "Treat as a signal for review, not as proof of misuse."))
    return out


# ---- dns / registration -----------------------------------------------------------------------

def rule_dns(inv, domain, now):
    out = []
    ds = _first(inv, "dnssec")
    if ds:
        if ds.value == "unsigned":
            out.append(_f("VST-DNS-001", "DNSSEC not enabled", Severity.INFO, domain, "No DNSKEY or DS record found for the zone.", "dns", M,
                          "DNSSEC adds origin authentication to DNS answers. It is optional, and many well-run domains do not use it.",
                          "Consider DNSSEC if the registrar and DNS host support it.", "RFC 4033", ds.observed_at))
        elif ds.value in ("dnskey-without-ds", "ds-without-dnskey"):
            out.append(_f("VST-DNS-002", "Inconsistent DNSSEC configuration", Severity.LOW, domain,
                          f"state={ds.value} (DNSKEY={ds.data.get('dnskey_count')}, DS={ds.data.get('ds_count')})", "dns", L,
                          "A DS record without a matching DNSKEY (or vice versa) can break validation on DNSSEC-validating resolvers. "
                          "VESTIGE checks presence only and did not validate signatures.",
                          "Verify with a validating tool (e.g. DNSViz / delv) and fix the DS/DNSKEY mismatch.", "RFC 4035", ds.observed_at))
    if inv.obs("dns_record") and not any(o.data.get("type") == "CAA" for o in inv.obs("dns_record")):
        out.append(_f("VST-DNS-003", "No CAA records", Severity.INFO, domain, f"No CAA record set at {domain}.", "dns", M,
                      "CAA restricts which certificate authorities may issue certificates. Absence means any CA may issue.",
                      "Consider publishing CAA records naming the CAs you use.", "RFC 8659"))
    wc = _first(inv, "wildcard_dns")
    if wc and wc.value == "present":
        out.append(_f("VST-DNS-004", "Wildcard DNS record in use", Severity.INFO, domain,
                      f"random probe {wc.data.get('probe')} resolved to {', '.join(wc.data.get('ips', []))}", "dns", H,
                      "Wildcard records answer for any name, so resolving subdomains do not individually prove a host exists. VESTIGE marks such results 'wildcard_only'.",
                      "No action required; be aware when interpreting subdomain results.", "RFC 4592"))
    return out


def rule_registration(inv, domain, now):
    reg = _first(inv, "registration")
    exp = _dt(reg.data.get("expires")) if reg else None
    if not exp:
        return []
    days = (exp - now).days
    if days < 0:
        sev, title = Severity.MEDIUM, "Domain registration expiry date is in the past"
    elif days <= 14:
        sev, title = Severity.MEDIUM, f"Domain registration expires in {days} days"
    elif days <= 60:
        sev, title = Severity.LOW, f"Domain registration expires in {days} days"
    else:
        return []
    return [_f("VST-REG-001", title, sev, domain, f"expiration: {reg.data['expires']} (via {reg.data.get('via')})", reg.source, H,
               "An expired or soon-to-expire domain can lapse, causing outages and exposing the name to re-registration by others.",
               "Renew the domain and enable auto-renew; check that registrar contacts are current.", "", reg.observed_at)]


# ---- web / tls --------------------------------------------------------------------------------

def rule_web(inv, domain, now):
    out = []
    r = _first(inv, "http_response")
    if r:
        h = r.data["headers"]
        host = r.value
        if r.data.get("final_url", "").startswith("https://"):
            if not h.get("strict-transport-security"):
                out.append(_f("VST-WEB-001", "HSTS header not set on HTTPS site", Severity.LOW, host,
                              f"{r.data['final_url']} returned HTTP {r.data['status']} without Strict-Transport-Security.", "direct-http", H,
                              "Without HSTS, a browser's first plain-HTTP visit can be downgraded or intercepted by a network attacker. "
                              "This is a hardening gap, not an exploitable flaw by itself.",
                              "Send Strict-Transport-Security: max-age=31536000; includeSubDomains once all subdomains support HTTPS.", "RFC 6797", r.observed_at))
            elif (h.get("hsts_max_age") or 0) < 15552000:
                out.append(_f("VST-WEB-002", "HSTS max-age is short", Severity.INFO, host,
                              f"max-age={h.get('hsts_max_age')} seconds", "direct-http", H,
                              "Short HSTS lifetimes weaken the protection (browsers forget the policy quickly).",
                              "Use at least 15552000 (180 days); 31536000 for preload eligibility.", "RFC 6797"))
        missing = [n for n in ("content-security-policy", "x-content-type-options", "referrer-policy", "permissions-policy") if not h.get(n)]
        if missing:
            out.append(_f("VST-WEB-003", "Browser hardening headers not set", Severity.INFO, host,
                          "Missing: " + ", ".join(missing), "direct-http", H,
                          "These headers reduce the impact of XSS, MIME sniffing and information leakage. Their absence is a defence-in-depth gap, "
                          "not a vulnerability; some are irrelevant for API-only hosts.",
                          "Evaluate each header against the application's needs and add where appropriate.",
                          "W3C CSP3 / Fetch / Referrer-Policy / Permissions-Policy", r.observed_at))
        if h.get("csp_unsafe_inline") or h.get("csp_unsafe_eval"):
            out.append(_f("VST-WEB-004", "CSP allows unsafe-inline/unsafe-eval", Severity.INFO, host,
                          f"unsafe-inline={h.get('csp_unsafe_inline')}, unsafe-eval={h.get('csp_unsafe_eval')}", "direct-http", H,
                          "These keywords weaken the XSS protection a CSP provides.", "Use nonces or hashes instead.", "W3C CSP3"))
        tech = {k: v for k, v in r.data.get("technology_headers", {}).items() if any(c.isdigit() for c in v) and k in ("server", "x-powered-by", "x-aspnet-version")}
        if tech:
            out.append(_f("VST-WEB-005", "Version information disclosed in HTTP headers", Severity.INFO, host,
                          "; ".join(f"{k}: {v}" for k, v in tech.items()), "direct-http", H,
                          "Version strings help attackers match known vulnerabilities, but they do not mean the software is vulnerable (it may be patched or masked).",
                          "Remove or genericise version banners.", "OWASP WSTG-INFO-02", r.observed_at))
        if "redirect not followed" in (r.data.get("redirect_note") or ""):
            out.append(_f("VST-WEB-006", "Redirect leaves the authorised scope", Severity.INFO, host,
                          r.data["redirect_note"], "direct-http", H,
                          "VESTIGE does not follow redirects to hosts outside the declared scope.", "Review the redirect target manually if relevant."))
    t = _first(inv, "tls_certificate")
    if t:
        d = t.data
        if d.get("error"):
            sev = Severity.MEDIUM
            out.append(_f("VST-TLS-002", "TLS certificate failed verification", sev, t.value, d["error"], "direct-tls", H,
                          "Clients that validate certificates will reject the connection or show warnings. Causes include expiry, hostname mismatch, an untrusted or incomplete chain "
                          "(a missing intermediate is a server fault), or a gap in the scanning machine's own CA bundle; confirm with a second tool.",
                          "Install a valid certificate chain that covers the hostname.", "RFC 5280 / RFC 6125", t.observed_at))
        elif d.get("days_until_expiry") is not None:
            days = d["days_until_expiry"]
            if days < 0:
                out.append(_f("VST-TLS-001", "TLS certificate has expired", Severity.HIGH, t.value, f"notAfter {d.get('not_after')}", "direct-tls", H,
                              "Browsers refuse or warn on expired certificates, causing outages.", "Renew and deploy the certificate.", "RFC 5280", t.observed_at))
            elif days <= 14:
                out.append(_f("VST-TLS-001", f"TLS certificate expires in {days} days", Severity.MEDIUM, t.value, f"notAfter {d.get('not_after')}", "direct-tls", H,
                              "An unrenewed certificate will cause outages at expiry.", "Renew or fix automated renewal.", "RFC 5280", t.observed_at))
            elif days <= 30:
                out.append(_f("VST-TLS-001", f"TLS certificate expires in {days} days", Severity.LOW, t.value, f"notAfter {d.get('not_after')}", "direct-tls", H,
                              "Renewal window is approaching.", "Verify automated renewal is working.", "RFC 5280", t.observed_at))
    s = _first(inv, "security_txt")
    if s:
        if s.value == "absent":
            out.append(_f("VST-WEB-010", "No security.txt published", Severity.INFO, domain, "Neither /.well-known/security.txt nor /security.txt returned a text file.", "direct-http", M,
                          "security.txt gives researchers a standard way to report vulnerabilities. It is optional.",
                          "Publish /.well-known/security.txt with Contact and Expires.", "RFC 9116", s.observed_at))
        elif s.data.get("problems"):
            out.append(_f("VST-WEB-011", "security.txt has problems", Severity.INFO, domain, "; ".join(s.data["problems"]), "direct-http", H,
                          "RFC 9116 requires Contact and a single, future Expires field.", "Fix the listed problems.", "RFC 9116", s.observed_at))
    return out


# ---- reputation / exposure / history ----------------------------------------------------------

def rule_reputation(inv, domain, now):
    out = []
    for o in inv.obs("reputation"):
        d = o.data
        subject = d.get("subject", o.value)
        if o.source == "abuseipdb":
            score = d.get("abuse_confidence_score") or 0
            if score >= 25 and not d.get("is_whitelisted"):
                sev = Severity.MEDIUM if score >= 75 else Severity.LOW
                out.append(_f("VST-REP-001", f"AbuseIPDB reports abuse confidence {score}% for {subject}", sev, subject,
                              f"score={score}, reports={d.get('total_reports')}, distinct reporters={d.get('distinct_reporters')}, last={d.get('last_reported_at')}",
                              "abuseipdb", M,
                              "AbuseIPDB aggregates community reports over 90 days. Shared hosting, NAT and compromised-then-cleaned hosts can inflate scores; it is not proof the owner is malicious.",
                              "Review the report categories on AbuseIPDB and check whether the host was compromised or is shared infrastructure.", "", o.observed_at))
        if o.source == "virustotal":
            mal = d.get("malicious", 0)
            if mal > 0:
                sev = Severity.MEDIUM if mal >= 5 else Severity.LOW
                out.append(_f("VST-REP-002", f"{mal} VirusTotal engine(s) flag {subject}", sev, subject,
                              f"malicious={mal}, suspicious={d.get('suspicious')}, harmless={d.get('harmless')}, undetected={d.get('undetected')}",
                              "virustotal", M,
                              "Security vendors' verdicts differ and include false positives. A flag is a lead for review, not a conclusion.",
                              "Inspect the engine names and categories on VirusTotal and corroborate with other evidence.", "", o.observed_at))
    for o in inv.obs("exposure_metadata"):
        if o.data.get("vulns"):
            out.append(_f("VST-EXP-001", f"Passive scanner data lists CVE identifiers for {o.value}", Severity.LOW, o.value,
                          f"{len(o.data['vulns'])} CVE ID(s) in Shodan InternetDB (unverified), e.g. {', '.join(o.data['vulns'][:3])}", o.source, L,
                          "InternetDB infers vulnerabilities from service banners seen by a crawler, which can be stale, backported-patched or wrong. VESTIGE did not test the host.",
                          "Verify the actual software version and patch status on the host (with authorisation).", "", o.observed_at))
    return out


def rule_history(inv, domain, now):
    stale = [o.value for o in inv.obs("subdomain")
             if set(o.data.get("sources", [])) <= {"wayback", "urlscan"} and o.data.get("dns_state") == "no_dns_answer"]
    if not stale:
        return []
    return [_f("VST-HIST-001", f"{len(stale)} historical hostname(s) no longer resolve", Severity.INFO, domain,
               ", ".join(sorted(stale)[:10]) + (" ..." if len(stale) > 10 else ""), "wayback/urlscan + dns", M,
               "These names appear in archives but returned no DNS answer when tested. They may be decommissioned; check that no dangling CNAMEs/records point to released resources. VESTIGE did not test for takeover.",
               "Confirm the hostnames are intentionally retired.")]


RULES: list[Callable] = [rule_dmarc, rule_spf, rule_mail_transport, rule_dns, rule_registration,
                         rule_web, rule_reputation, rule_history]


def evaluate(inv: Investigation, domain: str = "", now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(timezone.utc)
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule(inv, domain or inv.target, now))
    from vestige.core.models import SEVERITY_ORDER
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.id, f.target))
    return findings
