"""Email authentication, IP intelligence/reputation, phone metadata."""
import pytest

from tests.conftest import make_ctx, source
from vestige.core.models import Status
from vestige.core.scope import ValidationError
from vestige.modules import ip as ipmod
from vestige.modules import phone, reputation
from vestige.modules.dns import FakeResolver
from vestige.modules.email import (analyze_mail, infer_mail_provider, mask_email, parse_dmarc, parse_spf,
                                   validate_email)

D = "example.com"


# --------------------------------------------------------------------------- validation
@pytest.mark.parametrize("addr,local,domain", [
    ("user@example.com", "user", "example.com"), ("First.Last+tag@Example.COM", "First.Last+tag", "example.com"),
    ("a@bücher.example", "a", "xn--bcher-kva.example"), ("o'brien@example.com", "o'brien", "example.com"),
])
def test_validate_email_ok(addr, local, domain):
    assert validate_email(addr) == (local, domain)


@pytest.mark.parametrize("addr", ["", "plain", "a@b", "@example.com", "a@@example.com", "a b@example.com", ".a@example.com",
                                  "a..b@example.com", "a.@example.com", "a@example.com\nBcc:x@y.com", '"quoted"@example.com',
                                  "a@-bad.com", "ü@example.com", "x" * 65 + "@example.com", "a@1.2.3.4", "a@example.com trailing"])
def test_validate_email_rejects(addr):
    with pytest.raises(ValidationError):
        validate_email(addr)


def test_mask_hides_local_part():
    m = mask_email("johnsmith", "example.com")
    assert m.endswith("@example.com") and "johnsmith" not in m and m.startswith("j")


# ------------------------------------------------------------------------------ SPF
def test_spf_hard_fail_basic():
    p = parse_spf("v=spf1 ip4:192.0.2.0/24 include:_spf.google.com mx -all")
    assert p["all"] == "-" and p["includes"] == ["_spf.google.com"] and p["dns_lookup_terms"] == 2 and p["flags"] == []
    assert "reject" in p["policy"]


@pytest.mark.parametrize("rec,all_q,flag", [
    ("v=spf1 +all", "+", "'+all' allows any sender"), ("v=spf1 ?all", "?", None), ("v=spf1 ~all", "~", None),
    ("v=spf1 ip4:0.0.0.0/0 -all", "-", "entire address space"), ("v=spf1 ptr -all", "-", "deprecated 'ptr'"),
    ("v=spf1 ip4:10.0.0.0/8 -all", "-", "very large"),
])
def test_spf_flags(rec, all_q, flag):
    p = parse_spf(rec)
    assert p["all"] == all_q
    if flag:
        assert any(flag in f for f in p["flags"])
    else:
        assert p["flags"] == []


def test_spf_lookup_limit_and_redirect():
    p = parse_spf("v=spf1 " + " ".join(f"include:s{i}.example.com" for i in range(11)) + " -all")
    assert p["dns_lookup_terms"] == 11 and any("limit is 10" in f for f in p["flags"])
    r = parse_spf("v=spf1 redirect=_spf.example.com")
    assert r["redirect"] == "_spf.example.com" and "redirect" in r["policy"]


def test_spf_rejects_non_spf():
    with pytest.raises(ValueError):
        parse_spf("v=spf2 -all")


# ----------------------------------------------------------------------------- DMARC
def test_dmarc_parse():
    p = parse_dmarc("v=DMARC1; p=quarantine; pct=50; rua=mailto:a@x.com,mailto:b@x.com; adkim=s")
    assert p["policy"] == "quarantine" and p["pct"] == 50 and len(p["rua"]) == 2 and p["adkim"] == "s"


@pytest.mark.parametrize("rec", ["v=DMARC2; p=none", "p=none; v=DMARC1", "v=DMARC1; rua=mailto:a@x.com", ""])
def test_dmarc_invalid(rec):
    with pytest.raises(ValueError):
        parse_dmarc(rec)


# ------------------------------------------------------------------ mail orchestration
def mail_ctx(records, nx=(), **kw):
    r = FakeResolver(records, nxdomain=list(nx) + [f"_dmarc.{D}", f"_mta-sts.{D}", f"_smtp._tls.{D}"] if kw.pop("nx_defaults", True) else nx)
    return make_ctx({"https://raw.githubusercontent.com/": (500, "x")}, resolver=r, **kw)


def test_missing_records_are_reported_with_clear_state():
    ctx = mail_ctx({(D, "MX"): ["10 mx.example.com."], (D, "TXT"): ["unrelated"], ("mx.example.com", "A"): ["9.9.9.9"]})
    analyze_mail(ctx, D)
    kinds = {o.kind: o.value for o in ctx.inv.observations}
    assert kinds["spf"] == "missing" and kinds["dmarc"] == "missing" and kinds["mta_sts"] == "missing" and kinds["tls_rpt"] == "missing"
    assert ("mx.example.com", "resolves_to", "9.9.9.9") in {(r.subject, r.predicate, r.object) for r in ctx.inv.relationships}


def test_present_records_parsed():
    ctx = mail_ctx({(D, "MX"): ["10 aspmx.l.google.com."], (D, "TXT"): ["v=spf1 include:_spf.google.com -all"],
                    (f"_dmarc.{D}", "TXT"): ["v=DMARC1; p=reject; rua=mailto:r@example.com"],
                    (f"_mta-sts.{D}", "TXT"): ["v=STSv1; id=2024"], (f"_smtp._tls.{D}", "TXT"): ["v=TLSRPTv1; rua=mailto:t@example.com"]},
                   nx_defaults=False)
    analyze_mail(ctx, D)
    d = {o.kind: o for o in ctx.inv.observations}
    assert d["dmarc"].data["policy"] == "reject" and d["spf"].data["all"] == "-"
    assert d["mta_sts"].data["present"] and d["mta_sts"].data["policy_fetched"] is False  # passive: policy not fetched
    assert d["mail_provider"].value == "Google Workspace / Gmail"


def test_dmarc_inherited_from_parent_domain():
    sub = "mail.example.com"
    ctx = make_ctx(resolver=FakeResolver({(f"_dmarc.{D}", "TXT"): ["v=DMARC1; p=none"], (sub, "MX"): []},
                                         nxdomain=[f"_dmarc.{sub}", f"_mta-sts.{sub}", f"_smtp._tls.{sub}", sub + "-x"]))
    analyze_mail(ctx, sub, check_disposable=False)
    o = ctx.inv.obs("dmarc")[0]
    assert o.data["inherited"] is True and o.data["found_at"] == f"_dmarc.{D}"


def test_multiple_spf_records_flagged():
    ctx = mail_ctx({(D, "MX"): ["10 mx.example.com."], (D, "TXT"): ["v=spf1 -all", "v=spf1 +all"]})
    analyze_mail(ctx, D, check_disposable=False)
    assert ctx.inv.obs("spf")[0].value == "multiple-records"


def test_null_mx_means_no_mail():
    ctx = mail_ctx({(D, "MX"): ["0 ."]})
    analyze_mail(ctx, D, check_disposable=False)
    assert ctx.inv.obs("mx_null") and not ctx.inv.obs("mx")


def test_dkim_requires_explicit_selector():
    ctx = mail_ctx({(D, "MX"): ["10 mx.example.com."]})
    analyze_mail(ctx, D, check_disposable=False)
    assert not ctx.inv.obs("dkim") and not any(s.source.startswith("dkim") for s in ctx.inv.sources)
    assert any("no universal DKIM lookup" in l for l in ctx.inv.limitations)


def test_dkim_with_selector_found_missing_and_revoked():
    ctx = mail_ctx({(D, "MX"): ["10 mx.example.com."],
                    (f"s1._domainkey.{D}", "TXT"): ["v=DKIM1; k=rsa; p=MIGfMA0GCSq"],
                    (f"old._domainkey.{D}", "TXT"): ["v=DKIM1; p="]})
    analyze_mail(ctx, D, dkim_selectors=["s1", "old", "nope"], check_disposable=False)
    v = {o.data["selector"]: o for o in ctx.inv.obs("dkim")}
    assert v["s1"].data["present"] and not v["s1"].data["revoked"]
    assert v["old"].data["revoked"]
    assert v["nope"].data["present"] is False and "does not prove" in v["nope"].data["note"]


def test_invalid_dkim_selector_is_rejected_as_failed_source():
    ctx = mail_ctx({(D, "MX"): ["10 mx.example.com."]})
    analyze_mail(ctx, D, dkim_selectors=["bad selector!"], check_disposable=False)
    assert source(ctx.inv, "dkim:bad").status == Status.FAILED


def test_disposable_detection_and_fallback_provenance():
    ctx = make_ctx({"https://raw.githubusercontent.com/": (200, "\n".join(f"d{i}.test" for i in range(200)))},
                   resolver=FakeResolver({(D, "MX"): []}, nxdomain=[f"_dmarc.{D}", f"_mta-sts.{D}", f"_smtp._tls.{D}"]))
    from vestige.modules.email import load_disposable
    domains, prov = load_disposable(ctx)
    assert "d5.test" in domains and "maintained" in prov
    fallback_ctx = make_ctx({"https://raw.githubusercontent.com/": (500, "x")})
    domains, prov = load_disposable(fallback_ctx)
    assert "mailinator.com" in domains and "seed" in prov  # offline provenance is explicit


def test_mail_provider_inference():
    assert infer_mail_provider(["mx1.protection.outlook.com"]) == "Microsoft 365 / Exchange Online"
    assert infer_mail_provider(["mail.selfhosted.test"]) is None


# ------------------------------------------------------------------------------ IP / reputation
def test_cymru_names_and_parsing():
    assert ipmod.cymru_name("8.8.4.4") == "4.4.8.8.origin.asn.cymru.com"
    assert ipmod.cymru_name("2001:db8::1").endswith(".origin6.asn.cymru.com")
    assert len(ipmod.cymru_name("2001:db8::1").split(".origin6")[0].split(".")) == 32
    assert ipmod.parse_cymru_origin('"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"')["asn"] == 15169
    with pytest.raises(Exception):
        ipmod.parse_cymru_origin('"garbage"')


def test_private_ip_never_leaves_the_machine():
    ctx = make_ctx(creds={"ABUSEIPDB_KEY": "k"})
    info = ipmod.analyze_ip(ctx, "192.168.1.10")
    assert info["classification"] == "private"
    assert ctx.http.transport.calls == []  # no third-party request carried the private address
    assert ctx.resolver.calls == []        # not even DNS
    skipped = [s for s in ctx.inv.sources if s.status == Status.SKIPPED]
    assert len(skipped) >= 4 and all("not sent to third-party" in s.detail for s in skipped)


def test_public_ip_with_fixtures_includes_timestamps_and_sources():
    r = FakeResolver({("8.8.8.8.in-addr.arpa", "PTR"): ["dns.google."],
                      ("8.8.8.8.origin.asn.cymru.com", "TXT"): ['"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"'],
                      ("AS15169.asn.cymru.com", "TXT"): ['"15169 | US | arin | 2000-03-30 | GOOGLE, US"']})
    ctx = make_ctx({"https://ipapi.co/8.8.8.8/json/": (200, {"ip": "8.8.8.8", "city": "Mountain View", "country_name": "United States", "org": "GOOGLE"}),
                    "https://internetdb.shodan.io/8.8.8.8": (200, {"ip": "8.8.8.8", "ports": [53, 443], "vulns": [], "hostnames": ["dns.google"]})}, resolver=r)
    ipmod.analyze_ip(ctx, "8.8.8.8")
    by = {o.kind: o for o in ctx.inv.observations}
    assert by["asn"].value == "AS15169" and by["asn"].data["as_name"] == "GOOGLE, US"
    assert by["geolocation"].confidence.value == "low" and "approximate" in by["geolocation"].data["accuracy_note"]
    assert by["exposure_metadata"].data["ports"] == [53, 443]
    assert all(o.observed_at.endswith("Z") and o.source for o in ctx.inv.observations)
    assert source(ctx.inv, "reputation").status == Status.SKIPPED  # no key -> SKIPPED, not silently absent


def test_missing_abuseipdb_key_is_skipped_with_instruction():
    ctx = make_ctx()
    ipmod.analyze_ip(ctx, "8.8.8.8")
    s = source(ctx.inv, "reputation")
    assert s.status == Status.SKIPPED and "ABUSEIPDB_KEY" in s.detail


@pytest.mark.parametrize("status,expected_kind", [(401, "auth"), (403, "auth"), (429, "ratelimit"), (500, "server")])
def test_abuseipdb_errors_are_failed_never_success(status, expected_kind):
    ctx = make_ctx({"https://api.abuseipdb.com/": (status, {"errors": [{"detail": "nope"}]})}, creds={"ABUSEIPDB_KEY": "k"})
    ctx.run_source("ip", "abuse", lambda: reputation.abuseipdb(ctx, "8.8.8.8"), requires="ABUSEIPDB_KEY")
    s = source(ctx.inv, "abuse")
    assert s.status == Status.FAILED and expected_kind in s.detail and not ctx.inv.obs("reputation")


def test_abuseipdb_malformed_and_success():
    ctx = make_ctx({"https://api.abuseipdb.com/": (200, {"unexpected": True})}, creds={"ABUSEIPDB_KEY": "k"})
    ctx.run_source("ip", "abuse", lambda: reputation.abuseipdb(ctx, "8.8.8.8"))
    assert source(ctx.inv, "abuse").status == Status.FAILED
    ok = {"data": {"abuseConfidenceScore": 80, "totalReports": 12, "numDistinctUsers": 5, "lastReportedAt": "2026-01-01T00:00:00+00:00"}}
    ctx = make_ctx({"https://api.abuseipdb.com/": (200, ok)}, creds={"ABUSEIPDB_KEY": "k"})
    b = reputation.abuseipdb(ctx, "8.8.8.8")
    assert b.observations[0].data["abuse_confidence_score"] == 80 and "not proof" in b.observations[0].data["note"]


def test_ipapi_rate_limit_body_with_http_200_is_not_success():
    ctx = make_ctx({"https://ipapi.co/": (200, {"error": True, "reason": "RateLimited"})})
    ctx.run_source("ip", "geo", lambda: ipmod.geolocation(ctx, "8.8.8.8"))
    s = source(ctx.inv, "geo")
    assert s.status == Status.FAILED and "ratelimit" in s.detail


def test_virustotal_domain_parse():
    doc = {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 60, "undetected": 20}, "reputation": -3}}}
    assert reputation.parse_virustotal_domain(doc)["malicious"] == 2
    with pytest.raises(Exception):
        reputation.parse_virustotal_domain({})


# ------------------------------------------------------------------------------- phone
def test_phone_valid_indian_mobile():
    info = phone.describe(phone.parse_number("+919876543210"))
    assert info["e164"] == "+919876543210" and info["is_valid"] and info["region"] == "IN" and info["country_code"] == 91
    assert info["number_type"] == "mobile" and "NOT the current location" in info["geographic_note"]
    assert "not live carrier verification" in info["carrier_note"]


def test_phone_formats_normalise_to_e164():
    for raw in ["+91 98765 43210", "+91-9876543210", "(+91) 98765-43210"]:
        assert phone.describe(phone.parse_number(raw))["e164"] == "+919876543210"
    assert phone.describe(phone.parse_number("09876543210", "IN"))["e164"] == "+919876543210"


def test_phone_invalid_numbers():
    info = phone.describe(phone.parse_number("+9198765"))
    assert not info["is_valid"] and info["number_type"].startswith("n/a") and info["carrier_original_allocation"] is None
    assert phone.describe(phone.parse_number("+1555"))["is_valid"] is False


@pytest.mark.parametrize("raw", ["", "   ", "9876543210", "abc", "+", "+999999999999999999999"])
def test_phone_unparseable(raw):
    with pytest.raises(ValidationError):
        phone.parse_number(raw)


def test_phone_us_toll_free_type():
    assert phone.describe(phone.parse_number("+18005551234"))["country_code"] == 1


def test_numverify_uses_https_and_skips_without_key():
    ctx = make_ctx()
    phone.phone_recon(ctx, "+919876543210")
    s = source(ctx.inv, "numverify")
    assert s.status == Status.SKIPPED and "NUMVERIFY_KEY" in s.detail
    assert phone.NUMVERIFY_URL.startswith("https://") and not phone.NUMVERIFY_URL.startswith("http://")
    ctx = make_ctx({"https://apilayer.net/api/validate": (200, {"valid": True, "carrier": "Jio", "line_type": "mobile"})}, creds={"NUMVERIFY_KEY": "k"})
    phone.phone_recon(ctx, "+919876543210")
    assert all(c.startswith("https://") for c in ctx.http.transport.calls) and ctx.inv.obs("phone_provider_lookup")


def test_numverify_error_codes_not_success():
    ctx = make_ctx({"https://apilayer.net/": (200, {"success": False, "error": {"code": 101, "info": "invalid access key"}})}, creds={"NUMVERIFY_KEY": "k"})
    phone.phone_recon(ctx, "+919876543210")
    s = source(ctx.inv, "numverify")
    assert s.status == Status.FAILED and "auth" in s.detail
    assert "k" not in [c for c in ctx.http.transport.calls if "access_key=k" in c]  # key redacted in the call log


def test_phone_invalid_number_skips_provider():
    ctx = make_ctx(creds={"NUMVERIFY_KEY": "k"})
    phone.phone_recon(ctx, "+9198765")
    assert source(ctx.inv, "numverify").status == Status.SKIPPED and ctx.http.transport.calls == []


def test_dns_failures_in_mail_checks_are_reported_as_network_failures_not_internal_errors():
    r = FakeResolver(errors={(D, "MX"): "timeout", (f"_dmarc.{D}", "TXT"): "servfail", (D, "TXT"): "timeout"})
    ctx = make_ctx(resolver=r)
    analyze_mail(ctx, D, check_disposable=False)
    for name in ("mx", "spf", "dmarc"):
        s = source(ctx.inv, name)
        assert s.status == Status.FAILED and "internal error" not in s.detail and "DNS" in s.detail
