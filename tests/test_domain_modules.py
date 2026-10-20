"""DNS parsing, RDAP, WHOIS fallback, Certificate Transparency, passive subdomains."""
import pytest

from tests.conftest import make_ctx, source
from vestige.core.correlator import correlate
from vestige.core.http_client import ProviderError
from vestige.core.models import Status
from vestige.modules import certificates, rdap, subdomains
from vestige.modules.dns import FakeResolver, infer_dns_provider, lookup_dns, parse_mx, parse_soa

D = "example.com"


# ------------------------------------------------------------------------------ DNS
def test_parse_mx_and_soa():
    assert parse_mx("10 Mail.Example.COM.") == (10, "mail.example.com")
    assert parse_mx("0 .") == (0, "")
    assert parse_mx("garbage") is None and parse_mx("x mail.example.com") is None
    soa = parse_soa("ns1.example.com. admin.example.com. 2024010101 7200 3600 1209600 300")
    assert soa["serial"] == 2024010101 and soa["mname"] == "ns1.example.com" and soa["minimum"] == 300
    assert parse_soa("too short") is None


def test_dns_provider_inference():
    assert infer_dns_provider(["ada.ns.cloudflare.com."]) == "Cloudflare"
    assert infer_dns_provider(["ns-123.awsdns-45.org"]) == "Amazon Route 53"
    assert infer_dns_provider(["ns1.unknown-host.net"]) is None


def full_resolver(extra=None):
    rec = {(D, "A"): ["93.184.216.34"], (D, "AAAA"): ["2606:2800:220:1::1"], (D, "MX"): ["10 mx.example.com."],
           (D, "NS"): ["ns1.example.com.", "ns2.example.com."], (D, "TXT"): ["v=spf1 -all"],
           (D, "SOA"): ["ns1.example.com. h.example.com. 1 2 3 4 5"],
           ("34.216.184.93.in-addr.arpa", "PTR"): ["host.example.com."]}
    rec.update(extra or {})
    return FakeResolver(rec)


def test_lookup_dns_collects_records_and_relationships():
    ctx = make_ctx(resolver=full_resolver())
    b = ctx.run_source("dns", "dns-records", lambda: lookup_dns(ctx, D))
    assert b is not None
    types = {o.data["type"] for o in ctx.inv.obs("dns_record")}
    assert {"A", "AAAA", "MX", "NS", "TXT", "SOA"} <= types
    preds = {(r.predicate, r.object) for r in ctx.inv.relationships}
    assert ("resolves_to", "93.184.216.34") in preds and ("uses_mail_exchanger", "mx.example.com") in preds
    assert ("has_nameserver", "ns1.example.com") in preds
    assert [o.value for o in ctx.inv.obs("reverse_dns")] == ["93.184.216.34 host.example.com"]
    assert source(ctx.inv, "dns-records").status == Status.OK


def test_txt_record_is_joined_not_chunked():
    ctx = make_ctx(resolver=full_resolver())
    lookup = lookup_dns(ctx, D)
    assert any(o.data["value"] == "v=spf1 -all" for o in lookup.observations)


def test_wildcard_detection():
    r = full_resolver()
    r.wildcard = {D: {"A": ["1.2.3.4"]}}
    ctx = make_ctx(resolver=r)
    lookup_dns(ctx, D) or None
    b = lookup_dns(ctx, D)
    wc = [o for o in b.observations if o.kind == "wildcard_dns"][0]
    assert wc.value == "present" and wc.data["ips"] == ["1.2.3.4"]


def test_no_wildcard_when_random_label_is_nxdomain():
    b = lookup_dns(make_ctx(resolver=full_resolver()), D)
    assert [o for o in b.observations if o.kind == "wildcard_dns"][0].value == "absent"


@pytest.mark.parametrize("dnskey,ds,state", [
    (["257 3 13 AAAA"], ["1 13 2 AB"], "signed"), ([], [], "unsigned"),
    (["257 3 13 AAAA"], [], "dnskey-without-ds"), ([], ["1 13 2 AB"], "ds-without-dnskey")])
def test_dnssec_states(dnskey, ds, state):
    extra = {}
    if dnskey:
        extra[(D, "DNSKEY")] = dnskey
    if ds:
        extra[(D, "DS")] = ds
    b = lookup_dns(make_ctx(resolver=full_resolver(extra)), D)
    o = [x for x in b.observations if x.kind == "dnssec"][0]
    assert o.value == state and o.data["validated"] is False  # presence only, never claims validation


def test_nxdomain_domain_reports_status_not_crash():
    ctx = make_ctx(resolver=FakeResolver(nxdomain=[D]))
    ctx.run_source("dns", "dns-records", lambda: lookup_dns(ctx, D))
    assert [o.value for o in ctx.inv.obs("dns_status")] == ["NXDOMAIN"]


def test_dns_total_failure_is_failed_not_ok():
    errors = {(D, t): "timeout" for t in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]}
    ctx = make_ctx(resolver=FakeResolver(errors=errors))
    assert ctx.run_source("dns", "dns-records", lambda: lookup_dns(ctx, D)) is None
    assert source(ctx.inv, "dns-records").status == Status.FAILED


# ----------------------------------------------------------------------------- RDAP
BOOT = {"services": [[["com", "net"], ["http://rdap.insecure.test/", "https://rdap.verisign.test/"]], [["org"], ["https://rdap.org.test/"]]]}
RDAP_DOC = {
    "objectClassName": "domain", "ldhName": "EXAMPLE.COM", "status": ["client transfer prohibited"],
    "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
               {"eventAction": "expiration", "eventDate": "2030-08-13T04:00:00Z"},
               {"eventAction": "last changed", "eventDate": "2024-08-14T07:01:34Z"},
               {"eventAction": "last update of RDAP database", "eventDate": "2026-01-01T00:00:00Z"}],
    "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "SECRET PERSON"]]]},
                 {"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"]]],
                  "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}]}],
    "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}, {"ldhName": "b.iana-servers.net"}],
    "secureDNS": {"delegationSigned": True},
}


def test_bootstrap_prefers_https_and_handles_missing():
    assert rdap.find_rdap_base(BOOT, "com") == "https://rdap.verisign.test"
    assert rdap.find_rdap_base(BOOT, "ORG") == "https://rdap.org.test"
    assert rdap.find_rdap_base(BOOT, "zz") is None
    with pytest.raises(ProviderError):
        rdap.find_rdap_base({"nope": 1}, "com")


def test_parse_rdap_extracts_minimum_and_ignores_registrant():
    info = rdap.parse_rdap_domain(RDAP_DOC)
    assert info["registrar"] == "Example Registrar" and info["registrar_iana_id"] == "376"
    assert info["registered"].startswith("1995") and info["expires"].startswith("2030")
    assert info["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert info["dnssec_delegation_signed"] is True
    assert "SECRET PERSON" not in str(info)  # registrant data never collected


def test_rdap_rejects_non_domain_object():
    with pytest.raises(ProviderError):
        rdap.parse_rdap_domain({"objectClassName": "entity"})


def test_rdap_lookup_end_to_end():
    ctx = make_ctx({"https://data.iana.org/rdap/dns.json": (200, BOOT),
                    "https://rdap.verisign.test/domain/example.com": (200, RDAP_DOC)})
    b = rdap.rdap_lookup(ctx, D)
    assert b.observations[0].kind == "registration" and b.observations[0].data["via"] == "rdap"
    assert {r.object for r in b.relationships} == {"a.iana-servers.net", "b.iana-servers.net"}


def test_rdap_walks_up_from_subdomain_on_404():
    ctx = make_ctx({"https://data.iana.org/rdap/dns.json": (200, BOOT),
                    "https://rdap.verisign.test/domain/www.example.com": (404, {}),
                    "https://rdap.verisign.test/domain/example.com": (200, RDAP_DOC)})
    b = rdap.rdap_lookup(ctx, "www.example.com")
    assert b.observations[0].value == "example.com"


def test_rdap_unsupported_tld_then_failed_status():
    ctx = make_ctx({"https://data.iana.org/rdap/dns.json": (200, BOOT)})
    assert ctx.run_source("registration", "rdap", lambda: rdap.rdap_lookup(ctx, "example.zz")) is None
    s = source(ctx.inv, "rdap")
    assert s.status == Status.FAILED and "no RDAP service" in s.detail


def test_rdap_server_500_is_failed():
    ctx = make_ctx({"https://data.iana.org/rdap/dns.json": (200, BOOT), "https://rdap.verisign.test/domain/": (500, "oops")})
    ctx.run_source("registration", "rdap", lambda: rdap.rdap_lookup(ctx, D))
    assert source(ctx.inv, "rdap").status == Status.FAILED


def test_rdap_malformed_json_is_failed():
    ctx = make_ctx({"https://data.iana.org/rdap/dns.json": (200, BOOT), "https://rdap.verisign.test/domain/": (200, "<html>")})
    ctx.run_source("registration", "rdap", lambda: rdap.rdap_lookup(ctx, D))
    s = source(ctx.inv, "rdap")
    assert s.status == Status.FAILED and "malformed" in s.detail


WHOIS = """Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2030-08-13T04:00:00Z
Updated Date: 2024-08-14T07:01:34Z
Domain Status: clientTransferProhibited https://icann.org/epp#x
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
Registrant Name: SHOULD NOT BE COLLECTED
"""


def test_parse_whois_ignores_registrant():
    p = rdap.parse_whois(WHOIS)
    assert p["registrar"].startswith("Example") and p["expires"].startswith("2030")
    assert p["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert "SHOULD NOT" not in str(p)


def test_whois_fallback_uses_iana_referral():
    calls = []

    def raw(server, q, t):
        calls.append((server, q))
        return "refer: whois.registry.test\n" if server == "whois.iana.org" else WHOIS

    ctx = make_ctx()
    ctx.http.offline = False  # whois does not use HttpClient
    b = rdap.whois_lookup(ctx, D, raw_fn=raw)
    assert calls == [("whois.iana.org", "com"), ("whois.registry.test", D)]
    assert b.observations[0].data["via"] == "whois" and b.observations[0].confidence.value == "medium"


def test_whois_skipped_in_offline_mode():
    ctx = make_ctx()
    ctx.run_source("registration", "whois", lambda: rdap.whois_lookup(ctx, D, raw_fn=lambda *a: pytest.fail("network")))
    assert source(ctx.inv, "whois").status == Status.SKIPPED


# ------------------------------------------------------------------------ certificates
CRT = [
    {"id": 1, "issuer_name": "CA1", "common_name": "example.com", "name_value": "example.com\nwww.example.com\n*.dev.example.com",
     "not_before": "2024-01-01T00:00:00", "not_after": "2024-04-01T00:00:00", "entry_timestamp": "2024-01-01T01:00:00"},
    {"id": 2, "issuer_name": "CA1", "common_name": "api.example.com", "name_value": "api.example.com\nevil.com\nuser@example.com",
     "not_before": "2025-01-01T00:00:00", "not_after": "2025-04-01T00:00:00", "entry_timestamp": "2025-01-01T01:00:00"},
    {"id": 3, "common_name": "WWW.Example.com.", "name_value": "WWW.Example.com.", "not_before": "2023-01-01T00:00:00", "not_after": "2023-04-01T00:00:00"},
    "garbage", {"no_id": True},
]


def test_crtsh_newline_separated_sans_are_split():
    assert certificates.split_names("a.example.com\nb.example.com\r\n") == ["a.example.com", "b.example.com"]


def test_crtsh_parse_filters_normalises_and_dedupes():
    obs, rels, stats = certificates.parse_crtsh(CRT, D)
    subs = {o.value: o for o in obs if o.kind == "subdomain"}
    assert set(subs) == {"www.example.com", "dev.example.com", "api.example.com"}  # apex, evil.com, email excluded
    assert subs["dev.example.com"].data["from_wildcard_cert_only"] and subs["dev.example.com"].confidence.value == "low"
    assert subs["www.example.com"].data["first_seen"] == "2023-01-01T00:00:00"  # earliest across 2 certs
    assert subs["www.example.com"].data["cert_count"] == 2
    assert stats["certificates"] == 3
    assert all("\n" not in o.value for o in obs)


def test_crtsh_never_claims_liveness():
    obs, rels, _ = certificates.parse_crtsh(CRT, D)
    notes = [r.note for r in rels if r.predicate == "has_subdomain"]
    assert notes and all("liveness not tested" in n for n in notes)
    assert all("dns_state" not in o.data for o in obs if o.kind == "subdomain")


def test_crtsh_rejects_non_list():
    with pytest.raises(ProviderError):
        certificates.parse_crtsh({"error": "x"}, D)


def test_crtsh_lookup_empty_and_null():
    for body in ("", "null", "[]"):
        ctx = make_ctx({"https://crt.sh/": (200, body)})
        b = certificates.crtsh_lookup(ctx, D)
        assert b.observations == []


def test_crtsh_502_and_garbage_are_failed():
    ctx = make_ctx({"https://crt.sh/": (502, "<html>Bad Gateway</html>")})
    ctx.run_source("certificates", "crt.sh", lambda: certificates.crtsh_lookup(ctx, D))
    assert source(ctx.inv, "crt.sh").status == Status.FAILED
    ctx = make_ctx({"https://crt.sh/": (200, "<html>maintenance</html>")})
    ctx.run_source("certificates", "crt.sh", lambda: certificates.crtsh_lookup(ctx, D))
    assert source(ctx.inv, "crt.sh").status == Status.FAILED


# --------------------------------------------------------------------------- subdomains
def test_hackertarget_parse_and_filtering():
    out = subdomains.parse_hackertarget("www.example.com,1.2.3.4\nEVIL.com,5.6.7.8\nblog.example.com,\nuser@example.com,1.1.1.1\n", D)
    assert out == [("www.example.com", "1.2.3.4"), ("blog.example.com", None)]


@pytest.mark.parametrize("text", ["API count exceeded - Increase Quota with Membership", "error check your search parameter"])
def test_hackertarget_quota_text_is_failure_not_empty_success(text):
    ctx = make_ctx({"https://api.hackertarget.com/hostsearch/": (200, text)})
    ctx.run_source("subdomains", "hackertarget", lambda: subdomains.hackertarget(ctx, D))
    s = source(ctx.inv, "hackertarget")
    assert s.status == Status.FAILED and "rate" in s.detail.lower() or "quota" in s.detail.lower()


def test_optional_sources_skipped_without_credentials():
    ctx = make_ctx({"https://api.hackertarget.com/hostsearch/": (200, "www.example.com,1.1.1.1")})
    subdomains.discover_passive(ctx, D)
    assert source(ctx.inv, "alienvault-otx").status == Status.SKIPPED
    assert source(ctx.inv, "virustotal").status == Status.SKIPPED
    assert "OTX_API_KEY" in source(ctx.inv, "alienvault-otx").detail
    assert source(ctx.inv, "hackertarget").status == Status.OK


def test_otx_requires_auth_error_is_reported():
    ctx = make_ctx({"https://otx.alienvault.com/": (429, {"detail": "Anonymous access to this endpoint is limited"})},
                   creds={"OTX_API_KEY": "k"})
    ctx.run_source("subdomains", "alienvault-otx", lambda: subdomains.otx(ctx, D), requires="OTX_API_KEY")
    assert source(ctx.inv, "alienvault-otx").status == Status.FAILED


def test_otx_parse():
    doc = {"passive_dns": [{"hostname": "a.example.com", "address": "1.1.1.1", "record_type": "A", "first": "2020-01-01", "last": "2021-01-01"},
                           {"hostname": "a.example.com", "address": "2.2.2.2", "record_type": "A", "first": "2019-01-01", "last": "2022-01-01"},
                           {"hostname": "x.other.com"}, "junk"]}
    r = subdomains.parse_otx(doc, D)
    assert r == [{"name": "a.example.com", "first": "2019-01-01", "last": "2022-01-01", "ips": ["1.1.1.1", "2.2.2.2"]}]
    with pytest.raises(ProviderError):
        subdomains.parse_otx({"passive_dns": "nope"}, D)


def _ctx_with_subs(names, resolver, limit=200):
    ctx = make_ctx(resolver=resolver, limit=limit)
    from vestige.core.models import Confidence, Observation
    for n in names:
        ctx.inv.obs  # noqa: B018
        ctx.inv.observations.append(Observation("subdomain", n, "crt.sh", Confidence.MEDIUM, data={"sources": ["crt.sh"]}))
    return ctx


def test_resolution_states():
    r = FakeResolver({("ok.example.com", "A"): ["9.9.9.9"], ("wild.example.com", "A"): ["1.2.3.4"]},
                     nxdomain=["gone.example.com"],
                     errors={("slow.example.com", "A"): "timeout", ("slow.example.com", "AAAA"): "timeout"})
    ctx = _ctx_with_subs(["ok.example.com", "gone.example.com", "slow.example.com", "wild.example.com"], r)
    subdomains.resolve_subdomains(ctx, D, wildcard_ips={"1.2.3.4"})
    st = {o.value: o.data["dns_state"] for o in ctx.inv.obs("subdomain")}
    assert st == {"ok.example.com": "resolved", "gone.example.com": "no_dns_answer",
                  "slow.example.com": "unverified", "wild.example.com": "wildcard_only"}
    resolved = [rel for rel in ctx.inv.relationships if rel.predicate == "resolves_to"]
    assert {(x.subject, x.confidence.value) for x in resolved} == {("ok.example.com", "high"), ("wild.example.com", "low")}


def test_limit_leaves_remaining_unverified_and_untested():
    r = FakeResolver({(f"s{i}.example.com", "A"): ["9.9.9.9"] for i in range(5)})
    ctx = _ctx_with_subs([f"s{i}.example.com" for i in range(5)], r, limit=2)
    subdomains.resolve_subdomains(ctx, D)
    states = sorted(o.data["dns_state"] for o in ctx.inv.obs("subdomain"))
    assert states == ["resolved", "resolved", "unverified", "unverified", "unverified"]
    assert len({q[0] for q in r.calls}) == 2  # only 2 names were actually queried


def test_discovered_without_resolution_has_no_dns_state():
    obs, _, _ = certificates.parse_crtsh(CRT, D)
    assert all("dns_state" not in o.data for o in obs)  # "discovered" != "resolved"


def test_correlation_merges_sources_and_raises_confidence():
    from vestige.core.models import Confidence, Observation
    ctx = make_ctx()
    ctx.inv.observations += [Observation("subdomain", "a.example.com", "crt.sh", Confidence.MEDIUM, data={}),
                             Observation("subdomain", "a.example.com", "hackertarget", Confidence.MEDIUM, data={}),
                             Observation("subdomain", "b.example.com", "crt.sh", Confidence.MEDIUM, data={})]
    correlate(ctx.inv)
    o = {x.value: x for x in ctx.inv.observations}
    assert o["a.example.com"].data["sources"] == ["crt.sh", "hackertarget"] and o["a.example.com"].confidence.value == "high"
    assert o["b.example.com"].confidence.value == "medium"
