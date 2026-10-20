"""Offline demonstration built from CANNED RESPONSES.

Everything here is fixture data for the reserved name `vestige-demo.example`. No network traffic
is sent. Reports produced from it are marked mode="offline-fixture" and carry a prominent banner;
they must never be presented as live scan results.
"""
from __future__ import annotations

from datetime import datetime, timezone

from vestige.core.context import Context
from vestige.core.http_client import FixtureTransport, HttpClient
from vestige.core.models import Investigation
from vestige.core.scope import Scope
from vestige.modules.dns import FakeResolver
from vestige.modules.domain import investigate_domain

DEMO_DOMAIN = "vestige-demo.example"
DEMO_NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)  # fixed clock so output is reproducible
APEX_IPS = ["104.20.30.40", "104.20.30.41"]


def _rev(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"


def demo_resolver() -> FakeResolver:
    d = DEMO_DOMAIN
    rec = {
        (d, "A"): APEX_IPS, (d, "AAAA"): ["2606:4700:20::6814:1e28"],
        (d, "MX"): ["10 mx1.vestige-demo.example.", "20 mx2.vestige-demo.example."],
        (d, "NS"): ["ada.ns.cloudflare.com.", "bob.ns.cloudflare.com."],
        (d, "TXT"): ["v=spf1 include:_spf.google.com include:sendgrid.net ~all", "site-verification=demo-fixture-token"],
        (d, "SOA"): ["ada.ns.cloudflare.com. dns.cloudflare.com. 2345678901 10000 2400 604800 1800"],
        (f"_dmarc.{d}", "TXT"): [f"v=DMARC1; p=none; rua=mailto:dmarc-reports@{d}"],
        ("mx1." + d, "A"): ["142.250.10.26"], ("mx2." + d, "A"): ["142.250.10.27"],
        ("www." + d, "A"): [APEX_IPS[0]], ("api." + d, "A"): [APEX_IPS[1]],
        ("blog." + d, "A"): ["104.20.30.43"], ("vpn." + d, "A"): ["104.20.30.42"], ("mail." + d, "A"): ["142.250.10.26"],
        (_rev(APEX_IPS[0]), "TXT"): ['"13335 | 104.20.0.0/20 | US | arin | 2010-07-14"'],
        (_rev(APEX_IPS[1]), "TXT"): ['"13335 | 104.20.0.0/20 | US | arin | 2010-07-14"'],
        (_rev("104.20.30.42"), "TXT"): ['"13335 | 104.20.0.0/20 | US | arin | 2010-07-14"'],
        (_rev("104.20.30.43"), "TXT"): ['"13335 | 104.20.0.0/20 | US | arin | 2010-07-14"'],
        (_rev("142.250.10.26"), "TXT"): ['"15169 | 142.250.0.0/16 | US | arin | 2000-03-30"'],
        (_rev("142.250.10.27"), "TXT"): ['"15169 | 142.250.0.0/16 | US | arin | 2000-03-30"'],
        ("AS13335.asn.cymru.com", "TXT"): ['"13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"'],
        ("AS15169.asn.cymru.com", "TXT"): ['"15169 | US | arin | 2000-03-30 | GOOGLE, US"'],
        ("40.30.20.104.in-addr.arpa", "PTR"): ["demo-edge.vestige-demo.example."],
    }
    return FakeResolver(
        records=rec,
        nxdomain=[f"staging.{d}", f"old-shop.{d}", f"_mta-sts.{d}", f"_smtp._tls.{d}"],
        errors={(f"dev.{d}", "A"): "timeout", (f"dev.{d}", "AAAA"): "timeout"},
        wildcard={},
    )


def demo_transport() -> FixtureTransport:
    d = DEMO_DOMAIN
    crt = [
        {"id": 9001, "issuer_name": "C=US, O=Demo CA, CN=Demo CA R1", "common_name": d,
         "name_value": f"{d}\nwww.{d}\napi.{d}", "entry_timestamp": "2026-06-01T10:00:00", "not_before": "2026-06-01T00:00:00",
         "not_after": "2026-12-01T00:00:00", "serial_number": "01DEMO"},
        {"id": 9002, "issuer_name": "C=US, O=Demo CA, CN=Demo CA R1", "common_name": f"staging.{d}",
         "name_value": f"staging.{d}\n*.dev.{d}", "entry_timestamp": "2025-02-11T10:00:00", "not_before": "2025-02-11T00:00:00",
         "not_after": "2025-05-12T00:00:00", "serial_number": "02DEMO"},
        {"id": 9003, "issuer_name": "C=US, O=Demo CA, CN=Demo CA R1", "common_name": f"mail.{d}",
         "name_value": f"mail.{d}", "entry_timestamp": "2026-03-01T10:00:00", "not_before": "2026-03-01T00:00:00",
         "not_after": "2026-09-27T00:00:00", "serial_number": "03DEMO"},
    ]
    rdap = {
        "objectClassName": "domain", "ldhName": d, "status": ["client transfer prohibited"],
        "events": [{"eventAction": "registration", "eventDate": "2019-11-05T09:00:00Z"},
                   {"eventAction": "expiration", "eventDate": "2026-11-05T09:00:00Z"},
                   {"eventAction": "last changed", "eventDate": "2026-09-01T09:00:00Z"}],
        "entities": [{"objectClassName": "entity", "roles": ["registrar"],
                      "vcardArray": ["vcard", [["fn", {}, "text", "Demo Registrar Inc. (fixture)"]]],
                      "publicIds": [{"type": "IANA Registrar ID", "identifier": "9999"}]}],
        "nameservers": [{"ldhName": "ADA.NS.CLOUDFLARE.COM"}, {"ldhName": "BOB.NS.CLOUDFLARE.COM"}],
        "secureDNS": {"delegationSigned": False},
    }
    wayback = [["timestamp", "original", "statuscode", "mimetype"],
               ["20190301120000", f"http://old-shop.{d}/cart?session=abc123SECRET&item=4", "200", "text/html"],
               ["20200615080000", f"https://{d}/about", "200", "text/html"],
               ["20211010101010", f"https://blog.{d}/2021/hello-world", "200", "text/html"]]
    urlscan = {"results": [{"_id": "demo-0001", "task": {"time": "2026-08-14T10:00:00.000Z", "url": f"https://www.{d}/"},
                            "page": {"domain": f"www.{d}", "url": f"https://www.{d}/?token=SHOULD-BE-REDACTED", "ip": APEX_IPS[0],
                                     "asn": "AS13335", "server": "cloudflare"}}]}
    base = f"https://{d}"
    return FixtureTransport({
        "https://data.iana.org/rdap/dns.json": (200, {"services": [[["example"], ["https://rdap.demo.example/"]]]}),
        f"https://rdap.demo.example/domain/{d}": (200, rdap),
        "https://crt.sh/": (200, crt),
        "https://api.hackertarget.com/hostsearch/": (200, f"www.{d},{APEX_IPS[0]}\napi.{d},{APEX_IPS[1]}\nvpn.{d},104.20.30.42\n"),
        "https://web.archive.org/cdx/search/cdx": (200, wayback),
        "https://urlscan.io/api/v1/search/": (200, urlscan),
        "https://raw.githubusercontent.com/disposable-email-domains/": (200, "\n".join(f"disp{i}.example" for i in range(150))),
        f"https://ipapi.co/{APEX_IPS[0]}/json/": (200, {"ip": APEX_IPS[0], "city": "San Francisco", "region": "California",
                                                      "country_name": "United States", "country_code": "US", "org": "CLOUDFLARENET",
                                                      "asn": "AS13335", "timezone": "America/Los_Angeles", "latitude": 37.77, "longitude": -122.41}),
        f"https://ipapi.co/{APEX_IPS[1]}/json/": (429, {"error": True, "reason": "RateLimited"}),
        f"https://internetdb.shodan.io/{APEX_IPS[0]}": (200, {"ip": APEX_IPS[0], "ports": [80, 443], "hostnames": [], "tags": ["cdn"],
                                                              "cpes": [], "vulns": ["CVE-2021-41773"]}),
        f"https://internetdb.shodan.io/{APEX_IPS[1]}": (404, {"detail": "No information available"}),
        "https://api.abuseipdb.com/api/v2/check": (200, {"data": {"abuseConfidenceScore": 32, "totalReports": 7, "numDistinctUsers": 3,
                                                                 "lastReportedAt": "2026-09-20T12:00:00+00:00", "isWhitelisted": False,
                                                                 "usageType": "Content Delivery Network", "isp": "Demo CDN", "countryCode": "US"}}),
        f"{base}/robots.txt": (200, "User-agent: *\nDisallow: /admin\nDisallow: /tmp\nSitemap: " + base + "/sitemap.xml\n", {"content-type": "text/plain"}),
        f"{base}/sitemap.xml": (200, "<urlset><url><loc>" + base + "/</loc><lastmod>2026-09-01</lastmod></url></urlset>", {"content-type": "application/xml"}),
        f"{base}/.well-known/security.txt": (404, "not found"),
        f"{base}/security.txt": (404, "not found"),
        f"{base}/": (200, "<html>demo</html>", {"content-type": "text/html", "server": "nginx/1.18.0",
                                               "x-content-type-options": "nosniff"}),
    })


def demo_tls(host, port=443, timeout=8.0, ip=None) -> dict:
    return {"host": host, "verified": True, "hostname_valid": True, "protocol": "TLSv1.3", "issuer_org": "Demo CA (fixture)",
            "issuer_cn": "Demo CA R1", "subject_cn": host, "san": [host, f"www.{host}"],
            "not_before": "2026-09-01T00:00:00+00:00", "not_after": "2026-10-13T00:00:00+00:00", "days_until_expiry": 12}


def run_demo(on_source=None, workers: int = 4) -> Investigation:
    inv = Investigation(command="demo", target=DEMO_DOMAIN, mode="offline-fixture")
    http = HttpClient(transport=demo_transport(), retries=0)
    ctx = Context(http=http, inv=inv, resolver=demo_resolver(), scope=Scope(DEMO_DOMAIN, True, True),
                  creds={"ABUSEIPDB_KEY": "fixture-not-a-real-key"}, limit=200, max_workers=workers,
                  resolve_public_fn=lambda host, port=443: [APEX_IPS[0]], tls_fn=demo_tls, on_source=on_source)
    investigate_domain(ctx, DEMO_DOMAIN, dkim_selectors=["selector1"], now=DEMO_NOW)
    inv.limitations.insert(0, "FIXTURE DATA: produced from canned responses by `vestige demo`; no network requests were made.")
    return inv
