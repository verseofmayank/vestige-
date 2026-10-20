"""Authorisation gating, redirect scope validation, SSRF protection and header evaluation."""
from datetime import datetime, timezone

import pytest

from tests.conftest import authorised_scope, make_ctx, source
from vestige.core.models import Status
from vestige.core.scope import Scope, ScopeError
from vestige.modules import web

D = "example.com"
PUBLIC = lambda host, port=443: ["93.184.216.34"]  # noqa: E731
OK_TLS = lambda host, port=443, timeout=8.0, ip=None: {"host": host, "verified": True, "days_until_expiry": 90, "not_after": "x", "issuer_org": "CA"}  # noqa: E731


def web_ctx(routes, scope=None, resolve=PUBLIC):
    return make_ctx(routes, scope=scope or authorised_scope(), resolve_public_fn=resolve, tls_fn=OK_TLS)


def test_passive_mode_sends_no_http_and_marks_skipped():
    ctx = make_ctx({"https://example.com/": (200, "x")}, scope=Scope(D))
    web.web_checks(ctx, D)
    assert ctx.http.transport.calls == []
    assert {s.source: s.status for s in ctx.inv.sources} == {k: Status.SKIPPED for k in
                                                           ["http-response", "tls-certificate", "security.txt", "robots.txt/sitemap"]}
    assert any("passive mode" in s.detail for s in ctx.inv.sources)


def test_http_checks_alone_do_not_authorise():
    ctx = make_ctx({"https://example.com/": (200, "x")}, scope=Scope(D, http_checks=True))
    web.web_checks(ctx, D)
    assert ctx.http.transport.calls == []


def test_confirmation_alone_does_not_authorise():
    ctx = make_ctx({"https://example.com/": (200, "x")}, scope=Scope(D, confirmed_authorized=True))
    web.web_checks(ctx, D)
    assert ctx.http.transport.calls == []


def test_no_scope_object_means_passive():
    ctx = make_ctx({"https://example.com/": (200, "x")}, scope=None)
    web.web_checks(ctx, D)
    assert ctx.http.transport.calls == []


def test_unauthorised_direct_fetch_is_refused_even_if_called_directly():
    ctx = make_ctx({"https://example.com/": (200, "x")}, scope=Scope(D), resolve_public_fn=PUBLIC)
    with pytest.raises(ScopeError):
        web._safe_get(ctx, "https://example.com/")
    assert ctx.http.transport.calls == []


def test_authorised_run_collects_http_observations():
    ctx = web_ctx({"https://example.com/": (200, "<html>", {"content-type": "text/html", "Server": "nginx", "Strict-Transport-Security": "max-age=31536000"}),
                   "https://example.com/.well-known/security.txt": (404, ""), "https://example.com/security.txt": (404, ""),
                   "https://example.com/robots.txt": (404, ""), "https://example.com/sitemap.xml": (404, "")})
    web.web_checks(ctx, D)
    r = ctx.inv.obs("http_response")[0]
    assert r.data["status"] == 200 and r.data["headers"]["hsts_max_age"] == 31536000
    assert r.data["technology_headers"] == {"server": "nginx"}
    assert source(ctx.inv, "http-response").status == Status.OK


def test_redirect_to_in_scope_subdomain_is_followed():
    ctx = web_ctx({"https://example.com/": (301, "", {"Location": "https://www.example.com/home"}),
                   "https://www.example.com/home": (200, "ok")})
    chain, res, stop = web.follow_chain(ctx, "https://example.com/")
    assert [c["url"] for c in chain] == ["https://example.com/", "https://www.example.com/home"] and res.status == 200 and stop == ""


@pytest.mark.parametrize("target", ["https://evil.com/phish", "https://example.com.evil.com/", "https://notexample.com/",
                                    "http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080/admin", "file:///etc/passwd",
                                    "ftp://example.com/x"])
def test_redirect_outside_scope_is_not_followed(target):
    ctx = web_ctx({"https://example.com/": (302, "", {"Location": target})})
    chain, res, stop = web.follow_chain(ctx, "https://example.com/")
    assert len(chain) == 1 and chain[0]["redirect_to"] == target and "not followed" in stop
    assert ctx.http.transport.calls == ["https://example.com/"]  # the second request was never sent


def test_in_scope_name_resolving_to_private_address_is_refused():
    def resolver(host, port=443):
        if host == "internal.example.com":
            raise ScopeError("internal.example.com resolves to non-public address(es) ['10.0.0.5']; refusing to connect")
        return ["93.184.216.34"]
    ctx = web_ctx({"https://example.com/": (302, "", {"Location": "https://internal.example.com/"}),
                   "https://internal.example.com/": (200, "secret")}, resolve=resolver)
    chain, res, stop = web.follow_chain(ctx, "https://example.com/")
    assert "internal.example.com/" not in " ".join(ctx.http.transport.calls) and "non-public" in stop and res.status == 302


def test_real_resolver_guard_rejects_loopback():
    from vestige.core.scope import resolve_public
    with pytest.raises(ScopeError):
        resolve_public("localhost")


def test_redirect_loop_is_bounded():
    ctx = web_ctx({"https://example.com/": (302, "", {"Location": "https://example.com/"})})
    chain, res, stop = web.follow_chain(ctx, "https://example.com/")
    assert len(chain) == web.MAX_REDIRECTS + 1 and "redirects" in stop


def test_relative_redirects_resolve_inside_scope():
    ctx = web_ctx({"https://example.com/": (302, "", {"Location": "/login"}), "https://example.com/login": (200, "ok")})
    chain, res, _ = web.follow_chain(ctx, "https://example.com/")
    assert chain[-1]["url"] == "https://example.com/login"


def test_responses_are_size_limited():
    ctx = web_ctx({})
    # the helper passes a body cap to the client for every target request
    seen = {}
    orig = ctx.http.get

    def spy(url, **kw):
        seen.update(kw)
        return orig(url, **kw)
    ctx.http.get = spy
    ctx.http.transport.routes["https://example.com/"] = (200, "x")
    web._safe_get(ctx, "https://example.com/")
    assert seen["max_bytes"] <= 256 * 1024 and seen["allow_redirects"] is False and seen["retry"] is False


# ----------------------------------------------------------------------- parsers
def test_security_header_evaluation_missing_vs_present():
    h = web.evaluate_headers({"strict-transport-security": "max-age=100; includeSubDomains; preload",
                              "content-security-policy": "default-src 'self' 'unsafe-inline'"}, True)
    assert h["hsts_max_age"] == 100 and h["hsts_include_subdomains"] and h["hsts_preload"]
    assert h["csp_unsafe_inline"] and not h["csp_unsafe_eval"]
    assert h["x-content-type-options"] is None and h["referrer-policy"] is None and h["permissions-policy"] is None


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_security_txt_valid():
    p = web.parse_security_txt("Contact: mailto:sec@example.com\nExpires: 2027-01-01T00:00:00Z\nPreferred-Languages: en\n", NOW)
    assert p["problems"] == [] and p["fields"]["contact"] == ["mailto:sec@example.com"]


def test_security_txt_problems():
    p = web.parse_security_txt("Expires: 2020-01-01T00:00:00Z\n", NOW)
    assert "missing required 'Contact' field" in p["problems"] and any("in the past" in x for x in p["problems"])
    p = web.parse_security_txt("Contact: sec@example.com\n", NOW)
    assert "missing required 'Expires' field" in p["problems"] and any("mailto" in x for x in p["problems"])
    assert any("ISO 8601" in x for x in web.parse_security_txt("Contact: https://x.test\nExpires: soon\n", NOW)["problems"])
    assert any("only once" in x for x in web.parse_security_txt("Contact: https://x.test\nExpires: 2027-01-01T00:00:00Z\nExpires: 2028-01-01T00:00:00Z\n", NOW)["problems"])


def test_security_txt_pgp_detection():
    assert web.parse_security_txt("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nContact: https://x.test\nExpires: 2027-01-01T00:00:00Z\n", NOW)["pgp_signed"]


def test_robots_and_sitemap():
    r = web.parse_robots("User-agent: *\nDisallow: /a\nDisallow: /b # c\nAllow: /\nDisallow:\nSitemap: https://example.com/s.xml\n")
    assert r == {"disallow_rules": 2, "allow_rules": 1, "sitemaps": ["https://example.com/s.xml"], "user_agent_groups": 1}
    s = web.parse_sitemap("<urlset><url><loc>https://e.com/1</loc><lastmod>2024-01-02</lastmod></url><url><loc>https://e.com/2</loc><lastmod>2023-05-05</lastmod></url></urlset>")
    assert s["url_count"] == 2 and s["lastmod_min"] == "2023-05-05" and s["lastmod_max"] == "2024-01-02" and not s["is_index"]


def test_html_page_at_security_txt_path_is_not_accepted():
    ctx = web_ctx({"https://example.com/.well-known/security.txt": (200, "<html>soft 404</html>", {"content-type": "text/html"}),
                   "https://example.com/security.txt": (404, "")})
    web.web_checks(ctx, D)
    assert ctx.inv.obs("security_txt")[0].value == "absent"
