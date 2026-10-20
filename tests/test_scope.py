import pytest

from vestige.core.scope import (Scope, ScopeError, ValidationError, classify_ip, display_domain, in_scope,
                                is_public_ip, normalize_domain, normalize_hostname)


@pytest.mark.parametrize("raw,expected", [
    ("Example.COM", "example.com"),
    ("example.com.", "example.com"),
    ("  www.Example.com  ", "www.example.com"),
    ("bücher.example", "xn--bcher-kva.example"),
    ("münchen.de", "xn--mnchen-3ya.de"),
    ("*.example.com", "example.com"),
    ("xn--bcher-kva.example", "xn--bcher-kva.example"),
])
def test_normalize_domain_ok(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "   ", "localhost", "http://example.com", "example.com/path", "user@example.com", "example.com:8080",
    "exa mple.com", "-bad.example.com", "bad-.example.com", "a..b.com", "1.2.3.4", "example.123", "a" * 64 + ".com",
    "example.com?x=1", "_dmarc.example.com",
])
def test_normalize_domain_rejects(raw):
    with pytest.raises(ValidationError):
        normalize_domain(raw)


def test_underscore_allowed_only_when_requested():
    assert normalize_domain("_dmarc.example.com", allow_underscore=True) == "_dmarc.example.com"


def test_display_domain_roundtrip():
    assert display_domain("xn--bcher-kva.example") == "bücher.example"


def test_normalize_hostname_filters_garbage_and_scope():
    assert normalize_hostname("WWW.Example.com.", "example.com") == "www.example.com"
    assert normalize_hostname("*.dev.example.com", "example.com") == "dev.example.com"
    assert normalize_hostname("evil.com", "example.com") is None
    assert normalize_hostname("notexample.com", "example.com") is None  # suffix trick
    assert normalize_hostname("user@example.com", "example.com") is None
    assert normalize_hostname("1.2.3.4", "example.com") is None
    assert normalize_hostname("", "example.com") is None


def test_in_scope_suffix_boundaries():
    assert in_scope("example.com", "example.com")
    assert in_scope("a.b.example.com", "example.com")
    assert not in_scope("badexample.com", "example.com")
    assert not in_scope("example.com.evil.com", "example.com")


@pytest.mark.parametrize("ip,cls,public", [
    ("8.8.8.8", "public", True), ("1.1.1.1", "public", True),
    ("10.0.0.1", "private", False), ("192.168.1.5", "private", False), ("172.16.0.1", "private", False),
    ("127.0.0.1", "loopback", False), ("::1", "loopback", False),
    ("169.254.169.254", "link-local", False),  # cloud metadata address
    ("224.0.0.1", "multicast", False), ("0.0.0.0", "unspecified", False),
    ("240.0.0.1", "reserved", False), ("100.64.0.1", "shared-address-space (CGNAT)", False),
    ("fe80::1", "link-local", False), ("fc00::1", "private", False),
    ("2606:4700:4700::1111", "public", True), ("::ffff:127.0.0.1", "loopback", False),
])
def test_classify_ip(ip, cls, public):
    r = classify_ip(ip)
    assert r["classification"] == cls
    assert r["is_global"] is public
    assert is_public_ip(ip) is public


@pytest.mark.parametrize("bad", ["", "999.1.1.1", "abc", "1.2.3", "1.2.3.4.5", "example.com", "12345"])
def test_classify_ip_invalid(bad):
    with pytest.raises(ValidationError):
        classify_ip(bad)


def test_scope_blocks_http_by_default():
    s = Scope("example.com")
    assert not s.http_allowed
    with pytest.raises(ScopeError, match="--http-checks"):
        s.require_http()


def test_scope_needs_both_flags():
    with pytest.raises(ScopeError, match="--confirm-authorized"):
        Scope("example.com", http_checks=True).require_http()
    assert not Scope("example.com", confirmed_authorized=True).http_allowed
    assert Scope("example.com", True, True).http_allowed


def test_scope_check_url():
    s = Scope("example.com", True, True)
    assert s.check_url("https://www.example.com/x") == "www.example.com"
    for url in ["https://evil.com/", "https://example.com.evil.com/", "ftp://example.com/", "file:///etc/passwd",
                "https://user:pw@example.com/", "https://127.0.0.1/", "http://169.254.169.254/latest/meta-data/"]:
        with pytest.raises(ScopeError):
            s.check_url(url)


def test_scope_check_url_requires_authorisation():
    with pytest.raises(ScopeError):
        Scope("example.com").check_url("https://example.com/")
