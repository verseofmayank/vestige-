"""Username recon: a bare HTTP 200 must never be a 'FOUND'."""
import json

import pytest

from tests.conftest import make_ctx
from vestige.core.http_client import HttpResult
from vestige.core.scope import ValidationError
from vestige.modules import username as U

GITHUB = {"name": "GitHub", "url": "https://api.github.com/users/{u}", "profile": "https://github.com/{u}",
          "strategy": "json_path", "path": "login", "evidence_fields": ["name"]}
HN = {"name": "HN", "url": "https://hn.test/user/{u}.json", "profile": "https://hn.test/user?id={u}", "strategy": "json_path",
      "path": "id", "null_means_missing": True}
GL = {"name": "GL", "url": "https://gl.test/api/users?username={u}", "profile": "https://gl.test/{u}", "strategy": "json_list", "field": "username"}
CF = {"name": "CF", "url": "https://cf.test/api/user.info?handles={u}", "profile": "https://cf.test/{u}", "strategy": "json_path",
      "path": "result.0.handle", "not_found_status": [400], "not_found_body": "not found"}
KB = {"name": "KB", "url": "https://kb.test/lookup?usernames={u}", "profile": "https://kb.test/{u}", "strategy": "json_path",
      "path": "them.0.basics.username", "null_path_means_missing": "them.0"}


def res(status=200, body="", url="https://api.github.com/users/x", ctype="application/json", headers=None):
    if not isinstance(body, str):
        body = json.dumps(body)
    return HttpResult(status=status, url=url, headers={"content-type": ctype, **(headers or {})}, text=body)


def test_found_requires_api_echo_of_exact_username():
    r = U.evaluate(GITHUB, "torvalds", res(200, {"login": "torvalds", "name": "Linus"}))
    assert r["status"] == U.FOUND and r["confidence"] == "high" and r["evidence"] == {"name": "Linus"}
    assert r["profile_url"] == "https://github.com/torvalds"


def test_case_insensitive_match():
    assert U.evaluate(GITHUB, "Torvalds", res(200, {"login": "torvalds"}))["status"] == U.FOUND


def test_http_200_html_page_is_never_found():
    r = U.evaluate(GITHUB, "ghost", res(200, "<html><title>Welcome</title></html>", ctype="text/html"))
    assert r["status"] == U.UNKNOWN and "does not prove" in r["detail"]


def test_http_200_json_without_matching_field_is_unknown():
    assert U.evaluate(GITHUB, "ghost", res(200, {"message": "hello"}))["status"] == U.UNKNOWN
    assert U.evaluate(GITHUB, "ghost", res(200, {"login": "someone-else"}))["status"] == U.UNKNOWN


def test_404_is_not_found():
    r = U.evaluate(GITHUB, "ghost", res(404, {"message": "Not Found"}))
    assert r["status"] == U.NOT_FOUND and r["confidence"] == "high"


@pytest.mark.parametrize("status", [401, 403, 429, 999])
def test_blocks_and_rate_limits_are_blocked_not_notfound(status):
    r = U.evaluate(GITHUB, "x", res(status, "denied"))
    assert r["status"] == U.BLOCKED


def test_503_is_blocked_and_500_is_error():
    assert U.evaluate(GITHUB, "x", res(503, "")) ["status"] == U.BLOCKED
    assert U.evaluate(GITHUB, "x", res(500, ""))["status"] == U.ERROR


@pytest.mark.parametrize("body", ["<html>Just a moment...</html>", "<div class='g-recaptcha'>captcha</div>",
                                  "<title>Attention Required! | Cloudflare</title>", "Please verify you are human"])
def test_challenge_pages_are_blocked_even_with_200(body):
    r = U.evaluate(GITHUB, "x", res(200, body, ctype="text/html"))
    assert r["status"] == U.BLOCKED and r["status"] != U.FOUND


def test_cloudflare_mitigated_header():
    assert U.evaluate(GITHUB, "x", res(403, "", headers={"cf-mitigated": "challenge"}))["status"] == U.BLOCKED


def test_redirect_to_login_wall_is_blocked():
    r = U.evaluate(GITHUB, "x", res(200, "<html>Sign in</html>", url="https://api.github.com/login?return_to=/x", ctype="text/html"))
    assert r["status"] == U.BLOCKED and "login" in r["detail"]


def test_redirect_to_other_host_is_blocked():
    r = U.evaluate(GITHUB, "x", res(200, "{}", url="https://auth.other.example/sso"))
    assert r["status"] == U.BLOCKED and "different host" in r["detail"]


def test_null_means_missing_only_when_declared():
    assert U.evaluate(HN, "nobody", res(200, "null", url="https://hn.test/user/nobody.json"))["status"] == U.NOT_FOUND
    r = U.evaluate(GITHUB, "nobody", res(200, "null"))
    assert r["status"] == U.UNKNOWN  # platform did not declare null semantics


def test_json_list_strategy():
    u = "https://gl.test/api/users?username=bob"
    assert U.evaluate(GL, "bob", res(200, [], url=u))["status"] == U.NOT_FOUND
    assert U.evaluate(GL, "bob", res(200, [{"username": "bob"}], url=u))["status"] == U.FOUND
    assert U.evaluate(GL, "bob", res(200, [{"username": "bobby"}], url=u))["status"] == U.UNKNOWN  # substring/fuzzy match rejected


def test_custom_not_found_status_requires_body_marker():
    u = "https://cf.test/api/user.info?handles=x"
    assert U.evaluate(CF, "x", res(400, {"status": "FAILED", "comment": "handles: User with handle x not found"}, url=u))["status"] == U.NOT_FOUND
    assert U.evaluate(CF, "x", res(400, {"comment": "bad request"}, url=u))["status"] == U.UNKNOWN


def test_nested_path_and_empty_them():
    u = "https://kb.test/lookup?usernames=x"
    assert U.evaluate(KB, "x", res(200, {"them": [{"basics": {"username": "x"}}]}, url=u))["status"] == U.FOUND
    assert U.evaluate(KB, "x", res(200, {"them": [None]}, url=u))["status"] == U.NOT_FOUND


def test_validate_username():
    assert U.validate_username("@alice_01") == "alice_01"
    for bad in ["", "a b", "a/b", "../x", "a" * 65, "x?y=1", "é"]:
        with pytest.raises(ValidationError):
            U.validate_username(bad)


def test_platform_config_is_well_formed():
    plats = U.load_platforms()
    assert len(plats) >= 10
    names = [p["name"] for p in plats]
    assert len(names) == len(set(names))
    for p in plats:
        assert p["strategy"] in {"json_path", "json_list", "unverifiable"}
        if p["strategy"] != "unverifiable":
            assert p["url"].startswith("https://"), "HTTPS only"
            assert "{u}" in p["url"]


def test_unverifiable_platforms_are_never_requested_and_report_why():
    ctx = make_ctx({"https://": (200, "<html>")})
    results = U.username_recon(ctx, "someone")
    assert ctx.http.transport.calls  # real API platforms were queried (and failed: no fixture)
    assert all(not any(h in c for h in ("instagram.com", "x.com", "tiktok.com", "linkedin.com", "facebook.com")) for c in ctx.http.transport.calls)
    ig = [r for r in results if r["platform"] == "Instagram"][0]
    assert ig["status"] == U.UNKNOWN and ("login" in ig["detail"].lower() or "authentication" in ig["detail"].lower())


def test_invalid_format_for_platform_is_not_requested():
    ctx = make_ctx()
    gh = U.check_platform(ctx, U.load_platforms()[0], "bad_name_with_underscore")  # GitHub forbids '_'
    assert gh["status"] == U.UNKNOWN and "not valid on this platform" in gh["detail"] and ctx.http.transport.calls == []


def test_network_failure_is_error_and_sorted_last_among_reliable():
    routes = {"https://api.github.com/users/alice": (200, {"login": "alice"}),
              "https://gitlab.com/api/v4/users": (200, []),
              "https://www.reddit.com/user/alice/about.json": (403, "<html>blocked</html>", {"content-type": "text/html"})}
    ctx = make_ctx(routes)
    results = U.username_recon(ctx, "alice")
    assert results[0]["platform"] == "GitHub" and results[0]["status"] == U.FOUND  # reliable findings first
    order = [U.SORT_ORDER[r["status"]] for r in results]
    assert order == sorted(order)
    st = {r["platform"]: r["status"] for r in results}
    assert st["GitLab"] == U.NOT_FOUND and st["Reddit"] == U.BLOCKED
    assert st["Docker Hub"] == U.UNKNOWN  # alice is 5 chars but offline fixture missing -> offline error mapped to UNKNOWN
    assert any(l.startswith("FOUND means") for l in ctx.inv.limitations)


def test_github_token_sent_as_bearer_but_never_recorded():
    ctx = make_ctx({"https://api.github.com/users/alice": (200, {"login": "alice"})}, creds={"GITHUB_TOKEN": "ghp_" + "a" * 36})
    r = U.check_platform(ctx, U.load_platforms()[0], "alice")
    assert r["status"] == U.FOUND and "ghp_" not in json.dumps(r)
