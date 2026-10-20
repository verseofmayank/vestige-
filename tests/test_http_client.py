"""HttpClient: retries, backoff, Retry-After, size cap, cache, quotas, offline, secret safety."""
import requests
import pytest

from vestige import USER_AGENT
from vestige.core.cache import ResponseCache
from vestige.core.http_client import FixtureTransport, HttpClient, ProviderError


class FakeResp:
    def __init__(self, status=200, body=b"{}", headers=None, url="https://x.test/"):
        self.status_code, self._body, self.headers, self.url, self.encoding = status, body, headers or {}, url, "utf-8"

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i:i + chunk_size]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeSession:
    def __init__(self, script):
        self.script, self.calls, self.headers = list(script), [], {}

    def get(self, url, **kw):
        self.calls.append((url, kw))
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def client(script, **kw):
    sleeps = []
    s = FakeSession(script)
    kw.setdefault("jitter", False)
    c = HttpClient(session=s, sleep=sleeps.append, **kw)
    return c, s, sleeps


def test_identifiable_user_agent():
    c, s, _ = client([FakeResp()])
    assert s.headers["User-Agent"] == USER_AGENT and "VESTIGE" in USER_AGENT and "Mozilla" not in USER_AGENT


def test_success_returns_result():
    c, _, _ = client([FakeResp(200, b'{"a": 1}')])
    assert c.get("https://x.test/").json() == {"a": 1}


def test_retries_429_with_retry_after_then_succeeds():
    c, s, sleeps = client([FakeResp(429, headers={"retry-after": "2"}), FakeResp(200)], retries=2)
    assert c.get("https://x.test/").status == 200
    assert sleeps == [2.0] and len(s.calls) == 2


def test_retry_after_too_long_is_not_slept_and_raises_ratelimit():
    c, s, sleeps = client([FakeResp(429, headers={"retry-after": "3600"})], retries=3)
    with pytest.raises(ProviderError) as e:
        c.get("https://x.test/")
    assert e.value.kind == "ratelimit" and e.value.http_status == 429
    assert sleeps == [] and len(s.calls) == 1


def test_exponential_backoff_on_5xx_then_gives_up():
    c, s, sleeps = client([FakeResp(503)] * 3, retries=2, backoff=0.5)
    with pytest.raises(ProviderError) as e:
        c.get("https://x.test/")
    assert e.value.kind == "server"
    assert sleeps == [0.5, 1.0] and len(s.calls) == 3


@pytest.mark.parametrize("status,kind", [(401, "auth"), (403, "auth"), (404, "http"), (500, "server")])
def test_error_statuses_never_look_like_success(status, kind):
    c, _, _ = client([FakeResp(status)], retries=0)
    with pytest.raises(ProviderError) as e:
        c.get("https://x.test/")
    assert e.value.kind == kind


def test_ok_statuses_allow_404():
    c, _, _ = client([FakeResp(404)])
    assert c.get("https://x.test/", ok=(200, 404)).status == 404


def test_auth_errors_not_retried():
    c, s, sleeps = client([FakeResp(401)], retries=3)
    with pytest.raises(ProviderError):
        c.get("https://x.test/")
    assert len(s.calls) == 1 and sleeps == []


def test_timeout_is_retried_then_reported():
    c, s, sleeps = client([requests.Timeout("t"), requests.Timeout("t")], retries=1, backoff=0.25)
    with pytest.raises(ProviderError) as e:
        c.get("https://x.test/")
    assert e.value.kind == "timeout" and sleeps == [0.25]


def test_connection_error_reported_without_secret_leak():
    c, _, _ = client([requests.ConnectionError("failed https://api.test/?access_key=SUPERSECRET123")], retries=0,
                     secrets=["SUPERSECRET123"])
    with pytest.raises(ProviderError) as e:
        c.get("https://api.test/")
    assert e.value.kind == "network" and "SUPERSECRET123" not in str(e.value)


def test_retry_false_disables_retries():
    c, s, _ = client([FakeResp(503)], retries=5)
    with pytest.raises(ProviderError):
        c.get("https://x.test/", retry=False)
    assert len(s.calls) == 1


def test_response_size_is_capped():
    c, _, _ = client([FakeResp(200, b"A" * 100_000)])
    r = c.get("https://x.test/", max_bytes=10_000)
    assert r.truncated and len(r.text) == 10_000


def test_malformed_json_raises_provider_error():
    c, _, _ = client([FakeResp(200, b"<html>not json")])
    with pytest.raises(ProviderError) as e:
        c.get("https://x.test/").json()
    assert e.value.kind == "malformed"


def test_cache_hit_avoids_second_request(tmp_path):
    cache = ResponseCache(tmp_path / "c")
    c, s, _ = client([FakeResp(200, b'{"v": 1}')], cache=cache)
    assert c.get("https://x.test/a", cacheable=True).json() == {"v": 1}
    r = c.get("https://x.test/a", cacheable=True)
    assert r.from_cache and r.json() == {"v": 1} and len(s.calls) == 1


def test_cache_expires(tmp_path):
    now = [1000.0]
    cache = ResponseCache(tmp_path / "c", clock=lambda: now[0])
    c, s, _ = client([FakeResp(200, b"1"), FakeResp(200, b"2")], cache=cache)
    c.get("https://x.test/a", cacheable=True, ttl=60)
    now[0] += 61
    assert c.get("https://x.test/a", cacheable=True, ttl=60).text == "2"


def test_errors_are_not_cached(tmp_path):
    cache = ResponseCache(tmp_path / "c")
    c, s, _ = client([FakeResp(404), FakeResp(200, b"ok")], cache=cache)
    c.get("https://x.test/a", cacheable=True, ok=(200, 404))
    assert c.get("https://x.test/a", cacheable=True).text == "ok"


def test_cache_key_never_contains_secret(tmp_path):
    cache = ResponseCache(tmp_path / "c")
    c, _, _ = client([FakeResp(200, b"x")], cache=cache)
    c.get("https://api.test/v?access_key=TOPSECRET", cacheable=True)
    assert all("TOPSECRET" not in p.read_text() and "TOPSECRET" not in p.name for p in (tmp_path / "c").iterdir())


def test_quota_exhaustion():
    c, _, _ = client([FakeResp(), FakeResp()], quotas={"prov": 1})
    c.get("https://x.test/", source="prov")
    with pytest.raises(ProviderError) as e:
        c.get("https://x.test/", source="prov")
    assert e.value.kind == "quota"


def test_offline_mode_sends_nothing():
    s = FakeSession([])
    c = HttpClient(session=s, offline=True)
    with pytest.raises(ProviderError) as e:
        c.get("https://x.test/")
    assert e.value.kind == "offline" and s.calls == []


def test_fixture_transport_longest_prefix_and_missing():
    t = FixtureTransport({"https://a.test/": (200, "short"), "https://a.test/x": (200, "long")})
    c = HttpClient(transport=t)
    assert c.get("https://a.test/x/y").text == "long"
    with pytest.raises(ProviderError):
        c.get("https://other.test/")
