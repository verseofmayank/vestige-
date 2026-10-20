"""Shared test helpers. All tests are offline: HTTP via FixtureTransport/fake sessions, DNS via FakeResolver."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vestige.core.context import Context  # noqa: E402
from vestige.core.http_client import FixtureTransport, HttpClient  # noqa: E402
from vestige.core.models import Investigation  # noqa: E402
from vestige.core.scope import Scope  # noqa: E402
from vestige.modules.dns import FakeResolver  # noqa: E402


@pytest.fixture(autouse=True)
def isolate_env(monkeypatch, tmp_path):
    """No real credentials or cache from the developer's machine may influence tests."""
    for k in ("ABUSEIPDB_KEY", "VIRUSTOTAL_KEY", "OTX_API_KEY", "URLSCAN_KEY", "GITHUB_TOKEN", "NUMVERIFY_KEY", "SHODAN_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("VESTIGE_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.chdir(tmp_path)


def make_ctx(routes=None, resolver=None, creds=None, scope=None, target="example.com", limit=200, **kw) -> Context:
    transport = FixtureTransport(routes or {})
    http = HttpClient(transport=transport, retries=0)
    inv = Investigation(command="test", target=target)
    return Context(http=http, inv=inv, resolver=resolver or FakeResolver(), scope=scope, creds=creds or {}, limit=limit, **kw)


@pytest.fixture
def ctx_factory():
    return make_ctx


def source(inv, name):
    """Find a SourceResult by (prefix of) name."""
    matches = [s for s in inv.sources if s.source == name or s.source.startswith(name)]
    assert matches, f"no source named {name!r} in {[s.source for s in inv.sources]}"
    return matches[0]


def authorised_scope(root="example.com"):
    return Scope(root, http_checks=True, confirmed_authorized=True)
