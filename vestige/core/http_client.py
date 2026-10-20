"""Central HTTP client: identifiable User-Agent, timeouts, bounded retries with exponential
backoff, 429/Retry-After handling, response-size cap, TTL cache, per-source quotas,
offline/fixture transport and secret-safe logging.

Modules never call `requests` directly; they call `HttpClient.get` and receive either an
`HttpResult` or a `ProviderError` with a machine-readable `kind` so that a failing API can
never be reported as success.
"""
from __future__ import annotations

import email.utils
import json
import logging
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

import requests

from vestige import USER_AGENT
from vestige.core.cache import ResponseCache
from vestige.core.redact import redact_text, redact_url

log = logging.getLogger("vestige.http")

RETRY_STATUS = {429, 500, 502, 503, 504}
DEFAULT_MAX_BYTES = 5 * 1024 * 1024
MAX_RETRY_WAIT = 30.0


class ProviderError(Exception):
    """A source could not deliver trustworthy data.

    kind: auth | ratelimit | quota | server | network | timeout | malformed | http | offline
    """

    def __init__(self, kind: str, message: str, http_status: int | None = None):
        super().__init__(message)
        self.kind = kind
        self.http_status = http_status

    def __str__(self) -> str:  # noqa: D105
        return f"{self.kind}: {self.args[0]}"


@dataclass
class HttpResult:
    status: int
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    text: str = ""
    from_cache: bool = False
    truncated: bool = False
    elapsed: float = 0.0

    def json(self) -> Any:
        try:
            return json.loads(self.text)
        except ValueError as exc:
            raise ProviderError("malformed", "response is not valid JSON", self.status) from exc

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")


class FixtureTransport:
    """Offline transport: maps URL prefixes to canned responses. Used by tests and `demo`."""

    def __init__(self, routes: dict[str, tuple] | None = None):
        self.routes = routes or {}
        self.calls: list[str] = []

    def fetch(self, url: str, params: dict | None) -> HttpResult | None:
        from urllib.parse import urlencode
        full = url + (("&" if "?" in url else "?") + urlencode(params) if params else "")
        self.calls.append(redact_url(full))
        best = None
        for prefix in self.routes:
            if full.startswith(prefix) and (best is None or len(prefix) > len(best)):
                best = prefix
        if best is None:
            return None
        route = self.routes[best]
        status, body = route[0], route[1]
        extra = {k.lower(): v for k, v in (route[2] if len(route) > 2 else {}).items()}
        text = body if isinstance(body, str) else json.dumps(body)
        ctype = "text/plain" if isinstance(body, str) else "application/json"
        return HttpResult(status=status, url=full, headers={"content-type": ctype, **extra}, text=text)


def _parse_retry_after(value: str | None) -> float | None:
    if not value:
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        dt = email.utils.parsedate_to_datetime(value)
        return max(0.0, dt.timestamp() - time.time())
    except (TypeError, ValueError):
        return None


class HttpClient:
    def __init__(
        self,
        *,
        timeout: float = 10.0,
        retries: int = 2,
        backoff: float = 0.5,
        cache: ResponseCache | None = None,
        transport: FixtureTransport | None = None,
        offline: bool = False,
        max_bytes: int = DEFAULT_MAX_BYTES,
        secrets: Iterable[str] = (),
        quotas: dict[str, int] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        session: requests.Session | None = None,
        jitter: bool = True,
    ):
        self.timeout = timeout
        self.retries = max(0, retries)
        self.backoff = backoff
        self.cache = cache
        self.transport = transport
        self.offline = offline or transport is not None
        self.max_bytes = max_bytes
        self.secrets = [s for s in secrets if s]
        self.quotas = dict(quotas or {})
        self._sleep = sleep
        self._jitter = jitter
        self._session = session or requests.Session()
        self._session.headers["User-Agent"] = USER_AGENT
        self._lock = threading.Lock()
        self.request_count = 0

    # -- quota -----------------------------------------------------------------
    def _take_quota(self, source: str) -> None:
        if not source or source not in self.quotas:
            return
        with self._lock:
            if self.quotas[source] <= 0:
                raise ProviderError("quota", f"local request quota for '{source}' exhausted")
            self.quotas[source] -= 1

    # -- main entry point ------------------------------------------------------
    def get(
        self,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        source: str = "",
        ok: Iterable[int] = (200,),
        cacheable: bool = False,
        ttl: float = 3600,
        allow_redirects: bool = True,
        retry: bool = True,
        max_bytes: int | None = None,
        timeout: float | None = None,
    ) -> HttpResult:
        ok_set = set(ok)
        safe_url = redact_url(url)
        key = ResponseCache.make_key(url, params) if (self.cache and cacheable) else None
        if key:
            hit = self.cache.get(key, ttl)  # type: ignore[union-attr]
            if hit:
                log.debug("cache hit %s", safe_url)
                return HttpResult(hit["status"], url, {"content-type": hit.get("content_type", "")},
                                  hit["text"], from_cache=True)

        if self.transport is not None:
            res = self.transport.fetch(url, params)
            if res is None:
                raise ProviderError("offline", f"no fixture for {safe_url}")
            return self._classify(res, ok_set)
        if self.offline:
            raise ProviderError("offline", "offline mode: network access disabled")

        self._take_quota(source)
        attempts = (self.retries if retry else 0) + 1
        last: ProviderError | None = None
        for attempt in range(attempts):
            t0 = time.monotonic()
            try:
                res = self._send(url, params, headers, allow_redirects, max_bytes or self.max_bytes,
                                 timeout or self.timeout)
                res.elapsed = time.monotonic() - t0
            except requests.Timeout as exc:
                last = ProviderError("timeout", f"timed out after {timeout or self.timeout}s ({type(exc).__name__})")
            except requests.ConnectionError as exc:
                last = ProviderError("network", redact_text(f"connection failed: {exc}", self.secrets)[:200])
            except requests.RequestException as exc:
                raise ProviderError("network", redact_text(str(exc), self.secrets)[:200]) from exc
            else:
                log.debug("GET %s -> %s (%.2fs)", safe_url, res.status, res.elapsed)
                self.request_count += 1
                if res.status in RETRY_STATUS and res.status not in ok_set and attempt < attempts - 1:
                    wait = self._wait_for(res, attempt)
                    if wait is None:  # Retry-After longer than we are willing to wait
                        return self._classify(res, ok_set)
                    log.info("retrying %s in %.1fs (HTTP %s)", safe_url, wait, res.status)
                    self._sleep(wait)
                    continue
                result = self._classify(res, ok_set)
                if key and res.status == 200 and not res.truncated:
                    self.cache.put(key, res.status, res.content_type, res.text)  # type: ignore[union-attr]
                return result
            # network-level failure: back off then retry
            if attempt < attempts - 1:
                self._sleep(self._backoff(attempt))
        assert last is not None
        raise last

    # -- internals -------------------------------------------------------------
    def _backoff(self, attempt: int) -> float:
        base = self.backoff * (2 ** attempt)
        return base + (random.uniform(0, base / 4) if self._jitter else 0.0)

    def _wait_for(self, res: HttpResult, attempt: int) -> float | None:
        ra = _parse_retry_after(res.headers.get("retry-after"))
        if ra is not None:
            return None if ra > MAX_RETRY_WAIT else ra
        return self._backoff(attempt)

    def _send(self, url, params, headers, allow_redirects, max_bytes, timeout) -> HttpResult:
        with self._session.get(url, params=params, headers=headers, timeout=timeout,
                               allow_redirects=allow_redirects, stream=True) as r:
            chunks, size, truncated = [], 0, False
            for chunk in r.iter_content(chunk_size=16384):
                size += len(chunk)
                chunks.append(chunk)
                if size >= max_bytes:
                    truncated = True
                    break
            body = b"".join(chunks)[:max_bytes]
            enc = r.encoding or "utf-8"
            try:
                text = body.decode(enc, errors="replace")
            except LookupError:
                text = body.decode("utf-8", errors="replace")
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            return HttpResult(status=r.status_code, url=r.url, headers=hdrs, text=text, truncated=truncated)

    def _classify(self, res: HttpResult, ok_set: set[int]) -> HttpResult:
        if res.status in ok_set:
            return res
        s = res.status
        if s in (401, 403):
            raise ProviderError("auth", f"HTTP {s}: credentials missing, invalid or access denied", s)
        if s == 429:
            ra = res.headers.get("retry-after")
            raise ProviderError("ratelimit", f"HTTP 429: rate limited" + (f" (Retry-After {ra})" if ra else ""), s)
        if s >= 500:
            raise ProviderError("server", f"HTTP {s}: provider server error", s)
        raise ProviderError("http", f"unexpected HTTP {s}", s)
