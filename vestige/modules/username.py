"""Username reconnaissance with evidence-based verdicts.

Statuses: FOUND | NOT_FOUND | UNKNOWN | BLOCKED | ERROR.

A generic HTTP 200 is never enough: FOUND requires a platform-specific positive proof (the API
echoes back the same username). Login walls, CAPTCHAs, bot challenges, 403/429 are reported as
BLOCKED, not as "not found". VESTIGE never attempts to bypass any of them.
"""
from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor
from importlib import resources
from typing import Any
from urllib.parse import quote, urlsplit

from vestige.core.context import Context
from vestige.core.http_client import HttpResult, ProviderError
from vestige.core.models import Confidence, Observation, SourceResult, Status, utcnow
from vestige.core.scope import ValidationError

FOUND, NOT_FOUND, UNKNOWN, BLOCKED, ERROR = "FOUND", "NOT_FOUND", "UNKNOWN", "BLOCKED", "ERROR"
SORT_ORDER = {FOUND: 0, UNKNOWN: 1, BLOCKED: 2, ERROR: 3, NOT_FOUND: 4}

_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_CHALLENGE_MARKERS = (
    "captcha", "cf-challenge", "challenge-platform", "just a moment", "attention required",
    "verify you are human", "unusual traffic", "access denied", "enable javascript", "are you a robot",
    "bot detection", "px-captcha", "datadome",
)
_LOGIN_PATH_MARKERS = ("/login", "/signin", "/sign-in", "/accounts/login", "/authwall", "/i/flow", "/uas/login", "/checkpoint")


def load_platforms() -> list[dict]:
    with resources.files("vestige.data").joinpath("platforms.json").open("r", encoding="utf-8") as f:
        return json.load(f)["platforms"]


def validate_username(raw: str) -> str:
    u = (raw or "").strip().lstrip("@")
    if not _USERNAME_RE.match(u):
        raise ValidationError("username must be 1-64 characters from A-Z a-z 0-9 . _ -")
    return u


def _dig(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if isinstance(cur, list):
            if not part.isdigit() or int(part) >= len(cur):
                return None
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
        if cur is None:
            return None
    return cur


def detect_block(res: HttpResult, expected_host: str) -> str | None:
    """Return a human reason if the response is a block/login wall/challenge, else None."""
    if res.status == 429:
        return "rate limited (HTTP 429)"
    if res.status in (401, 403):
        return f"access denied (HTTP {res.status}); site blocks unauthenticated/automated requests"
    if res.status == 999:
        return "site refuses automated requests (HTTP 999)"
    if res.headers.get("cf-mitigated") == "challenge":
        return "Cloudflare challenge"
    final = urlsplit(res.url)
    fhost = (final.hostname or "").lower()
    if fhost and expected_host and fhost.removeprefix("www.") != expected_host.removeprefix("www."):
        return f"redirected to a different host ({fhost})"
    if any(m in final.path.lower() for m in _LOGIN_PATH_MARKERS):
        return "redirected to a login page (login wall)"
    if "html" in res.content_type.lower() or res.text.lstrip()[:1] == "<":
        low = res.text[:20000].lower()
        for m in _CHALLENGE_MARKERS:
            if m in low:
                return f"bot challenge / CAPTCHA page detected ('{m}')"
    if res.status == 503:
        return "service unavailable / possible bot protection (HTTP 503)"
    return None


def evaluate(platform: dict, username: str, res: HttpResult) -> dict:
    """Pure function: platform definition + response -> verdict dict. Fully unit-testable."""
    profile = platform["profile"].format(u=quote(username, safe=""))
    base = {"platform": platform["name"], "profile_url": profile, "http_status": res.status}
    expected_host = urlsplit(platform.get("url", platform["profile"]).format(u="x")).hostname or ""

    blocked = detect_block(res, expected_host)
    if blocked:
        return {**base, "status": BLOCKED, "confidence": "high", "detail": blocked}
    if res.status >= 500:
        return {**base, "status": ERROR, "confidence": "high", "detail": f"server error (HTTP {res.status})"}

    nf_status = platform.get("not_found_status", [404])
    if res.status in nf_status:
        needle = platform.get("not_found_body")
        if res.status == 404 or not needle or needle.lower() in res.text.lower():
            return {**base, "status": NOT_FOUND, "confidence": "high",
                    "detail": f"API returned HTTP {res.status} (no such user)"}
        return {**base, "status": UNKNOWN, "confidence": "low", "detail": f"HTTP {res.status} without expected 'not found' body"}
    if res.status != 200:
        return {**base, "status": UNKNOWN, "confidence": "low", "detail": f"unexpected HTTP {res.status}"}

    try:
        doc = json.loads(res.text)
    except ValueError:
        return {**base, "status": UNKNOWN, "confidence": "low",
                "detail": "HTTP 200 but body is not JSON; a 200 page alone does not prove a profile exists"}

    strategy = platform["strategy"]
    if strategy == "json_list":
        if not isinstance(doc, list):
            return {**base, "status": UNKNOWN, "confidence": "low", "detail": "unexpected JSON shape (expected list)"}
        if not doc:
            return {**base, "status": NOT_FOUND, "confidence": "high", "detail": "API returned an empty result list"}
        for item in doc:
            if isinstance(item, dict) and str(item.get(platform["field"], "")).lower() == username.lower():
                return {**base, "status": FOUND, "confidence": "high",
                        "detail": f"API returned a user whose '{platform['field']}' equals the username",
                        "evidence": _evidence(platform, item)}
        return {**base, "status": UNKNOWN, "confidence": "low", "detail": "list returned but no exact username match"}

    # json_path
    if doc is None and platform.get("null_means_missing"):
        return {**base, "status": NOT_FOUND, "confidence": "medium", "detail": "API returned null for this user"}
    got = _dig(doc, platform["path"])
    if got is None:
        miss = platform.get("null_path_means_missing")
        if miss and _dig(doc, miss) is None and isinstance(doc, dict):
            return {**base, "status": NOT_FOUND, "confidence": "medium", "detail": "API result is empty for this user"}
        return {**base, "status": UNKNOWN, "confidence": "low",
                "detail": f"HTTP 200 but field '{platform['path']}' missing; cannot prove existence"}
    if str(got).lower() == username.lower():
        return {**base, "status": FOUND, "confidence": "high",
                "detail": f"API field '{platform['path']}' equals the username",
                "evidence": _evidence(platform, doc if isinstance(doc, dict) else {})}
    return {**base, "status": UNKNOWN, "confidence": "low",
            "detail": f"API returned a different value for '{platform['path']}'; not treated as a match"}


def _evidence(platform: dict, doc: dict) -> dict:
    out = {}
    for f in platform.get("evidence_fields", []):
        v = doc.get(f)
        if isinstance(v, (str, int, float, bool)) and v != "":
            out[f] = str(v)[:80]
    return out


def check_platform(ctx: Context, platform: dict, username: str) -> dict:
    name = platform["name"]
    profile = platform["profile"].format(u=quote(username, safe=""))
    if platform["strategy"] == "unverifiable":
        return {"platform": name, "profile_url": profile, "status": UNKNOWN, "confidence": "high",
                "detail": platform.get("reason", "cannot be verified without authentication"), "http_status": None}
    if not re.match(platform.get("regex", ".*"), username):
        return {"platform": name, "profile_url": profile, "status": UNKNOWN, "confidence": "high",
                "detail": "username format is not valid on this platform; not queried", "http_status": None}
    headers = {"Accept": "application/json"}
    env = platform.get("auth_env")
    if env and env in ctx.creds:
        headers["Authorization"] = f"Bearer {ctx.creds[env]}"
    try:
        res = ctx.http.get(platform["url"].format(u=quote(username, safe="")), headers=headers,
                           source=f"username:{name}", ok=range(100, 600), retry=False, max_bytes=512 * 1024)
    except ProviderError as exc:
        status = UNKNOWN if exc.kind == "offline" else ERROR
        return {"platform": name, "profile_url": profile, "status": status, "confidence": "high",
                "detail": str(exc), "http_status": exc.http_status}
    return evaluate(platform, username, res)


def username_recon(ctx: Context, username: str, *, only_found: bool = False) -> list[dict]:
    platforms = load_platforms()
    with ThreadPoolExecutor(max_workers=max(1, min(ctx.max_workers, 12))) as pool:
        results = list(pool.map(lambda p: check_platform(ctx, p, username), platforms))
    results.sort(key=lambda r: (SORT_ORDER[r["status"]], r["platform"].lower()))
    now = utcnow()
    for r in results:
        conf = {"high": Confidence.HIGH, "medium": Confidence.MEDIUM}.get(r["confidence"], Confidence.LOW)
        ctx.inv.observations.append(Observation("username_check", r["platform"], r["platform"], conf, now, {
            k: v for k, v in r.items() if k not in ("platform",)}))
        st = {FOUND: Status.OK, NOT_FOUND: Status.OK, UNKNOWN: Status.SKIPPED,
              BLOCKED: Status.FAILED, ERROR: Status.FAILED}[r["status"]]
        ctx.record(SourceResult("username", r["platform"], st, f"{r['status']}: {r['detail']}",
                                        items=1 if r["status"] == FOUND else 0, http_status=r.get("http_status")))
    ctx.inv.limitations.append(
        "FOUND means the platform's API confirmed the exact username exists; it does not prove the account belongs to a particular person.")
    ctx.inv.limitations.append(
        "UNKNOWN/BLOCKED platforms could not be verified (login wall, bot protection, rate limit). VESTIGE does not bypass these.")
    return results
