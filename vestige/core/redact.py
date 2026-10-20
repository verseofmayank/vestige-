"""Secret and sensitive-value redaction for logs, reports and archived URLs."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"

# Query/field names whose values must never be stored or logged.
SENSITIVE_PARAMS = {
    "access_key", "api_key", "apikey", "key", "token", "access_token", "auth", "authorization",
    "password", "passwd", "pwd", "secret", "session", "sessionid", "sid", "jwt", "signature",
    "sig", "code", "otp", "email", "mail", "phone", "bearer", "client_secret", "refresh_token",
    "x-api-key", "credential", "credentials",
}
SENSITIVE_HEADERS = {"authorization", "key", "x-apikey", "x-api-key", "api-key", "cookie", "set-cookie"}

_TOKEN_PATTERNS = [
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),           # GitHub tokens
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),                       # AWS access key id
    re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),  # JWT
]
_BEARER = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{12,}")
_KV = re.compile(r"(?i)((?:access_key|api_key|apikey|token|key)=)[^&\s]+")


def redact_url(url: str) -> str:
    """Replace values of sensitive query parameters; drop userinfo and fragment."""
    try:
        p = urlsplit(url)
        host = p.hostname or ""
        if p.port:
            host = f"{host}:{p.port}"
    except ValueError:
        return REDACTED
    q = []
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        q.append((k, REDACTED if k.lower() in SENSITIVE_PARAMS else v))
    return urlunsplit((p.scheme, host, p.path, urlencode(q, safe="[]"), ""))


def redact_text(text: str, secrets: list[str] | None = None) -> str:
    """Remove known secret values and token-shaped strings from free text."""
    out = text
    for s in secrets or []:
        if s and len(s) >= 4:
            out = out.replace(s, REDACTED)
    for pat in _TOKEN_PATTERNS:
        out = pat.sub(REDACTED, out)
    out = _BEARER.sub(lambda m: m.group(1) + REDACTED, out)
    out = _KV.sub(lambda m: m.group(1) + REDACTED, out)
    return out


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {k: (REDACTED if k.lower() in SENSITIVE_HEADERS else v) for k, v in headers.items()}


def redact_obj(obj, secrets: list[str] | None = None):
    """Recursively redact every string inside a JSON-compatible structure (keeps the structure valid)."""
    if isinstance(obj, str):
        return redact_text(obj, secrets)
    if isinstance(obj, list):
        return [redact_obj(x, secrets) for x in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v, secrets) for k, v in obj.items()}
    return obj
