"""Target validation and scope enforcement.

Scope rules:
* A target domain is normalised (IDNA/punycode, lowercase, no trailing dot) and validated.
* Hostnames are in scope when they equal the target or are a subdomain of it.
* Direct HTTP traffic to a target needs BOTH --http-checks and --confirm-authorized.
* Destinations resolving to private/reserved addresses are refused (SSRF protection).
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

import idna


class ValidationError(ValueError):
    """User-input error; shown as a clean message, never a stack trace."""


class ScopeError(PermissionError):
    """An action was blocked by scope/authorisation rules."""


_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")  # underscore: _dmarc, _domainkey
_BAD_CHARS = set(" /@:?#\\\"'<>,;\n\r\t")


def normalize_domain(raw: str, *, allow_underscore: bool = False) -> str:
    """Return the lowercase ASCII (punycode) form of a domain name, or raise ValidationError."""
    if raw is None or not raw.strip():
        raise ValidationError("domain is empty")
    d = raw.strip().lower().rstrip(".")
    if any(c in _BAD_CHARS for c in d):
        raise ValidationError(f"'{raw}' is not a bare domain name (no scheme, path, port or '@'); e.g. example.com")
    try:
        ipaddress.ip_address(d)
    except ValueError:
        pass
    else:
        raise ValidationError(f"'{raw}' is an IP address; use the 'ip' command")
    if d.startswith("*."):
        d = d[2:]
    try:
        ascii_d = ".".join(
            (lbl if lbl.isascii() else idna.encode(lbl, uts46=True).decode("ascii"))
            for lbl in d.split(".")
        )
    except idna.IDNAError as exc:
        raise ValidationError(f"invalid internationalised domain '{raw}': {exc}") from exc
    if len(ascii_d) > 253:
        raise ValidationError("domain longer than 253 characters")
    labels = ascii_d.split(".")
    if len(labels) < 2:
        raise ValidationError(f"'{raw}' needs at least two labels (e.g. example.com)")
    for lbl in labels:
        if not _LABEL_RE.match(lbl) or (not allow_underscore and "_" in lbl):
            raise ValidationError(f"invalid label '{lbl}' in domain '{raw}'")
    if labels[-1].isdigit():
        raise ValidationError(f"'{raw}' has a numeric TLD")
    return ascii_d


def display_domain(ascii_domain: str) -> str:
    """Unicode form of a punycode domain, for display only."""
    try:
        return idna.decode(ascii_domain)
    except idna.IDNAError:
        return ascii_domain


def normalize_hostname(raw: str, root: str | None = None) -> str | None:
    """Normalise a discovered hostname. Returns None if it is not a plausible hostname
    (emails, IPs, garbage) or, when `root` is given, if it is outside that domain."""
    h = (raw or "").strip()
    if not h:
        return None
    try:
        h = normalize_domain(h, allow_underscore=True)
    except ValidationError:
        return None
    if root and not in_scope(h, root):
        return None
    return h


def in_scope(host: str, root: str) -> bool:
    host = host.lower().rstrip(".")
    root = root.lower().rstrip(".")
    return host == root or host.endswith("." + root)


def classify_ip(ip: str) -> dict:
    """Validate an IPv4/IPv6 literal and classify it. Raises ValidationError if invalid."""
    try:
        a = ipaddress.ip_address(ip.strip().strip("[]"))
    except ValueError as exc:
        raise ValidationError(f"'{ip}' is not a valid IPv4/IPv6 address") from exc
    if a.version == 6 and getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    if a.is_loopback:
        cls = "loopback"
    elif a.is_link_local:
        cls = "link-local"
    elif a.is_multicast:
        cls = "multicast"
    elif a.is_unspecified:
        cls = "unspecified"
    elif a.is_reserved:
        cls = "reserved"
    elif a.is_private:
        cls = "private"
    elif a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10"):
        cls = "shared-address-space (CGNAT)"
    elif not a.is_global:
        cls = "special-purpose"
    else:
        cls = "public"
    return {"address": str(a), "version": a.version, "classification": cls, "is_global": cls == "public"}


def is_public_ip(ip: str) -> bool:
    try:
        return classify_ip(ip)["is_global"]
    except ValidationError:
        return False


def resolve_public(host: str, port: int = 443) -> list[str]:
    """Resolve host and return its addresses; raise ScopeError if any is non-public."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeError(f"{host} does not resolve ({exc})") from exc
    addrs = sorted({i[4][0] for i in infos})
    bad = [a for a in addrs if not is_public_ip(a)]
    if bad:
        raise ScopeError(f"{host} resolves to non-public address(es) {bad}; refusing to connect")
    return addrs


@dataclass
class Scope:
    """Run-time scope for one investigation."""
    root: str
    http_checks: bool = False
    confirmed_authorized: bool = False

    @property
    def http_allowed(self) -> bool:
        return self.http_checks and self.confirmed_authorized

    def require_http(self) -> None:
        if not self.http_checks:
            raise ScopeError("direct HTTP checks are disabled (passive mode); use --http-checks together with --confirm-authorized")
        if not self.confirmed_authorized:
            raise ScopeError("direct HTTP checks need --confirm-authorized: confirm you are authorised to test this target")

    def check_url(self, url: str) -> str:
        """Validate a URL for direct fetching: http/https, no credentials, in-scope host."""
        self.require_http()
        p = urlsplit(url)
        if p.scheme not in ("http", "https"):
            raise ScopeError(f"scheme '{p.scheme}' not allowed")
        if p.username or p.password:
            raise ScopeError("credentials in URL are not allowed")
        host = (p.hostname or "").lower()
        if not host or not in_scope(host, self.root):
            raise ScopeError(f"{host or url} is outside the authorised scope ({self.root})")
        return host

    def to_dict(self) -> dict:
        return {"root_domain": self.root, "http_checks_enabled": self.http_allowed,
                "mode": "active-http-authorised" if self.http_allowed else "passive"}
