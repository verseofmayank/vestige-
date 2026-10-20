"""Self-contained HTML report (inline CSS, no JavaScript, no external resources).

All values are rendered through Jinja2 autoescaping; nothing is marked |safe.
"""
from __future__ import annotations

from importlib import resources

from jinja2 import Environment, select_autoescape

from vestige.core.models import Investigation
from vestige.core.redact import redact_obj

_env: Environment | None = None


def _environment() -> Environment:
    global _env
    if _env is None:
        tpl = resources.files("vestige.reporting").joinpath("report.html.j2").read_text(encoding="utf-8")
        _env = Environment(autoescape=select_autoescape(default=True, default_for_string=True),
                           trim_blocks=True, lstrip_blocks=True)
        _env.globals["tpl_source"] = tpl
        _env.filters["pretty"] = lambda v: ", ".join(map(str, v)) if isinstance(v, (list, tuple)) else ("" if v is None else str(v))
    return _env


def view_model(d: dict) -> dict:
    obs = d["observations"]

    def of(kind):
        return [o for o in obs if o["kind"] == kind]

    subs = sorted(of("subdomain"), key=lambda o: ({"resolved": 0, "wildcard_only": 1, "unverified": 2, "no_dns_answer": 3}.get(o["data"].get("dns_state", "unverified"), 2), o["value"]))
    users = of("username_check")
    users.sort(key=lambda o: ({"FOUND": 0, "UNKNOWN": 1, "BLOCKED": 2, "ERROR": 3, "NOT_FOUND": 4}.get(o["data"].get("status"), 5), o["value"]))
    return {
        "d": d, "meta": d["investigation"], "summary": d["summary"], "findings": d["findings"], "sources": d["sources"],
        "limitations": d["limitations"],
        "dns_records": sorted(of("dns_record"), key=lambda o: (o["data"].get("type", ""), o["value"])),
        "registration": of("registration"), "dnssec": of("dnssec"), "wildcard": of("wildcard_dns"),
        "dns_provider": of("dns_provider"), "reverse_dns": of("reverse_dns"),
        "subdomains": subs, "certificates": of("certificate")[:50],
        "mail": [o for k in ("mx", "mx_null", "mx_absent", "mail_provider", "spf", "dmarc", "mta_sts", "tls_rpt", "dkim", "disposable_domain") for o in of(k)],
        "ips": [o for k in ("ip_classification", "asn", "geolocation", "exposure_metadata", "reputation") for o in of(k)],
        "web": [o for k in ("http_response", "tls_certificate", "security_txt", "robots_txt", "sitemap") for o in of(k)],
        "history": of("historical_url")[:200], "history_total": len(of("historical_url")),
        "usernames": users, "phone": of("phone_metadata") + of("phone_provider_lookup"),
        "relationships": d["relationships"],
        "sev_order": ["high", "medium", "low", "info"],
    }


def to_html(inv: Investigation, secrets: list[str] | None = None) -> str:
    env = _environment()
    template = env.from_string(env.globals["tpl_source"])
    return template.render(**view_model(redact_obj(inv.to_dict(), secrets or [])))
