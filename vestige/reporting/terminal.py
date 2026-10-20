"""Rich terminal rendering. All untrusted strings go through `esc` to prevent markup injection."""
from __future__ import annotations

from rich.console import Console
from rich.markup import escape as esc
from rich.panel import Panel
from rich.table import Table

from vestige.core.models import SEVERITY_ORDER, Investigation, Severity, Status

BANNER = r"""
██╗   ██╗███████╗███████╗████████╗██╗ ██████╗ ███████╗
██║   ██║██╔════╝██╔════╝╚══██╔══╝██║██╔════╝ ██╔════╝
██║   ██║█████╗  ███████╗   ██║   ██║██║  ███╗█████╗
╚██╗ ██╔╝██╔══╝  ╚════██║   ██║   ██║██║   ██║██╔══╝
 ╚████╔╝ ███████╗███████║   ██║   ██║╚██████╔╝███████╗
  ╚═══╝  ╚══════╝╚══════╝   ╚═╝   ╚═╝ ╚═════╝ ╚══════╝"""

STATUS_STYLE = {Status.OK: "green", Status.EMPTY: "dim", Status.FAILED: "bold red", Status.SKIPPED: "yellow"}
SEV_STYLE = {Severity.HIGH: "bold red", Severity.MEDIUM: "dark_orange", Severity.LOW: "yellow", Severity.INFO: "cyan"}
USER_STYLE = {"FOUND": "bold green", "NOT_FOUND": "dim", "UNKNOWN": "yellow", "BLOCKED": "red", "ERROR": "bold red"}


def show_banner(console: Console) -> None:
    console.print(BANNER, style="bold cyan", highlight=False)
    console.print("  [bold white]OSINT & External Attack Surface Intelligence[/]   [green]by mayhack[/]")
    console.print("  [yellow]Traces Left Behind...[/]  [dim]Authorised, passive-first reconnaissance only.[/]\n")


def render(console: Console, inv: Investigation, *, verbose: bool = False, max_rows: int = 25) -> None:
    mode = "[bold black on yellow] FIXTURE DATA - offline demo, NOT a live scan [/]" if inv.mode != "live" else ""
    scope = inv.scope.get("mode", "")
    console.print(Panel(f"[bold]{esc(inv.target)}[/]  [dim]{esc(inv.command)} - {esc(scope)}[/]\n{mode}",
                        title="Investigation", border_style="cyan"))
    _kinds(console, inv, max_rows)
    _findings(console, inv)
    _sources(console, inv, verbose)
    s = inv.summary()
    c = s["sources"]
    console.print(f"\n[bold]Checked:[/] [green]{c['OK']} ok[/] - [dim]{c['EMPTY']} empty[/] - "
                  f"[red]{c['FAILED']} failed[/] - [yellow]{c['SKIPPED']} skipped[/]   "
                  f"[bold]Findings:[/] " + " ".join(f"[{SEV_STYLE[sv]}]{s['findings'][sv.value]} {sv.value}[/]" for sv in Severity))
    if inv.limitations and verbose:
        console.print("\n[bold]Limitations / unknowns[/]")
        for lim in inv.limitations:
            console.print(f"  [dim]- {esc(lim)}[/]")
    elif inv.limitations:
        console.print(f"[dim]{len(inv.limitations)} limitation(s) recorded; use --verbose or open the report for details.[/]")


def _t(title, *cols):
    t = Table(title=title, title_justify="left", header_style="bold", show_edge=False, pad_edge=False)
    for c in cols:
        t.add_column(c, overflow="fold")
    return t


def _kinds(console, inv, n):
    obs = lambda k: [o for o in inv.observations if o.kind == k]  # noqa: E731
    reg = obs("registration")
    if reg:
        d = reg[0].data
        t = _t("Registration (" + esc(str(d.get("via", ""))) + ")", "Field", "Value")
        for k in ("registered_domain", "domain", "registrar", "registered", "expires", "last_changed", "status", "nameservers"):
            v = d.get(k)
            if v:
                t.add_row(k, esc(", ".join(v) if isinstance(v, list) else str(v)))
        console.print(t)
    dns = obs("dns_record")
    if dns:
        t = _t("DNS records", "Type", "Value")
        for o in dns[:n]:
            t.add_row(o.data["type"], esc(str(o.data["value"])[:120]))
        console.print(t)
        if len(dns) > n:
            console.print(f"[dim]  ... {len(dns) - n} more records in the report[/]")
    for k in ("dnssec", "wildcard_dns", "dns_provider"):
        for o in obs(k):
            console.print(f"[bold]{k}:[/] {esc(o.value)} [dim]({esc(o.source)})[/]")
    subs = obs("subdomain")
    if subs:
        t = _t(f"Subdomains ({len(subs)})", "Name", "DNS state", "Addresses", "Sources")
        order = {"resolved": 0, "wildcard_only": 1, "unverified": 2, "no_dns_answer": 3}
        for o in sorted(subs, key=lambda o: (order.get(o.data.get("dns_state", "unverified"), 2), o.value))[:n]:
            st = o.data.get("dns_state", "unverified")
            t.add_row(esc(o.value), f"[{'green' if st == 'resolved' else 'yellow' if st != 'no_dns_answer' else 'dim'}]{st}[/]",
                      esc(", ".join(o.data.get("resolved_ips", []))[:60]), esc(", ".join(o.data.get("sources", []))))
        console.print(t)
        if len(subs) > n:
            console.print(f"[dim]  ... {len(subs) - n} more in the report[/]")
    mail = [o for k in ("mx", "mail_provider", "spf", "dmarc", "mta_sts", "tls_rpt", "dkim", "disposable_domain") for o in obs(k)]
    if mail:
        t = _t("Mail infrastructure & authentication", "Check", "Result")
        for o in mail:
            t.add_row(o.kind, esc(o.value[:110]))
        console.print(t)
    ipobs = [o for k in ("ip_classification", "asn", "geolocation", "exposure_metadata", "reputation", "reverse_dns") for o in obs(k)]
    if ipobs:
        t = _t("IP / infrastructure", "Kind", "Subject", "Summary", "Source")
        for o in ipobs[:n]:
            t.add_row(o.kind, esc(o.value[:40]), esc(_summ(o)), esc(o.source))
        console.print(t)
    web = [o for k in ("http_response", "tls_certificate", "security_txt", "robots_txt") for o in obs(k)]
    if web:
        t = _t("Web / TLS (authorised direct checks)", "Check", "Result")
        for o in web:
            t.add_row(o.kind, esc(_summ(o)))
        console.print(t)
    users = obs("username_check")
    if users:
        t = _t("Username results (reliable findings first)", "Platform", "Status", "Conf.", "Why / profile")
        order = {"FOUND": 0, "UNKNOWN": 1, "BLOCKED": 2, "ERROR": 3, "NOT_FOUND": 4}
        for o in sorted(users, key=lambda o: (order.get(o.data["status"], 5), o.value)):
            st = o.data["status"]
            why = o.data["profile_url"] if st == "FOUND" else o.data["detail"]
            t.add_row(esc(o.value), f"[{USER_STYLE[st]}]{st}[/]", o.confidence.value, esc(why[:90]))
        console.print(t)
    for o in obs("phone_metadata"):
        d = o.data
        t = _t("Phone metadata (numbering-plan data, not live)", "Field", "Value")
        for k in ("e164", "country_code", "region", "is_valid", "is_possible", "number_type", "geographic_area", "carrier_original_allocation"):
            t.add_row(k, esc(str(d.get(k))))
        console.print(t)
        console.print("[dim]  Area/carrier reflect original numbering allocation, not the subscriber's location or current carrier.[/]")
    hist = obs("historical_url")
    if hist:
        console.print(f"[bold]Historical URLs:[/] {len(hist)} (archives; first/last seen in the report)")


def _summ(o) -> str:
    d = o.data
    if o.kind == "asn":
        return f"{o.value} {d.get('as_name') or ''} {d.get('prefix') or ''}".strip()
    if o.kind == "geolocation":
        return f"{d.get('city') or '?'}, {d.get('country') or '?'} ({d.get('org') or '?'}) approx."
    if o.kind == "exposure_metadata":
        return f"ports {d.get('ports')} cves {len(d.get('vulns', []))}"
    if o.kind == "reputation":
        return ", ".join(f"{k}={d[k]}" for k in ("abuse_confidence_score", "total_reports", "malicious", "suspicious") if k in d)
    if o.kind == "ip_classification":
        return d.get("classification", "")
    if o.kind == "http_response":
        return f"HTTP {d.get('status')} final={d.get('final_url')}"
    if o.kind == "tls_certificate":
        return d.get("error") or f"issuer={d.get('issuer_org')} expires in {d.get('days_until_expiry')} days"
    if o.kind == "security_txt":
        return "absent" if o.value == "absent" else ("problems: " + "; ".join(d.get("problems", [])) if d.get("problems") else "valid")
    if o.kind == "robots_txt":
        return f"disallow rules={d.get('disallow_rules', 0)}" if d.get("present") else "not found"
    return o.value


def _findings(console, inv):
    if not inv.findings:
        console.print("\n[dim]No findings from the rules that could be evaluated.[/]")
        return
    t = _t("Findings (observations - not confirmed vulnerabilities)", "Sev", "ID", "Title", "Evidence", "Conf.")
    for f in sorted(inv.findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.id)):
        t.add_row(f"[{SEV_STYLE[f.severity]}]{f.severity.value.upper()}[/]", f.id, esc(f.title), esc(f.evidence[:100]), f.confidence.value)
    console.print()
    console.print(t)


def _sources(console, inv, verbose):
    rows = inv.sources
    if not verbose:
        rows = [s for s in rows if s.status in (Status.FAILED, Status.SKIPPED)]
        if not rows:
            return
        title = "Sources that did not return data (use --verbose for all)"
    else:
        title = "All sources"
    t = _t(title, "Module", "Source", "Status", "Detail")
    for s in rows:
        t.add_row(s.module, esc(s.source), f"[{STATUS_STYLE[s.status]}]{s.status.value}[/]", esc(s.detail[:100]))
    console.print()
    console.print(t)
