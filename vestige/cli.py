"""VESTIGE command-line interface (Click + Rich)."""
from __future__ import annotations

import json
import logging
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.console import Console
from rich.markup import escape

from vestige import TOOL_NAME, __version__
from vestige.core.cache import ResponseCache
from vestige.core.context import CREDENTIAL_VARS, Context, load_credentials
from vestige.core.correlator import correlate
from vestige.core.http_client import HttpClient
from vestige.core.models import Investigation, SourceResult, Status, utcnow
from vestige.core.redact import redact_text
from vestige.core.scope import Scope, ScopeError, ValidationError, display_domain, normalize_domain
from vestige.reporting import terminal
from vestige.reporting.diff import DiffError, compare, load_report
from vestige.reporting.export import DEFAULT_OUT_DIR, purge, write_outputs

CTX = dict(help_option_names=["-h", "--help"], max_content_width=100)
console = Console(highlight=False)
err_console = Console(stderr=True, highlight=False)


class _RedactFilter(logging.Filter):
    def __init__(self, secrets):
        super().__init__()
        self.secrets = secrets

    def filter(self, record):
        record.msg = redact_text(record.getMessage(), self.secrets)
        record.args = ()
        return True


def setup_logging(verbose: bool, secrets: list[str]) -> None:
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s", "%H:%M:%S"))
    h.addFilter(_RedactFilter(secrets))
    root = logging.getLogger("vestige")
    root.handlers[:] = [h]
    root.setLevel(logging.DEBUG if verbose else logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def common_options(f):
    for opt in reversed([
        click.option("--report", "-r", "reports", multiple=True, type=click.Choice(["json", "html", "md", "all"]),
                     help="Write a report file (repeatable): json, html, md, all."),
        click.option("--out-dir", default=DEFAULT_OUT_DIR, show_default=True, help="Directory for report files."),
        click.option("--timeout", type=click.FloatRange(1, 120), default=10.0, show_default=True, help="Per-request timeout in seconds."),
        click.option("--limit", type=click.IntRange(1, 5000), default=200, show_default=True, help="Max results per source / names to DNS-test."),
        click.option("--offline", is_flag=True, help="Send no network traffic (everything not local is SKIPPED)."),
        click.option("--no-cache", is_flag=True, help="Disable the on-disk response cache."),
        click.option("--verbose", "-v", is_flag=True, help="Show every source, limitations and debug logging."),
    ]):
        f = opt(f)
    return f


def http_options(f):
    f = click.option("--confirm-authorized", is_flag=True,
                     help="Confirm you are authorised to test this target (required with --http-checks).")(f)
    f = click.option("--http-checks", is_flag=True,
                     help="Enable direct HTTP/TLS checks against the target (OFF by default = passive only).")(f)
    return f


class _Run:
    """Holds one invocation's context; builds Investigation + Context and finishes the run."""

    def __init__(self, command: str, target: str, *, timeout, limit, offline, no_cache, verbose, scope: Scope | None = None):
        self.verbose = verbose
        self.creds = load_credentials()
        setup_logging(verbose, list(self.creds.values()))
        from vestige.modules.dns import DnspythonResolver, OfflineResolver
        cache = ResponseCache(enabled=not no_cache and not offline)
        http = HttpClient(timeout=timeout, cache=cache, offline=offline, secrets=self.creds.values())
        resolver = OfflineResolver() if offline else DnspythonResolver(timeout=min(timeout, 8))
        self.inv = Investigation(command=command, target=target, mode="live")
        self.inv.scope = scope.to_dict() if scope else {"mode": "passive"}
        self.status = None
        self.ctx = Context(http=http, inv=self.inv, resolver=resolver, scope=scope, creds=self.creds, limit=limit,
                           on_source=self._progress)

    def _progress(self, sr: SourceResult) -> None:
        if self.status:
            self.status.update(f"[cyan]{escape(sr.module)}[/] / {escape(sr.source)}: {sr.status.value}")

    def __enter__(self):
        self.status = console.status("[cyan]Starting...[/]", spinner="dots")
        self.status.start()
        return self

    def __exit__(self, *exc):
        self.status.stop()
        return False

    def finish(self, reports, out_dir, verbose):
        self.inv.finished_at = utcnow()
        correlate(self.inv)
        self.inv.sources.sort(key=lambda s: (s.module, s.source))
        terminal.render(console, self.inv, verbose=verbose)
        if reports:
            paths = write_outputs(self.inv, list(reports), out_dir, self.creds.values())
            console.print("\n[bold green]Report files:[/]")
            for p in paths:
                console.print(f"  {escape(str(p.resolve()))}")


class VestigeGroup(click.Group):
    """Turns expected user errors into clean messages (no stack traces)."""

    def invoke(self, ctx):
        try:
            return super().invoke(ctx)
        except (ValidationError, ScopeError, DiffError) as exc:
            err_console.print(f"[bold red]Error:[/] {escape(str(exc))}")
            ctx.exit(2)
        except click.ClickException:
            raise
        except (KeyboardInterrupt, EOFError):
            err_console.print("[yellow]Interrupted.[/]")
            ctx.exit(130)
        except Exception as exc:  # noqa: BLE001
            if "--verbose" in sys.argv or "-v" in sys.argv:
                err_console.print(escape(traceback.format_exc()))
            err_console.print(f"[bold red]Unexpected error:[/] {escape(type(exc).__name__)}: {escape(str(exc))[:200]}  "
                              "[dim](re-run with --verbose for details)[/]")
            ctx.exit(1)


@click.group(cls=VestigeGroup, context_settings=CTX)
@click.version_option(__version__, "--version", prog_name=TOOL_NAME)
@click.pass_context
def cli(ctx):
    """
    \b
    VESTIGE: OSINT & external attack surface intelligence
    by mayhack | Traces Left Behind...

    \b
    Passive-first. Direct HTTP/TLS contact with a target needs BOTH
    --http-checks and --confirm-authorized. Use only on assets you are
    authorised to assess.

    \b
    Examples:
      python vestige.py recon -d example.com --report html
      python vestige.py domain -d example.com
      python vestige.py email -e user@example.com --dkim-selector selector1
      python vestige.py ip -i 8.8.8.8
      python vestige.py username -u targetuser
      python vestige.py phone -p +919876543210
      python vestige.py diff old.json new.json
      python vestige.py demo            (offline fixture demonstration)
    """
    if ctx.invoked_subcommand and "--help" not in sys.argv and "-h" not in sys.argv:
        terminal.show_banner(console)


def _scope(domain: str, http_checks: bool, confirm: bool) -> Scope:
    if confirm and not http_checks:
        raise ScopeError("--confirm-authorized has no effect without --http-checks")
    return Scope(domain, http_checks, confirm)


# --------------------------------------------------------------------------------------- recon

@cli.command(context_settings=CTX)
@click.option("--domain", "-d", required=True, help="Target domain (e.g. example.com).")
@click.option("--modules", "-m", default="all", show_default=True,
              help="Comma list from: dns,rdap,certs,subdomains,email,ips,archive,reputation,web (or 'all').")
@click.option("--dkim-selector", "dkim", multiple=True, help="DKIM selector to look up (repeatable); there is no universal DKIM lookup.")
@click.option("--no-resolve", is_flag=True, help="Do not DNS-test discovered subdomains (they stay 'unverified').")
@http_options
@common_options
def recon(domain, modules, dkim, no_resolve, http_checks, confirm_authorized, reports, out_dir, timeout, limit, offline, no_cache, verbose):
    """Unified investigation: DNS, RDAP, CT, subdomains, mail security, IP intel, history, findings."""
    from vestige.modules.domain import ALL_MODULES, investigate_domain
    d = normalize_domain(domain)
    mods = ALL_MODULES if modules.strip().lower() == "all" else [m.strip() for m in modules.split(",") if m.strip()]
    bad = [m for m in mods if m not in ALL_MODULES]
    if bad:
        raise ValidationError(f"unknown module(s): {', '.join(bad)}; choose from {', '.join(ALL_MODULES)}")
    _investigate("recon", d, mods, dkim, not no_resolve, http_checks, confirm_authorized, reports, out_dir, timeout, limit, offline, no_cache, verbose)


@cli.command(context_settings=CTX)
@click.option("--domain", "-d", required=True, help="Target domain (e.g. example.com).")
@http_options
@common_options
def domain(domain, http_checks, confirm_authorized, reports, out_dir, timeout, limit, offline, no_cache, verbose):
    """Domain recon: DNS, RDAP/WHOIS, certificates (CT), passive subdomains."""
    from vestige.modules.domain import DOMAIN_COMMAND_MODULES
    d = normalize_domain(domain)
    _investigate("domain", d, DOMAIN_COMMAND_MODULES, (), True, http_checks, confirm_authorized, reports, out_dir, timeout, limit, offline, no_cache, verbose)


def _investigate(command, d, mods, dkim, resolve, http_checks, confirm, reports, out_dir, timeout, limit, offline, no_cache, verbose):
    from vestige.modules.domain import investigate_domain
    scope = _scope(d, http_checks, confirm)
    run = _Run(command, display_domain(d), timeout=timeout, limit=limit, offline=offline, no_cache=no_cache, verbose=verbose, scope=scope)
    with run:
        investigate_domain(run.ctx, d, modules=mods, dkim_selectors=list(dkim) or None, resolve=resolve)
    run.finish(reports, out_dir, verbose)


# ---------------------------------------------------------------------------------------- email

@cli.command(context_settings=CTX)
@click.option("--email", "-e", required=True, help="Target email address.")
@click.option("--dkim-selector", "dkim", multiple=True, help="DKIM selector to look up (repeatable).")
@common_options
def email(email, dkim, reports, out_dir, timeout, limit, offline, no_cache, verbose):
    """Email recon: syntax, MX, SPF, DMARC, MTA-STS, TLS-RPT, DKIM (selector), disposable domains."""
    from vestige.modules.domain import investigate_domain
    from vestige.modules.email import mask_email, validate_email
    local, d = validate_email(email)
    masked = mask_email(local, d)  # the local part is not stored or reported
    run = _Run("email", masked, timeout=timeout, limit=limit, offline=offline, no_cache=no_cache, verbose=verbose, scope=Scope(d))
    with run:
        investigate_domain(run.ctx, d, modules=["dns", "email"], dkim_selectors=list(dkim) or None, resolve=False)
        run.inv.target = masked
    run.inv.limitations.append("Mailbox existence is NOT tested (no SMTP probing). Only public domain-level mail metadata is collected; "
                               "the local part is masked in reports. Breach/credential lookups are intentionally not part of VESTIGE.")
    run.finish(reports, out_dir, verbose)


# -------------------------------------------------------------------------------------------- ip

@cli.command(context_settings=CTX)
@click.option("--ip", "-i", required=True, help="Target IPv4/IPv6 address.")
@click.option("--no-reputation", is_flag=True, help="Skip AbuseIPDB lookup.")
@common_options
def ip(ip, no_reputation, reports, out_dir, timeout, limit, offline, no_cache, verbose):
    """IP recon: classification, rDNS, ASN, geo (approx.), passive exposure metadata, reputation."""
    from vestige.core import rules
    from vestige.modules.ip import analyze_ip
    from vestige.core.scope import classify_ip
    addr = classify_ip(ip)["address"]
    run = _Run("ip", addr, timeout=timeout, limit=limit, offline=offline, no_cache=no_cache, verbose=verbose)
    with run:
        analyze_ip(run.ctx, addr, reputation=not no_reputation)
    run.inv.findings = rules.evaluate(run.inv, addr)
    run.finish(reports, out_dir, verbose)


# ---------------------------------------------------------------------------------------- username

@cli.command(context_settings=CTX)
@click.option("--username", "-u", required=True, help="Username to look up.")
@click.option("--workers", type=click.IntRange(1, 12), default=8, show_default=True, help="Max parallel lookups.")
@common_options
def username(username, workers, reports, out_dir, timeout, limit, offline, no_cache, verbose):
    """Username recon on platforms with verifiable lookups (never bypasses logins or bot protection)."""
    from vestige.modules.username import FOUND, username_recon, validate_username
    u = validate_username(username)
    run = _Run("username", u, timeout=min(timeout, 15), limit=limit, offline=offline, no_cache=True, verbose=verbose)
    run.ctx.max_workers = workers
    with run:
        results = username_recon(run.ctx, u)
    run.finish(reports, out_dir, verbose)
    console.print(f"\n[bold]{sum(r['status'] == FOUND for r in results)} confirmed of {len(results)} platforms checked.[/] "
                  "[dim]UNKNOWN/BLOCKED are not 'not found'; they could not be verified.[/]")


# -------------------------------------------------------------------------------------------- phone

@cli.command(context_settings=CTX)
@click.option("--phone", "-p", required=True, help="Phone number in international format (e.g. +919876543210).")
@click.option("--region", help="Default region (ISO code, e.g. IN) for numbers without a leading '+'.")
@click.option("--no-provider", is_flag=True, help="Do not call the optional NumVerify API.")
@common_options
def phone(phone, region, no_provider, reports, out_dir, timeout, limit, offline, no_cache, verbose):
    """Phone metadata: E.164, validity, region, line type, original carrier allocation (offline data)."""
    from vestige.modules.phone import parse_number, phone_recon
    parse_number(phone, region)  # validate before building anything
    run = _Run("phone", "phone number (masked)", timeout=timeout, limit=limit, offline=offline, no_cache=True, verbose=verbose)
    with run:
        info = phone_recon(run.ctx, phone, region=region, provider=not no_provider)
    e = info["e164"]
    run.inv.target = e[:-4].replace(e[3:-4], "*" * len(e[3:-4])) + e[-4:] if len(e) > 8 else e
    run.finish(reports, out_dir, verbose)


# --------------------------------------------------------------------------------------------- diff

@cli.command(context_settings=CTX)
@click.argument("old", type=click.Path(exists=True, dir_okay=False))
@click.argument("new", type=click.Path(exists=True, dir_okay=False))
@click.option("--json", "json_out", type=click.Path(dir_okay=False), help="Also write the comparison as JSON.")
def diff(old, new, json_out):
    """Compare two VESTIGE JSON reports offline (changes only where both runs could observe)."""
    result = compare(load_report(old), load_report(new))
    from rich.table import Table
    c = result["counts"]
    console.print(f"[bold]Comparing[/] {escape(result['old']['target'])} ({escape(result['old']['started_at'])}) -> "
                  f"{escape(result['new']['target'])} ({escape(result['new']['started_at'])})")
    for w in result["warnings"]:
        console.print(f"[yellow]Warning:[/] {escape(w)}")
    t = Table(title="Observation changes", title_justify="left", header_style="bold", show_edge=False)
    for col in ("Change", "Kind", "Value / detail"):
        t.add_column(col, overflow="fold")
    for a in result["observations"]["added"]:
        t.add_row("[green]ADDED[/]", a["kind"], escape(str(a["value"])))
    for r in result["observations"]["removed"]:
        t.add_row("[red]REMOVED[/]", r["kind"], escape(str(r["value"])))
    for ch in result["observations"]["changed"]:
        t.add_row("[yellow]CHANGED[/]", ch["kind"], escape(f"{ch.get('value', '')} {ch.get('old')} -> {ch.get('new')} {ch.get('detail', '')}".strip()))
    console.print(t if t.row_count else "[dim]No observation changes between comparable data.[/]")
    f = result["findings"]
    for label, items, style in (("NEW findings", f["new"], "red"), ("RESOLVED findings", f["resolved"], "green")):
        for x in items:
            console.print(f"[{style}]{label}:[/] [{x['severity']}] {escape(x['id'])} {escape(x['title'])} ({escape(x['target'])})")
    for x in f["severity_changed"]:
        console.print(f"[yellow]Severity changed:[/] {escape(x['id'])} {x['old']} -> {x['new']}")
    if result["not_comparable"]:
        console.print(f"\n[dim]{len(result['not_comparable'])} item(s) not comparable (a source failed/was skipped/absent in one run); NOT reported as changes.[/]")
    console.print(f"\n[bold]Summary:[/] +{c['added']} -{c['removed']} ~{c['changed']} | findings +{c['findings_new']} -{c['findings_resolved']} | not comparable {c['not_comparable']}")
    if json_out:
        Path(json_out).write_text(json.dumps(result, indent=2), encoding="utf-8")
        console.print(f"[bold green]Wrote:[/] {escape(str(Path(json_out).resolve()))}")


# --------------------------------------------------------------------------------------------- demo

@cli.command(context_settings=CTX)
@click.option("--report", "-r", "reports", multiple=True, type=click.Choice(["json", "html", "md", "all"]), default=("all",), show_default=True)
@click.option("--out-dir", default="examples/demo-output", show_default=True)
@click.option("--verbose", "-v", is_flag=True)
def demo(reports, out_dir, verbose):
    """Offline demonstration from canned FIXTURE responses (no network, no API keys)."""
    from vestige.demo import run_demo
    setup_logging(verbose, [])
    console.print("[bold black on yellow] FIXTURE DATA [/] This demo uses canned responses for the reserved name "
                  "vestige-demo.example. It is NOT a live scan.\n")
    inv = run_demo()
    terminal.render(console, inv, verbose=verbose)
    paths = write_outputs(inv, list(reports), out_dir, [])
    console.print("\n[bold green]Report files:[/]")
    for p in paths:
        console.print(f"  {escape(str(p.resolve()))}")


# -------------------------------------------------------------------------------------- housekeeping

@cli.command(context_settings=CTX)
@click.option("--out-dir", default=DEFAULT_OUT_DIR, show_default=True)
@click.option("--older-than-days", type=float, help="Only delete artifacts older than this.")
@click.option("--cache", "clear_cache", is_flag=True, help="Also clear the response cache.")
@click.option("--dry-run", is_flag=True, help="List what would be deleted.")
def purge_cmd(out_dir, older_than_days, clear_cache, dry_run):
    """Delete VESTIGE-generated report files (vestige-*.json|html|md) in --out-dir; nothing else is touched."""
    removed = purge(out_dir, older_than_days=older_than_days, dry_run=dry_run)
    for p in removed:
        console.print(f"{'would delete' if dry_run else 'deleted'}: {escape(str(p))}")
    console.print(f"[bold]{len(removed)} file(s) {'would be ' if dry_run else ''}removed.[/]")
    if clear_cache and not dry_run:
        console.print(f"[bold]{ResponseCache().clear()} cache entr(ies) removed.[/]")


cli.add_command(purge_cmd, "purge")


@cli.command(context_settings=CTX)
def sources():
    """Show which optional API credentials are configured (values are never printed)."""
    from rich.table import Table
    creds = load_credentials()
    t = Table(title="Credentials (environment / .env)", title_justify="left", header_style="bold")
    for c in ("Variable", "Used for", "State"):
        t.add_column(c)
    for k, desc in CREDENTIAL_VARS.items():
        t.add_row(k, desc, "[green]set[/]" if k in creds else "[yellow]not set (feature SKIPPED)[/]")
    console.print(t)
    console.print("[dim]Keyless sources: DNS, RDAP, crt.sh, HackerTarget, Wayback, urlscan search, Team Cymru ASN, ipapi.co, Shodan InternetDB.[/]")


def main() -> None:
    for stream in (sys.stdout, sys.stderr):  # box-drawing banner must not crash legacy Windows code pages
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    cli(prog_name="vestige")
