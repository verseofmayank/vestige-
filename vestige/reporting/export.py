"""JSON / Markdown export and safe artifact storage."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from vestige.core.models import SEVERITY_ORDER, Investigation, Severity
from vestige.core.redact import redact_obj

ARTIFACT_PREFIX = "vestige-"
ARTIFACT_SUFFIXES = (".json", ".html", ".md")
DEFAULT_OUT_DIR = "vestige-output"


def safe_dict(inv: Investigation, secrets: list[str] | None = None) -> dict:
    """The report dict with known secret values and token-shaped strings scrubbed (structure stays valid)."""
    return redact_obj(inv.to_dict(), secrets or [])


def to_json(inv: Investigation, secrets: list[str] | None = None) -> str:
    """Stable-schema JSON."""
    return json.dumps(safe_dict(inv, secrets), indent=2, ensure_ascii=False)


def to_markdown(inv: Investigation, secrets: list[str] | None = None) -> str:
    d = safe_dict(inv, secrets)
    meta = d["investigation"]
    L: list[str] = []
    L.append(f"# VESTIGE report: {meta['target']}")
    if meta["mode"] != "live":
        L.append("\n> **FIXTURE DATA: this is an offline demonstration, not a live scan.**")
    L.append(f"\n- Command: `{meta['command']}`\n- Started: {meta['started_at']}\n- Finished: {meta['finished_at'] or 'n/a'}")
    L.append(f"- Scope: `{json.dumps(meta['scope'])}`")
    s = d["summary"]
    L.append(f"- Sources: {s['sources']['OK']} OK, {s['sources']['EMPTY']} empty, {s['sources']['FAILED']} failed, {s['sources']['SKIPPED']} skipped")
    L.append("\n## Findings (observations, not confirmed vulnerabilities)\n")
    if not d["findings"]:
        L.append("_No findings were produced by the rules that could be evaluated._")
    for f in d["findings"]:
        L.append(f"### [{f['severity'].upper()}] {f['id']}: {f['title']}")
        L.append(f"- **Target:** {f['target']}\n- **Evidence:** {f['evidence']}\n- **Source:** {f['source']} · **Confidence:** {f['confidence']} · **Observed:** {f['observed_at']}")
        L.append(f"- **Why it matters:** {f['explanation']}\n- **Next step:** {f['recommendation']}")
        if f["standard"]:
            L.append(f"- **Reference:** {f['standard']}")
        L.append("")
    L.append("## Module and source status\n\n| Module | Source | Status | Items | Detail |\n|---|---|---|---|---|")
    for r in d["sources"]:
        L.append(f"| {r['module']} | {_md(r['source'])} | {r['status']} | {r['items']} | {_md(r['detail'])} |")
    L.append("\n## Observations\n")
    kinds: dict[str, list] = {}
    for o in d["observations"]:
        kinds.setdefault(o["kind"], []).append(o)
    for k in sorted(kinds):
        L.append(f"### {k} ({len(kinds[k])})\n")
        for o in kinds[k][:100]:
            L.append(f"- `{_md(o['value'])}` ({o['confidence']}; {_md(o['source'])})")
        if len(kinds[k]) > 100:
            L.append(f"- … {len(kinds[k]) - 100} more (see JSON)")
        L.append("")
    L.append("## Limitations\n")
    L.extend(f"- {x}" for x in d["limitations"])
    return "\n".join(L) + "\n"


def _md(s) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def _slug(s: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s)
    s = re.sub(r"\.{2,}", ".", s)
    return s[:60].strip("_.") or "target"


def write_outputs(inv: Investigation, formats: list[str], out_dir: str | Path = DEFAULT_OUT_DIR,
                  secrets: list[str] | None = None) -> list[Path]:
    """Write requested report formats; returns the created file paths."""
    from vestige.reporting.html_report import to_html
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = f"{ARTIFACT_PREFIX}{inv.command}-{_slug(inv.target)}-{stamp}"
    fmts = {"json", "html", "md"} if "all" in formats else set(formats)
    written = []
    renderers = {"json": (".json", lambda: to_json(inv, secrets)),
                 "html": (".html", lambda: to_html(inv, secrets)),
                 "md": (".md", lambda: to_markdown(inv, secrets))}
    for f in sorted(fmts):
        ext, fn = renderers[f]
        p = out / (base + ext)
        p.write_text(fn(), encoding="utf-8")
        written.append(p)
    return written


def purge(out_dir: str | Path = DEFAULT_OUT_DIR, *, older_than_days: float | None = None, dry_run: bool = False) -> list[Path]:
    """Delete VESTIGE-generated artifacts only (vestige-*.json|html|md) from out_dir. Never recurses."""
    out = Path(out_dir)
    removed = []
    if not out.is_dir():
        return removed
    now = datetime.now().timestamp()
    for p in sorted(out.iterdir()):
        if not (p.is_file() and not p.is_symlink() and p.name.startswith(ARTIFACT_PREFIX) and p.suffix in ARTIFACT_SUFFIXES):
            continue
        if older_than_days is not None and (now - p.stat().st_mtime) < older_than_days * 86400:
            continue
        if not dry_run:
            p.unlink()
        removed.append(p)
    return removed


def sorted_findings(inv: Investigation):
    return sorted(inv.findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.id))


__all__ = ["to_json", "to_markdown", "write_outputs", "purge", "Severity"]
