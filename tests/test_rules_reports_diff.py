"""Findings engine, reports (JSON/HTML/Markdown), redaction, artifact storage, diff."""
import json
from datetime import datetime, timezone

import pytest

from tests.conftest import make_ctx
from vestige.core import rules
from vestige.core.models import Confidence, Investigation, Observation, Severity, SourceResult, Status
from vestige.core.redact import REDACTED, redact_headers, redact_text, redact_url
from vestige.demo import DEMO_NOW, run_demo
from vestige.reporting import diff as D
from vestige.reporting.export import purge, to_json, to_markdown, write_outputs
from vestige.reporting.html_report import to_html

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def inv_with(*obs, sources=()):
    inv = Investigation(command="t", target="example.com")
    inv.observations += list(obs)
    inv.sources += list(sources)
    return inv


def O(kind, value, source="dns", /, **data):
    return Observation(kind, value, source, Confidence.HIGH, "2026-06-01T00:00:00Z", data)


def ids(findings):
    return {f.id for f in findings}


# ---------------------------------------------------------------------------- rules
def test_missing_dmarc_with_mail_is_finding_with_all_required_fields():
    inv = inv_with(O("dmarc", "missing", present=False), O("mx", "mx.example.com", priority=10))
    f = [x for x in rules.evaluate(inv, "example.com", NOW) if x.id == "VST-MAIL-001"][0]
    assert f.severity == Severity.MEDIUM and f.standard == "RFC 7489"
    for attr in ("id", "title", "evidence", "source", "observed_at", "explanation", "recommendation"):
        assert getattr(f, attr)
    assert f.confidence == Confidence.HIGH and f.kind == "observation"


def test_missing_dmarc_without_mail_is_lower_severity():
    inv = inv_with(O("dmarc", "missing", present=False))
    assert [x for x in rules.evaluate(inv, "example.com", NOW) if x.id == "VST-MAIL-001"][0].severity == Severity.LOW


def test_dmarc_p_none_is_informational_not_alarming():
    inv = inv_with(O("dmarc", "v=DMARC1; p=none", present=True, valid=True, policy="none", pct=100, rua=[], found_at="_dmarc.example.com"))
    f = [x for x in rules.evaluate(inv, "example.com", NOW) if x.id == "VST-MAIL-002"][0]
    assert f.severity == Severity.INFO


def test_reject_dmarc_produces_no_dmarc_finding():
    inv = inv_with(O("dmarc", "v=DMARC1; p=reject", present=True, valid=True, policy="reject", pct=100, rua=["x"]))
    assert not [f for f in rules.evaluate(inv, "example.com", NOW) if f.id.startswith("VST-MAIL-00")]


def test_spf_plus_all_flagged_but_tilde_all_is_not():
    bad = inv_with(O("spf", "v=spf1 +all", present=True, valid=True, all="+", mechanisms=["+all"], flags=[], dns_lookup_terms=0, redirect=None, policy="x"))
    good = inv_with(O("spf", "v=spf1 ~all", present=True, valid=True, all="~", mechanisms=["~all"], flags=[], dns_lookup_terms=0, redirect=None, policy="x"))
    assert "VST-MAIL-011" in ids(rules.evaluate(bad, "example.com", NOW))
    assert "VST-MAIL-011" not in ids(rules.evaluate(good, "example.com", NOW))


def test_spf_unparseable_creates_no_spf_policy_claims():
    inv = inv_with(O("spf", "unparseable", present=True, valid=False))
    assert not [f for f in rules.evaluate(inv, "example.com", NOW) if f.id.startswith("VST-MAIL-01")]


def http_obs(**headers):
    base = {k: None for k in web_headers()}
    base.update(headers)
    return O("http_response", "example.com", "direct-http", final_url="https://example.com/", status=200, headers=base,
             technology_headers={}, redirect_note="")


def web_headers():
    return ["strict-transport-security", "content-security-policy", "x-content-type-options", "referrer-policy", "permissions-policy", "x-frame-options"]


def test_missing_hsts_on_https_is_low_and_not_a_vulnerability_claim():
    f = [x for x in rules.evaluate(inv_with(http_obs()), "example.com", NOW) if x.id == "VST-WEB-001"][0]
    assert f.severity == Severity.LOW and "not an exploitable flaw" in f.explanation


def test_hsts_present_with_good_max_age_has_no_hsts_finding():
    inv = inv_with(http_obs(**{"strict-transport-security": "max-age=31536000", "hsts_max_age": 31536000}))
    assert not ids(rules.evaluate(inv, "example.com", NOW)) & {"VST-WEB-001", "VST-WEB-002"}


def test_missing_security_headers_never_exceed_low():
    inv = inv_with(http_obs())
    web = [f for f in rules.evaluate(inv, "example.com", NOW) if f.id.startswith("VST-WEB")]
    assert web and all(f.severity in (Severity.LOW, Severity.INFO) for f in web)


@pytest.mark.parametrize("days,sev", [(-3, Severity.HIGH), (7, Severity.MEDIUM), (20, Severity.LOW), (90, None)])
def test_certificate_expiry_thresholds(days, sev):
    inv = inv_with(O("tls_certificate", "example.com", "direct-tls", days_until_expiry=days, not_after="2026-07-01", verified=True))
    fs = [f for f in rules.evaluate(inv, "example.com", NOW) if f.id == "VST-TLS-001"]
    assert (fs[0].severity if fs else None) == sev


def test_tls_verification_failure():
    inv = inv_with(O("tls_certificate", "example.com", "direct-tls", error="certificate verification failed: hostname mismatch", verified=False))
    assert "VST-TLS-002" in ids(rules.evaluate(inv, "example.com", NOW))


@pytest.mark.parametrize("score,expected", [(5, None), (24, None), (25, Severity.LOW), (74, Severity.LOW), (75, Severity.MEDIUM), (100, Severity.MEDIUM)])
def test_abuse_score_thresholds_are_conservative(score, expected):
    inv = inv_with(O("reputation", "abuseipdb:1.2.3.4", "abuseipdb", subject="1.2.3.4", abuse_confidence_score=score, total_reports=3,
                     distinct_reporters=2, last_reported_at="x", is_whitelisted=False))
    fs = [f for f in rules.evaluate(inv, "example.com", NOW) if f.id == "VST-REP-001"]
    assert (fs[0].severity if fs else None) == expected
    if fs:
        assert "not proof" in fs[0].explanation


def test_no_finding_ever_says_malicious_and_no_high_from_reputation():
    inv = inv_with(O("reputation", "virustotal:x", "virustotal", subject="x.com", malicious=50, suspicious=0, harmless=1, undetected=1),
                   O("reputation", "abuseipdb:1.2.3.4", "abuseipdb", subject="1.2.3.4", abuse_confidence_score=100, total_reports=900, distinct_reporters=300,
                     last_reported_at="x", is_whitelisted=False))
    fs = rules.evaluate(inv, "example.com", NOW)
    assert fs and all(f.severity != Severity.HIGH for f in fs)
    assert all("malicious" not in f.title.lower() for f in fs)  # titles state counts/scores, never a verdict


def test_registration_expiry():
    mk = lambda d: inv_with(O("registration", "example.com", "rdap", expires=d, via="rdap"))  # noqa: E731
    assert "VST-REG-001" in ids(rules.evaluate(mk("2026-06-10T00:00:00Z"), "example.com", NOW))
    assert "VST-REG-001" not in ids(rules.evaluate(mk("2030-06-10T00:00:00Z"), "example.com", NOW))
    assert "VST-REG-001" not in ids(rules.evaluate(mk("garbage"), "example.com", NOW))


def test_findings_sorted_by_severity():
    fs = run_demo().findings
    order = [f.severity for f in fs]
    from vestige.core.models import SEVERITY_ORDER
    assert [SEVERITY_ORDER[s] for s in order] == sorted(SEVERITY_ORDER[s] for s in order)


# ------------------------------------------------------------------------ redaction
def test_redact_url_params_userinfo_fragment():
    u = redact_url("https://user:pw@api.test:8443/p?access_key=SECRET&q=ok&token=T#frag")
    assert "SECRET" not in u and "pw" not in u and "frag" not in u and "q=ok" in u and "access_key=" + REDACTED in u


def test_redact_text_known_secrets_and_token_shapes():
    t = redact_text("key=abcd1234 ghp_" + "a" * 36 + " Bearer abcdefghijklmnop1234 eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij my SECRETVALUE here", ["SECRETVALUE"])
    for leaked in ("abcd1234", "ghp_a", "abcdefghijklmnop1234", "eyJhbGci", "SECRETVALUE"):
        assert leaked not in t
    assert redact_text("short", ["abc"]) == "short"  # too-short secrets are ignored (avoid mangling)


def test_redact_headers():
    h = redact_headers({"Authorization": "Bearer x", "Key": "abc", "Accept": "json", "X-API-Key": "k"})
    assert h["Authorization"] == REDACTED and h["Key"] == REDACTED and h["X-API-Key"] == REDACTED and h["Accept"] == "json"


def test_secrets_never_appear_in_any_report_format():
    inv = Investigation(command="t", target="example.com")
    inv.observations.append(O("dns_record", "x", "dns", type="TXT", value="leak=TOPSECRETKEY123 here"))
    inv.limitations.append("token TOPSECRETKEY123")
    for text in (to_json(inv, ["TOPSECRETKEY123"]), to_html(inv, ["TOPSECRETKEY123"]), to_markdown(inv, ["TOPSECRETKEY123"])):
        assert "TOPSECRETKEY123" not in text


# ------------------------------------------------------------------------- reports
def test_json_schema_is_stable():
    d = json.loads(to_json(run_demo()))
    assert set(d) == {"schema_version", "tool", "investigation", "sources", "observations", "relationships", "findings", "limitations", "summary"}
    assert d["schema_version"] == "1.0" and d["tool"]["name"] == "VESTIGE" and d["investigation"]["mode"] == "offline-fixture"
    f = d["findings"][0]
    assert set(f) == {"id", "title", "severity", "target", "evidence", "source", "confidence", "explanation", "recommendation", "standard", "observed_at", "kind"}
    assert set(d["sources"][0]) == {"module", "source", "status", "detail", "items", "duration_s", "http_status", "queried_at"}


def test_demo_output_is_deterministic_apart_from_timestamps():
    import re

    def scrub(o):  # drop wall-clock fields anywhere in the structure
        if isinstance(o, dict):
            return {k: scrub(v) for k, v in o.items() if not (k.endswith("_at") or k in ("duration_s", "first_seen", "last_seen"))}
        if isinstance(o, list):
            return [scrub(x) for x in o]
        return o

    def norm(inv):
        text = json.dumps(scrub(json.loads(to_json(inv))), sort_keys=True)
        return re.sub(r"vestige-[0-9a-f]{12}", "RAND", text)  # random wildcard-probe label
    runs = {norm(run_demo()) for _ in range(8)}
    assert len(runs) == 1


def test_demo_is_labelled_fixture_everywhere():
    inv = run_demo()
    assert inv.mode == "offline-fixture" and inv.limitations[0].startswith("FIXTURE DATA")
    assert "FIXTURE DATA" in to_html(inv) and "FIXTURE DATA" in to_markdown(inv)


def test_html_escapes_untrusted_content():
    evil = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
    inv = Investigation(command="t", target=evil)
    inv.observations += [O("dns_record", evil, "dns", type="TXT", value=evil),
                         O("subdomain", "a." + evil, "crt.sh", dns_state=evil, sources=[evil], resolved_ips=[evil]),
                         O("username_check", evil, evil, status=evil, detail=evil, profile_url=evil, confidence="high")]
    inv.sources.append(SourceResult("m", evil, Status.OK, evil))
    inv.limitations.append(evil)
    from vestige.core.models import Finding
    inv.findings.append(Finding("X-1", evil, Severity.LOW, evil, evil, evil, Confidence.LOW, evil, evil, evil))
    html = to_html(inv)
    assert "<script>alert" not in html and "<img src=x" not in html and "onerror=alert" not in html.replace("onerror=alert(2)&gt;", "")
    assert "&lt;script&gt;" in html


def test_html_is_self_contained():
    html = to_html(run_demo())
    import re
    assert not re.search(r"<(script|link|iframe)\b", html, re.I)
    assert not re.search(r"""(src|href)\s*=\s*["']https?://""", html, re.I)
    assert "@import" not in html and "Content-Security-Policy" in html and "default-src 'none'" in html
    assert "viewport" in html and "prefers-color-scheme" in html


def test_html_contains_expected_sections():
    html = to_html(run_demo())
    for needle in ("Findings", "What was checked", "Subdomains", "Mail infrastructure", "Limitations", "VST-MAIL-002", "not confirmed vulnerabilit"):
        assert needle in html


def test_markdown_report():
    md = to_markdown(run_demo())
    assert md.startswith("# VESTIGE report") and "## Findings" in md and "| Module | Source | Status |" in md


def test_write_outputs_and_purge_only_touch_vestige_files(tmp_path):
    inv = run_demo()
    paths = write_outputs(inv, ["all"], tmp_path)
    assert {p.suffix for p in paths} == {".json", ".html", ".md"} and all(p.name.startswith("vestige-") for p in paths)
    keep = [tmp_path / "notes.json", tmp_path / "vestige-keep.txt", tmp_path / "other.html"]
    for k in keep:
        k.write_text("x")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "vestige-nested.json").write_text("x")
    assert len(purge(tmp_path, dry_run=True)) == 3 and all(p.exists() for p in paths)
    removed = purge(tmp_path)
    assert len(removed) == 3 and not any(p.exists() for p in paths)
    assert all(k.exists() for k in keep) and (tmp_path / "sub" / "vestige-nested.json").exists()


def test_filename_cannot_escape_out_dir(tmp_path):
    inv = Investigation(command="t", target="../../etc/passwd")
    paths = write_outputs(inv, ["json"], tmp_path)
    assert paths[0].parent == tmp_path and ".." not in paths[0].name and "/" not in paths[0].name


# --------------------------------------------------------------------------- diff
def report(obs=(), sources=(), findings=(), target="example.com", mode="live"):
    inv = Investigation(command="recon", target=target, mode=mode)
    inv.observations += list(obs)
    inv.sources += [SourceResult(m, s, st) for m, s, st in sources]
    inv.findings += list(findings)
    return json.loads(to_json(inv))


def sub(name, ref="crt.sh", srcs=None, state=None):
    d = {"source_refs": [ref], "sources": srcs or [ref]}
    if state:
        d["dns_state"] = state
    return Observation("subdomain", name, ", ".join(d["sources"]), Confidence.MEDIUM, "t", d)


OKS = [("certificates", "crt.sh", Status.OK)]


def test_diff_identical_reports_have_no_changes():
    r = report([sub("a.example.com")], OKS)
    c = D.compare(r, r)["counts"]
    assert (c["added"], c["removed"], c["changed"], c["not_comparable"]) == (0, 0, 0, 0)


def test_diff_added_and_removed_when_both_runs_could_observe():
    old, new = report([sub("a.example.com"), sub("b.example.com")], OKS), report([sub("a.example.com"), sub("c.example.com")], OKS)
    r = D.compare(old, new)
    assert [x["value"] for x in r["observations"]["added"]] == ["c.example.com"]
    assert [x["value"] for x in r["observations"]["removed"]] == ["b.example.com"]


def test_diff_does_not_invent_removals_when_source_failed_in_new_run():
    old = report([sub("a.example.com"), sub("b.example.com")], OKS)
    new = report([], [("certificates", "crt.sh", Status.FAILED)])
    r = D.compare(old, new)
    assert r["observations"]["removed"] == [] and r["counts"]["not_comparable"] == 2


def test_diff_does_not_invent_additions_when_source_missing_in_old_run():
    old = report([], [("certificates", "crt.sh", Status.SKIPPED)])
    new = report([sub("a.example.com")], OKS)
    r = D.compare(old, new)
    assert r["observations"]["added"] == [] and r["counts"]["not_comparable"] == 1


def test_diff_detects_dmarc_change_and_dns_state_change():
    mk = lambda pol: Observation("dmarc", f"v=DMARC1; p={pol}", "dns", Confidence.HIGH, "t", {"policy": pol, "source_refs": ["dmarc"]})  # noqa: E731
    srcs = [("email", "dmarc", Status.OK)]
    r = D.compare(report([mk("none")], srcs), report([mk("reject")], srcs))
    ch = r["observations"]["changed"][0]
    assert ch["kind"] == "dmarc" and "none -> reject" in ch["detail"]
    r = D.compare(report([sub("a.example.com", state="resolved")], OKS), report([sub("a.example.com", state="no_dns_answer")], OKS))
    assert any(c["kind"] == "subdomain_dns_state" and c["old"] == "resolved" for c in r["observations"]["changed"])
    # unverified is "unknown", not a change
    r = D.compare(report([sub("a.example.com", state="resolved")], OKS), report([sub("a.example.com", state="unverified")], OKS))
    assert not r["observations"]["changed"]


def test_diff_findings_new_resolved_and_severity():
    from vestige.core.models import Finding
    mk = lambda i, sev: Finding(i, "t", sev, "example.com", "e", "s", Confidence.HIGH, "x", "y")  # noqa: E731
    old = report(findings=[mk("A", Severity.LOW), mk("B", Severity.LOW)])
    new = report(findings=[mk("B", Severity.MEDIUM), mk("C", Severity.LOW)])
    f = D.compare(old, new)["findings"]
    assert [x["id"] for x in f["new"]] == ["C"] and [x["id"] for x in f["resolved"]] == ["A"]
    assert f["severity_changed"] == [{"id": "B", "target": "example.com", "old": "low", "new": "medium"}]


def test_diff_warns_on_target_mismatch_and_fixture_data():
    r = D.compare(report(target="a.com"), report(target="b.com", mode="offline-fixture"))
    assert any("targets differ" in w for w in r["warnings"]) and any("FIXTURE" in w for w in r["warnings"])


def test_diff_load_errors(tmp_path):
    with pytest.raises(D.DiffError, match="cannot read"):
        D.load_report(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(D.DiffError, match="not valid JSON"):
        D.load_report(bad)
    other = tmp_path / "other.json"
    other.write_text('{"hello": 1}')
    with pytest.raises(D.DiffError, match="not a VESTIGE report"):
        D.load_report(other)
    v2 = report()
    v2["schema_version"] = "2.0"
    f = tmp_path / "v2.json"
    f.write_text(json.dumps(v2))
    with pytest.raises(D.DiffError, match="unsupported schema_version"):
        D.load_report(f)


def test_diff_demo_against_itself_is_clean():
    r = report_from(run_demo())
    c = D.compare(r, r)["counts"]
    assert c["added"] == c["removed"] == c["changed"] == c["findings_new"] == c["findings_resolved"] == 0


def report_from(inv):
    return json.loads(to_json(inv))


def test_html_status_table_shows_item_counts_not_method_reprs():
    html = to_html(run_demo())
    assert "built-in method" not in html and "object at 0x" not in html
