"""CLI behaviour via Click's CliRunner (offline only)."""
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from vestige.cli import cli

runner = CliRunner()


def run(*args):
    return runner.invoke(cli, list(args), catch_exceptions=False)


def test_help_lists_existing_and_new_commands():
    r = run("--help")
    assert r.exit_code == 0
    for cmd in ("email", "domain", "ip", "username", "phone", "recon", "diff", "demo", "purge", "sources"):
        assert cmd in r.output


@pytest.mark.parametrize("cmd,flag", [("email", "-e"), ("domain", "-d"), ("ip", "-i"), ("username", "-u"), ("phone", "-p"), ("recon", "-d")])
def test_legacy_short_flags_preserved(cmd, flag):
    assert flag in run(cmd, "--help").output


def test_version():
    assert "VESTIGE" in run("--version").output


def test_demo_runs_offline_and_writes_all_reports(tmp_path):
    r = run("demo", "--out-dir", str(tmp_path))
    assert r.exit_code == 0 and "FIXTURE DATA" in r.output and "NOT a live scan" in r.output
    files = sorted(p.suffix for p in tmp_path.iterdir())
    assert files == [".html", ".json", ".md"]
    data = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert data["investigation"]["mode"] == "offline-fixture" and data["findings"]


def test_invalid_domain_is_clean_error_not_traceback():
    r = runner.invoke(cli, ["recon", "-d", "http://bad domain/"])
    assert r.exit_code == 2 and "Traceback" not in r.output and "Error" in r.output + (r.stderr if r.stderr_bytes else "")


@pytest.mark.parametrize("args", [["domain", "-d", "1.2.3.4"], ["email", "-e", "nope"], ["ip", "-i", "999.9.9.9"],
                                  ["username", "-u", "a b"], ["phone", "-p", "12345"], ["recon", "-d", "example.com", "-m", "bogus"]])
def test_invalid_inputs_exit_2_without_traceback(args):
    r = runner.invoke(cli, args)
    assert r.exit_code == 2 and "Traceback" not in r.output


def test_confirm_without_http_checks_is_rejected():
    r = runner.invoke(cli, ["recon", "-d", "example.com", "--offline", "--confirm-authorized"])
    assert r.exit_code == 2


def test_offline_recon_runs_without_network_and_skips_everything_remote(tmp_path):
    r = run("recon", "-d", "example.com", "--offline", "--report", "json", "--out-dir", str(tmp_path))
    assert r.exit_code == 0
    d = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert d["investigation"]["scope"]["mode"] == "passive"
    # offline: nothing may be reported FAILED or as having returned remote data; remote sources are SKIPPED
    assert d["summary"]["sources"]["FAILED"] == 0
    ok = [s["source"] for s in d["sources"] if s["status"] == "OK"]
    assert ok == ["disposable-list"]  # local seed list only; its detail states the maintained list was unreachable


def test_offline_ip_private_address(tmp_path):
    r = run("ip", "-i", "10.1.2.3", "--offline", "--report", "json", "--out-dir", str(tmp_path))
    assert r.exit_code == 0
    d = json.loads(next(tmp_path.glob("*.json")).read_text(encoding="utf-8"))
    assert d["observations"][0]["data"]["classification"] == "private"


def test_phone_command_masks_number_in_report(tmp_path):
    r = run("phone", "-p", "+919876543210", "--offline", "--report", "json", "--out-dir", str(tmp_path))
    assert r.exit_code == 0
    text = next(tmp_path.glob("*.json")).read_text(encoding="utf-8")
    d = json.loads(text)
    assert "9876543210" not in d["investigation"]["target"] and d["investigation"]["target"].endswith("3210")


def test_email_command_masks_local_part(tmp_path):
    r = run("email", "-e", "john.doe@example.com", "--offline", "--report", "json", "--out-dir", str(tmp_path))
    assert r.exit_code == 0
    text = next(tmp_path.glob("*.json")).read_text(encoding="utf-8")
    assert "john.doe" not in text and "example.com" in text


def test_diff_command_roundtrip(tmp_path):
    run("demo", "--out-dir", str(tmp_path), "--report", "json")
    f = next(tmp_path.glob("*.json"))
    r = run("diff", str(f), str(f))
    assert r.exit_code == 0 and "+0 -0 ~0" in r.output


def test_diff_rejects_non_vestige_file(tmp_path):
    bad = tmp_path / "x.json"
    bad.write_text("{}")
    r = runner.invoke(cli, ["diff", str(bad), str(bad)])
    assert r.exit_code == 2 and "not a VESTIGE report" in r.output


def test_purge_command(tmp_path):
    (tmp_path / "vestige-a.json").write_text("{}")
    (tmp_path / "keep.json").write_text("{}")
    assert "1 file(s) would be removed" in run("purge", "--out-dir", str(tmp_path), "--dry-run").output
    assert (tmp_path / "vestige-a.json").exists()
    run("purge", "--out-dir", str(tmp_path))
    assert not (tmp_path / "vestige-a.json").exists() and (tmp_path / "keep.json").exists()


def test_sources_never_prints_secret_values(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_KEY", "SUPERSECRETVALUE")
    r = run("sources")
    assert "SUPERSECRETVALUE" not in r.output and "ABUSEIPDB_KEY" in r.output and "set" in r.output
