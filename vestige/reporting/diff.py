"""Offline comparison of two VESTIGE JSON reports.

Principle: report a change only when both runs could actually observe the thing. If a source
failed/was skipped in either run, absence is "not comparable", never "removed".
"""
from __future__ import annotations

import json
from pathlib import Path

# Volatile or noisy kinds that are not compared item-by-item.
IGNORED_KINDS = {"geolocation", "ip_classification", "historical_url", "username_check", "phone_metadata", "reverse_dns"}
# Kinds that hold one value per target, so a different value is a *change* not add+remove.
SINGLE_VALUED = {"spf", "dmarc", "dnssec", "wildcard_dns", "mta_sts", "tls_rpt", "disposable_domain", "registration", "dns_provider"}
# observation source token -> prefix of the SourceResult.source that produced it
_OK = {"OK", "EMPTY"}


class DiffError(ValueError):
    pass


def load_report(path: str | Path) -> dict:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise DiffError(f"cannot read {path}: {exc.strerror}") from exc
    except ValueError as exc:
        raise DiffError(f"{path} is not valid JSON") from exc
    if not isinstance(doc, dict) or doc.get("tool", {}).get("name") != "VESTIGE" or "investigation" not in doc:
        raise DiffError(f"{path} is not a VESTIGE report")
    if str(doc.get("schema_version", "")).split(".")[0] != "1":
        raise DiffError(f"{path}: unsupported schema_version {doc.get('schema_version')!r}")
    return doc


def _sources_ok(report: dict, ref: str) -> bool:
    """Did the SourceResult named `ref` run successfully (OK/EMPTY) in this report?"""
    return any(s["source"] == ref and s["status"] in _OK for s in report.get("sources", []))


def _refs(o: dict) -> list[str]:
    return o.get("data", {}).get("source_refs") or []


def _index(report: dict) -> dict[tuple[str, str], dict]:
    return {(o["kind"], o["value"]): o for o in report.get("observations", []) if o["kind"] not in IGNORED_KINDS}


def _comparable_side(report: dict, o: dict) -> bool:
    """True if every source that produced `o` ran successfully in `report`. Unknown provenance -> False."""
    refs = _refs(o)
    return bool(refs) and all(_sources_ok(report, r) for r in refs)


def compare(old: dict, new: dict) -> dict:
    oi, ni = _index(old), _index(new)
    added, removed, changed, not_comparable = [], [], [], []
    by_kind_old: dict[str, list] = {}
    by_kind_new: dict[str, list] = {}
    for (k, v), o in oi.items():
        by_kind_old.setdefault(k, []).append(o)
    for (k, v), o in ni.items():
        by_kind_new.setdefault(k, []).append(o)

    handled: set[tuple[str, str]] = set()
    for kind in sorted(SINGLE_VALUED & (set(by_kind_old) | set(by_kind_new))):
        o_list, n_list = by_kind_old.get(kind, []), by_kind_new.get(kind, [])
        if o_list and n_list:
            ov, nv = sorted(x["value"] for x in o_list), sorted(x["value"] for x in n_list)
            for x in o_list + n_list:
                handled.add((x["kind"], x["value"]))
            if ov != nv:
                if _comparable_side(old, o_list[0]) and _comparable_side(new, n_list[0]):
                    changed.append({"kind": kind, "old": ov, "new": nv, "detail": _single_detail(kind, o_list[0], n_list[0])})
                else:
                    not_comparable.append({"kind": kind, "reason": "source unavailable in one run"})
            elif kind == "registration":
                d = _single_detail(kind, o_list[0], n_list[0])
                if d:
                    changed.append({"kind": kind, "old": ov, "new": nv, "detail": d})
        elif n_list and not o_list:
            handled.add((kind, n_list[0]["value"]))
            if _comparable_side(old, n_list[0]):
                added.append({"kind": kind, "value": n_list[0]["value"], "source": n_list[0]["source"]})
            else:
                not_comparable.append({"kind": kind, "reason": "not collected successfully in the older report"})
        elif o_list and not n_list:
            handled.add((kind, o_list[0]["value"]))
            if _comparable_side(new, o_list[0]):
                removed.append({"kind": kind, "value": o_list[0]["value"], "source": o_list[0]["source"]})
            else:
                not_comparable.append({"kind": kind, "reason": "not collected successfully in the newer report"})

    for key, n in sorted(ni.items()):
        if key in handled or key in oi:
            continue
        if _comparable_side(old, n):
            added.append({"kind": key[0], "value": key[1], "source": n["source"]})
        else:
            not_comparable.append({"kind": key[0], "value": key[1], "reason": "source did not run successfully in the older report"})
    for key, o in sorted(oi.items()):
        if key in handled or key in ni:
            continue
        if _comparable_side(new, o):
            removed.append({"kind": key[0], "value": key[1], "source": o["source"]})
        else:
            not_comparable.append({"kind": key[0], "value": key[1], "reason": "source did not run successfully in the newer report"})

    # DNS-state transitions of subdomains present in both
    for key, n in sorted(ni.items()):
        if key[0] == "subdomain" and key in oi:
            a, b = oi[key]["data"].get("dns_state"), n["data"].get("dns_state")
            if a and b and a != b and "unverified" not in (a, b):
                changed.append({"kind": "subdomain_dns_state", "value": key[1], "old": a, "new": b})

    fo = {(f["id"], f["target"]): f for f in old.get("findings", [])}
    fn = {(f["id"], f["target"]): f for f in new.get("findings", [])}
    f_new = [fn[k] for k in sorted(fn) if k not in fo]
    f_gone = [fo[k] for k in sorted(fo) if k not in fn]
    f_sev = [{"id": k[0], "target": k[1], "old": fo[k]["severity"], "new": fn[k]["severity"]}
             for k in sorted(fo) if k in fn and fo[k]["severity"] != fn[k]["severity"]]

    return {
        "old": _meta(old), "new": _meta(new),
        "warnings": ([f"targets differ: {old['investigation']['target']} vs {new['investigation']['target']}"]
                     if old["investigation"]["target"] != new["investigation"]["target"] else [])
                    + (["one report is FIXTURE data, not a live scan"] if "live" != old["investigation"]["mode"] or "live" != new["investigation"]["mode"] else []),
        "observations": {"added": added, "removed": removed, "changed": changed},
        "not_comparable": not_comparable,
        "findings": {"new": f_new, "resolved": f_gone, "severity_changed": f_sev},
        "counts": {"added": len(added), "removed": len(removed), "changed": len(changed),
                   "not_comparable": len(not_comparable), "findings_new": len(f_new), "findings_resolved": len(f_gone)},
    }


def _meta(r: dict) -> dict:
    i = r["investigation"]
    return {"target": i["target"], "started_at": i["started_at"], "mode": i["mode"]}


def _single_detail(kind: str, o: dict, n: dict) -> str:
    od, nd = o.get("data", {}), n.get("data", {})
    if kind == "registration":
        diffs = [f"{k}: {od.get(k)} -> {nd.get(k)}" for k in ("registrar", "expires", "status", "nameservers") if od.get(k) != nd.get(k)]
        return "; ".join(diffs)
    if kind == "dmarc":
        return f"policy {od.get('policy')} -> {nd.get('policy')}" if od.get("policy") != nd.get("policy") else ""
    return ""
