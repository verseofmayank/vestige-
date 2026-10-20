"""Correlation and de-duplication.

Observations and relationships coming from different sources are merged by key. When
independent sources agree, the merged record lists all of them and confidence is raised one
level (documented limitation: sources can share an upstream, e.g. CT logs, so this is
corroboration, not proof).

Relationship predicates are deliberately descriptive of *observations*; none of them asserts
ownership. Shared hosting, shared certificates and shared nameservers are never treated as
evidence of common ownership.
"""
from __future__ import annotations

from vestige.core.models import Confidence, Investigation, Observation, Relationship

PREDICATES = {
    "has_subdomain": "domain -> subdomain name seen by a source",
    "resolves_to": "hostname -> IP address returned by DNS at observation time",
    "announced_by": "IP -> ASN that announces the covering prefix (BGP origin)",
    "covered_by_certificate": "hostname -> certificate (CT log entry) listing it as a SAN",
    "uses_mail_exchanger": "domain -> MX host",
    "has_nameserver": "domain -> NS host",
    "has_reputation_observation": "domain/IP -> third-party reputation record (not a verdict)",
    "archived_as": "domain -> historical URL host seen in an archive",
}

_ORDER = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH]


def _bump(c: Confidence) -> Confidence:
    return _ORDER[min(_ORDER.index(c) + 1, len(_ORDER) - 1)]


def _max(a: Confidence, b: Confidence) -> Confidence:
    return a if _ORDER.index(a) >= _ORDER.index(b) else b


def _sources(o) -> list[str]:
    if isinstance(o, Observation):
        return list(o.data.get("sources") or [s for s in o.source.split(", ") if s])
    return [s for s in o.source.split(", ") if s]


def merge_observations(items: list[Observation]) -> list[Observation]:
    merged: dict[tuple[str, str], Observation] = {}
    # Sort first: sources finish in thread order, but the merged result must not depend on it.
    for o in sorted(items, key=lambda x: (x.kind, x.value, x.source, x.observed_at)):
        k = o.key()
        if k not in merged:
            o.data = dict(o.data)
            o.data["sources"] = sorted(set(_sources(o)))
            o.source = ", ".join(o.data["sources"])
            merged[k] = o
            continue
        m = merged[k]
        srcs = sorted(set(m.data["sources"]) | set(_sources(o)))
        new_source = len(srcs) > len(m.data["sources"])
        m.data["sources"] = srcs
        m.source = ", ".join(srcs)
        refs = sorted(set(m.data.get("source_refs", [])) | set(o.data.get("source_refs", [])))
        if refs:
            m.data["source_refs"] = refs
        m.confidence = _max(m.confidence, o.confidence)
        if new_source:
            m.confidence = _bump(m.confidence)
        m.observed_at = min(m.observed_at, o.observed_at)
        for dk, dv in o.data.items():  # fill gaps; widen first/last-seen windows
            if dk in ("sources", "source_refs"):
                continue
            if dk == "first_seen" and dv and (not m.data.get(dk) or dv < m.data[dk]):
                m.data[dk] = dv
            elif dk == "last_seen" and dv and (not m.data.get(dk) or dv > m.data[dk]):
                m.data[dk] = dv
            elif dk not in m.data:
                m.data[dk] = dv
    return sorted(merged.values(), key=lambda x: (x.kind, x.value))


def merge_relationships(items: list[Relationship]) -> list[Relationship]:
    merged: dict[tuple[str, str, str], Relationship] = {}
    for r in sorted(items, key=lambda x: (x.key(), x.source, x.observed_at)):
        k = r.key()
        if k not in merged:
            merged[k] = r
            continue
        m = merged[k]
        srcs = sorted(set(_sources(m)) | set(_sources(r)))
        grew = len(srcs) > len(_sources(m))
        m.source = ", ".join(srcs)
        m.confidence = _max(m.confidence, r.confidence)
        if grew:
            m.confidence = _bump(m.confidence)
        m.observed_at = min(m.observed_at, r.observed_at)
    return sorted(merged.values(), key=lambda x: x.key())


def correlate(inv: Investigation) -> Investigation:
    """De-duplicate observations/relationships in place and derive cross-source links."""
    inv.observations = merge_observations(inv.observations)
    inv.relationships = merge_relationships(inv.relationships)
    return inv


def graph_summary(inv: Investigation) -> dict[str, list[str]]:
    """Adjacency view {subject: ["predicate -> object", ...]} used by reports."""
    out: dict[str, list[str]] = {}
    for r in inv.relationships:
        out.setdefault(r.subject, []).append(f"{r.predicate} -> {r.object}")
    return {k: sorted(set(v)) for k, v in sorted(out.items())}
