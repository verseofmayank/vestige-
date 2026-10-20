"""Structured records shared by every module, the correlator and the reporters.

Everything is a plain dataclass that serialises to JSON-compatible dicts.
"""
from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "1.0"


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class Status(str, enum.Enum):
    """Execution status of one source/module."""
    OK = "OK"            # ran and returned data
    EMPTY = "EMPTY"      # ran successfully, source had nothing
    FAILED = "FAILED"    # error: network, auth, rate limit, malformed response
    SKIPPED = "SKIPPED"  # not run: missing credential, disabled, not authorised, offline


class Confidence(str, enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2, Severity.INFO: 3}


@dataclass
class SourceResult:
    """What happened when a source was queried; shown in every report."""
    module: str
    source: str
    status: Status
    detail: str = ""
    items: int = 0
    duration_s: float = 0.0
    http_status: int | None = None
    queried_at: str = field(default_factory=utcnow)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Observation:
    """A single fact seen by a source. `kind` is e.g. dns_record, subdomain, ip_info."""
    kind: str
    value: str
    source: str
    confidence: Confidence = Confidence.MEDIUM
    observed_at: str = field(default_factory=utcnow)
    data: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple[str, str]:
        return (self.kind, self.value)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["confidence"] = self.confidence.value
        return d


@dataclass
class Relationship:
    """subject --predicate--> object, with provenance. Never implies ownership."""
    subject: str
    predicate: str
    object: str
    source: str
    confidence: Confidence = Confidence.MEDIUM
    observed_at: str = field(default_factory=utcnow)
    note: str = ""

    def key(self) -> tuple[str, str, str]:
        return (self.subject, self.predicate, self.object)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["confidence"] = self.confidence.value
        return d


@dataclass
class Finding:
    """An explainable, evidence-backed security observation (not a confirmed vulnerability)."""
    id: str
    title: str
    severity: Severity
    target: str
    evidence: str
    source: str
    confidence: Confidence
    explanation: str
    recommendation: str
    standard: str = ""
    observed_at: str = field(default_factory=utcnow)
    kind: str = "observation"  # always an observation; VESTIGE never asserts a confirmed vulnerability

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        return d


@dataclass
class Investigation:
    """The root record: one scan, serialised as the stable JSON report."""
    command: str
    target: str
    mode: str = "live"  # live | offline-fixture
    started_at: str = field(default_factory=utcnow)
    finished_at: str = ""
    scope: dict[str, Any] = field(default_factory=dict)
    sources: list[SourceResult] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def add_source(self, s: SourceResult) -> None:
        self.sources.append(s)

    def extend(self, obs: list[Observation], rels: list[Relationship] | None = None) -> None:
        self.observations.extend(obs)
        if rels:
            self.relationships.extend(rels)

    def obs(self, kind: str) -> list[Observation]:
        return [o for o in self.observations if o.kind == kind]

    def to_dict(self) -> dict[str, Any]:
        from vestige import TOOL_NAME, __version__
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": {"name": TOOL_NAME, "version": __version__},
            "investigation": {
                "command": self.command,
                "target": self.target,
                "mode": self.mode,
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "scope": self.scope,
            },
            "sources": [s.to_dict() for s in self.sources],
            "observations": [o.to_dict() for o in self.observations],
            "relationships": [r.to_dict() for r in self.relationships],
            "findings": [f.to_dict() for f in self.findings],
            "limitations": list(self.limitations),
            "summary": self.summary(),
        }

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {s.value: 0 for s in Status}
        for s in self.sources:
            counts[s.status.value] += 1
        sev: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            sev[f.severity.value] += 1
        return {"sources": counts, "findings": sev,
                "observations": len(self.observations),
                "relationships": len(self.relationships)}
