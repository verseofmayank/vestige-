"""Run context and per-source execution wrapper.

`Context.run_source` is the single place where provider failures are converted into an
honest SourceResult (FAILED / SKIPPED / EMPTY / OK). A failing source never aborts an
investigation, and a failure is never reported as success.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from typing import Callable

from vestige.core.http_client import HttpClient, ProviderError
from vestige.core.models import Investigation, Observation, Relationship, SourceResult, Status
from vestige.core.redact import redact_text
from vestige.core.scope import Scope

log = logging.getLogger("vestige")

# Environment variable names (also read from a local .env file).
CREDENTIAL_VARS = {
    "ABUSEIPDB_KEY": "AbuseIPDB reputation",
    "VIRUSTOTAL_KEY": "VirusTotal domain intelligence",
    "OTX_API_KEY": "AlienVault OTX passive DNS",
    "URLSCAN_KEY": "urlscan.io search (higher limits; optional)",
    "GITHUB_TOKEN": "GitHub API (higher rate limit; optional)",
    "NUMVERIFY_KEY": "NumVerify phone lookup",
    "SHODAN_KEY": "reserved (Shodan InternetDB needs no key)",
}


def load_credentials() -> dict[str, str]:
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:  # python-dotenv is optional at runtime
        pass
    return {k: os.environ[k] for k in CREDENTIAL_VARS if os.environ.get(k)}


@dataclass
class Batch:
    """What a source function returns."""
    observations: list[Observation] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    detail: str = ""
    http_status: int | None = None
    # A source may report partial success: items were found but something was incomplete.
    partial: str = ""
    # For sources that annotate existing observations instead of adding new ones.
    count: int | None = None


@dataclass
class Context:
    http: HttpClient
    inv: Investigation
    resolver: object | None = None
    scope: Scope | None = None
    creds: dict[str, str] = field(default_factory=dict)
    limit: int = 500
    max_workers: int = 8
    # Test/demo hooks for the web module (None = real network behaviour).
    resolve_public_fn: Callable | None = None
    tls_fn: Callable | None = None
    on_source: Callable[[SourceResult], None] | None = None  # progress callback

    def record(self, sr: SourceResult) -> None:
        self.inv.add_source(sr)
        if self.on_source:
            try:
                self.on_source(sr)
            except Exception:  # noqa: BLE001 - UI callbacks must never break a scan
                log.debug("progress callback failed", exc_info=True)

    def secrets(self) -> list[str]:
        return list(self.creds.values())

    def run_source(self, module: str, source: str, fn: Callable[[], Batch], *,
                   requires: str | None = None, skip_reason: str | None = None) -> Batch | None:
        """Execute one source and record its status. Returns the Batch on success, else None."""
        if skip_reason:
            self.record(SourceResult(module, source, Status.SKIPPED, skip_reason))
            return None
        if requires and requires not in self.creds:
            self.record(SourceResult(
                module, source, Status.SKIPPED,
                f"{requires} not set; see docs/API_SETUP.md"))
            return None
        t0 = time.monotonic()
        try:
            batch = fn()
        except ProviderError as exc:
            status = Status.SKIPPED if exc.kind == "offline" else Status.FAILED
            self.record(SourceResult(
                module, source, status, redact_text(str(exc), self.secrets()),
                duration_s=round(time.monotonic() - t0, 2), http_status=exc.http_status))
            log.debug("source %s failed: %s", source, exc)
            return None
        except Exception as exc:  # noqa: BLE001 - last-resort guard; reported, never hidden
            log.debug("internal error in %s", source, exc_info=True)
            self.record(SourceResult(
                module, source, Status.FAILED,
                redact_text(f"internal error ({type(exc).__name__}): {exc}", self.secrets())[:300],
                duration_s=round(time.monotonic() - t0, 2)))
            return None
        n = batch.count if batch.count is not None else len(batch.observations)
        for o in batch.observations:  # provenance used by the offline diff to judge comparability
            o.data["source_refs"] = [source]
        status = Status.OK if n else Status.EMPTY
        detail = batch.detail or ("no data returned by source" if not n else "")
        if batch.partial:
            detail = (detail + "; " if detail else "") + "partial: " + batch.partial
        self.record(SourceResult(module, source, status, detail, items=n,
                                         duration_s=round(time.monotonic() - t0, 2),
                                         http_status=batch.http_status))
        self.inv.extend(batch.observations, batch.relationships)
        return batch
