# VESTIGE Architecture

## Goals that shaped the design

1. **Honest results.** A failed, rate-limited or unauthenticated source must be visible as such.
2. **Passive first.** Anything that touches the target directly is explicit opt-in and scope-checked.
3. **Explainable output.** Every record carries source, time, confidence; findings carry evidence and reasoning.
4. **Testable offline.** Network and DNS are injected, so the whole pipeline runs against fixtures.

## Layout

```
vestige.py                 entry point  (python vestige.py ...)
vestige/
  cli.py                   Click commands, Rich progress, clean error handling
  demo.py                  offline FIXTURE demonstration (canned HTTP + DNS)
  core/
    models.py              Investigation / SourceResult / Observation / Relationship / Finding dataclasses
    scope.py               domain normalisation (IDNA), IP classification, Scope (authorisation + scope checks)
    http_client.py         HttpClient: UA, timeout, retry+backoff, 429/Retry-After, size cap, cache, quotas, offline/fixtures
    cache.py               TTL file cache (keys derived from *redacted* URLs)
    redact.py              secret / token / sensitive-query redaction
    context.py             Context + run_source(): the only place provider failures become SourceResults
    correlator.py          merge/dedupe observations + relationships; deterministic ordering
    rules.py               rule engine -> Finding records
  modules/
    dns.py rdap.py certificates.py subdomains.py   domain intelligence
    email.py ip.py reputation.py                    mail security, IP intel, third-party reputation
    username.py phone.py                            identifier intelligence
    web.py                                          opt-in HTTP/TLS inspection
    archive.py                                      Wayback + urlscan (read-only)
    domain.py                                       orchestrator for `domain`/`recon`/`email`
  reporting/
    export.py              JSON, Markdown, file writing, purge
    html_report.py + report.html.j2   self-contained HTML (Jinja2, autoescape)
    terminal.py            Rich rendering (untrusted text is escaped)
    diff.py                offline report comparison
  data/                    platforms.json, dns_providers.json, disposable_seed.txt
tests/                     pytest suite (offline)
```

## Data flow

```
 CLI args --validate--> Scope + Context(HttpClient, Resolver, creds)
                              |
        modules call ctx.run_source(module, source, fn)   (parallel for independent passive sources)
                              |   fn -> Batch(observations, relationships)    ProviderError -> FAILED/SKIPPED
                              v
                 Investigation { sources[], observations[], relationships[] }
                              |  correlate(): merge by key, union sources, bump confidence on corroboration
                              |  resolve_subdomains(): DNS-test discovered names (bounded thread pool)
                              |  rules.evaluate(): observations -> findings
                              v
        terminal.render()  |  export.to_json / to_markdown  |  html_report.to_html  |  diff.compare
```

### Why `run_source`
Every provider call goes through one wrapper that (a) skips with a clear reason when a credential is
missing, (b) converts `ProviderError(kind=auth|ratelimit|quota|server|network|timeout|malformed|http)` into
`FAILED` with the cause, (c) turns offline mode into `SKIPPED`, and (d) guards against unexpected exceptions
(`FAILED: internal error`) so one bug or one provider never aborts the investigation. The `kind` also stops the
client from retrying things that cannot succeed (401/403) and from sleeping on absurd `Retry-After` values.

### HTTP client behaviour
* Identifiable User-Agent `VESTIGE-OSINT/<version> (+repo URL)`, never a browser spoof.
* Retries (2 by default, set in code) only for connection errors, timeouts and 429/500/502/503/504, with exponential
  backoff (`0.5s, 1s, ...` plus small jitter). `Retry-After` (seconds or HTTP-date) is honoured up to 30 s; longer
  waits fail fast as `ratelimit` instead of hanging.
* Streaming read with a hard byte cap per request (5 MB default, 30 MB for crt.sh, 256 KB for target pages); truncated
  responses are flagged and, for JSON APIs, rejected as malformed.
* Per-source request quotas per run (`DEFAULT_QUOTAS`) protect free tiers.
* Only successful (200) responses explicitly marked cacheable are cached (TTL); cache keys use the redacted URL.
* `FixtureTransport` replaces the network for tests/demo. `--offline` raises `offline` errors that become `SKIPPED`.

### Concurrency
* Independent passive sources (RDAP, crt.sh, each subdomain source, Wayback, urlscan, mail checks) run in a small
  `ThreadPoolExecutor` (max 6).
* Subdomain DNS verification and username lookups use bounded pools (`max_workers`, `--workers`, max 12). Threads are
  appropriate because the work is I/O-bound and the libraries (requests, dnspython) are synchronous. Shared state is
  limited to list appends and a lock-guarded quota counter; results are sorted afterwards so output is deterministic.

### Correlation model
Observations are `(kind, value)` with `source`, `observed_at`, `confidence`, `data`. Relationships are
`subject -predicate-> object` with source, time and confidence. Allowed predicates: `has_subdomain`, `resolves_to`,
`announced_by` (IP→ASN), `covered_by_certificate`, `uses_mail_exchanger`, `has_nameserver`,
`has_reputation_observation`, `archived_as`. None asserts ownership; shared hosting, shared certificates or shared
nameservers are **not** treated as evidence of common ownership.
When two sources report the same record they are merged, the `sources` list is unioned, and confidence is raised one
level. This is *corroboration, not proof*: sources can share an upstream (for example CT logs).
Merging is order-independent (inputs are sorted first) because sources finish in thread order.

### Findings engine
`rules.py` is a list of small functions `rule_*(investigation, domain, now) -> [Finding]` that read **structured
observations only**. Each finding has ID, title, severity, target, evidence, source, confidence, explanation,
recommendation, standard reference and `kind="observation"`. Severity policy: missing hardening headers ≤ LOW;
reputation results ≤ MEDIUM and always described as third-party opinion; expired certificate is the only HIGH.
No numeric aggregate risk score exists, on purpose.

### Reports
JSON is built from `Investigation.to_dict()` and passed through `redact_obj`, which scrubs known secret values and
token-shaped strings **per string** (redacting serialized text can corrupt JSON; this was a real bug caught by tests).
HTML is rendered by Jinja2 with autoescaping enabled for string templates; nothing is `|safe`; a restrictive
`Content-Security-Policy` meta tag is included; no JavaScript, no external CSS/fonts/images.

### Scope and safety layering (web checks)
`Scope.http_allowed` (both flags) → `Scope.check_url` (scheme, no credentials, host within the authorised domain) →
`resolve_public` (every address public) → request with `allow_redirects=False`, body cap, no retries → each redirect
re-validated → max 5 hops. See [SECURITY.md](SECURITY.md) for the residual DNS-rebinding race.

## Design decisions / non-goals
* **No SQLite.** Scan history is the JSON reports plus `diff`; a database would add a schema and migration surface
  without improving comparison. Revisit if long-term trending is needed.
* **No graph database.** The correlation graph is a few hundred edges; a list of typed edges is enough.
* **No async rewrite.** Threads + bounded pools meet the performance need with simpler code and tests.
* **No brute-force subdomain discovery** and no active port scanning.
* **Dependencies** (each justified): `click` CLI, `rich` UI, `requests` HTTP, `dnspython` DNS, `phonenumbers` offline
  phone data, `Jinja2` safe HTML templating, `idna` IDN handling, `python-dotenv` optional `.env` loading;
  `pytest` for development only. WHOIS and RDAP use stdlib sockets/requests (no `python-whois`).
