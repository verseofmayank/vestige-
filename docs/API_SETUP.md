# Optional provider credentials

VESTIGE runs fully without any key. A source whose key is missing is reported as **SKIPPED** with the variable name
(`ABUSEIPDB_KEY not set; see docs/API_SETUP.md`); it is never silently omitted and never reported as success.

Keys are read from environment variables, or from a `.env` file in the working directory (`cp env.example .env`).
`.env` is git-ignored. Keys are never written to reports, logs or the cache (see [SECURITY.md](SECURITY.md)).
`python vestige.py sources` shows which are set (values are never printed).

| Variable | Provider / endpoint | Used by | Free tier & notes (verify current terms before relying on them) |
|---|---|---|---|
| *(none)* | RDAP (IANA bootstrap + registries) | `domain`, `recon` | public |
| *(none)* | crt.sh | `domain`, `recon` | public, often overloaded (502/timeouts happen) |
| *(none)* | HackerTarget `hostsearch` | subdomains | very small free daily quota; quota text arrives with HTTP 200 and is detected |
| *(none)* | Wayback CDX | archive | public, slow at times |
| *(none)* | Team Cymru DNS, Shodan InternetDB, ipapi.co | `ip`, `recon` | public; ipapi.co is rate-limited (returns an `error` body) |
| `URLSCAN_KEY` | urlscan.io `GET /api/v1/search/` header `API-Key` | archive | Works anonymously with lower quotas (documented as 30/min, 100/h, 500/day per IP); key raises limits. VESTIGE only searches; it never submits scans |
| `OTX_API_KEY` | AlienVault OTX `/api/v1/indicators/domain/<d>/passive_dns`, header `X-OTX-API-KEY` | subdomains | **Anonymous access now returns HTTP 429** ("Anonymous access to this endpoint is limited"), so a free OTX account key is needed |
| `VIRUSTOTAL_KEY` | VirusTotal API v3 `/domains/<d>` and `/domains/<d>/subdomains`, header `x-apikey` | reputation, subdomains | Public API: 4 req/min, 500/day, non-commercial use only. VESTIGE caps itself at 25 calls per run |
| `ABUSEIPDB_KEY` | AbuseIPDB v2 `GET /api/v2/check`, header `Key`, `maxAgeInDays=90` | `ip`, `recon` | Free plan ≈ 1,000 checks/day (limiter resets 00:00 UTC) |
| `GITHUB_TOKEN` | GitHub REST `GET /users/<name>` as `Authorization: Bearer` | `username` | Optional; raises the unauthenticated 60 req/h limit. No scopes needed (public data). Never printed |
| `NUMVERIFY_KEY` | NumVerify (apilayer) `https://apilayer.net/api/validate` | `phone` | Free plan ≈ 100 req/month (official pages list HTTPS as included in the free tier; if your plan lacks it you will get a clear `FAILED`, and VESTIGE will **not** fall back to HTTP) |

## Behaviour on errors (what you will see)

| Provider response | VESTIGE status |
|---|---|
| key missing | `SKIPPED`: "<VAR> not set; see docs/API_SETUP.md" |
| HTTP 401/403 | `FAILED`: `auth: credentials missing, invalid or access denied` |
| HTTP 429 | retried with `Retry-After`/backoff (max 30 s wait); then `FAILED`: `ratelimit` |
| HTTP 5xx / network / timeout | retried with exponential backoff; then `FAILED` with the kind |
| 200 with an error body (ipapi, NumVerify, HackerTarget) | `FAILED` (the body is inspected) |
| invalid/unexpected JSON | `FAILED`: `malformed` |
| local per-run budget used up | `FAILED`: `quota` |

## Verification status of integrations

| Integration | How it was verified |
|---|---|
| IANA RDAP + Verisign RDAP, HackerTarget, urlscan search, ipapi.co, Shodan InternetDB, Team Cymru DNS, disposable-email list, GitHub/GitLab/HN/Keybase/DEV/Docker Hub/Mastodon/Lichess/Chess.com/Codeforces/Bitbucket/Reddit APIs, DNS record queries, direct HTTP/TLS check | called **live** during development (see `PROGRESS.md`); parsers also covered by mocked tests |
| crt.sh | **live calls returned HTTP 502** throughout development (provider outage), so the parser is verified against mocked/fixture JSON in the documented crt.sh format only; the failure path (`FAILED: server: HTTP 502`) was observed live |
| Wayback CDX | live calls **timed out / were unreachable** from the development network; parser verified against mocked data in the documented CDX JSON format; the timeout path was observed live |
| WHOIS fallback | mocked socket function only (never exercised live) |
| OTX, VirusTotal, AbuseIPDB, NumVerify, urlscan *with* key | **not called live** (no keys used); request shapes follow provider documentation; parsers and error handling covered by mocked tests |
