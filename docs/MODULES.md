# Modules and data sources

"Key" = optional API credential (see [API_SETUP.md](API_SETUP.md)). "Direct" = traffic reaches the *target's* infrastructure.

| Module (file) | Sources | Key | Direct to target? | Status values you may see |
|---|---|---|---|---|
| DNS (`dns.py`) | system/configured recursive resolver | no | No (recursive resolvers contact the authoritative servers on your behalf) | OK / FAILED (all queries failed) / SKIPPED (`--offline`) |
| Registration (`rdap.py`) | IANA RDAP bootstrap + registry RDAP; WHOIS fallback | no | No | OK / EMPTY (RDAP 404) / FAILED (`unsupported`: no RDAP for TLD → WHOIS fallback) |
| Certificates (`certificates.py`) | crt.sh | no | No | FAILED on 5xx/timeouts (common) |
| Subdomains (`subdomains.py`) | HackerTarget, AlienVault OTX, VirusTotal | OTX, VT | No | HackerTarget quota text → FAILED `ratelimit` |
| Archive (`archive.py`) | Wayback CDX, urlscan.io search (read-only) | urlscan optional | No | Wayback often times out |
| Email (`email.py`) | DNS TXT/MX; disposable-email-domains list (GitHub) | no | No (MTA-STS policy file only with `--http-checks`) | one SourceResult per check |
| IP (`ip.py`, `reputation.py`) | Team Cymru DNS, ipapi.co, Shodan InternetDB, AbuseIPDB | AbuseIPDB | No | private IPs → SKIPPED (not sent anywhere) |
| Username (`username.py`) | per-platform public APIs (`data/platforms.json`) | GitHub token optional | No (third-party platforms) | FOUND/NOT_FOUND/UNKNOWN/BLOCKED/ERROR |
| Phone (`phone.py`) | `phonenumbers` (offline); NumVerify (HTTPS) | NumVerify | No | provider SKIPPED without key |
| Web/TLS (`web.py`) | the target | no | **Yes, opt-in only** | SKIPPED in passive mode |

## DNS
Queries A, AAAA, MX, NS, TXT, CNAME, SOA, CAA at the apex. TXT strings are joined (a TXT record is a list of ≤255-byte
chunks; SPF/DKIM values are split across chunks). Wildcard detection resolves a random non-existent label
(`vestige-<12 hex>.<domain>`); answers mean a wildcard exists and subdomain results matching those addresses are marked
`wildcard_only`. DNSSEC: reports `signed` (DNSKEY and DS present), `unsigned`, `dnskey-without-ds`, `ds-without-dnskey`.
**Limitation:** presence only; VESTIGE does not validate signatures or chain of trust.

## Registration (RDAP)
Bootstrap file `https://data.iana.org/rdap/dns.json` maps TLD → RDAP base URL (RFC 9224). The domain object
(RFC 9083) provides events (registration, expiration, last changed), status, nameservers, registrar. For a subdomain
input VESTIGE walks up the labels until RDAP answers (no Public Suffix List is bundled, so `co.uk`-style names may take
an extra request). Registrant/contact entities are ignored.

## Certificates & subdomains
crt.sh `name_value` contains one SAN per line; each is split, lowercased, IDNA-normalised, wildcard-stripped and
filtered to the target domain (so `evil.com`, `user@example.com` and `notexample.com` are rejected). Names that only
appear in wildcard certificates get `low` confidence. **Subdomain states** (set by DNS verification):

| State | Meaning |
|---|---|
| (absent) / `unverified` | discovered passively, **not** tested, or the lookup errored/timed out, or beyond `--limit` |
| `resolved` | A/AAAA lookup returned addresses at test time (still not proof the host serves anything) |
| `wildcard_only` | answers equal the zone's wildcard answers; may not be a distinct host |
| `no_dns_answer` | no A/AAAA answer (NXDOMAIN or empty) |

## Email
* `validate_email`: exactly one `@`, local part ≤64 chars from the RFC 5322 atom set with correct dot placement, domain
  via the same normaliser. Quoted and internationalised local parts are rejected deliberately.
* SPF (RFC 7208): mechanisms, qualifiers, `include` list, DNS-lookup term count (top level only, nested includes are
  *not* expanded), flags for `+all`, `ptr`, `/0` ranges, huge ranges; multiple SPF records → `permerror` observation.
* DMARC (RFC 7489): `v=DMARC1` must come first; `p` required; parent-domain fallback; `pct`, `rua`, `ruf`, alignment.
* MTA-STS (RFC 8461) / TLS-RPT (RFC 8460): TXT records; the policy file is fetched only with `--http-checks --confirm-authorized`.
* DKIM: **only** with `--dkim-selector`. A missing selector does not prove DKIM is unused. Empty `p=` = revoked key.
* Null MX (RFC 7505) recognised. Mail provider inferred from MX hostnames (heuristic, low confidence).
* Disposable detection: maintained list from the `disposable-email-domains` project, cached 7 days, with a small bundled
  seed used (and reported in the detail) when the download fails.
* Removed: the original BreachDirectory call (returned credential material) and Kickbox integration.

## IP
Classification uses Python's `ipaddress` plus explicit CGNAT/special-purpose handling (IPv4-mapped IPv6 is unwrapped).
ASN comes from Team Cymru's DNS service (`<reversed-ip>.origin.asn.cymru.com`, then `AS<n>.asn.cymru.com`).
ipapi.co returns an `error` JSON body with HTTP 200 when rate limited; this is detected and reported as `ratelimit`.
Shodan InternetDB (`internetdb.shodan.io/<ip>`, free, no key) returns ports/CPEs/tags/CVE IDs; 404 = no data.
AbuseIPDB (`/api/v2/check`, header `Key`, `maxAgeInDays=90`). A score is a *community report aggregate*.

## Username
`data/platforms.json` declares how each platform proves existence:

| Strategy | Meaning |
|---|---|
| `json_path` | official/stable JSON API; FOUND only if the value at `path` equals the username (case-insensitive) |
| `json_list` | API returns a list; FOUND only if an item's `field` equals the username; `[]` → NOT_FOUND |
| `unverifiable` | login-walled/bot-protected platform; **never requested**; always UNKNOWN with the reason |

Decision order for every response: block detection first (429/401/403/999, `cf-mitigated`, redirect to another host or a
`/login`-style path, CAPTCHA/challenge markers in HTML, 503) → BLOCKED; 5xx → ERROR; documented not-found status →
NOT_FOUND; non-200 → UNKNOWN; non-JSON 200 → UNKNOWN; JSON without an exact match → UNKNOWN. Usernames are validated
(`[A-Za-z0-9._-]{1,64}`), URL-quoted, and checked against each platform's own format regex before any request.
Platforms currently implemented and exercised live: GitHub, GitLab, Hacker News, Keybase, DEV, Docker Hub,
Mastodon (mastodon.social), Lichess, Chess.com, Codeforces, Bitbucket, Gravatar; Reddit usually returns BLOCKED (403) to unauthenticated clients. Adding a platform = adding a JSON entry (and a fixture-based test).

## Phone
`phonenumbers.parse` → E.164, `is_possible_number_with_reason`, `is_valid_number`, `number_type`, geocoder description
and original carrier from bundled metadata. NumVerify (`https://apilayer.net/api/validate`, key as `access_key`) is
optional; HTTPS only. Reports mask all but the country code and last four digits.

## Web/TLS (opt-in)
Root host only, `GET` only. Records status, redirect chain (scope-validated), technology headers (`Server`,
`X-Powered-By`, …), HSTS (max-age/includeSubDomains/preload), CSP (flags `unsafe-inline`/`unsafe-eval`),
`X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, TLS verification result/issuer/expiry (full chain +
hostname verification with the certifi CA bundle), `security.txt` (RFC 9116: required Contact/Expires, expiry,
HTML soft-404 rejection), `robots.txt` counts and sitemap size (regex-parsed; no XML parser on untrusted input).

## Archive
Wayback CDX (`collapse=urlkey`, so `first_seen` is the earliest capture and `last_seen` is not the last capture; the
record says so). URLs are normalised (lowercase host, default ports stripped, sorted query) and sensitive query values
are replaced with `[REDACTED]` **before storage**. urlscan: `GET /api/v1/search/?q=domain:<d>` only; VESTIGE has no code
path that submits a scan.
