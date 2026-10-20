# Security, scope, privacy and responsible use

## Authorised use only
VESTIGE is for security research on assets you own or have **written permission** to assess, and for education.
Collecting public data is not the same as having permission to test. Follow the terms of every provider you query.

## Passive by default; active needs two flags
| Mode | Traffic that reaches the target | How to get it |
|---|---|---|
| Passive (default) | none directly. DNS goes through your recursive resolver; third-party APIs see the *domain name* you ask about | default |
| Active HTTP/TLS | GETs to the apex host over HTTPS (+ `robots.txt`, `sitemap.xml`, `security.txt`, MTA-STS policy), one TLS handshake | `--http-checks` **and** `--confirm-authorized` |

`--http-checks` alone or `--confirm-authorized` alone sends nothing (tested). `--confirm-authorized` without
`--http-checks` is rejected with an error. The report records which mode was used (`scope.mode`).

## Active-check safeguards (see `core/scope.py`, `modules/web.py`; all unit-tested)
* Only GET. No payloads, no authentication attempts, no fuzzing, no brute force, no port scanning.
* Start URL and **every redirect hop** must be the authorised domain or a subdomain of it. Out-of-scope or non-HTTP(S)
  redirects (`evil.com`, `example.com.evil.com`, `file://`, `127.0.0.1`, `169.254.169.254`) are recorded but **not followed**.
* Credentials in URLs are refused; max 5 redirects; response bodies are capped (256 KB pages, 1 MB sitemap); no retries on target requests.
* Before connecting, the hostname is resolved and **refused if any address is non-public** (private, loopback,
  link-local, reserved, CGNAT, multicast), which blocks SSRF-style pivots to internal services.
* TLS verification is never disabled; failures are reported rather than bypassed.
* **Residual risk:** the address check and the later connection are separate DNS resolutions, so a hostile DNS server
  could in principle answer differently the second time (DNS rebinding, a time-of-check/time-of-use gap). Mitigation
  here is scope restriction to the domain you declared authority over; fully pinning the connection to the checked
  IP would require a custom transport adapter (listed as future work).

## What VESTIGE will not do
Bypass logins, CAPTCHAs, privacy settings or anti-bot protections (those platforms are reported `UNKNOWN`/`BLOCKED`);
probe mailboxes (no SMTP `RCPT TO`/VRFY); look up breaches or credentials; scrape contacts; find addresses or
identities from phone numbers; submit URLs to public scanners; brute-force subdomains.

## Privacy
* The local part of an email address is validated in memory and **masked** (`j***@example.com`) in all outputs.
* Phone numbers are masked in report targets (country code + last four digits kept). The full E.164 value still
  appears in the phone observation of that report, so treat phone reports as personal data.
* Archived URLs: sensitive query parameter **values** (tokens, keys, sessions, emails, phones…) are replaced by
  `[REDACTED]` before they are stored. Userinfo and fragments are dropped.
* Registrant/contact entities from RDAP/WHOIS are not collected.
* Private/loopback/reserved IPs are never sent to third-party services.
* Use `python vestige.py purge --out-dir <dir> --cache` to delete generated reports and cached responses.
  `purge` only deletes files named `vestige-*.json|html|md` directly in the given directory (no recursion, no symlinks).

## Secrets handling
* API keys come only from environment variables / `.env` (git-ignored). `env.example` contains no values.
* The HTTP client redacts known key values and token shapes (GitHub PATs, AWS key IDs, JWTs, `Bearer …`, `access_key=`…)
  from error messages and the `--verbose` log (logging filter). Cache keys are derived from the redacted URL.
* Reports are scrubbed per string for the loaded key values; keys are never intentionally placed in reports.
* `python vestige.py sources` shows only *set / not set*.
* NumVerify is called over **HTTPS only**; the original code used `http://`.
* Do not commit `.env`, reports or `vestige-output/` (ignored by `.gitignore`).

## Reputation & exposure data are not verdicts
AbuseIPDB scores, VirusTotal engine counts and Shodan InternetDB CVE lists are third-party opinions. They can be
stale, wrong, or inflated by shared infrastructure. VESTIGE caps their findings at MEDIUM, describes them as such,
and never labels a domain malicious.

## Reporting a vulnerability in VESTIGE
Open a private security advisory on the GitHub repository, or contact the maintainer (mayhack).
