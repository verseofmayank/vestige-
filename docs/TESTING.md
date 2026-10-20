# Testing

```bash
pip install -r requirements-dev.txt
python -m pytest            # all tests are offline: no network, no API keys
```

**Recorded result** (Windows 11, Python 3.12.11, run during development, full output in [test-results.txt](test-results.txt)):

```
============================= 309 passed in 3.65s =============================
```

Live smoke runs (not part of pytest) were also performed: `recon -d example.com`, `domain ... --http-checks --confirm-authorized`,
`ip -i 8.8.8.8`, `email`, `phone`, `username -u torvalds`. During them crt.sh returned HTTP 502 and Wayback timed out; both were reported as `FAILED`.

## How tests stay offline and deterministic
`FixtureTransport` (canned HTTP by URL prefix), `FakeResolver` (canned DNS, NXDOMAIN, timeouts, wildcards), a fake `requests`
session for retry/backoff, injected `resolve_public_fn`/`tls_fn` hooks for the web module, a fixed clock for the demo, an autouse
fixture that removes API-key env vars and isolates the cache directory.

## Coverage map
| File | Covers |
|---|---|
| `test_scope.py` | domain normalisation (IDN/punycode, rejects URLs/IPs/bad labels), hostname filtering, scope suffix tricks, IPv4/IPv6 classification (private, loopback, link-local/metadata, reserved, CGNAT), authorisation flags |
| `test_http_client.py` | UA, 429+Retry-After, backoff timings, 401/403/404/5xx classification, timeouts, secret-free errors, size cap, malformed JSON, cache TTL/keys, quotas, offline |
| `test_domain_modules.py` | DNS parsing, wildcard, DNSSEC states, NXDOMAIN/total failure, RDAP bootstrap/parse/walk-up/errors, WHOIS fallback, crt.sh parsing (newline SANs, wildcard, out-of-scope), HackerTarget quota text, OTX parse, subdomain states, `--limit`, correlation |
| `test_email_ip_phone.py` | email validation/masking, SPF/DMARC parsing, missing/present/inherited records, DKIM selector rules, disposable fallback, private-IP no-egress, AbuseIPDB 401/403/429/500/malformed, ipapi 200-with-error, phone validity/formats, NumVerify HTTPS/skip/error |
| `test_username.py` | HTML-200 false positives, 403/429/503/999, CAPTCHA, login redirect, other-host redirect, null semantics, list/nested strategies, unverifiable platforms never requested, ordering |
| `test_web_scope.py` | passive mode sends nothing, both flags required, redirect scope (evil.com, suffix tricks, metadata IP, file://), private-resolution refusal, loop bound, header/security.txt/robots parsing |
| `test_rules_reports_diff.py` | finding fields and conservative severities, thresholds, redaction (URL/text/headers/all report formats), JSON schema stability, determinism, HTML escaping and self-containment, purge safety, diff incl. "source failed ⇒ not comparable" |
| `test_cli.py` | commands/flags preserved, clean errors (exit 2, no traceback), offline runs, masking, diff/purge/sources |

## Bugs found by these tests (and fixed)
Total DNS failure reported wildcard/DNSSEC claims; redacting serialized JSON corrupted it; mail checks reported DNS failures as "internal error";
CIDR 240/4 classified `private` instead of `reserved`; merge order depended on thread timing; `(+91) ...` phone format rejected;
TLS check used a missing OS CA store (found by live run); HTML status table printed `dict.items` (found by screenshot, then regression-tested).

## Not covered
Live provider behaviour for keyed APIs; crt.sh/Wayback happy paths against the real services; WHOIS over a real socket; real DNS-rebinding scenarios.
