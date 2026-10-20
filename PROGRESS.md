# VESTIGE: Progress

Legend: [x] done and tested | [~] done with stated limits | [ ] not done

- [x] Phase 1: audit of original code (`docs/AUDIT.md`)
- [x] Phase 2: package structure (`vestige/`), old `*_recon.py` scripts replaced (history preserved)
- [x] Phase 3: DNS, RDAP (+WHOIS fallback), CT, passive subdomains, DNS verification, wildcard, DNSSEC presence
- [~] crt.sh and Wayback: code + mocked tests; live services failed (502 / timeout) during development
- [x] Phase 4: email security (SPF, DMARC, MTA-STS, TLS-RPT, DKIM selector, disposable list, mail infra); breach lookup removed
- [x] Phase 5: IP intelligence (classification, rDNS, ASN, geo, InternetDB, AbuseIPDB)
- [x] Phase 6: username engine (evidence-based statuses, platforms.json, 12 verifiable + 5 unverifiable)
- [x] Phase 7: phone metadata (E.164, validity, type, region, carrier allocation, NumVerify over HTTPS)
- [x] Phase 8: web/TLS opt-in (two flags, scope-validated redirects, SSRF guard)
- [~] Phase 9: Wayback/urlscan/VirusTotal/OTX (keyed ones not exercised live)
- [x] Phase 10: `recon` command
- [x] Phase 11: correlation (JSON model; SQLite deliberately skipped)
- [x] Phase 12: rule engine
- [x] Phase 13: terminal, JSON, HTML, Markdown reports, `diff`
- [x] Phase 14-15: reliability features, Rich CLI
- [x] Phase 16: 309 offline tests passing, offline demo (`python vestige.py demo`)
- [x] Phase 17: docs

## Pending / future
DNS-rebinding-proof connection pinning; DNSSEC validation; Public Suffix List; recursive SPF expansion; subdomain-takeover candidate checks;
live verification of keyed providers; SQLite history if trend analysis is wanted.

The old `demo.png` (screenshot of the previous tool) was removed because it no longer matches the UI.
