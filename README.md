# VESTIGE: OSINT & External Attack Surface Intelligence
### by mayhack | *Traces Left Behind...*

![Python](https://img.shields.io/badge/Python-3.12+-blue)
![Platform](https://img.shields.io/badge/Platform-Kali%20%7C%20Ubuntu%20%7C%20WSL%20%7C%20Windows-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

VESTIGE collects, correlates and reports **publicly available** intelligence about domains, IP addresses,
email infrastructure, usernames and phone-number metadata, for **authorised** security research and education.

It is deliberately *passive-first*, *evidence-based* and *honest about what it does not know*:

* Every source reports its own status: `OK`, `EMPTY`, `FAILED`, `SKIPPED`. A failing or rate-limited API is never shown as success.
* Findings are **observations with evidence, source, confidence, explanation and a recommended next step**, never "confirmed vulnerabilities" and never an unexplained risk score.
* A discovered subdomain is only called *resolved* after a DNS lookup actually returned an address.
* A username is only `FOUND` when the platform's own API echoes the exact username. An HTTP 200 never counts.
* Nothing contacts the target over HTTP unless you pass **both** `--http-checks` and `--confirm-authorized`.

> **Legal / ethical use.** Use VESTIGE only on assets you own or are explicitly authorised to assess.
> See [docs/SECURITY.md](docs/SECURITY.md).

---

## Install

```bash
git clone https://github.com/verseofmayank/vestige-.git
cd vestige-
python3 -m venv .venv && source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python vestige.py --help
```

Python 3.12+. Works on Kali, Ubuntu, Windows (native or WSL). Optional: `pip install -e .` gives a `vestige` command.
Optional API keys: copy `env.example` to `.env` ([docs/API_SETUP.md](docs/API_SETUP.md)). **Everything marked "no key" below works without any.**

## Try it offline (no network, no keys)

```bash
python vestige.py demo
```
Produces `examples/demo-output/*.{json,html,md}` from canned **fixture** responses for the reserved name
`vestige-demo.example`. Output is clearly labelled FIXTURE DATA; it is a demonstration of the report format, not a scan.
A pre-generated copy is committed in [examples/demo-output/](examples/demo-output/).

## Commands

| Command | What it does | Needs a key? |
|---|---|---|
| `recon -d example.com [--report html]` | Unified investigation (all modules below) + correlation + findings | no (optional keys add sources) |
| `domain -d example.com` | DNS, RDAP/WHOIS, Certificate Transparency, passive subdomains + DNS verification | no |
| `email -e user@example.com [--dkim-selector S]` | Syntax, MX, SPF, DMARC, MTA-STS, TLS-RPT, DKIM (explicit selector), disposable list | no |
| `ip -i 8.8.8.8` | Classification, rDNS, ASN, approximate geo, Shodan InternetDB, AbuseIPDB | AbuseIPDB key optional |
| `username -u name` | Evidence-based lookups on platforms with verifiable APIs | no (GitHub token optional) |
| `phone -p +919876543210` | E.164, validity, region, line type, original carrier allocation (offline library) | NumVerify optional |
| `diff old.json new.json` | Offline comparison of two JSON reports | no |
| `demo` | Offline fixture demonstration | no |
| `sources` | Which optional credentials are configured (never prints values) | no |
| `purge` | Delete generated `vestige-*` report files / cache | no |

Common options: `--report json|html|md|all` (repeatable), `--out-dir`, `--timeout`, `--limit`, `--offline`, `--no-cache`, `-v/--verbose`.

```bash
# Flagship command: passive recon + HTML report (no direct contact with the target)
python vestige.py recon -d example.com --report html --report json

# Choose modules
python vestige.py recon -d example.com -m dns,rdap,email

# Add direct HTTP/TLS checks: ONLY for targets you are authorised to test
python vestige.py recon -d example.com --http-checks --confirm-authorized --report html

# Compare two runs
python vestige.py diff vestige-output/vestige-recon-example.com-OLD.json vestige-output/vestige-recon-example.com-NEW.json
```

## What each module actually does (and does not do)

* **DNS**: A, AAAA, MX, NS, TXT, CNAME, SOA, CAA; wildcard detection (random-label probe); DNSKEY/DS *presence* (signatures are **not** validated); reverse DNS; DNS-provider inference from NS names (heuristic, low confidence).
* **Registration**: RDAP via IANA bootstrap (registrar, dates, status, nameservers; registrant/contact data is never collected). WHOIS (port 43) only as a fallback when RDAP is unavailable.
* **Certificate Transparency** (crt.sh): certificates and the names on them. CT shows *issuance*, not liveness or ownership. crt.sh is frequently overloaded; a 5xx is reported as `FAILED`, not silently ignored.
* **Passive subdomains**: crt.sh, HackerTarget (free tier, tiny quota), AlienVault OTX (key), VirusTotal (key), Wayback and urlscan *read-only search*. No brute forcing. Names are normalised (IDNA), de-duplicated and scope-filtered; sources that agree raise confidence one level.
* **Email**: public mail-infrastructure metadata only. Mailbox existence is **not** tested, and no breach/credential lookups exist in VESTIGE. In reports the local part of the address is masked.
* **IP**: private/reserved addresses are classified locally and **never sent to third parties**. ASN via Team Cymru DNS, geolocation via ipapi.co (approximate), exposure metadata via Shodan InternetDB (passive, may be stale), reputation via AbuseIPDB (key).
* **Username**: see [docs/MODULES.md](docs/MODULES.md#username). Instagram, X, TikTok, LinkedIn and Facebook are listed but reported `UNKNOWN` by design (login walls); VESTIGE never bypasses authentication, CAPTCHAs or bot protection.
* **Phone**: offline `phonenumbers` data. Region and carrier describe the *original numbering-plan allocation*, not the subscriber's location or live carrier.
* **Web/TLS** (opt-in): redirect chain restricted to the authorised scope, public-address-only destinations, security headers, TLS certificate, `security.txt` (RFC 9116), `robots.txt`/sitemap. A missing header is a hardening observation, not a vulnerability.

## Reports

JSON (stable schema, `schema_version` 1.0), a self-contained HTML report (inline CSS, no JavaScript, no external resources, autoescaped), and Markdown. See [examples/demo-output/](examples/demo-output/).

## Testing

```bash
pip install -r requirements-dev.txt
python -m pytest
```
All tests are offline (mocked HTTP and DNS). Recorded output and what each test file covers: [docs/TESTING.md](docs/TESTING.md).

## Documentation

[ARCHITECTURE](docs/ARCHITECTURE.md) · [MODULES](docs/MODULES.md) · [API_SETUP](docs/API_SETUP.md) · [SECURITY](docs/SECURITY.md) · [TESTING](docs/TESTING.md) · [INTERVIEW_PREP](docs/INTERVIEW_PREP.md) · [AUDIT](docs/AUDIT.md) · [PROGRESS](PROGRESS.md)

## Known limitations

* Passive sources are incomplete; absence of a subdomain proves nothing.
* crt.sh, Wayback and free-tier APIs are unreliable or rate-limited; expect some `FAILED`/`SKIPPED` rows (that is the tool being honest).
* Not implemented: brute-force subdomain discovery (by design), SQLite scan history (JSON + `diff` is sufficient), DNSSEC signature validation, passive-DNS providers beyond OTX, breach lookups (removed on privacy grounds), per-target active scanning.
* Verification status per provider is listed in [docs/API_SETUP.md](docs/API_SETUP.md#verification-status-of-integrations): keyed providers (OTX, VirusTotal, AbuseIPDB, NumVerify) were **not** called live, and crt.sh/Wayback were unavailable during development, so their parsers are tested against mocked responses only.

## License

MIT. See [LICENSE](LICENSE).

**Author:** mayhack, *Traces Left Behind...*
