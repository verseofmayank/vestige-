# VESTIGE report: vestige-demo.example

> **FIXTURE DATA: this is an offline demonstration, not a live scan.**

- Command: `demo`
- Started: 2026-10-20T20:42:11Z
- Finished: 2026-10-20T20:42:11Z
- Scope: `{"root_domain": "vestige-demo.example", "http_checks_enabled": true, "mode": "active-http-authorised"}`
- Sources: 22 OK, 0 empty, 0 failed, 3 skipped

## Findings (observations, not confirmed vulnerabilities)

### [MEDIUM] VST-TLS-001: TLS certificate expires in 12 days
- **Target:** vestige-demo.example
- **Evidence:** notAfter 2026-10-13T00:00:00+00:00
- **Source:** direct-tls · **Confidence:** high · **Observed:** 2026-10-20T20:42:11Z
- **Why it matters:** An unrenewed certificate will cause outages at expiry.
- **Next step:** Renew or fix automated renewal.
- **Reference:** RFC 5280

### [LOW] VST-EXP-001: Passive scanner data lists CVE identifiers for 104.20.30.40
- **Target:** 104.20.30.40
- **Evidence:** 1 CVE ID(s) in Shodan InternetDB (unverified), e.g. CVE-2021-41773
- **Source:** shodan-internetdb · **Confidence:** low · **Observed:** 2026-10-20T20:42:11Z
- **Why it matters:** InternetDB infers vulnerabilities from service banners seen by a crawler, which can be stale, backported-patched or wrong. VESTIGE did not test the host.
- **Next step:** Verify the actual software version and patch status on the host (with authorisation).

### [LOW] VST-REG-001: Domain registration expires in 35 days
- **Target:** vestige-demo.example
- **Evidence:** expiration: 2026-11-05T09:00:00Z (via rdap)
- **Source:** rdap (rdap.demo.example) · **Confidence:** high · **Observed:** 2026-10-20T20:42:11Z
- **Why it matters:** An expired or soon-to-expire domain can lapse, causing outages and exposing the name to re-registration by others.
- **Next step:** Renew the domain and enable auto-renew; check that registrar contacts are current.

### [LOW] VST-REP-001: AbuseIPDB reports abuse confidence 32% for 104.20.30.40
- **Target:** 104.20.30.40
- **Evidence:** score=32, reports=7, distinct reporters=3, last=2026-09-20T12:00:00+00:00
- **Source:** abuseipdb · **Confidence:** medium · **Observed:** 2026-10-20T20:42:11Z
- **Why it matters:** AbuseIPDB aggregates community reports over 90 days. Shared hosting, NAT and compromised-then-cleaned hosts can inflate scores; it is not proof the owner is malicious.
- **Next step:** Review the report categories on AbuseIPDB and check whether the host was compromised or is shared infrastructure.

### [LOW] VST-REP-001: AbuseIPDB reports abuse confidence 32% for 104.20.30.41
- **Target:** 104.20.30.41
- **Evidence:** score=32, reports=7, distinct reporters=3, last=2026-09-20T12:00:00+00:00
- **Source:** abuseipdb · **Confidence:** medium · **Observed:** 2026-10-20T20:42:11Z
- **Why it matters:** AbuseIPDB aggregates community reports over 90 days. Shared hosting, NAT and compromised-then-cleaned hosts can inflate scores; it is not proof the owner is malicious.
- **Next step:** Review the report categories on AbuseIPDB and check whether the host was compromised or is shared infrastructure.

### [LOW] VST-REP-001: AbuseIPDB reports abuse confidence 32% for 2606:4700:20::6814:1e28
- **Target:** 2606:4700:20::6814:1e28
- **Evidence:** score=32, reports=7, distinct reporters=3, last=2026-09-20T12:00:00+00:00
- **Source:** abuseipdb · **Confidence:** medium · **Observed:** 2026-10-20T20:42:11Z
- **Why it matters:** AbuseIPDB aggregates community reports over 90 days. Shared hosting, NAT and compromised-then-cleaned hosts can inflate scores; it is not proof the owner is malicious.
- **Next step:** Review the report categories on AbuseIPDB and check whether the host was compromised or is shared infrastructure.

### [LOW] VST-WEB-001: HSTS header not set on HTTPS site
- **Target:** vestige-demo.example
- **Evidence:** https://vestige-demo.example/ returned HTTP 200 without Strict-Transport-Security.
- **Source:** direct-http · **Confidence:** high · **Observed:** 2026-10-20T20:42:11Z
- **Why it matters:** Without HSTS, a browser's first plain-HTTP visit can be downgraded or intercepted by a network attacker. This is a hardening gap, not an exploitable flaw by itself.
- **Next step:** Send Strict-Transport-Security: max-age=31536000; includeSubDomains once all subdomains support HTTPS.
- **Reference:** RFC 6797

### [INFO] VST-DNS-001: DNSSEC not enabled
- **Target:** vestige-demo.example
- **Evidence:** No DNSKEY or DS record found for the zone.
- **Source:** dns · **Confidence:** medium · **Observed:** 2026-10-20T20:42:11Z
- **Why it matters:** DNSSEC adds origin authentication to DNS answers. It is optional, and many well-run domains do not use it.
- **Next step:** Consider DNSSEC if the registrar and DNS host support it.
- **Reference:** RFC 4033

### [INFO] VST-DNS-003: No CAA records
- **Target:** vestige-demo.example
- **Evidence:** No CAA record set at vestige-demo.example.
- **Source:** dns · **Confidence:** medium · **Observed:** 2026-10-20T20:42:11Z
- **Why it matters:** CAA restricts which certificate authorities may issue certificates. Absence means any CA may issue.
- **Next step:** Consider publishing CAA records naming the CAs you use.
- **Reference:** RFC 8659

### [INFO] VST-HIST-001: 1 historical hostname(s) no longer resolve
- **Target:** vestige-demo.example
- **Evidence:** old-shop.vestige-demo.example
- **Source:** wayback/urlscan + dns · **Confidence:** medium · **Observed:** 2026-10-20T20:42:11Z
- **Why it matters:** These names appear in archives but returned no DNS answer when tested. They may be decommissioned; check that no dangling CNAMEs/records point to released resources. VESTIGE did not test for takeover.
- **Next step:** Confirm the hostnames are intentionally retired.

### [INFO] VST-MAIL-002: DMARC policy is monitoring-only (p=none)
- **Target:** vestige-demo.example
- **Evidence:** _dmarc.vestige-demo.example: p=none; reports to mailto:dmarc-reports@vestige-demo.example
- **Source:** dns · **Confidence:** high · **Observed:** 2026-10-20T20:42:11Z
- **Why it matters:** p=none asks receivers not to act on failing mail. It is a normal first step of a DMARC rollout but offers no enforcement.
- **Next step:** If reports show legitimate mail is aligned, move to p=quarantine and then p=reject.
- **Reference:** RFC 7489 s6.3

### [INFO] VST-MAIL-020: No MTA-STS policy published
- **Target:** vestige-demo.example
- **Evidence:** No TXT record at _mta-sts.vestige-demo.example
- **Source:** dns · **Confidence:** high · **Observed:** 2026-10-20T20:42:11Z
- **Why it matters:** MTA-STS lets a domain require TLS for inbound SMTP and protects against downgrade attacks. Adoption is optional.
- **Next step:** Consider publishing MTA-STS (start in testing mode) and TLS-RPT.
- **Reference:** RFC 8461

### [INFO] VST-WEB-003: Browser hardening headers not set
- **Target:** vestige-demo.example
- **Evidence:** Missing: content-security-policy, referrer-policy, permissions-policy
- **Source:** direct-http · **Confidence:** high · **Observed:** 2026-10-20T20:42:11Z
- **Why it matters:** These headers reduce the impact of XSS, MIME sniffing and information leakage. Their absence is a defence-in-depth gap, not a vulnerability; some are irrelevant for API-only hosts.
- **Next step:** Evaluate each header against the application's needs and add where appropriate.
- **Reference:** W3C CSP3 / Fetch / Referrer-Policy / Permissions-Policy

### [INFO] VST-WEB-005: Version information disclosed in HTTP headers
- **Target:** vestige-demo.example
- **Evidence:** server: nginx/1.18.0
- **Source:** direct-http · **Confidence:** high · **Observed:** 2026-10-20T20:42:11Z
- **Why it matters:** Version strings help attackers match known vulnerabilities, but they do not mean the software is vulnerable (it may be patched or masked).
- **Next step:** Remove or genericise version banners.
- **Reference:** OWASP WSTG-INFO-02

### [INFO] VST-WEB-010: No security.txt published
- **Target:** vestige-demo.example
- **Evidence:** Neither /.well-known/security.txt nor /security.txt returned a text file.
- **Source:** direct-http · **Confidence:** medium · **Observed:** 2026-10-20T20:42:11Z
- **Why it matters:** security.txt gives researchers a standard way to report vulnerabilities. It is optional.
- **Next step:** Publish /.well-known/security.txt with Contact and Expires.
- **Reference:** RFC 9116

## Module and source status

| Module | Source | Status | Items | Detail |
|---|---|---|---|---|
| archive | urlscan (read-only search) | OK | 2 | anonymous (low rate limits) |
| archive | wayback | OK | 5 |  |
| certificates | crt.sh | OK | 8 | 3 certs, 6 names |
| dns | dns-records | OK | 14 |  |
| email | disposable-list | OK | 1 | disposable-email-domains (GitHub, maintained list) |
| email | dkim:selector1 | OK | 1 |  |
| email | dmarc | OK | 1 |  |
| email | mta-sts | OK | 1 |  |
| email | mx | OK | 2 |  |
| email | spf | OK | 1 |  |
| email | tls-rpt | OK | 1 |  |
| ips | asn (team-cymru) | OK | 6 |  |
| ips | exposure (shodan-internetdb) | OK | 1 | partial: 2606:4700:20::6814:1e28: offline |
| ips | geolocation (ipapi.co) | OK | 1 | partial: 104.20.30.41: ratelimit |
| registration | rdap | OK | 1 |  |
| reputation | abuseipdb (apex IPs) | OK | 3 |  |
| reputation | virustotal (domain) | SKIPPED | 0 | VIRUSTOTAL_KEY not set; see docs/API_SETUP.md |
| subdomains | alienvault-otx | SKIPPED | 0 | OTX_API_KEY not set; see docs/API_SETUP.md |
| subdomains | dns-verification | OK | 7 | 7 of 8 discovered names tested |
| subdomains | hackertarget | OK | 3 |  |
| subdomains | virustotal | SKIPPED | 0 | VIRUSTOTAL_KEY not set; see docs/API_SETUP.md |
| web | http-response | OK | 1 |  |
| web | robots.txt/sitemap | OK | 2 |  |
| web | security.txt | OK | 1 |  |
| web | tls-certificate | OK | 1 |  |

## Observations

### asn (2)

- `AS13335` (high; team-cymru-dns)
- `AS15169` (high; team-cymru-dns)

### certificate (3)

- `crt.sh:9001` (high; crt.sh)
- `crt.sh:9002` (high; crt.sh)
- `crt.sh:9003` (high; crt.sh)

### disposable_domain (1)

- `no` (medium; disposable-list)

### dkim (1)

- `selector1: not found` (medium; dns)

### dmarc (1)

- `v=DMARC1; p=none; rua=mailto:dmarc-reports@vestige-demo.example` (high; dns)

### dns_provider (1)

- `Cloudflare` (low; dns (inferred from NS names))

### dns_record (10)

- `vestige-demo.example A 104.20.30.40` (high; dns)
- `vestige-demo.example A 104.20.30.41` (high; dns)
- `vestige-demo.example AAAA 2606:4700:20::6814:1e28` (high; dns)
- `vestige-demo.example MX 10 mx1.vestige-demo.example.` (high; dns)
- `vestige-demo.example MX 20 mx2.vestige-demo.example.` (high; dns)
- `vestige-demo.example NS ada.ns.cloudflare.com.` (high; dns)
- `vestige-demo.example NS bob.ns.cloudflare.com.` (high; dns)
- `vestige-demo.example SOA ada.ns.cloudflare.com. dns.cloudflare.com. 2345678901 10000 2400 604800 1800` (high; dns)
- `vestige-demo.example TXT site-verification=demo-fixture-token` (high; dns)
- `vestige-demo.example TXT v=spf1 include:_spf.google.com include:sendgrid.net ~all` (high; dns)

### dnssec (1)

- `unsigned` (medium; dns)

### exposure_metadata (1)

- `104.20.30.40` (medium; shodan-internetdb)

### geolocation (1)

- `104.20.30.40` (low; ipapi.co)

### historical_url (4)

- `http://old-shop.vestige-demo.example/cart?item=4&session=[REDACTED]` (medium; wayback)
- `https://blog.vestige-demo.example/2021/hello-world` (medium; wayback)
- `https://vestige-demo.example/about` (medium; wayback)
- `https://www.vestige-demo.example/?token=[REDACTED]` (medium; urlscan)

### http_response (1)

- `vestige-demo.example` (high; direct-http)

### mta_sts (1)

- `missing` (high; dns)

### mx (2)

- `mx1.vestige-demo.example` (high; dns)
- `mx2.vestige-demo.example` (high; dns)

### registration (1)

- `vestige-demo.example` (high; rdap (rdap.demo.example))

### reputation (3)

- `abuseipdb:104.20.30.40` (medium; abuseipdb)
- `abuseipdb:104.20.30.41` (medium; abuseipdb)
- `abuseipdb:2606:4700:20::6814:1e28` (medium; abuseipdb)

### reverse_dns (1)

- `104.20.30.40 demo-edge.vestige-demo.example` (medium; dns)

### robots_txt (1)

- `vestige-demo.example` (high; direct-http)

### security_txt (1)

- `absent` (medium; direct-http)

### sitemap (1)

- `https://vestige-demo.example/sitemap.xml` (high; direct-http)

### spf (1)

- `v=spf1 include:_spf.google.com include:sendgrid.net ~all` (high; dns)

### subdomain (8)

- `api.vestige-demo.example` (high; crt.sh, hackertarget)
- `blog.vestige-demo.example` (low; wayback)
- `dev.vestige-demo.example` (low; crt.sh)
- `mail.vestige-demo.example` (medium; crt.sh)
- `old-shop.vestige-demo.example` (low; wayback)
- `staging.vestige-demo.example` (medium; crt.sh)
- `vpn.vestige-demo.example` (medium; hackertarget)
- `www.vestige-demo.example` (high; crt.sh, hackertarget, urlscan)

### tls_certificate (1)

- `vestige-demo.example` (high; direct-tls)

### tls_rpt (1)

- `missing` (high; dns)

### wildcard_dns (1)

- `absent` (medium; dns)

## Limitations

- FIXTURE DATA: produced from canned responses by `vestige demo`; no network requests were made.
- Direct checks inspected only the root host over HTTPS. Missing headers are configuration observations, not exploitable vulnerabilities. A DNS-rebinding race between the public-address check and the request is possible in principle (see docs/SECURITY.md).
- Passive subdomain sources are incomplete by nature; absence of a name is not evidence it does not exist.
- Subdomain states: 'resolved' = DNS returned an address at test time; 'no_dns_answer' = no A/AAAA answer; 'wildcard_only' = answer matches a wildcard record; 'unverified' = not tested or lookup error.
- Third-party reputation and exposure data are other parties' observations, not VESTIGE verdicts.
