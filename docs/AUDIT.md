# VESTIGE — Audit of the original implementation

Audited commit: `68caa82` ("fix: resume-ready cleanup"). Every file was read in full
(`vestige.py`, `banner.py`, `domain_recon.py`, `email_recon.py`, `ip_recon.py`,
`phone_recon.py`, `username_recon.py`, `requirements.txt`, `env.example`, `README.md`).
The original code is ~400 lines; each `*_recon.py` returns one pre-formatted Rich string.

The observations in the task brief were validated against the code. Status of each:

| # | Claim | Verified? | Evidence in original code |
|---|-------|-----------|---------------------------|
| 1 | Username enumeration treats HTTP 200 as "Found" | **Confirmed** | `username_recon.check_platform`: if no `not_found` string matches, `status_code in [200,301,302]` → "Found". 20+ platforms have `not_found: None` or the generic string `"404"`; sites that return 200 for a login wall (LinkedIn, Instagram, X) are always "Found". |
| 2 | Login pages / challenges / 429s are not distinguished | **Confirmed** | 403/429/503 fall into "Not Found"; redirects are followed blindly, so a redirect to `/login` is a 200 "Found". |
| 3 | Phone integration uses insecure HTTP | **Confirmed** | `phone_recon.py` calls `http://apilayer.net/api/validate` with the API key in the query string (cleartext). |
| 4 | Broad exception handlers hide API errors | **Confirmed** | Bare `except:` in `domain_recon` (x4), `ip_recon`, `username_recon`, `email_recon`. A 401/429 from AbuseIPDB or ipapi is silently dropped (the `if r.status_code == 200` has no `else` in the AbuseIPDB and NumVerify branches), so the output simply omits the section. |
| 5 | No structured output | **Confirmed** | Every module returns one `\n`-joined Rich-markup string. Nothing is machine-readable. |
| 6 | WHOIS only, no RDAP | **Confirmed** | `python-whois` only; and it is imported lazily but **missing from `requirements.txt`**. |
| 7 | No tests | **Confirmed** | No `tests/` directory, no CI. |
| 8 | Source auth requirements undocumented | **Partly** | README lists keys but not quotas, which modules are keyless, or which are skipped. `KICKBOX_KEY` gates a Kickbox endpoint that needs no key. |

## Additional defects found

* **crt.sh parsing bug.** `name_value` contains *newline-separated* SANs. The original code
  treated each value as one name, producing "subdomains" that contain `\n`, and the `*.` strip is
  applied only to the start of the combined string.
* **No input validation.** The IP command interpolates raw user input into a URL; the domain command
  accepts anything `socket.gethostbyname` accepts (including IPs and `http://…`).
* **Email regex** `[^@]+@[^@]+\.[^@]+` is used with `re.match`, accepting whitespace, multiple `@`
  in the local part is rejected but a trailing garbage tail is not; no IDN handling.
* **Phone country guess** by digit prefix (`startswith('1')`, `'91'`, `'44'`) is wrong for most
  inputs and ignores the numbering plan; no E.164 normalisation or validity check.
* **Direct target traffic without opt-in.** `domain_recon` unconditionally fetches
  `https://<target>` (with a spoofed browser User-Agent) — a direct, active request.
  `redirects=True` follows redirects anywhere, including internal addresses.
* **Spoofed User-Agent** (`Mozilla/5.0 …`) on all username probes; no identifiable agent.
* **Breach integration** (BreachDirectory) returns credential material in the response and was
  enabled whenever a key was present. Printed raw entries to the terminal.
* **Third-party GeoIP of private input.** Private/loopback addresses would be sent to ipapi.co.
* **No retry, backoff, rate-limit handling, caching, or response-size limit.** 15 concurrent threads
  with no per-host limit.
* **Unpinned semantics / unsupported claims.** README advertises "47+ platforms" although most
  detections are not reliable; "Fast parallel searches" with no bound per host.
* **Dependency pins** (`rich==13.7.0`, `requests==2.31.0`) are stale; replaced with minimum-version
  ranges.

## What worked and was kept

* The CLI surface (`email -e`, `domain -d`, `ip -i`, `username -u`, `phone -p`) and Click/Rich stack.
* The ASCII banner and branding.
* The GitHub official-API approach, AbuseIPDB request shape, crt.sh as a source, `.env` key loading.
* The `.env`/env-var key convention (same variable names kept: `ABUSEIPDB_KEY`, `GITHUB_TOKEN`,
  `NUMVERIFY_KEY`).

## Decisions

* The legacy `*_recon.py` files were replaced by modules in the `vestige/` package (history preserved in Git).
* The breach-check integration was **removed**, not hidden behind a flag: the provider returns
  credential material, which conflicts with the privacy goals. Documented in `docs/SECURITY.md`.
* `KICKBOX_KEY` is no longer used; disposable detection uses a public maintained blocklist.
