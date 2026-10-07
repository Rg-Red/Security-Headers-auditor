# Security-Headers-Auditor

Passive web security header scanner with a SOC-style dark terminal UI.
Fetches a target over HTTPS, follows redirects to the final landing page,
deep-inspects every security-relevant response header (not just presence),
and produces a deterministic 0-100 security score with an A+ to F grade.

**Developed by USER-Bi** (GitHub: [Rg-Red](https://github.com/Rg-Red))

## Architecture (strict modularity)

| File | Responsibility |
|---|---|
| `rules.py` | **Single source of truth.** Every header definition, regex/value validator, severity weight, scoring matrix and fix recommendation. |
| `header_auditor.py` | **Execution engine only.** HTTP client + redirect chain tracker, response parser, grader, rich terminal visualizer, JSON reporter, CLI. Contains zero header-specific knowledge. |
| `test_headers.py` | Offline unit tests (no network) covering secure sets, weak HSTS, unsafe CSP, missing headers, redirect simulation and individual validators. |

To add, remove or re-tune a header check, edit `rules.py` only - the engine
picks up new rules automatically via `rules.RULES` and `rules.VALIDATORS`.

## Audited headers

| Header | Category | Deep inspection |
|---|---|---|
| `Strict-Transport-Security` | Transport | `max-age` strength (≥180d warn, ≥365d pass), `includeSubDomains`, `preload` |
| `Content-Security-Policy` | Content Injection | `default-src`/`script-src` fallback coverage; flags `'unsafe-inline'`, `'unsafe-eval'`, wildcard/`data:`/`http:` sources |
| `X-Frame-Options` | Clickjacking | Must be `DENY` or `SAMEORIGIN`; flags obsolete `ALLOW-FROM` |
| `X-Content-Type-Options` | MIME Sniffing | Must be exactly `nosniff` |
| `Referrer-Policy` | Information Leakage | Rejects `unsafe-url`; rewards strict/no-referrer policies |
| `Permissions-Policy` | Feature Policy | Flags wildcard (`*`) feature grants |
| `Cross-Origin-Opener-Policy` | Cross-Origin Isolation | Must be in `same-origin` / `same-origin-allow-popups` / `unsafe-none` |
| `Cross-Origin-Resource-Policy` | Cross-Origin Isolation | Must be in `same-origin` / `same-site` / `cross-origin` |
| `Cross-Origin-Embedder-Policy` | Cross-Origin Isolation | Informational (0 weight), checked for valid values |
| `X-XSS-Protection` | Legacy | Informational; recommends `0` on modern stacks |
| `Server`, `X-Powered-By` | Fingerprinting | Informational-only advisory |

## Scoring matrix

Each **scored** header contributes a fixed weight to a 100-point total.
A header earns its full weight on `PASS`, half on `WARNING`, and zero on
`FAIL`/`MISSING`. Informational headers (`X-XSS-Protection`,
`Cross-Origin-Embedder-Policy`, `Server`, `X-Powered-By`) never affect the
score.

| Header | Weight |
|---|---|
| Content-Security-Policy | 25 |
| Strict-Transport-Security | 20 |
| X-Frame-Options | 15 |
| X-Content-Type-Options | 10 |
| Referrer-Policy | 10 |
| Permissions-Policy | 10 |
| Cross-Origin-Opener-Policy | 5 |
| Cross-Origin-Resource-Policy | 5 |
| **Total** | **100** |

### Letter grade

| Score | Grade |
|---|---|
| 97-100 | A+ |
| 93-96 | A |
| 90-92 | A- |
| 87-89 | B+ |
| 83-86 | B |
| 80-82 | B- |
| 77-79 | C+ |
| 73-76 | C |
| 70-72 | C- |
| 60-69 | D |
| 0-59 | F |

### Risk bands

`HARDENED` (≥90) · `ACCEPTABLE` (≥75) · `WEAK` (≥60) · `CRITICAL` (<60)

## Usage

```bash
pip install -r requirements.txt

# Basic scan
python header_auditor.py example.com

# Custom timeout, skip TLS verification, export JSON report
python header_auditor.py https://example.com -t 15 -k -o

# Scripted / CI-friendly run (no ASCII banner)
python header_auditor.py example.com --no-banner -o
```

| Flag | Description |
|---|---|
| `-t, --timeout` | Request timeout in seconds (default 10) |
| `-k, --insecure` | Disable TLS certificate verification |
| `-o, --output` | Export a JSON report to `reports/` |
| `--no-banner` | Suppress the ASCII banner for scripted runs |

JSON reports are written to `reports/headers_<host>_<timestamp>.json` and
include the redirect chain, every finding (status, severity, raw value, fix),
the score and the grade.

## Running the test suite

```bash
python -m unittest test_headers.py -v
```

All 31 tests run fully offline against mocked HTTP responses and must pass
(secure header set, weak HSTS, unsafe CSP, missing headers, redirect-chain
simulation, and individual validator unit coverage).

## Disclaimer

Security-Headers-Auditor only performs **passive** inspection of HTTP
response headers already returned by the target. It sends no exploit
payloads and performs no authentication bypass attempts. Always have
authorization before scanning a target you do not own.

## Author

**USER-Bi** - GitHub: [Rg-Red](https://github.com/Rg-Red)