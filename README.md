# Site-Check

A small, **non-destructive** security self-testing toolkit in Python, for
checking your *own* website against standard web attacks before you put it
live. Built for exactly the use case of "I run this control-room site and I
want to find the obvious holes before an attacker does."

> ⚠️ **Only run this against systems you own or are explicitly authorized (in
> writing) to test.** Unauthorized scanning may be illegal where you live. The
> tool asks you to confirm authorization before every run.

## What it checks

| Check      | What it looks for |
|------------|-------------------|
| `headers`  | Missing/weak security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy; stack-leaking headers |
| `tls`      | HTTPS in use, TLS protocol version, weak ciphers, certificate validity & expiry |
| `cookies`  | `Secure`, `HttpOnly`, `SameSite` flags on cookies |
| `recon`    | Exposed sensitive files (`.git`, `.env`, backups, DB dumps…), dangerous HTTP methods, HTTP→HTTPS redirect |
| `direnum`  | Discovery of common admin / interface / debug paths |
| `csrf`     | Anti-CSRF token presence on state-changing forms |
| `xss`      | Reflected-input encoding (reflected-XSS **detection**, not exploitation) |
| `sqli`     | SQL-injection **indicators** (error-based, boolean-based, optional time-based) |

The active checks (`xss`, `sqli`) are **detection-only**: they inject benign
markers / a single quote and observe the response. They do not attempt to
extract data, modify the database, or run working exploit payloads.

## Design choices that keep it safe

- **One host at a time.** No mass scanning, no target lists.
- **Rate limited** (default 5 req/s, `--rps` to change) so you don't DoS your own box.
- **Authorization gate** before every run (`--yes` to assert it non-interactively).
- **Read-mostly.** POST forms are not auto-submitted (they're flagged for manual review).

## Install

```bash
pip install -r requirements.txt
```

Python 3.9+.

## Usage

```bash
# Full scan with a human-readable worklist + JSON
python sitecheck.py https://your-control-room.example.com

# Just the passive checks, gentler rate
python sitecheck.py https://site.example.com --only headers,tls,cookies,recon --rps 2

# Authenticated scan (test behind login): pass a session cookie and/or header
python sitecheck.py https://site.example.com \
    --cookie "session=PASTE_YOUR_SESSION" \
    --header "Authorization: Bearer PASTE_TOKEN"

# Include the slower time-based blind SQLi probe
python sitecheck.py "https://site.example.com/item?id=1" --time-based

# List checks without running
python sitecheck.py --list-checks
```

### Testing parameterised endpoints

The `xss` and `sqli` checks work on URL query parameters and GET forms. To test
them, point the scanner at a URL that *has* parameters, e.g.:

```bash
python sitecheck.py "https://site.example.com/search?q=test"
```

## Output

Three outputs per run:

1. **Console** — coloured, grouped by severity, live.
2. **`sitecheck-report.md`** — a tick-box remediation worklist, highest severity
   first. This is the "list of things to work through" — fix top-down and
   re-run.
3. **`sitecheck-report.json`** — machine-readable, good for diffing between runs
   or wiring into a pre-deploy CI gate.

The process exits `3` if anything **HIGH or above** is found, `0` otherwise — so
you can gate a deployment on it:

```bash
python sitecheck.py https://staging.example.com --yes || echo "Fix findings before deploy"
```

## Severity guide

| Severity   | Meaning |
|------------|---------|
| `CRITICAL` | Direct path to compromise (exposed secrets, confirmed SQL error). Fix now. |
| `HIGH`     | Serious weakness (no HTTPS, XSS reflection, insecure session cookie). |
| `MEDIUM`   | Hardening gap that aids an attacker (missing clickjacking protection, no CSRF token). |
| `LOW`      | Minor leakage / best-practice miss. |
| `INFO`     | Context, not a problem. |

## What this is *not*

This is a first-pass hygiene scanner. It catches the common, standard mistakes
— the ones automated attackers probe for. It is **not** a substitute for a
professional penetration test or a code audit, especially for a system wired to
off-site monitoring/OT. Use it to clean up the obvious issues, then get a human
expert to look at the rest.

## Project layout

```
sitecheck.py          CLI entrypoint / orchestrator
sitecheck/
  core.py             HTTP client, rate limiter, auth gate, Finding model
  headers.py          security header audit
  tls.py              TLS / certificate checks
  cookies.py          cookie-flag audit
  recon.py            exposed files / methods / redirect
  direnum.py          content discovery
  forms.py            HTML form parsing (shared)
  csrf.py             CSRF token presence
  xss.py              reflected-XSS detection
  sqli.py             SQL-injection detection
  report.py           console / markdown / json reporting
wordlists/common.txt  default direnum wordlist
```
