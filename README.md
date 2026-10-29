# VAPT Web Application Scanner

[![CI](https://github.com/Bunny538/vapt-webapp-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Bunny538/vapt-webapp-scanner/actions)

A lightweight **Vulnerability Assessment and Penetration Testing (VAPT)** toolkit for web applications:

1. **`vapt`**: a Python scanner that crawls a site and runs non-destructive security checks mapped to **CWE** and the **OWASP Top 10 (2021)**.
2. **`lab`**: a deliberately vulnerable Flask app (plus a `--hardened` fixed version) to practise against and to prove the scanner works.
3. **Reports** in JSON, Markdown and self-contained HTML, a CI pipeline, and Docker support.

> **Legal notice.** Only scan systems you own or have **written permission** to test. The scanner refuses non-local targets unless you pass `--authorized`. Unauthorised scanning is illegal in most jurisdictions. Results are automated and need manual verification.

## What it checks

| Check | Detects | Mapping |
|---|---|---|
| `headers` | Missing CSP, X-Frame-Options, nosniff, Referrer-Policy, HSTS, weak CSP | A05, CWE-693/1021 |
| `cookies` | Missing HttpOnly / Secure / SameSite | A05/A02, CWE-1004/614 |
| `cors` | Reflected Origin (with credentials), wildcard | A05, CWE-942 |
| `methods` | TRACE / PUT / DELETE enabled | A05, CWE-650 |
| `disclosure` | Version banners, stack traces, directory listing, sensitive HTML comments | A05, CWE-200/209/548 |
| `paths` | Exposed `.git`, `.env`, backups, phpinfo, server-status, actuator, API docs, robots.txt | A05, CWE-538/530 |
| `forms` | POST forms without CSRF token, passwords over HTTP | A01/A02, CWE-352/319 |
| `tls` | No HTTPS, invalid/expiring cert, legacy TLS | A02, CWE-295/326 |
| `redirect` | Open redirect | A01, CWE-601 |
| `xss` | Reflected XSS (inert marker tag, nothing executes) | A03, CWE-79 |
| `traversal` | Path traversal / arbitrary file read (canary files only) | A01, CWE-22 |
| `authbypass` | SQL-injection login bypass (needs `--test-post`) | A03, CWE-89 |
| `sqli` | Error-based and boolean-based SQL injection (no data extraction) | A03, CWE-89 |

**Safety by design:** GET-only injection by default (`--test-post` is opt-in), request budget (`--max-requests`), rate limiting (`--delay`), same-origin crawling, benign payloads only, no exploitation or data extraction.

## Quick start

```bash
git clone https://github.com/Bunny538/vapt-webapp-scanner.git
cd vapt-webapp-scanner
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt && pip install -e .

# Terminal 1: start the vulnerable lab (localhost only)
python -m lab.app --port 5000

# Terminal 2: scan it
vapt scan http://127.0.0.1:5000
```

Open `reports/report.html` in a browser, or use the dashboard below. A pre-generated example is in [`sample-report/`](sample-report/).

### Web dashboard

```bash
vapt serve            # http://127.0.0.1:8080
```

Start scans from the browser, watch progress live, filter findings, and download HTML, Markdown, JSON or SARIF reports. The dashboard binds to loopback, rejects foreign `Host` headers and non-JSON POSTs (DNS-rebinding and cross-site protection), and enforces the same scope guard as the CLI.

### Before / after remediation

```bash
python -m lab.app --port 5001 --hardened
vapt scan http://127.0.0.1:5001 --out reports-hardened
```

The hardened build fixes the vulnerabilities (output encoding, parameterised SQL, redirect validation, security headers, cookie flags, no exposed files) and scans with no medium or higher findings.

### Docker

```bash
docker compose up --build --abort-on-container-exit   # starts lab + scanner, writes ./reports
```

The lab is bound to `127.0.0.1` only.

## CLI reference

```text
vapt scan <url> [--authorized] [--checks xss,sqli,...] [--max-pages 25] [--max-depth 2]
                [--max-requests 500] [--delay 0.2] [--timeout 10] [--test-post] [--insecure]
                [--header 'Name: value'] [--cookie 'sid=...'] [--out reports]
                [--format json,md,html,sarif] [--baseline report.json] [--fail-on {critical,high,medium,low,info,none}]
vapt list-checks
```

`--baseline` compares against an earlier `report.json`, so `--fail-on` only gates on *new* findings. `--format sarif` writes `report.sarif` for GitHub code scanning.

Exit codes: `0` clean, `1` finding at or above `--fail-on` (default `high`, useful in CI), `2` usage or scope error.

Authenticated scan example: `vapt scan https://staging.example.com --authorized --cookie "sessionid=abc" --delay 0.3`

## Architecture

```text
vapt/
  cli.py        argparse entry point, exit codes
  scanner.py    scope guard, orchestration, dedupe/sort
  crawler.py    same-origin crawl -> pages, forms, injectable parameters
  http.py       requests wrapper: rate limit, request budget, timeouts
  checks/       one module per check, each exposes NAME + run(ctx) -> [Finding]
  web/          Flask dashboard (`vapt serve`): JSON API + static single-page UI
  report.py     JSON / Markdown / HTML writers (HTML-escaped)
lab/app.py      vulnerable + hardened Flask target
tests/          pytest: lab is started in-process; asserts detections and no false positives
```

### Add your own check

```python
# vapt/checks/mycheck.py
from ..models import Finding
NAME = "mycheck"

def run(ctx):
    r = ctx.client.get(ctx.base + "/something")
    return [Finding("VAPT-MY-001", "Title", "low", ctx.base, "What is wrong", "How to fix")] if r and r.ok else []
```

Register it in `vapt/checks/__init__.py`.

## Deploying to GitHub

```bash
git init && git add . && git commit -m "Initial commit: VAPT web app scanner"
git branch -M main
git remote add origin https://github.com/Bunny538/vapt-webapp-scanner.git
git push -u origin main
```

The workflow in `.github/workflows/ci.yml` runs the tests on Python 3.10-3.12, scans the lab, and uploads the reports as a build artifact. 

## Limitations and roadmap

- Heuristic detection: expect false positives and negatives. Always verify manually.
- No JavaScript rendering (SPAs need a headless browser), no stored/DOM XSS, no authentication flows beyond a supplied cookie or header.
- Ideas: Playwright-based crawling, SSRF probes, CVSS scoring.

## License

MIT, see [LICENSE](LICENSE).
