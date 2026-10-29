"""Command-line interface."""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .checks import ALL
from .models import SEVERITY_ORDER
from .report import ORDER, finding_key, load_baseline, write_reports
from .scanner import ScanConfig, ScanError, ScopeError, run_scan

BANNER = "vapt-scanner {v} - for authorised security testing only".format(v=__version__)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vapt", description=BANNER)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list-checks", help="show available checks")
    w = sub.add_parser("serve", help="start the web dashboard")
    w.add_argument("--host", default="127.0.0.1")
    w.add_argument("--port", type=int, default=8080)
    w.add_argument("--with-lab", action="store_true",
                   help="also start the practice lab on 127.0.0.1:5000 (localhost only)")
    s = sub.add_parser("scan", help="scan a web application")
    s.add_argument("target", help="base URL, e.g. http://127.0.0.1:5000")
    s.add_argument("--authorized", action="store_true",
                   help="confirm you own the target or have written permission (required for non-local hosts)")
    s.add_argument("--max-pages", type=int, default=25)
    s.add_argument("--max-depth", type=int, default=2)
    s.add_argument("--max-requests", type=int, default=500, help="hard request budget")
    s.add_argument("--delay", type=float, default=0.0, help="seconds between requests")
    s.add_argument("--timeout", type=float, default=10.0)
    s.add_argument("--test-post", action="store_true", help="also fuzz POST forms (may change application state)")
    s.add_argument("--insecure", action="store_true", help="do not verify TLS certificates")
    s.add_argument("--header", action="append", default=[], metavar="'Name: value'")
    s.add_argument("--cookie", help="Cookie header value for authenticated scans")
    s.add_argument("--checks", help="comma-separated subset of checks")
    s.add_argument("--out", default="reports", help="report output directory")
    s.add_argument("--format", default="json,md,html", help="comma-separated: json,md,html,sarif")
    s.add_argument("--baseline", metavar="report.json",
                   help="previous JSON report; only findings not in it count towards --fail-on")
    s.add_argument("--fail-on", default="high", choices=[*ORDER[::-1], "none"],
                   help="exit 1 if a finding at/above this severity exists (default: high)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "list-checks":
        for name, mod in ALL.items():
            print(f"{name:12s} {(mod.__doc__ or '').strip().splitlines()[0]}")
        return 0

    if args.cmd == "serve":
        from .web import serve
        serve(args.host, args.port, args.with_lab)
        return 0

    headers = {}
    for h in args.header:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()
    cfg = ScanConfig(
        target=args.target, authorized=args.authorized, max_pages=args.max_pages, max_depth=args.max_depth,
        delay=args.delay, timeout=args.timeout, max_requests=args.max_requests, test_post=args.test_post,
        verify_tls=not args.insecure, headers=headers, cookie=args.cookie,
        checks=[c.strip() for c in args.checks.split(",")] if args.checks else None,
    )
    print(BANNER, file=sys.stderr)
    try:
        result = run_scan(cfg, log=lambda m: print(m, file=sys.stderr))
    except (ScopeError, ScanError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    paths = write_reports(result, args.out, [f.strip() for f in args.format.split(",")])
    print(f"\nTarget: {result.target}  ({result.pages} pages, {result.points} params, {result.requests} requests, {result.duration}s)")
    summary = result.summary()
    print("  " + "  ".join(f"{sev}: {summary[sev]}" for sev in ORDER))
    for f in result.findings:
        loc = f"{f.url}" + (f" [{f.parameter}]" if f.parameter else "")
        print(f"  [{f.severity.upper():8s}] {f.id:20s} {f.title}  -> {loc}")
    for e in result.errors:
        print(f"  ! check error: {e}", file=sys.stderr)
    print("\nReports: " + ", ".join(str(p) for p in paths))

    gating = result.findings
    if args.baseline:
        try:
            known = load_baseline(args.baseline)
        except (OSError, ValueError, KeyError) as exc:
            print(f"error: cannot read baseline: {exc}", file=sys.stderr)
            return 2
        gating = [f for f in gating if finding_key(f) not in known]
        print(f"Baseline: {len(result.findings) - len(gating)} known, {len(gating)} new finding(s)")
    if args.fail_on != "none" and any(SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[args.fail_on] for f in gating):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
