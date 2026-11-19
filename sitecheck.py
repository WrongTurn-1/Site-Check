#!/usr/bin/env python3
"""
Site-Check  --  authorized web self-testing toolkit
===================================================

A small set of NON-DESTRUCTIVE checks for standard web weaknesses, meant to be
run by an owner against their own site before go-live.

    python sitecheck.py https://your-control-room.example.com

Run `python sitecheck.py --help` for options. Only test systems you own or are
explicitly authorized to test.
"""

from __future__ import annotations
import sys
import argparse

from sitecheck.core import (
    ScanContext, confirm_authorization, resolve_target, preflight,
)
from sitecheck import headers, tls, cookies, recon, csrf, xss, sqli, direnum, report


CHECKS = {
    "headers": "HTTP security headers (HSTS, CSP, X-Frame-Options, ...)",
    "tls": "TLS protocol / certificate inspection",
    "cookies": "Cookie flags (Secure, HttpOnly, SameSite)",
    "recon": "Exposed files, dangerous methods, HTTP->HTTPS",
    "direnum": "Common admin/interface path discovery",
    "csrf": "Anti-CSRF token presence on forms",
    "xss": "Reflected-XSS reflection test (detection only)",
    "sqli": "SQL-injection indicators (detection only)",
}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sitecheck",
        description="Non-destructive security self-test for your own website.",
        epilog="Only scan systems you own or are authorized in writing to test.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("url", nargs="?", help="Base URL of the target, e.g. https://site.example.com")
    p.add_argument("--only", help="Comma-separated subset of checks to run "
                                  f"({', '.join(CHECKS)})")
    p.add_argument("--skip", help="Comma-separated checks to skip")
    p.add_argument("--rps", type=float, default=5.0,
                   help="Max requests per second (default 5). Be gentle on prod.")
    p.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout seconds")
    p.add_argument("--insecure", action="store_true",
                   help="Do not verify TLS (still reports the problem)")
    p.add_argument("--time-based", action="store_true",
                   help="Enable the slower time-based blind SQLi check")
    p.add_argument("--wordlist", help="Custom wordlist file for direnum")
    p.add_argument("--header", action="append", default=[],
                   help="Extra request header 'Name: value' (repeatable); e.g. an auth token")
    p.add_argument("--cookie", action="append", default=[],
                   help="Cookie 'name=value' to send (repeatable); e.g. a logged-in session")
    p.add_argument("--report", default="sitecheck-report.md",
                   help="Markdown worklist output path (default sitecheck-report.md)")
    p.add_argument("--json", dest="json_out", default="sitecheck-report.json",
                   help="JSON output path (default sitecheck-report.json)")
    p.add_argument("--no-color", action="store_true", help="Disable coloured console output")
    p.add_argument("--yes", action="store_true",
                   help="Assert authorization non-interactively (use responsibly)")
    p.add_argument("-v", "--verbose", action="store_true", help="Log each request")
    p.add_argument("--list-checks", action="store_true", help="List available checks and exit")
    return p


def _kv(items: list[str], sep: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items:
        if sep in item:
            k, v = item.split(sep, 1)
            out[k.strip()] = v.strip()
    return out


def select_checks(args) -> list[str]:
    chosen = list(CHECKS)
    if args.only:
        chosen = [c.strip() for c in args.only.split(",") if c.strip() in CHECKS]
    if args.skip:
        skip = {c.strip() for c in args.skip.split(",")}
        chosen = [c for c in chosen if c not in skip]
    return chosen


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_checks:
        print("Available checks:")
        for name, desc in CHECKS.items():
            print(f"  {name:10} {desc}")
        return 0

    if not args.url:
        print("error: a target url is required (or use --list-checks)", file=sys.stderr)
        return 2

    if not args.url.startswith(("http://", "https://")):
        print("error: url must start with http:// or https://", file=sys.stderr)
        return 2

    ok, info = resolve_target(args.url)
    if not ok:
        print(f"error: {info}", file=sys.stderr)
        return 2

    if not confirm_authorization(args.url, assume_yes=args.yes):
        print("Authorization not confirmed. Aborting.", file=sys.stderr)
        return 1

    ctx = ScanContext(
        base_url=args.url,
        rps=args.rps,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        extra_headers=_kv(args.header, ":"),
        cookies=_kv(args.cookie, "="),
        verbose=args.verbose,
    )

    ok, msg = preflight(ctx)
    if msg:
        print("\n" + msg + "\n")
    if not ok:
        return 2

    checks = select_checks(args)
    print(f"\nRunning {len(checks)} check(s) against {args.url} "
          f"at <= {args.rps} req/s ...\n")

    runners = {
        "headers": lambda: headers.run(ctx),
        "tls": lambda: tls.run(ctx),
        "cookies": lambda: cookies.run(ctx),
        "recon": lambda: recon.run(ctx),
        "direnum": lambda: direnum.run(ctx, wordlist=args.wordlist),
        "csrf": lambda: csrf.run(ctx),
        "xss": lambda: xss.run(ctx),
        "sqli": lambda: sqli.run(ctx, time_based=args.time_based),
    }

    for name in checks:
        print(f"[*] {name} ...")
        try:
            runners[name]()
        except Exception as e:  # a single broken check must not kill the run
            print(f"    ! {name} errored: {e}", file=sys.stderr)

    report.print_console(ctx.findings, use_color=not args.no_color)
    report.write_markdown(ctx.findings, args.report, args.url)
    report.write_json(ctx.findings, args.json_out, args.url)
    print(f"\nWorklist written to: {args.report}")
    print(f"JSON written to:     {args.json_out}")

    # Exit non-zero if anything HIGH+ was found (useful in CI / pre-deploy gates).
    from sitecheck.core import Severity
    worst = max((f.severity for f in ctx.findings), default=Severity.INFO)
    return 3 if worst >= Severity.HIGH else 0


if __name__ == "__main__":
    sys.exit(main())
