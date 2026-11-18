"""Security-header audit. Passive: one request, inspect the response headers."""

from __future__ import annotations
from .core import ScanContext, Finding, Severity

MODULE = "headers"

# header -> (severity if missing, human remediation)
EXPECTED = {
    "strict-transport-security": (
        Severity.HIGH,
        "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' "
        "so browsers refuse to talk to the site over plain HTTP.",
    ),
    "content-security-policy": (
        Severity.HIGH,
        "Define a Content-Security-Policy to constrain script/style sources. This is your "
        "strongest defence against XSS. Start restrictive and loosen as needed.",
    ),
    "x-frame-options": (
        Severity.MEDIUM,
        "Add 'X-Frame-Options: DENY' (or a CSP frame-ancestors directive) to block "
        "clickjacking of the control-room UI.",
    ),
    "x-content-type-options": (
        Severity.MEDIUM,
        "Add 'X-Content-Type-Options: nosniff' to stop MIME-type sniffing.",
    ),
    "referrer-policy": (
        Severity.LOW,
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' to limit referrer leakage.",
    ),
    "permissions-policy": (
        Severity.LOW,
        "Add a Permissions-Policy to disable device features (camera, geolocation, etc.) "
        "the control room does not need.",
    ),
}

# headers whose presence is a (mild) problem - they leak stack details
LEAKY = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


def run(ctx: ScanContext) -> None:
    resp = ctx.get(ctx.base_url)
    if resp is None:
        ctx.add(Finding(MODULE, "Target did not respond to the baseline request",
                        Severity.INFO, url=ctx.base_url))
        return

    headers = {k.lower(): v for k, v in resp.headers.items()}

    for name, (sev, fix) in EXPECTED.items():
        if name not in headers:
            ctx.add(Finding(
                MODULE, f"Missing security header: {name}", sev,
                detail="The server did not set this header on the main page.",
                remediation=fix, url=ctx.base_url,
            ))

    # HSTS present but weak?
    hsts = headers.get("strict-transport-security", "")
    if hsts and "max-age" in hsts:
        try:
            age = int(hsts.split("max-age=")[1].split(";")[0].strip())
            if age < 15552000:  # < 180 days
                ctx.add(Finding(
                    MODULE, "HSTS max-age is short", Severity.LOW,
                    detail=f"max-age={age}s is below the recommended ~1 year.",
                    evidence=hsts, remediation="Raise max-age to at least 31536000.",
                    url=ctx.base_url))
        except (ValueError, IndexError):
            pass

    # CSP with unsafe directives?
    csp = headers.get("content-security-policy", "")
    for bad in ("unsafe-inline", "unsafe-eval"):
        if bad in csp:
            ctx.add(Finding(
                MODULE, f"CSP allows '{bad}'", Severity.MEDIUM,
                detail="This significantly weakens CSP's XSS protection.",
                evidence=csp[:200],
                remediation=f"Remove '{bad}'; use nonces or hashes for inline scripts.",
                url=ctx.base_url))

    # Information leakage
    for name in LEAKY:
        if name in headers and headers[name].strip():
            ctx.add(Finding(
                MODULE, f"Server leaks '{name}' header", Severity.LOW,
                detail="Version/stack details help an attacker target known CVEs.",
                evidence=f"{name}: {headers[name]}",
                remediation=f"Suppress or genericise the '{name}' header at the proxy/server.",
                url=ctx.base_url))

    if not any(f.module == MODULE and f.severity >= Severity.MEDIUM for f in ctx.findings):
        ctx.add(Finding(MODULE, "Core security headers look reasonable", Severity.INFO,
                        url=ctx.base_url))
