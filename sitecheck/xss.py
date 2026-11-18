"""
Reflected-XSS probe.

Detection only: we inject a unique, benign marker and check whether it comes
back *unescaped* in an HTML context. We never inject working exploit payloads
and never target third parties - one host, your host.
"""

from __future__ import annotations
import secrets
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from .core import ScanContext, Finding, Severity
from .forms import discover_forms, query_params

MODULE = "xss"

# A marker that, if reflected raw, proves HTML injection is possible - but the
# marker itself does nothing (no <script>, no event handler that executes).
def _marker() -> str:
    return f"scXSS{secrets.token_hex(4)}"

# Characters that must be encoded in HTML output. If they survive raw, output
# encoding is missing.
PROBE_CHARS = "<>\"'"


def run(ctx: ScanContext) -> None:
    _probe_url_params(ctx)
    _probe_forms(ctx)


def _reflects_raw(resp, marker: str) -> tuple[bool, str]:
    if resp is None:
        return False, ""
    body = resp.text or ""
    probe = f"{marker}{PROBE_CHARS}"
    if probe in body:
        return True, probe
    # Partial: marker present and at least one special char unescaped nearby.
    if marker in body:
        idx = body.find(marker)
        window = body[idx: idx + len(probe) + 10]
        if any(c in window for c in "<>"):
            return True, window
    return False, ""


def _probe_url_params(ctx: ScanContext) -> None:
    params = query_params(ctx.base_url)
    if not params:
        return
    parsed = urlparse(ctx.base_url)
    base_q = dict(parse_qsl(parsed.query))
    for param in params:
        marker = _marker()
        q = dict(base_q)
        q[param] = f"{marker}{PROBE_CHARS}"
        test_url = urlunparse(parsed._replace(query=urlencode(q)))
        resp = ctx.get(test_url)
        hit, evidence = _reflects_raw(resp, marker)
        if hit:
            ctx.add(Finding(
                MODULE, f"Reflected input not HTML-encoded (param '{param}')", Severity.HIGH,
                detail="Injected special characters were reflected unescaped - a likely "
                       "reflected-XSS sink.",
                evidence=evidence,
                remediation="Context-aware output encoding on all reflected values; add a "
                            "strict Content-Security-Policy as defence in depth.",
                url=test_url))


def _probe_forms(ctx: ScanContext) -> None:
    for form in discover_forms(ctx):
        # Only probe GET forms actively (POSTing could change state).
        if form.method != "get":
            ctx.add(Finding(
                MODULE, "POST form not auto-probed for XSS (avoids state change)",
                Severity.INFO,
                detail=f"Manually test form at {form.action} for stored/reflected XSS.",
                url=form.source_url))
            continue
        marker = _marker()
        data = {name: (val or "test") for name, val in form.inputs.items()}
        # inject into the first text-like field
        target_field = next(iter(form.inputs), None)
        if not target_field:
            continue
        data[target_field] = f"{marker}{PROBE_CHARS}"
        resp = ctx.get(form.action, params=data)
        hit, evidence = _reflects_raw(resp, marker)
        if hit:
            ctx.add(Finding(
                MODULE, f"Form field '{target_field}' reflected unescaped", Severity.HIGH,
                detail="GET form input is reflected without HTML encoding.",
                evidence=evidence,
                remediation="Encode output; validate input server-side.",
                url=form.action))
