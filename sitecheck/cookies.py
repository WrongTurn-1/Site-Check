"""Cookie-flag audit. Passive: inspect Set-Cookie headers from the main page."""

from __future__ import annotations
from .core import ScanContext, Finding, Severity

MODULE = "cookies"


def run(ctx: ScanContext) -> None:
    resp = ctx.get(ctx.base_url)
    if resp is None:
        return

    # requests collapses duplicate headers, so read the raw cookie jar too.
    raw_set_cookie = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw, "headers") else []
    if not raw_set_cookie:
        sc = resp.headers.get("Set-Cookie")
        raw_set_cookie = [sc] if sc else []

    if not raw_set_cookie:
        ctx.add(Finding(MODULE, "No cookies set on the main page", Severity.INFO,
                        url=ctx.base_url))
        return

    for cookie_str in raw_set_cookie:
        lower = cookie_str.lower()
        name = cookie_str.split("=", 1)[0].strip()
        session_like = any(k in name.lower() for k in ("sess", "auth", "token", "sid", "login"))

        if "secure" not in lower:
            ctx.add(Finding(
                MODULE, f"Cookie '{name}' missing Secure flag",
                Severity.HIGH if session_like else Severity.MEDIUM,
                detail="Without Secure, the cookie can be sent over plain HTTP.",
                evidence=cookie_str[:120],
                remediation="Set the 'Secure' attribute on all cookies.", url=ctx.base_url))

        if "httponly" not in lower:
            ctx.add(Finding(
                MODULE, f"Cookie '{name}' missing HttpOnly flag",
                Severity.HIGH if session_like else Severity.MEDIUM,
                detail="Without HttpOnly, JavaScript (and thus XSS) can read the cookie.",
                evidence=cookie_str[:120],
                remediation="Set 'HttpOnly' on session/auth cookies.", url=ctx.base_url))

        if "samesite" not in lower:
            ctx.add(Finding(
                MODULE, f"Cookie '{name}' missing SameSite attribute", Severity.MEDIUM,
                detail="SameSite=Lax/Strict mitigates CSRF.",
                evidence=cookie_str[:120],
                remediation="Set 'SameSite=Lax' (or Strict for the control panel).",
                url=ctx.base_url))
        elif "samesite=none" in lower and "secure" not in lower:
            ctx.add(Finding(
                MODULE, f"Cookie '{name}' uses SameSite=None without Secure", Severity.HIGH,
                remediation="SameSite=None requires Secure.", url=ctx.base_url))
