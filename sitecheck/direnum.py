"""
Content discovery against common admin / interface paths.

Uses a small bundled wordlist focused on the kind of endpoints a control-room
app exposes. Rate-limited and single-host by design.
"""

from __future__ import annotations
import os
from urllib.parse import urljoin
from .core import ScanContext, Finding, Severity

MODULE = "direnum"

_DEFAULT = [
    "admin", "administrator", "login", "dashboard", "panel", "console",
    "api", "api/v1", "api/docs", "swagger", "swagger-ui", "graphql",
    "config", "settings", "status", "health", "metrics", "debug",
    "test", "dev", "staging", "backup", "old", "tmp", "uploads",
    "monitor", "monitoring", "control", "scada", "hmi", "telemetry",
    "user", "users", "account", "register", "logout", "reset",
    ".git", ".env", "actuator", "actuator/env", "phpmyadmin", "adminer",
]


def _load_wordlist(path: str | None) -> list[str]:
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    return _DEFAULT


def run(ctx: ScanContext, wordlist: str | None = None) -> None:
    words = _load_wordlist(wordlist)
    base = ctx.base_url if ctx.base_url.endswith("/") else ctx.base_url + "/"

    # Calibrate against a random path to detect catch-all 200 responses.
    cal = ctx.get(urljoin(base, "sitecheck_nonexistent_a9f3c1/"), allow_redirects=False)
    soft404_len = len(cal.content) if cal is not None and cal.status_code == 200 else None

    for word in words:
        url = urljoin(base, word)
        resp = ctx.get(url, allow_redirects=False)
        if resp is None:
            continue
        code = resp.status_code
        if code == 200:
            if soft404_len is not None and abs(len(resp.content) - soft404_len) < 24:
                continue  # looks like the catch-all page
            sev = Severity.MEDIUM if word in (".git", ".env", "debug", "actuator/env") \
                else Severity.LOW
            ctx.add(Finding(
                MODULE, f"Path found (200): /{word}", sev,
                detail="Confirm this endpoint should be publicly reachable.",
                evidence=f"{len(resp.content)} bytes",
                remediation="Restrict, authenticate, or remove if not intended for the public.",
                url=url))
        elif code in (401, 403):
            ctx.add(Finding(
                MODULE, f"Path present but protected ({code}): /{word}", Severity.INFO,
                detail="Access-controlled - good, but confirms the endpoint exists.",
                url=url))
        elif code in (301, 302, 307, 308):
            loc = resp.headers.get("Location", "")
            ctx.add(Finding(
                MODULE, f"Path redirects ({code}): /{word}", Severity.INFO,
                evidence=f"-> {loc}", url=url))
