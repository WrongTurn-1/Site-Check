"""
Recon: low-touch discovery of commonly-exposed endpoints and misconfigurations.

All GETs, all against the single target host. Nothing here is destructive.
"""

from __future__ import annotations
from urllib.parse import urljoin
from .core import ScanContext, Finding, Severity

MODULE = "recon"

# Paths that often leak sensitive data if reachable.
SENSITIVE_PATHS = {
    "/.git/HEAD": (Severity.CRITICAL, "Exposed .git directory - full source may be downloadable."),
    "/.git/config": (Severity.CRITICAL, "Exposed .git config."),
    "/.env": (Severity.CRITICAL, "Exposed .env - likely contains secrets/credentials."),
    "/.env.local": (Severity.CRITICAL, "Exposed local env file."),
    "/config.php": (Severity.HIGH, "Config file reachable."),
    "/wp-config.php": (Severity.HIGH, "WordPress config reachable."),
    "/.htaccess": (Severity.MEDIUM, "Apache config reachable."),
    "/.svn/entries": (Severity.HIGH, "Exposed SVN metadata."),
    "/.DS_Store": (Severity.LOW, "macOS metadata leaks directory listing."),
    "/backup.zip": (Severity.HIGH, "Backup archive reachable."),
    "/backup.sql": (Severity.CRITICAL, "Database dump reachable."),
    "/db.sql": (Severity.CRITICAL, "Database dump reachable."),
    "/phpinfo.php": (Severity.MEDIUM, "phpinfo() leaks environment details."),
    "/server-status": (Severity.MEDIUM, "Apache server-status exposed."),
    "/.well-known/security.txt": (Severity.INFO, "security.txt present (good practice)."),
    "/robots.txt": (Severity.INFO, "robots.txt present."),
    "/admin": (Severity.INFO, "Admin path responds - ensure it is well protected."),
    "/.aws/credentials": (Severity.CRITICAL, "Cloud credentials file reachable."),
}

DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}


def run(ctx: ScanContext) -> None:
    soft404 = _calibrate_soft404(ctx)
    _check_paths(ctx, soft404)
    _check_methods(ctx)
    _check_http_to_https(ctx)


def _calibrate_soft404(ctx: ScanContext):
    """Fetch a path that cannot exist. If it returns 200, the server has a
    catch-all (common for SPAs) and we must not treat every 200 as a hit.
    Returns the catch-all body length, or None if the server 404s properly."""
    probe = urljoin(ctx.base_url, "/sitecheck_nope_8f3a2b1c")
    resp = ctx.get(probe, allow_redirects=False)
    if resp is not None and resp.status_code == 200:
        return len(resp.content)
    return None


def _looks_present(resp) -> bool:
    if resp is None:
        return False
    # Treat 200/401/403 as "exists"; 403 on .git still confirms the dir is there.
    return resp.status_code in (200, 206, 401, 403)


def _check_paths(ctx: ScanContext, soft404) -> None:
    for path, (sev, note) in SENSITIVE_PATHS.items():
        url = urljoin(ctx.base_url, path)
        resp = ctx.get(url, allow_redirects=False)
        if resp is None:
            continue
        if resp.status_code == 200:
            # Skip catch-all/soft-404 responses that just echo the same page.
            if soft404 is not None and abs(len(resp.content) - soft404) < 32:
                continue
            ctx.add(Finding(
                MODULE, f"Reachable path: {path}", sev,
                detail=note, evidence=f"HTTP {resp.status_code}, {len(resp.content)} bytes",
                remediation="Block or remove this path from the public server.",
                url=url))
        elif resp.status_code in (401, 403) and sev >= Severity.HIGH:
            ctx.add(Finding(
                MODULE, f"Protected but present: {path}", Severity.LOW,
                detail=f"{note} (returns {resp.status_code} - present but access-controlled).",
                url=url))


def _check_methods(ctx: ScanContext) -> None:
    resp = ctx.request("OPTIONS", ctx.base_url, allow_redirects=False)
    if resp is None:
        return
    allow = resp.headers.get("Allow", "") or resp.headers.get("Access-Control-Allow-Methods", "")
    enabled = {m.strip().upper() for m in allow.split(",") if m.strip()}
    risky = enabled & DANGEROUS_METHODS
    if risky:
        ctx.add(Finding(
            MODULE, f"Dangerous HTTP methods advertised: {', '.join(sorted(risky))}",
            Severity.MEDIUM, evidence=f"Allow: {allow}",
            remediation="Disable methods the app does not use (especially PUT/DELETE/TRACE).",
            url=ctx.base_url))


def _check_http_to_https(ctx: ScanContext) -> None:
    """If HTTPS target, confirm the HTTP version redirects up."""
    if ctx.scheme != "https":
        return
    http_url = f"http://{ctx.host}" + (f":{80}" if ctx.port not in (443, 80) else "") + "/"
    resp = ctx.get(http_url, allow_redirects=False)
    if resp is None:
        return
    loc = resp.headers.get("Location", "")
    if resp.status_code in (301, 302, 307, 308) and loc.startswith("https://"):
        ctx.add(Finding(MODULE, "HTTP redirects to HTTPS", Severity.INFO, url=http_url))
    elif resp.status_code == 200:
        ctx.add(Finding(
            MODULE, "Site also serves content over plain HTTP", Severity.HIGH,
            detail="HTTP should redirect to HTTPS, not serve the app.",
            remediation="Force an HTTP->HTTPS redirect and enable HSTS.", url=http_url))
