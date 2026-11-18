"""TLS / certificate inspection. Passive: opens one TLS socket, reads the cert."""

from __future__ import annotations
import ssl
import socket
from datetime import datetime, timezone
from .core import ScanContext, Finding, Severity

MODULE = "tls"

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def run(ctx: ScanContext) -> None:
    if ctx.scheme != "https":
        ctx.add(Finding(
            MODULE, "Site is being tested over plain HTTP", Severity.HIGH,
            detail="A control-room UI linked to off-site monitoring must use HTTPS end to end.",
            remediation="Serve everything over TLS and redirect HTTP->HTTPS.",
            url=ctx.base_url))
        return

    host, port = ctx.host, ctx.port
    context = ssl.create_default_context()
    # We still want to inspect a cert even if it fails validation, so do a
    # two-stage check: strict first, then permissive for diagnostics.
    try:
        with socket.create_connection((host, port), timeout=ctx.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                cipher = ssock.cipher()
        _inspect(ctx, cert, proto, cipher)
    except ssl.SSLCertVerificationError as e:
        ctx.add(Finding(
            MODULE, "Certificate failed validation", Severity.HIGH,
            detail="Browsers will show a security warning.", evidence=str(e),
            remediation="Install a valid cert from a trusted CA (e.g. Let's Encrypt) "
                        "covering this hostname.",
            url=ctx.base_url))
        _inspect_insecure(ctx, host, port)
    except (socket.timeout, ConnectionError, OSError) as e:
        ctx.add(Finding(MODULE, "Could not establish TLS connection", Severity.INFO,
                        evidence=str(e), url=ctx.base_url))


def _inspect(ctx, cert, proto, cipher):
    if proto in WEAK_PROTOCOLS:
        ctx.add(Finding(
            MODULE, f"Negotiated weak TLS protocol: {proto}", Severity.HIGH,
            remediation="Disable TLS < 1.2 at the server. Prefer TLS 1.3.",
            url=ctx.base_url))
    else:
        ctx.add(Finding(MODULE, f"TLS protocol: {proto}", Severity.INFO, url=ctx.base_url))

    if cipher:
        name = cipher[0]
        if any(w in name for w in ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")):
            ctx.add(Finding(MODULE, f"Weak cipher negotiated: {name}", Severity.HIGH,
                            remediation="Restrict to modern AEAD ciphers (AES-GCM, ChaCha20).",
                            url=ctx.base_url))

    # Expiry
    not_after = cert.get("notAfter")
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                ctx.add(Finding(MODULE, "Certificate has EXPIRED", Severity.CRITICAL,
                                evidence=f"expired {not_after}", url=ctx.base_url))
            elif days < 21:
                ctx.add(Finding(MODULE, f"Certificate expires in {days} days", Severity.MEDIUM,
                                remediation="Renew now / check auto-renewal.", url=ctx.base_url))
            else:
                ctx.add(Finding(MODULE, f"Certificate valid for {days} more days",
                                Severity.INFO, url=ctx.base_url))
        except ValueError:
            pass


def _inspect_insecure(ctx, host, port):
    """Pull cert details even when validation failed, for diagnostics only."""
    try:
        bad_ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=ctx.timeout) as sock:
            with bad_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()  # may be {} without verification
                proto = ssock.version()
        if proto in WEAK_PROTOCOLS:
            ctx.add(Finding(MODULE, f"Negotiated weak TLS protocol: {proto}", Severity.HIGH,
                            url=ctx.base_url))
    except Exception:
        pass
