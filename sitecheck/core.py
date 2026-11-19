"""
Shared infrastructure for the Site-Check toolkit.

Everything here is intentionally conservative:
  * one target host at a time (no mass scanning)
  * global rate limiting so you never hammer your own box
  * an authorization gate so the tools are opt-in
  * a single, structured Finding model so every module reports the same way
"""

from __future__ import annotations

import sys
import time
import json
import socket
import threading
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any, Optional
from urllib.parse import urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover
    print("Missing dependency 'requests'. Install with: pip install -r requirements.txt",
          file=sys.stderr)
    raise


# --------------------------------------------------------------------------- #
# Severity + Finding model
# --------------------------------------------------------------------------- #

class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name

    @property
    def color(self) -> str:
        return {
            Severity.INFO: "\033[36m",      # cyan
            Severity.LOW: "\033[32m",       # green
            Severity.MEDIUM: "\033[33m",    # yellow
            Severity.HIGH: "\033[31m",      # red
            Severity.CRITICAL: "\033[1;31m" # bold red
        }[self]


@dataclass
class Finding:
    module: str
    title: str
    severity: Severity
    detail: str = ""
    evidence: str = ""
    remediation: str = ""
    url: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d

    def render(self, use_color: bool = True) -> str:
        reset = "\033[0m" if use_color else ""
        col = self.severity.color if use_color else ""
        tag = f"{col}[{self.severity.label:^8}]{reset}"
        out = [f"{tag} {self.module}: {self.title}"]
        if self.url:
            out.append(f"           url: {self.url}")
        if self.detail:
            out.append(f"           {self.detail}")
        if self.evidence:
            ev = self.evidence if len(self.evidence) < 300 else self.evidence[:297] + "..."
            out.append(f"           evidence: {ev}")
        if self.remediation:
            out.append(f"           fix: {self.remediation}")
        return "\n".join(out)


# --------------------------------------------------------------------------- #
# Rate-limited HTTP client
# --------------------------------------------------------------------------- #

def _silence_insecure_warnings() -> None:
    """When TLS verification is intentionally off, suppress urllib3's repeated
    InsecureRequestWarning - we already warn the user ourselves, once."""
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass


class RateLimiter:
    """Simple token-spacing limiter: at most `rps` requests per second."""

    def __init__(self, rps: float):
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delta = now - self._last
            if delta < self.min_interval:
                time.sleep(self.min_interval - delta)
            self._last = time.monotonic()


@dataclass
class ScanContext:
    """Carries shared config + state through a scan run."""
    base_url: str
    rps: float = 5.0
    timeout: float = 10.0
    user_agent: str = "SiteCheck/1.0 (authorized security self-test)"
    verify_tls: bool = True
    max_redirects: int = 5
    extra_headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    verbose: bool = False

    def __post_init__(self):
        self.limiter = RateLimiter(self.rps)
        self.findings: list[Finding] = []
        self.session = self._build_session()
        parsed = urlparse(self.base_url)
        self.host = parsed.hostname or ""
        self.scheme = parsed.scheme or "https"
        self.port = parsed.port or (443 if self.scheme == "https" else 80)

    def _build_session(self) -> requests.Session:
        if not self.verify_tls:
            _silence_insecure_warnings()
        s = requests.Session()
        retry = Retry(total=2, backoff_factor=0.3,
                      status_forcelist=[502, 503, 504],
                      allowed_methods=frozenset(["GET", "HEAD", "OPTIONS", "POST"]))
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        s.headers.update({"User-Agent": self.user_agent})
        s.headers.update(self.extra_headers)
        if self.cookies:
            s.cookies.update(self.cookies)
        s.max_redirects = self.max_redirects
        return s

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Rate-limited request. Returns None on network error (logged, non-fatal)."""
        self.limiter.wait()
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify_tls)
        kwargs.setdefault("allow_redirects", True)
        try:
            resp = self.session.request(method, url, **kwargs)
            if self.verbose:
                print(f"  -> {method} {url} [{resp.status_code}]", file=sys.stderr)
            return resp
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"  -> {method} {url} FAILED: {e}", file=sys.stderr)
            return None

    def get(self, url: str, **kwargs):
        return self.request("GET", url, **kwargs)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)


# --------------------------------------------------------------------------- #
# Authorization gate
# --------------------------------------------------------------------------- #

AUTH_BANNER = """\
============================================================
  Site-Check  --  authorized self-testing toolkit
============================================================
You are about to actively probe:

    {target}

Only run this against systems you own or are explicitly
authorized (in writing) to test. Unauthorized scanning may
be illegal in your jurisdiction.
============================================================"""


def confirm_authorization(target: str, assume_yes: bool = False) -> bool:
    print(AUTH_BANNER.format(target=target))
    if assume_yes:
        print("Authorization asserted via --yes flag.\n")
        return True
    try:
        ans = input("Type 'I AM AUTHORIZED' to continue: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return ans == "I AM AUTHORIZED"


def resolve_target(url: str) -> tuple[bool, str]:
    """Light sanity check that the host resolves before we start."""
    host = urlparse(url).hostname
    if not host:
        return False, f"Could not parse a hostname from: {url}"
    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        return False, f"DNS resolution failed for host: {host}"
    return True, host


def dump_json(findings: list[Finding], path: str) -> None:
    with open(path, "w") as fh:
        json.dump([f.to_dict() for f in findings], fh, indent=2)


# --------------------------------------------------------------------------- #
# Preflight: reachability + TLS sanity before we run the real checks
# --------------------------------------------------------------------------- #

COMMON_WEB_PORTS = [80, 443, 8080, 8000, 8443, 8888, 3000, 5000, 5173, 9000]


def _tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=min(timeout, 3.0)):
            return True
    except OSError:
        return False


def _probe_common_ports(host: str, timeout: float) -> list[int]:
    return [p for p in COMMON_WEB_PORTS if _tcp_open(host, p, timeout)]


def preflight(ctx: "ScanContext") -> tuple[bool, str]:
    """Verify the target is actually reachable before scanning.

    Returns (ok, message). On an untrusted TLS cert this flips
    ctx.verify_tls to False (with a loud notice) so the HTTP-client checks
    can still run - the cert problem is still reported by the tls module.
    """
    host, port, scheme = ctx.host, ctx.port, ctx.scheme

    # 1) Is anything listening on the target port at all?
    if not _tcp_open(host, port, ctx.timeout):
        others = _probe_common_ports(host, ctx.timeout)
        lines = [
            f"Cannot reach {host}:{port} - the connection was refused or timed out.",
            "That is a connectivity problem, not a security result: nothing is "
            "listening there (or a firewall is dropping the connection).",
        ]
        if others:
            plist = ", ".join(str(p) for p in others)
            lines.append(f"However, these ports ARE open on {host}: {plist}")
            lines.append(f"Re-run against one of them, e.g.:  "
                         f"python sitecheck.py http://{host}:{others[0]}")
        else:
            lines.append("None of the common web ports (80, 443, 8080, 8000, ...) "
                         "responded either. Check the app is running and bound to "
                         "0.0.0.0 (not 127.0.0.1), and that the host firewall allows "
                         "the port.")
        return False, "\n".join(lines)

    # 2) HTTPS: does the certificate validate? If not, continue insecurely.
    if scheme == "https" and ctx.verify_tls:
        import ssl
        try:
            sslctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=ctx.timeout) as s:
                with sslctx.wrap_socket(s, server_hostname=host):
                    pass
        except ssl.SSLError:
            ctx.verify_tls = False
            _silence_insecure_warnings()
            return True, (
                "NOTE: the target's TLS certificate is not trusted (self-signed, "
                "or issued for a different name). This is normal before a domain and "
                "real certificate are in place.\n"
                "Continuing with certificate verification OFF so the application-layer "
                "checks can run. The certificate itself is still reported as a finding."
            )
        except OSError:
            pass  # transient; let the real checks surface it

    return True, ""
