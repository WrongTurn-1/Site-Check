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
