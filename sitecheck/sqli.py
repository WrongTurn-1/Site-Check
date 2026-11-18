"""
SQL-injection probe.

Detection only, non-destructive:
  * error-based: inject a single quote, look for DB error signatures
  * boolean-based: compare a true-condition vs false-condition response
We deliberately do NOT attempt to extract data, stack queries, or run
anything that could modify the database. Time-based blind is OFF by default
(enable with --time-based) and uses a short, single sleep.
"""

from __future__ import annotations
import re
import time
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from .core import ScanContext, Finding, Severity
from .forms import query_params

MODULE = "sqli"

# Signatures of a database coughing up an error.
ERROR_SIGNATURES = [
    r"SQL syntax.*MySQL", r"Warning.*mysqli?", r"MySqlException",
    r"valid MySQL result", r"PostgreSQL.*ERROR", r"pg_query\(\)",
    r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite",
    r"ORA-\d{5}", r"Oracle error", r"Microsoft OLE DB Provider for SQL Server",
    r"Unclosed quotation mark after the character string",
    r"SQLServer JDBC Driver", r"ODBC SQL Server Driver", r"SQLSTATE\[",
    r"Incorrect syntax near", r"quoted string not properly terminated",
]
_ERROR_RE = re.compile("|".join(ERROR_SIGNATURES), re.IGNORECASE)

# Non-destructive boolean payloads (append to a parameter value).
TRUE_PAYLOAD = "' AND '1'='1"
FALSE_PAYLOAD = "' AND '1'='2"
ERROR_PAYLOAD = "'"
# Single short sleep, only when --time-based is explicitly enabled.
TIME_PAYLOAD = "' AND SLEEP(5)-- -"


def run(ctx: ScanContext, time_based: bool = False) -> None:
    params = query_params(ctx.base_url)
    if not params:
        ctx.add(Finding(MODULE, "No URL query parameters to test for SQLi", Severity.INFO,
                        detail="Point the scanner at URLs with parameters (e.g. ?id=1) or test "
                               "API endpoints manually.",
                        url=ctx.base_url))
        return

    parsed = urlparse(ctx.base_url)
    base_q = dict(parse_qsl(parsed.query))

    for param in params:
        _test_param(ctx, parsed, base_q, param, time_based)


def _build(parsed, base_q, param, value):
    q = dict(base_q)
    q[param] = value
    return urlunparse(parsed._replace(query=urlencode(q)))


def _test_param(ctx, parsed, base_q, param, time_based):
    original = base_q.get(param, "1")

    # 1) Error-based
    err_url = _build(parsed, base_q, param, original + ERROR_PAYLOAD)
    err_resp = ctx.get(err_url)
    if err_resp is not None and _ERROR_RE.search(err_resp.text or ""):
        m = _ERROR_RE.search(err_resp.text)
        ctx.add(Finding(
            MODULE, f"Database error triggered by quote (param '{param}')", Severity.CRITICAL,
            detail="A single quote produced a SQL error - strong indication of injectable input.",
            evidence=m.group(0) if m else "",
            remediation="Use parameterised queries / prepared statements everywhere. Never "
                        "concatenate user input into SQL.",
            url=err_url))
        return  # already confirmed; no need to push further

    # 2) Boolean-based differential
    base_resp = ctx.get(_build(parsed, base_q, param, original))
    true_resp = ctx.get(_build(parsed, base_q, param, original + TRUE_PAYLOAD))
    false_resp = ctx.get(_build(parsed, base_q, param, original + FALSE_PAYLOAD))
    if all(r is not None for r in (base_resp, true_resp, false_resp)):
        lt, lf = len(true_resp.content), len(false_resp.content)
        # TRUE should look like the baseline; FALSE should differ noticeably.
        base_len = len(base_resp.content)
        true_like_base = abs(lt - base_len) <= max(16, base_len * 0.02)
        false_differs = abs(lf - lt) > max(32, lt * 0.05)
        if true_like_base and false_differs:
            ctx.add(Finding(
                MODULE, f"Boolean-based SQLi indicator (param '{param}')", Severity.HIGH,
                detail=f"TRUE/FALSE payloads produced different responses "
                       f"(true={lt}B, false={lf}B, baseline={base_len}B).",
                remediation="Parameterise queries; add strict server-side input validation.",
                url=_build(parsed, base_q, param, original + TRUE_PAYLOAD)))
            return

    # 3) Time-based blind (opt-in only)
    if time_based:
        t0 = time.monotonic()
        ctx.get(_build(parsed, base_q, param, original + TIME_PAYLOAD))
        elapsed = time.monotonic() - t0
        if elapsed >= 4.5:
            ctx.add(Finding(
                MODULE, f"Time-based blind SQLi indicator (param '{param}')", Severity.HIGH,
                detail=f"Response delayed {elapsed:.1f}s after a SLEEP(5) payload.",
                remediation="Parameterise queries. Confirm manually before concluding.",
                url=ctx.base_url))
