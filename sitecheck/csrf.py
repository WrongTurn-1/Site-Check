"""CSRF posture: do state-changing forms carry an anti-CSRF token?"""

from __future__ import annotations
from .core import ScanContext, Finding, Severity
from .forms import discover_forms

MODULE = "csrf"


def run(ctx: ScanContext) -> None:
    forms = discover_forms(ctx)
    if not forms:
        ctx.add(Finding(MODULE, "No HTML forms found on the main page", Severity.INFO,
                        detail="If the app is a SPA/API, check CSRF protection at the API layer.",
                        url=ctx.base_url))
        return

    for form in forms:
        if form.method == "post" and not form.has_csrf_token:
            ctx.add(Finding(
                MODULE, "POST form without a visible anti-CSRF token", Severity.MEDIUM,
                detail=f"Form action={form.action} fields={list(form.inputs)}",
                remediation="Add a per-session CSRF token (synchroniser pattern) and/or "
                            "rely on SameSite cookies. Critical for the control panel's "
                            "state-changing actions.",
                url=form.source_url))
        elif form.method == "post":
            ctx.add(Finding(MODULE, "POST form includes an anti-CSRF token", Severity.INFO,
                            url=form.source_url))
