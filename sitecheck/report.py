"""
Report generation.

Produces three views of the same findings:
  * console  - coloured, grouped by severity (live feedback)
  * markdown - a tick-box worklist you can work through, highest severity first
  * json     - machine-readable, for diffing between runs / CI
"""

from __future__ import annotations
import json
from collections import defaultdict
from datetime import datetime, timezone
from .core import Finding, Severity

ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _group(findings: list[Finding]) -> dict[Severity, list[Finding]]:
    g: dict[Severity, list[Finding]] = defaultdict(list)
    for f in findings:
        g[f.severity].append(f)
    return g


def summary_counts(findings: list[Finding]) -> dict[str, int]:
    g = _group(findings)
    return {sev.label: len(g.get(sev, [])) for sev in ORDER}


# --------------------------------------------------------------------------- #
# Console
# --------------------------------------------------------------------------- #

def print_console(findings: list[Finding], use_color: bool = True) -> None:
    g = _group(findings)
    print("\n" + "=" * 60)
    print("  SCAN RESULTS")
    print("=" * 60)
    for sev in ORDER:
        items = g.get(sev, [])
        if not items:
            continue
        print(f"\n--- {sev.label} ({len(items)}) ---")
        for f in items:
            print(f.render(use_color=use_color))
    counts = summary_counts(findings)
    actionable = sum(v for k, v in counts.items() if k != "INFO")
    print("\n" + "=" * 60)
    print("  SUMMARY: " + "  ".join(f"{k}={v}" for k, v in counts.items()))
    print(f"  {actionable} actionable finding(s) to review.")
    print("=" * 60)


# --------------------------------------------------------------------------- #
# Markdown worklist
# --------------------------------------------------------------------------- #

def write_markdown(findings: list[Finding], path: str, target: str) -> None:
    g = _group(findings)
    counts = summary_counts(findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines: list[str] = []
    lines.append(f"# Site-Check remediation worklist")
    lines.append("")
    lines.append(f"- **Target:** `{target}`")
    lines.append(f"- **Generated:** {now}")
    lines.append(f"- **Summary:** "
                 + ", ".join(f"{k} {v}" for k, v in counts.items()))
    lines.append("")
    lines.append("Work top-down: CRITICAL and HIGH items are the ones most likely to get "
                 "the control room compromised. Tick each box as you fix and re-test.")
    lines.append("")

    item_no = 0
    for sev in ORDER:
        items = g.get(sev, [])
        if not items:
            continue
        if sev == Severity.INFO:
            lines.append(f"## {sev.label} (informational — no action required)")
        else:
            lines.append(f"## {sev.label} ({len(items)})")
        lines.append("")
        for f in items:
            item_no += 1
            lines.append(f"- [ ] **{f.title}**  _(`{f.module}`)_")
            if f.url:
                lines.append(f"    - Location: `{f.url}`")
            if f.detail:
                lines.append(f"    - What: {f.detail}")
            if f.evidence:
                ev = f.evidence.replace("`", "'")
                ev = ev if len(ev) < 200 else ev[:197] + "..."
                lines.append(f"    - Evidence: `{ev}`")
            if f.remediation:
                lines.append(f"    - Fix: {f.remediation}")
            lines.append("")

    if item_no == 0:
        lines.append("_No findings recorded._")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #

def write_json(findings: list[Finding], path: str, target: str) -> None:
    payload = {
        "target": target,
        "generated": datetime.now(timezone.utc).isoformat(),
        "summary": summary_counts(findings),
        "findings": [f.to_dict() for f in findings],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
