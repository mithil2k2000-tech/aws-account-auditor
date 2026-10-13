"""Turning an audit result into something to read or to feed elsewhere."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime

from .models import Severity
from .runner import AuditResult


def summary_counts(result: AuditResult) -> dict[str, int]:
    counts = Counter(f.severity for f in result.findings)
    return {s.name: counts.get(s, 0) for s in sorted(Severity, reverse=True)}


def monthly_waste(result: AuditResult) -> float:
    return round(sum(f.monthly_cost_usd or 0 for f in result.findings), 2)


def to_json(result: AuditResult) -> str:
    return json.dumps(
        {
            "account_id": result.account_id,
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "regions": result.regions,
            "summary": summary_counts(result),
            "estimated_monthly_waste_usd": monthly_waste(result),
            "findings": [f.to_dict() for f in result.sorted_findings()],
            "errors": result.errors,
        },
        indent=2,
        default=str,
    )


def to_markdown(result: AuditResult) -> str:
    lines = [
        f"# AWS account audit: {result.account_id}",
        "",
        f"Generated {datetime.now(UTC):%Y-%m-%d %H:%M} UTC across {len(result.regions)} region(s).",
        "",
        "| Severity | Findings |",
        "| --- | --- |",
    ]
    lines += [f"| {name} | {count} |" for name, count in summary_counts(result).items()]
    waste = monthly_waste(result)
    if waste:
        lines += [
            "",
            f"Estimated spend on unused resources: **${waste:,.2f} a month** "
            "(list prices; an estimate, not your bill).",
        ]
    for finding in result.sorted_findings():
        lines += [
            "",
            f"## {finding.severity.name}: {finding.check}",
            "",
            f"- **Resource:** `{finding.resource}` ({finding.region})",
            f"- **What:** {finding.message}",
            f"- **Fix:** {finding.remediation}",
        ]
        if finding.monthly_cost_usd:
            lines.append(f"- **Cost:** about ${finding.monthly_cost_usd:,.2f} a month")
    if result.errors:
        lines += ["", "## Checks that could not run", ""]
        lines += [f"- `{e['check']}` in {e['region']}: {e['error']}" for e in result.errors]
    if not result.findings:
        lines += ["", "No findings."]
    return "\n".join(lines) + "\n"


def to_text(result: AuditResult, colour: bool = True) -> str:
    colours = {
        Severity.CRITICAL: "\033[1;31m",
        Severity.HIGH: "\033[31m",
        Severity.MEDIUM: "\033[33m",
        Severity.LOW: "\033[36m",
        Severity.INFO: "\033[2m",
    }
    reset = "\033[0m" if colour else ""
    lines = [f"Account {result.account_id}, {len(result.regions)} region(s)", ""]
    for finding in result.sorted_findings():
        tag = f"{finding.severity.name:<8}"
        if colour:
            tag = f"{colours[finding.severity]}{tag}{reset}"
        cost = f"  (~${finding.monthly_cost_usd:,.2f}/month)" if finding.monthly_cost_usd else ""
        lines.append(f"{tag} {finding.region:<14} {finding.message}{cost}")
    counts = ", ".join(f"{n.lower()} {c}" for n, c in summary_counts(result).items() if c)
    lines += ["", f"Findings: {counts or 'none'}"]
    if monthly_waste(result):
        lines.append(f"Estimated monthly spend on unused resources: ${monthly_waste(result):,.2f}")
    for error in result.errors:
        lines.append(f"Could not run {error['check']} in {error['region']}: {error['error']}")
    return "\n".join(lines) + "\n"
