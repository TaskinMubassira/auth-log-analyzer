"""Output formats: readable text, JSON and CSV."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import asdict

from .detectors import Finding

ICONS = {"critical": "[!!]", "high": "[! ]", "medium": "[~ ]", "low": "[. ]"}


def as_text(findings: list[Finding], source: str, total_events: int) -> str:
    lines = [f"Log analysis: {source}", f"Events parsed: {total_events}   Findings: {len(findings)}", ""]
    if not findings:
        lines.append("No suspicious activity found.")
    for f in findings:
        lines.append(f"{ICONS[f.severity]} {f.severity.upper():8} {f.rule:24} {f.ip}")
        lines.append(f"      {f.summary}")
        lines.append(f"      {f.first_seen}  ->  {f.last_seen}")
        lines.extend(f"      - {d}" for d in f.details)
        lines.append("")
    return "\n".join(lines)


def as_json(findings: list[Finding]) -> str:
    return json.dumps([asdict(f) for f in findings], indent=2)


def as_csv(findings: list[Finding]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["severity", "rule", "ip", "summary", "count", "first_seen", "last_seen"])
    for f in findings:
        writer.writerow([f.severity, f.rule, f.ip, f.summary, f.count, f.first_seen, f.last_seen])
    return buffer.getvalue()
