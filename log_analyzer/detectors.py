"""Detection rules. Each one returns Findings sorted from most to least severe."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Iterable

from .parsers import HttpEvent, LoginEvent

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

SUSPICIOUS_PATHS = re.compile(
    r"(/\.env|/\.git/|/wp-login\.php|/wp-admin|/phpmyadmin|/etc/passwd|/server-status|\.\./|/cgi-bin/|/xmlrpc\.php)", re.I
)
INJECTION = re.compile(r"(union(\s|%20|\+)+select|' *or *'1' *= *'1|%27|<script|%3Cscript|sleep\(\d+\))", re.I)
SCANNER_AGENTS = re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan)", re.I)


@dataclass
class Finding:
    rule: str
    severity: str
    ip: str
    summary: str
    count: int
    first_seen: str
    last_seen: str
    details: list[str] = field(default_factory=list)


def _max_in_window(times: list, window: timedelta) -> int:
    """Largest number of events that fall inside any single time window."""
    times = sorted(times)
    best = start = 0
    for end in range(len(times)):
        while times[end] - times[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def detect_login_attacks(
    events: Iterable[LoginEvent], threshold: int = 5, window: timedelta = timedelta(minutes=10), spray_users: int = 4
) -> list[Finding]:
    by_ip: dict[str, list[LoginEvent]] = defaultdict(list)
    for event in events:
        by_ip[event.ip].append(event)

    findings = []
    for ip, items in by_ip.items():
        items.sort(key=lambda e: e.time)
        failures = [e for e in items if not e.success]
        if not failures:
            continue
        first, last = items[0].time.isoformat(sep=" "), items[-1].time.isoformat(sep=" ")
        users = sorted({e.user for e in failures})
        burst = _max_in_window([e.time for e in failures], window)

        if burst >= threshold and len(users) >= spray_users:
            findings.append(Finding("password-spraying", "high", ip,
                                    f"{len(failures)} failed logins across {len(users)} different users",
                                    len(failures), first, last, [f"users tried: {', '.join(users[:10])}"]))
        elif burst >= threshold:
            findings.append(Finding("brute-force", "high", ip,
                                    f"{burst} failed logins within {int(window.total_seconds() // 60)} minutes",
                                    len(failures), first, last, [f"target users: {', '.join(users)}"]))

        # A success right after a run of failures from the same IP may mean the password was guessed.
        streak = 0
        for event in items:
            if not event.success:
                streak += 1
            elif streak >= threshold:
                findings.append(Finding("success-after-failures", "critical", ip,
                                        f"Successful login as '{event.user}' after {streak} failures",
                                        streak + 1, first, event.time.isoformat(sep=" "),
                                        ["Check this account now: possible compromised password"]))
                streak = 0
            else:
                streak = 0
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], -f.count))


def detect_web_attacks(events: Iterable[HttpEvent], not_found_threshold: int = 20) -> list[Finding]:
    by_ip: dict[str, list[HttpEvent]] = defaultdict(list)
    for event in events:
        by_ip[event.ip].append(event)

    findings = []
    for ip, items in by_ip.items():
        items.sort(key=lambda e: e.time)
        first, last = items[0].time.isoformat(sep=" "), items[-1].time.isoformat(sep=" ")

        injections = [e for e in items if INJECTION.search(e.path)]
        if injections:
            findings.append(Finding("injection-attempt", "high", ip, f"{len(injections)} requests with SQL injection / XSS patterns",
                                    len(injections), first, last, [e.path[:120] for e in injections[:5]]))

        probes = [e for e in items if SUSPICIOUS_PATHS.search(e.path)]
        if probes:
            findings.append(Finding("sensitive-path-probe", "medium", ip, f"{len(probes)} requests for sensitive files or admin panels",
                                    len(probes), first, last, sorted({e.path[:120] for e in probes})[:5]))

        tools = {m.group(1).lower() for e in items if (m := SCANNER_AGENTS.search(e.agent))}
        not_found = sum(1 for e in items if e.status == 404)
        if tools or not_found >= not_found_threshold:
            reason = f"scanner user-agent: {', '.join(sorted(tools))}" if tools else f"{not_found} '404 Not Found' responses"
            findings.append(Finding("scanner", "medium" if tools else "low", ip, reason, len(items), first, last))
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], -f.count))
