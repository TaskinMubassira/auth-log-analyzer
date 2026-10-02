"""Turn raw log lines into structured events.

Supported formats:
- Linux auth.log (OpenSSH): failed and accepted logins
- Nginx / Apache "combined" access logs
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator

SSH_FAILED = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: Failed (?:password|publickey) for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port \d+"
)
SSH_ACCEPTED = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: Accepted (?:password|publickey) for "
    r"(?P<user>\S+) from (?P<ip>[\d.:a-fA-F]+) port \d+"
)
ACCESS = re.compile(
    r'^(?P<ip>[\d.:a-fA-F]+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) \S+(?: "[^"]*" "(?P<agent>[^"]*)")?'
)


@dataclass(frozen=True)
class LoginEvent:
    time: datetime
    ip: str
    user: str
    success: bool


@dataclass(frozen=True)
class HttpEvent:
    time: datetime
    ip: str
    method: str
    path: str
    status: int
    agent: str


def parse_auth_log(lines: Iterable[str], year: int | None = None) -> Iterator[LoginEvent]:
    """auth.log has no year in its timestamps, so the current year is assumed unless one is given."""
    year = year or datetime.now().year
    for line in lines:
        for pattern, success in ((SSH_FAILED, False), (SSH_ACCEPTED, True)):
            match = pattern.match(line)
            if match:
                when = datetime.strptime(f"{year} {' '.join(match['ts'].split())}", "%Y %b %d %H:%M:%S")
                yield LoginEvent(when, match["ip"], match["user"], success)
                break


def parse_access_log(lines: Iterable[str]) -> Iterator[HttpEvent]:
    for line in lines:
        match = ACCESS.match(line)
        if match:
            when = datetime.strptime(match["ts"], "%d/%b/%Y:%H:%M:%S %z")
            yield HttpEvent(when, match["ip"], match["method"], match["path"], int(match["status"]), match["agent"] or "")


def detect_format(first_lines: list[str]) -> str:
    """'auth' or 'access', guessed from the first lines of a file."""
    for line in first_lines:
        if "sshd[" in line:
            return "auth"
        if ACCESS.match(line):
            return "access"
    raise ValueError("Unknown log format (expected an OpenSSH auth.log or an Nginx/Apache access log)")
