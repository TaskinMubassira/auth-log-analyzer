"""Command line interface: python -m log_analyzer <logfile> [--format text|json|csv]"""

from __future__ import annotations

import argparse
import gzip
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

from .detectors import detect_login_attacks, detect_web_attacks
from .parsers import detect_format, parse_access_log, parse_auth_log
from .report import as_csv, as_json, as_text


def read_lines(path: Path) -> list[str]:
    opener = gzip.open if path.suffix == ".gz" else open  # rotated logs are often gzipped
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        return handle.read().splitlines()


def parse_since(value: str, now: datetime | None = None) -> datetime:
    """'24h', '7d', '30m' (relative to now) or a date/time such as '2026-10-01' / '2026-10-01 14:00'."""
    match = re.fullmatch(r"(\d+)([mhd])", value.strip().lower())
    if match:
        amount, unit = int(match[1]), match[2]
        delta = {"m": timedelta(minutes=amount), "h": timedelta(hours=amount), "d": timedelta(days=amount)}[unit]
        return (now or datetime.now()) - delta
    try:
        return datetime.fromisoformat(value.strip())
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid --since value: {value!r} (use 24h, 7d or 2026-10-01)") from None


def _naive(moment: datetime) -> datetime:
    """Access logs carry a UTC offset, auth.log does not; compare both as local wall-clock time."""
    return moment.replace(tzinfo=None)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="log_analyzer", description="Find brute force, spraying and web attacks in server logs.")
    parser.add_argument("logfile", type=Path, help="auth.log or access.log (.gz supported)")
    parser.add_argument("--format", choices=["text", "json", "csv"], default="text")
    parser.add_argument("--threshold", type=int, default=5, help="failed logins that count as an attack (default 5)")
    parser.add_argument("--window", type=int, default=10, help="time window in minutes (default 10)")
    parser.add_argument("--year", type=int, help="year for auth.log timestamps (default: this year)")
    parser.add_argument("--since", type=parse_since, help="only events after this: 24h, 7d, 30m or a date like 2026-10-01")
    args = parser.parse_args(argv)

    if not args.logfile.is_file():
        parser.error(f"file not found: {args.logfile}")
    lines = read_lines(args.logfile)
    try:
        kind = detect_format(lines[:50])
    except ValueError as error:
        parser.error(str(error))

    if kind == "auth":
        events = [e for e in parse_auth_log(lines, args.year) if not args.since or _naive(e.time) >= args.since]
        findings = detect_login_attacks(events, args.threshold, timedelta(minutes=args.window))
    else:
        events = [e for e in parse_access_log(lines) if not args.since or _naive(e.time) >= args.since]
        findings = detect_web_attacks(events)

    output = {"json": lambda: as_json(findings), "csv": lambda: as_csv(findings)}.get(
        args.format, lambda: as_text(findings, str(args.logfile), len(events))
    )()
    print(output)
    # Exit code 2 when something critical or high was found, so the tool can drive alerts.
    return 2 if any(f.severity in ("critical", "high") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
