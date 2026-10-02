"""Command line interface: python -m log_analyzer <logfile> [--format text|json|csv]"""

from __future__ import annotations

import argparse
import gzip
import sys
from datetime import timedelta
from pathlib import Path

from .detectors import detect_login_attacks, detect_web_attacks
from .parsers import detect_format, parse_access_log, parse_auth_log
from .report import as_csv, as_json, as_text


def read_lines(path: Path) -> list[str]:
    opener = gzip.open if path.suffix == ".gz" else open  # rotated logs are often gzipped
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        return handle.read().splitlines()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="log_analyzer", description="Find brute force, spraying and web attacks in server logs.")
    parser.add_argument("logfile", type=Path, help="auth.log or access.log (.gz supported)")
    parser.add_argument("--format", choices=["text", "json", "csv"], default="text")
    parser.add_argument("--threshold", type=int, default=5, help="failed logins that count as an attack (default 5)")
    parser.add_argument("--window", type=int, default=10, help="time window in minutes (default 10)")
    parser.add_argument("--year", type=int, help="year for auth.log timestamps (default: this year)")
    args = parser.parse_args(argv)

    if not args.logfile.is_file():
        parser.error(f"file not found: {args.logfile}")
    lines = read_lines(args.logfile)
    try:
        kind = detect_format(lines[:50])
    except ValueError as error:
        parser.error(str(error))

    if kind == "auth":
        events = list(parse_auth_log(lines, args.year))
        findings = detect_login_attacks(events, args.threshold, timedelta(minutes=args.window))
    else:
        events = list(parse_access_log(lines))
        findings = detect_web_attacks(events)

    output = {"json": lambda: as_json(findings), "csv": lambda: as_csv(findings)}.get(
        args.format, lambda: as_text(findings, str(args.logfile), len(events))
    )()
    print(output)
    # Exit code 2 when something critical or high was found, so the tool can drive alerts.
    return 2 if any(f.severity in ("critical", "high") for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
