from datetime import datetime, timedelta
from pathlib import Path

import pytest

from log_analyzer import detect_login_attacks, detect_web_attacks, parse_access_log, parse_auth_log
from log_analyzer.cli import main
from log_analyzer.parsers import LoginEvent, detect_format

SAMPLES = Path(__file__).parent.parent / "samples"


def lines(name):
    return (SAMPLES / name).read_text().splitlines()


def test_parse_auth_log_lines():
    events = list(parse_auth_log(lines("auth.log"), year=2026))
    assert len(events) == 40  # the CRON line is ignored
    first = events[1]
    assert (first.ip, first.user, first.success) == ("203.0.113.45", "root", False)
    assert first.time == datetime(2026, 10, 2, 3, 1, 0)


def test_invalid_user_lines_are_parsed():
    line = "Oct  2 03:10:00 web01 sshd[9]: Failed password for invalid user admin from 198.51.100.23 port 1 ssh2"
    (event,) = parse_auth_log([line], year=2026)
    assert event.user == "admin"


def test_parse_access_log_lines():
    events = list(parse_access_log(lines("access.log")))
    assert len(events) == 39
    assert events[0].status == 200 and events[0].path == "/"


def test_detect_format():
    assert detect_format(lines("auth.log")) == "auth"
    assert detect_format(lines("access.log")) == "access"
    with pytest.raises(ValueError):
        detect_format(["hello world"])


def test_login_findings_from_sample():
    findings = detect_login_attacks(parse_auth_log(lines("auth.log"), year=2026))
    rules = {(f.rule, f.ip) for f in findings}
    assert ("success-after-failures", "203.0.113.99") in rules
    assert ("password-spraying", "198.51.100.23") in rules
    assert ("brute-force", "203.0.113.45") in rules
    assert findings[0].severity == "critical"
    # One typo before a successful login is normal and must not be reported.
    assert not any(f.ip == "192.0.2.10" for f in findings)


def test_failures_spread_over_time_are_not_brute_force():
    start = datetime(2026, 1, 1)
    slow = [LoginEvent(start + timedelta(hours=i), "192.0.2.1", "root", False) for i in range(10)]
    assert detect_login_attacks(slow) == []


def test_web_findings_from_sample():
    findings = detect_web_attacks(parse_access_log(lines("access.log")))
    rules = {(f.rule, f.ip) for f in findings}
    assert ("injection-attempt", "203.0.113.12") in rules
    assert ("sensitive-path-probe", "198.51.100.77") in rules
    assert ("scanner", "203.0.113.200") in rules
    assert not any(f.ip == "192.0.2.50" for f in findings)  # normal visitor


@pytest.mark.parametrize("fmt", ["text", "json", "csv"])
def test_cli_exit_code_and_formats(capsys, fmt):
    code = main([str(SAMPLES / "auth.log"), "--year", "2026", "--format", fmt])
    assert code == 2
    assert "203.0.113.99" in capsys.readouterr().out


def test_parse_since_relative_and_absolute():
    from log_analyzer.cli import parse_since

    now = datetime(2026, 10, 2, 12, 0)
    assert parse_since("24h", now) == datetime(2026, 10, 1, 12, 0)
    assert parse_since("7d", now) == datetime(2026, 9, 25, 12, 0)
    assert parse_since("2026-10-02 03:20") == datetime(2026, 10, 2, 3, 20)


def test_since_filters_out_older_events(capsys):
    # Only the 03:20 onwards part of the sample: the guessed password, not the earlier brute force.
    main([str(SAMPLES / "auth.log"), "--year", "2026", "--since", "2026-10-02 03:20", "--format", "csv"])
    out = capsys.readouterr().out
    assert "203.0.113.99" in out and "203.0.113.45" not in out
