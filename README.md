# 🔎 Auth Log Analyzer

A Python command line tool that reads **server logs** and points out attacks: SSH brute force, password spraying,
a successful login after many failures (a likely compromised password), and web attacks such as SQL injection
attempts, probing for `/.env` or `/wp-login.php`, and automated scanners.

```text
$ python -m log_analyzer samples/auth.log
Log analysis: samples/auth.log
Events parsed: 40   Findings: 4

[!!] CRITICAL success-after-failures   203.0.113.99
      Successful login as 'tasmia' after 6 failures
      2026-10-02 03:20:10  ->  2026-10-02 03:26:40
      - Check this account now: possible compromised password

[! ] HIGH     password-spraying        198.51.100.23
      16 failed logins across 8 different users
      - users tried: admin, git, oracle, pi, postgres, test, ubuntu, user

[! ] HIGH     brute-force              203.0.113.45
      14 failed logins within 10 minutes
      - target users: root
```

## What it detects

| Rule | Log | Severity | How |
|---|---|---|---|
| `success-after-failures` | auth.log | critical | A successful login from an IP right after ≥ 5 failures from it |
| `password-spraying` | auth.log | high | ≥ 5 failures in 10 minutes spread over ≥ 4 usernames |
| `brute-force` | auth.log | high | ≥ 5 failures in 10 minutes against the same account(s) |
| `injection-attempt` | access.log | high | SQL injection / XSS patterns in the URL (`UNION SELECT`, `' OR '1'='1`, `<script>`) |
| `sensitive-path-probe` | access.log | medium | Requests for `/.env`, `/.git/`, `/wp-login.php`, `/phpmyadmin`, `../` … |
| `scanner` | access.log | medium / low | Tool user-agents (sqlmap, nikto, gobuster…) or ≥ 20 “404 Not Found” |

Thresholds can be changed with `--threshold` and `--window`.

## Getting started

```bash
git clone https://github.com/TaskinMubassira/auth-log-analyzer.git
cd auth-log-analyzer
python -m venv .venv
.venv\Scripts\activate          # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -e ".[dev]"

python -m log_analyzer samples/auth.log                 # SSH logins
python -m log_analyzer samples/access.log               # Nginx / Apache
python -m log_analyzer /var/log/auth.log --format json  # real server, JSON output
python -m log_analyzer access.log.2.gz --format csv > report.csv
python -m log_analyzer /var/log/auth.log --since 24h      # only the last 24 hours
pytest
```

The exit code is **2** when a critical or high finding is present, so the tool can be scheduled with cron
and trigger an alert.

## Supported formats

- **Linux `auth.log` / `secure`** (OpenSSH): `Failed password`, `Failed publickey`, `Accepted …`, `invalid user`
- **Nginx / Apache combined access logs**
- Gzipped rotated logs (`.gz`)

The sample logs in [`samples/`](samples) use reserved documentation IP addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

## Project structure

```text
log_analyzer/
├── parsers.py     # regex parsers for auth.log and access logs
├── detectors.py   # detection rules (brute force, spraying, web attacks)
├── report.py      # text, JSON and CSV output
└── cli.py         # command line interface
samples/           # example logs with attacks
tests/             # pytest tests
```

## Ideas for next steps

GeoIP country lookup for attacking IPs, automatic blocking with `fail2ban`/firewall rules, and Windows Event Log support.

## License

MIT © Tasmia Taskin Mubassira
